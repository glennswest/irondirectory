//! LDAP-over-TCP message framing: each `LdapMessage` is a self-delimiting
//! BER-encoded SEQUENCE, so framing means reading the outer tag+length
//! header to know how many more bytes make up one complete message.
//!
//! Deliberately hand-rolls the tag/length parse (rather than relying on
//! `rasn`'s decode-error introspection to distinguish "not enough bytes
//! yet" from "malformed input") -- the outer tag is always a single-byte
//! universal SEQUENCE (`0x30`), so this is a handful of lines and avoids
//! depending on decoder-internal error semantics.
//!
//! Limits (finding 6bbcf7596b07): every length a client sends is checked
//! against [`Limits`] as soon as its header is in, before any of the
//! payload is buffered, and a frame that has started must be complete
//! within [`Limits::frame_timeout`]. Without them a client could declare a
//! huge length and trickle bytes forever, growing one buffer per
//! connection until the server ran out of memory. The LDAP cap is AD's
//! `MaxReceiveBuffer` default (10 MiB); the SASL one is that plus room for
//! the GSS wrap, and is the receive size the security-layer challenge
//! advertises (RFC 4752 §3.3). Between messages a connection may sit idle.

use std::time::Duration;

use rasn_ldap::LdapMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// The largest LDAP message accepted, BER header included: AD's
/// `MaxReceiveBuffer` default.
pub const MAX_LDAP_MESSAGE: usize = 10 * 1024 * 1024;

/// The largest SASL security-layer buffer accepted (RFC 4752 §3.4), the
/// 4-octet length prefix excluded: one wrapped message of up to
/// [`MAX_LDAP_MESSAGE`] plus the GSS token's header, confounder, padding
/// and checksum (well under 1 KiB for every AES enctype).
pub const MAX_SASL_BUFFER: usize = MAX_LDAP_MESSAGE + 1024;

/// How long a frame may take to arrive once its first byte has.
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(120);

/// The limits a reader enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest frame accepted, in bytes (LDAP: the whole BER message;
    /// SASL: the payload after the length prefix).
    pub max_len: usize,
    /// How long a started frame may take to complete.
    pub frame_timeout: Duration,
}

impl Limits {
    pub const LDAP: Limits = Limits { max_len: MAX_LDAP_MESSAGE, frame_timeout: FRAME_TIMEOUT };
    pub const SASL: Limits = Limits { max_len: MAX_SASL_BUFFER, frame_timeout: FRAME_TIMEOUT };
}

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("expected a SEQUENCE tag (0x30), got {0:#04x}")]
    UnexpectedTag(u8),
    #[error("indefinite-length BER is not supported over LDAP-over-TCP")]
    IndefiniteLength,
    #[error("a frame of {len} bytes is over the {max}-byte limit")]
    TooLarge { len: u128, max: usize },
    #[error("a frame did not arrive within {0:?} of its first byte")]
    Timeout(Duration),
    #[error("connection closed mid-message")]
    UnexpectedEof,
    #[error("BER decode error: {0}")]
    Decode(#[from] rasn::error::DecodeError),
    #[error("BER encode error: {0}")]
    Encode(#[from] rasn::error::EncodeError),
}

/// Returns the total byte length of the outer `LdapMessage` SEQUENCE once
/// its tag+length header is fully present in `buf`, or `None` if more
/// bytes are needed just to read the header. A total over `max` is
/// `TooLarge`, whatever the number of length octets.
fn ber_message_len(buf: &[u8], max: usize) -> Result<Option<usize>, FramingError> {
    if buf.is_empty() {
        return Ok(None);
    }
    if buf[0] != 0x30 {
        return Err(FramingError::UnexpectedTag(buf[0]));
    }
    if buf.len() < 2 {
        return Ok(None);
    }
    let first_len_byte = buf[1];
    let (header, length) = if first_len_byte & 0x80 == 0 {
        (2usize, first_len_byte as u128)
    } else {
        let num_octets = (first_len_byte & 0x7f) as usize;
        if num_octets == 0 {
            return Err(FramingError::IndefiniteLength);
        }
        if buf.len() < 2 + num_octets {
            return Ok(None);
        }
        // Up to 126 length octets: accumulate saturating, so any length
        // that does not fit is simply too large.
        let mut length: u128 = 0;
        for &b in &buf[2..2 + num_octets] {
            length = length.saturating_mul(256).saturating_add(b as u128);
        }
        (2 + num_octets, length)
    };
    let total = (header as u128).saturating_add(length);
    if total > max as u128 {
        return Err(FramingError::TooLarge { len: total, max });
    }
    Ok(Some(total as usize))
}

/// Reads more bytes into `buf`. Once a frame has started (`deadline` is
/// set), the read must finish by then.
async fn fill<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut Vec<u8>, deadline: Option<Instant>, limits: &Limits) -> Result<usize, FramingError> {
    let mut chunk = [0u8; 4096];
    let n = match deadline {
        Some(d) => tokio::time::timeout_at(d, reader.read(&mut chunk)).await.map_err(|_| FramingError::Timeout(limits.frame_timeout))??,
        None => reader.read(&mut chunk).await?,
    };
    buf.extend_from_slice(&chunk[..n]);
    Ok(n)
}

/// Reads the next `LdapMessage` off `reader`, buffering into `buf` across
/// calls (so partial reads from a prior call aren't lost). Returns `Ok(None)`
/// on a clean EOF between messages (no partial message pending). Enforces
/// [`Limits::LDAP`].
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<LdapMessage>, FramingError> {
    read_message_with(reader, buf, &Limits::LDAP).await
}

/// [`read_message`] with explicit limits.
pub async fn read_message_with<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limits: &Limits,
) -> Result<Option<LdapMessage>, FramingError> {
    let mut deadline = None;
    loop {
        if let Some(total) = ber_message_len(buf, limits.max_len)? {
            if buf.len() >= total {
                let msg: LdapMessage = rasn::ber::decode(&buf[..total])?;
                buf.drain(..total);
                return Ok(Some(msg));
            }
        }
        if !buf.is_empty() && deadline.is_none() {
            deadline = Some(Instant::now() + limits.frame_timeout);
        }
        if fill(reader, buf, deadline, limits).await? == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(FramingError::UnexpectedEof);
        }
    }
}

/// Writes one `LdapMessage` as a complete BER encoding.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &LdapMessage,
) -> Result<(), FramingError> {
    let bytes = rasn::ber::encode(msg)?;
    writer.write_all(&bytes).await?;
    Ok(())
}

/// RFC 4752 §3.4's SASL security-layer framing: each buffer (here, a GSS
/// Wrap token wrapping one BER-encoded `LdapMessage`) is preceded by a
/// 4-octet network-byte-order length. Crypto-agnostic on purpose -- the
/// caller (session.rs, which has the negotiated session key/enctype)
/// does the actual GSS wrap/unwrap; this only frames the resulting bytes.
/// Enforces [`Limits::SASL`].
pub async fn read_sized_buffer<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, FramingError> {
    read_sized_buffer_with(reader, buf, &Limits::SASL).await
}

/// [`read_sized_buffer`] with explicit limits.
pub async fn read_sized_buffer_with<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limits: &Limits,
) -> Result<Option<Vec<u8>>, FramingError> {
    let mut deadline = None;
    loop {
        if buf.len() >= 4 {
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if len > limits.max_len {
                return Err(FramingError::TooLarge { len: len as u128, max: limits.max_len });
            }
            if buf.len() >= 4 + len {
                let payload = buf[4..4 + len].to_vec();
                buf.drain(..4 + len);
                return Ok(Some(payload));
            }
        }
        if !buf.is_empty() && deadline.is_none() {
            deadline = Some(Instant::now() + limits.frame_timeout);
        }
        if fill(reader, buf, deadline, limits).await? == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(FramingError::UnexpectedEof);
        }
    }
}

/// Writes `payload` (an already-GSS-wrapped token) with its RFC 4752
/// §3.4 4-octet length prefix.
pub async fn write_sized_buffer<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), FramingError> {
    writer.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    writer.write_all(payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ber_message_len_any(buf: &[u8]) -> Result<Option<usize>, FramingError> {
        ber_message_len(buf, usize::MAX)
    }

    const SHORT: Limits = Limits { max_len: 64, frame_timeout: Duration::from_millis(200) };

    /// An LDAP UnbindRequest, message id 1: 30 05 02 01 01 42 00.
    const UNBIND: [u8; 7] = [0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00];

    #[test]
    fn a_declared_length_over_the_limit_is_refused_from_the_header_alone() {
        // 30 84 7f ff ff ff: 2 GiB declared, nothing of it sent.
        assert!(matches!(ber_message_len(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff], MAX_LDAP_MESSAGE), Err(FramingError::TooLarge { .. })));
        // Exactly at the limit is fine; one past it is not.
        let at = MAX_LDAP_MESSAGE - 5; // 30 83 xx xx xx + body
        let hdr = |n: usize| [0x30, 0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8];
        assert_eq!(ber_message_len(&hdr(at), MAX_LDAP_MESSAGE).unwrap(), Some(MAX_LDAP_MESSAGE));
        assert!(matches!(ber_message_len(&hdr(at + 1), MAX_LDAP_MESSAGE), Err(FramingError::TooLarge { .. })));
    }

    #[test]
    fn many_length_octets_are_too_large_not_silently_truncated() {
        // Nine length octets 01 00..00 = 2^64: used to wrap to 0.
        let mut b = vec![0x30, 0x89, 0x01];
        b.extend([0u8; 8]);
        assert!(matches!(ber_message_len_any(&b), Err(FramingError::TooLarge { .. })));
        // 126 octets of leading zeros then a small value is still exact.
        let mut b = vec![0x30, 0xfe];
        b.extend([0u8; 125]);
        b.push(5);
        assert_eq!(ber_message_len_any(&b).unwrap(), Some(2 + 126 + 5));
    }

    #[tokio::test]
    async fn read_message_refuses_an_oversize_frame_before_buffering_it() {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        client.write_all(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]).await.unwrap();
        client.write_all(&[0u8; 4000]).await.unwrap();
        let mut buf = Vec::new();
        let r = read_message_with(&mut server, &mut buf, &SHORT).await;
        assert!(matches!(r, Err(FramingError::TooLarge { .. })), "{r:?}");
        assert!(buf.len() <= 4096 + 6, "buffered {} bytes", buf.len());
    }

    #[tokio::test]
    async fn an_incomplete_frame_times_out_and_an_idle_connection_does_not() {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        // Idle, nothing sent: still waiting after longer than the frame timeout.
        let mut buf = Vec::new();
        let idle = tokio::time::timeout(Duration::from_millis(500), read_message_with(&mut server, &mut buf, &SHORT)).await;
        assert!(idle.is_err(), "an idle connection was given up on: {idle:?}");
        // Half a message, then silence: Timeout.
        client.write_all(&UNBIND[..3]).await.unwrap();
        let t0 = std::time::Instant::now();
        let r = read_message_with(&mut server, &mut buf, &SHORT).await;
        assert!(matches!(r, Err(FramingError::Timeout(_))), "{r:?}");
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_frame_arriving_in_pieces_within_the_deadline_is_read() {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let writer = tokio::spawn(async move {
            for b in UNBIND {
                client.write_all(&[b]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            client
        });
        let mut buf = Vec::new();
        let msg = read_message_with(&mut server, &mut buf, &SHORT).await.unwrap().unwrap();
        assert_eq!(msg.message_id, 1);
        drop(writer.await.unwrap());
        assert!(read_message_with(&mut server, &mut buf, &SHORT).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sasl_buffers_are_capped_and_timed_out_too() {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let mut buf = Vec::new();
        client.write_all(&[0, 0, 0, 64]).await.unwrap();
        client.write_all(&[7u8; 64]).await.unwrap();
        assert_eq!(read_sized_buffer_with(&mut server, &mut buf, &SHORT).await.unwrap().unwrap(), vec![7u8; 64]);
        client.write_all(&[0xff, 0xff, 0xff, 0xff]).await.unwrap();
        assert!(matches!(read_sized_buffer_with(&mut server, &mut buf, &SHORT).await, Err(FramingError::TooLarge { .. })));

        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let mut buf = Vec::new();
        client.write_all(&[0, 0, 0, 10, 1, 2]).await.unwrap();
        assert!(matches!(read_sized_buffer_with(&mut server, &mut buf, &SHORT).await, Err(FramingError::Timeout(_))));
        // The default SASL cap is what the security-layer challenge advertises
        // (a 3-octet field).
        assert!(MAX_SASL_BUFFER <= 0x00FF_FFFF);
    }

    #[test]
    fn short_form_length() {
        // tag=0x30, length=0x05 (short form) -> total 2 + 5 = 7. The
        // header alone is enough to compute this -- ber_message_len
        // doesn't need the body to have arrived yet (read_message checks
        // `buf.len() >= total` separately).
        assert_eq!(ber_message_len_any(&[0x30, 0x05, 0, 0, 0, 0, 0]).unwrap(), Some(7));
        assert_eq!(ber_message_len_any(&[0x30, 0x05, 0, 0]).unwrap(), Some(7));
        assert_eq!(ber_message_len_any(&[0x30]).unwrap(), None); // header itself incomplete
    }

    #[test]
    fn long_form_length() {
        // tag=0x30, length octet 0x82 (2 length bytes follow) = 0x0100 = 256
        let mut buf = vec![0x30, 0x82, 0x01, 0x00];
        buf.extend(std::iter::repeat_n(0u8, 256));
        assert_eq!(ber_message_len_any(&buf).unwrap(), Some(4 + 256));
    }

    #[test]
    fn rejects_non_sequence_tag() {
        assert!(matches!(
            ber_message_len_any(&[0x04, 0x01, 0x00]),
            Err(FramingError::UnexpectedTag(0x04))
        ));
    }
}
