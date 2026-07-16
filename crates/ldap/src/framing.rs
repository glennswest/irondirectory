//! LDAP-over-TCP message framing: each `LdapMessage` is a self-delimiting
//! BER-encoded SEQUENCE, so framing means reading the outer tag+length
//! header to know how many more bytes make up one complete message.
//!
//! Deliberately hand-rolls the tag/length parse (rather than relying on
//! `rasn`'s decode-error introspection to distinguish "not enough bytes
//! yet" from "malformed input") -- the outer tag is always a single-byte
//! universal SEQUENCE (`0x30`), so this is a handful of lines and avoids
//! depending on decoder-internal error semantics.

use rasn_ldap::LdapMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("expected a SEQUENCE tag (0x30), got {0:#04x}")]
    UnexpectedTag(u8),
    #[error("indefinite-length BER is not supported over LDAP-over-TCP")]
    IndefiniteLength,
    #[error("BER length overflowed usize")]
    LengthOverflow,
    #[error("connection closed mid-message")]
    UnexpectedEof,
    #[error("BER decode error: {0}")]
    Decode(#[from] rasn::error::DecodeError),
    #[error("BER encode error: {0}")]
    Encode(#[from] rasn::error::EncodeError),
}

/// Returns the total byte length of the outer `LdapMessage` SEQUENCE once
/// its tag+length header is fully present in `buf`, or `None` if more
/// bytes are needed just to read the header.
fn ber_message_len(buf: &[u8]) -> Result<Option<usize>, FramingError> {
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
    if first_len_byte & 0x80 == 0 {
        return Ok(Some(2 + first_len_byte as usize));
    }
    let num_octets = (first_len_byte & 0x7f) as usize;
    if num_octets == 0 {
        return Err(FramingError::IndefiniteLength);
    }
    if buf.len() < 2 + num_octets {
        return Ok(None);
    }
    let mut length: usize = 0;
    for &b in &buf[2..2 + num_octets] {
        length = length
            .checked_shl(8)
            .ok_or(FramingError::LengthOverflow)?;
        length |= b as usize;
    }
    Ok(Some(2 + num_octets + length))
}

/// Reads the next `LdapMessage` off `reader`, buffering into `buf` across
/// calls (so partial reads from a prior call aren't lost). Returns `Ok(None)`
/// on a clean EOF between messages (no partial message pending).
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<LdapMessage>, FramingError> {
    loop {
        if let Some(total) = ber_message_len(buf)? {
            if buf.len() >= total {
                let msg: LdapMessage = rasn::ber::decode(&buf[..total])?;
                buf.drain(..total);
                return Ok(Some(msg));
            }
        }
        let mut chunk = [0u8; 4096];
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(FramingError::UnexpectedEof);
        }
        buf.extend_from_slice(&chunk[..n]);
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
pub async fn read_sized_buffer<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, FramingError> {
    loop {
        if buf.len() >= 4 {
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if buf.len() >= 4 + len {
                let payload = buf[4..4 + len].to_vec();
                buf.drain(..4 + len);
                return Ok(Some(payload));
            }
        }
        let mut chunk = [0u8; 4096];
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(FramingError::UnexpectedEof);
        }
        buf.extend_from_slice(&chunk[..n]);
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

    #[test]
    fn short_form_length() {
        // tag=0x30, length=0x05 (short form) -> total 2 + 5 = 7. The
        // header alone is enough to compute this -- ber_message_len
        // doesn't need the body to have arrived yet (read_message checks
        // `buf.len() >= total` separately).
        assert_eq!(ber_message_len(&[0x30, 0x05, 0, 0, 0, 0, 0]).unwrap(), Some(7));
        assert_eq!(ber_message_len(&[0x30, 0x05, 0, 0]).unwrap(), Some(7));
        assert_eq!(ber_message_len(&[0x30]).unwrap(), None); // header itself incomplete
    }

    #[test]
    fn long_form_length() {
        // tag=0x30, length octet 0x82 (2 length bytes follow) = 0x0100 = 256
        let mut buf = vec![0x30, 0x82, 0x01, 0x00];
        buf.extend(std::iter::repeat(0u8).take(256));
        assert_eq!(ber_message_len(&buf).unwrap(), Some(4 + 256));
    }

    #[test]
    fn rejects_non_sequence_tag() {
        assert!(matches!(
            ber_message_len(&[0x04, 0x01, 0x00]),
            Err(FramingError::UnexpectedTag(0x04))
        ));
    }
}
