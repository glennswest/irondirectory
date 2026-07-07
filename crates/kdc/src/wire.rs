//! Kerberos wire framing (RFC 4120 §7.2): UDP carries exactly one DER
//! message per datagram; TCP prefixes each message with its length as 4
//! octets, network byte order, high bit reserved (must be zero).
//!
//! Message-type dispatch for an incoming `KRB-KDC-REQ` peeks at the raw
//! DER tag byte rather than trying each `rasn` type in turn: `rasn-kerberos`
//! bakes the APPLICATION tag into each top-level type's own decode
//! (`AsReq` only ever decodes tag 10, `TgsReq` only tag 12), and for a
//! constructed APPLICATION-class tag under 31 the tag number is just the
//! low 5 bits of the first byte -- exact and O(1), no guess-and-check.

use rasn_kerberos::{AsReq, KrbError, TgsReq};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("empty message")]
    Empty,
    #[error("unrecognized message type (tag {0})")]
    UnknownMessageType(u8),
    #[error("DER decode failed: {0}")]
    Decode(#[from] rasn::error::DecodeError),
    #[error("DER encode failed: {0}")]
    Encode(#[from] rasn::error::EncodeError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TCP message length {0} exceeds the sanity limit ({1})")]
    TooLarge(u32, u32),
}

/// A decoded `KRB-KDC-REQ` (RFC 4120 §5.4.1) -- the two request types
/// share a body shape (`KdcReq`) but are distinct DER-tagged types.
pub enum KdcRequest {
    As(AsReq),
    Tgs(TgsReq),
}

/// A response to send back: `KRB-KDC-REP` (success) or `KRB-ERROR`.
pub enum KdcResponse {
    AsRep(rasn_kerberos::AsRep),
    TgsRep(rasn_kerberos::TgsRep),
    Error(KrbError),
}

impl KdcResponse {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let bytes = match self {
            KdcResponse::AsRep(r) => rasn::der::encode(r)?,
            KdcResponse::TgsRep(r) => rasn::der::encode(r)?,
            KdcResponse::Error(e) => rasn::der::encode(e)?,
        };
        Ok(bytes)
    }
}

/// Decodes a single DER-encoded `KRB-KDC-REQ` message (one UDP datagram,
/// or one already-length-delimited TCP message).
pub fn decode_request(bytes: &[u8]) -> Result<KdcRequest, WireError> {
    let Some(&first) = bytes.first() else {
        return Err(WireError::Empty);
    };
    let tag = first & 0x1F;
    match tag {
        10 => Ok(KdcRequest::As(rasn::der::decode(bytes)?)),
        12 => Ok(KdcRequest::Tgs(rasn::der::decode(bytes)?)),
        other => Err(WireError::UnknownMessageType(other)),
    }
}

/// A generous but finite cap on an incoming TCP message length, to avoid
/// trying to allocate an attacker-controlled buffer of near-4GiB (the
/// field is 31 usable bits per RFC 4120 §7.2.2).
const MAX_TCP_MESSAGE_LEN: u32 = 1 << 20; // 1 MiB

/// Reads one length-prefixed message from a Kerberos TCP stream.
/// Returns `Ok(None)` on a clean EOF before any bytes of a new message
/// arrive (as opposed to a truncated message, which errors).
pub async fn read_tcp_message<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<Option<Vec<u8>>, WireError> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) & 0x7FFF_FFFF; // high bit reserved, must be zero on input we generate; mask defensively on input we receive
    if len > MAX_TCP_MESSAGE_LEN {
        return Err(WireError::TooLarge(len, MAX_TCP_MESSAGE_LEN));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Writes one length-prefixed message to a Kerberos TCP stream.
pub async fn write_tcp_message<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S, message: &[u8]) -> Result<(), WireError> {
    let len = u32::try_from(message.len()).map_err(|_| WireError::TooLarge(u32::MAX, MAX_TCP_MESSAGE_LEN))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(message).await?;
    Ok(())
}
