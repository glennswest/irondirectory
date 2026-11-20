//! `ncacn_np`: SMB named pipes forwarded by rocketsmbd (#53, rocketsmbd#83).
//!
//! Windows reaches SAMR, LSARPC and NETLOGON as DCE/RPC over SMB named pipes
//! on `IPC$`. rocketsmbd serves SMB and forwards each opened pipe to a Unix
//! stream socket, one connection per pipe, prefixed by a preamble that says
//! who the SMB session authenticated as and gives the session's key
//! (rocketsmbd `docs/IPC-PIPES.md`). After the preamble the stream carries
//! only DCE/RPC PDUs, handled by the same loop as `ncacn_ip_tcp`
//! ([`crate::server`]); the identity decides what SAMR allows, and the
//! session key is the CEK of SAMR's AES password buffers ([`crate::samr_aes`]).
//!
//! Only a Unix socket: the preamble carries the session key. The socket's
//! file mode is what keeps other local users from impersonating rocketsmbd
//! (iron-rpcd creates it 0660; share the group with rocketsmbd only).
//!
//! Preamble v1, little-endian, a *str* being a u16 byte length and bytes:
//! `"RSMBPIPE"`, u16 version 1, u16 reserved 0, u32 length of the rest, then
//! u16 flags (0x1 signed, 0x2 sealed, 0x4 Kerberos), u16 dialect, str pipe,
//! str session_key, str user, str domain, str user_sid, u16 n, n x str group
//! SIDs. A preamble that does not parse closes the connection (rocketsmbd's
//! way to learn a pipe was refused).

use std::sync::Arc;

use iron_partition::Sid;
use tokio::io::AsyncReadExt;
use tokio::net::UnixListener;

use crate::server::AppState;

pub const MAGIC: &[u8; 8] = b"RSMBPIPE";
pub const VERSION: u16 = 1;
/// Upper bound on the preamble body: a PAC rarely carries more than a few
/// hundred groups; this refuses a runaway length before allocating it.
const MAX_BODY: u32 = 64 * 1024;

pub const FLAG_SIGNED: u16 = 0x1;
pub const FLAG_SEALED: u16 = 0x2;
pub const FLAG_KERBEROS: u16 = 0x4;

const ADMINISTRATOR_RID: u32 = 500;
const DOMAIN_ADMINS_RID: u32 = 512;

/// Who an SMB session authenticated as, from the preamble.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeIdentity {
    pub flags: u16,
    pub dialect: u16,
    pub pipe: String,
    pub session_key: Vec<u8>,
    pub user: String,
    pub domain: String,
    pub user_sid: Option<Sid>,
    pub groups: Vec<Sid>,
}

impl PipeIdentity {
    /// A Domain Admin of `domain_sid`: a Kerberos session (the SIDs come
    /// from the KDC-signed PAC) whose user is that domain's Administrator
    /// (RID 500) or a member of its Domain Admins (RID 512). An NTLM
    /// session carries no SIDs and is never one.
    pub fn is_domain_admin(&self, domain_sid: &Sid) -> bool {
        if self.flags & FLAG_KERBEROS == 0 {
            return false;
        }
        let is = |sid: &Sid, rid: u32| *sid == domain_sid.with_sub_authority(rid);
        self.user_sid.as_ref().is_some_and(|s| is(s, ADMINISTRATOR_RID)) || self.groups.iter().any(|g| is(g, DOMAIN_ADMINS_RID))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PreambleError {
    #[error("not a rocketsmbd pipe preamble (magic)")]
    Magic,
    #[error("unsupported preamble version {0}")]
    Version(u16),
    #[error("preamble length {0} is out of range")]
    Length(u32),
    #[error("preamble ends inside a field")]
    Truncated,
    #[error("preamble has {0} bytes after its last field")]
    Trailing(usize),
    #[error("preamble {0} is not UTF-8")]
    Utf8(&'static str),
    #[error("preamble SID {0:?} does not parse")]
    Sid(String),
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PreambleError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()).ok_or(PreambleError::Truncated)?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, PreambleError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn bytes(&mut self) -> Result<&'a [u8], PreambleError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn text(&mut self, what: &'static str) -> Result<String, PreambleError> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| PreambleError::Utf8(what))
    }
    fn sid(&mut self, what: &'static str) -> Result<Option<Sid>, PreambleError> {
        let s = self.text(what)?;
        if s.is_empty() {
            return Ok(None);
        }
        Sid::parse(&s).map(Some).ok_or(PreambleError::Sid(s))
    }
}

/// Checks the 16-byte fixed header; the body length that follows.
pub fn parse_header(header: &[u8; 16]) -> Result<u32, PreambleError> {
    if &header[..8] != MAGIC {
        return Err(PreambleError::Magic);
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != VERSION {
        return Err(PreambleError::Version(version));
    }
    let len = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
    if len == 0 || len > MAX_BODY {
        return Err(PreambleError::Length(len));
    }
    Ok(len)
}

/// Parses the body after the fixed header.
pub fn parse_body(body: &[u8]) -> Result<PipeIdentity, PreambleError> {
    let mut c = Cursor { buf: body, pos: 0 };
    let flags = c.u16()?;
    let dialect = c.u16()?;
    let pipe = c.text("pipe")?;
    let session_key = c.bytes()?.to_vec();
    let user = c.text("user")?;
    let domain = c.text("domain")?;
    let user_sid = c.sid("user_sid")?;
    let n = c.u16()?;
    let mut groups = Vec::with_capacity(n as usize);
    for _ in 0..n {
        if let Some(g) = c.sid("group")? {
            groups.push(g);
        }
    }
    if c.pos != body.len() {
        return Err(PreambleError::Trailing(body.len() - c.pos));
    }
    Ok(PipeIdentity { flags, dialect, pipe, session_key, user, domain, user_sid, groups })
}

/// Reads and parses the preamble from the start of `stream`.
pub async fn read_preamble<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Result<PipeIdentity, PreambleError>> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).await?;
    let len = match parse_header(&header) {
        Ok(len) => len,
        Err(e) => return Ok(Err(e)),
    };
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    Ok(parse_body(&body))
}

/// Serves pipe connections on `listener` until it errors.
pub async fn serve(listener: UnixListener, app: Arc<AppState>) -> std::io::Result<()> {
    let mut n: u64 = 0;
    loop {
        let (mut stream, _) = listener.accept().await?;
        n += 1;
        let peer = format!("pipe#{n}");
        let app = app.clone();
        tokio::spawn(async move {
            let identity = match read_preamble(&mut stream).await {
                Ok(Ok(id)) => id,
                Ok(Err(e)) => {
                    tracing::warn!(%peer, "pipe refused: {e}");
                    return;
                }
                Err(e) => {
                    tracing::debug!(%peer, "pipe closed before its preamble: {e}");
                    return;
                }
            };
            tracing::info!(%peer, pipe = %identity.pipe, user = %identity.user, kerberos = identity.flags & FLAG_KERBEROS != 0, "accepted pipe");
            if let Err(e) = crate::server::handle_connection(stream, &peer, app, Some(identity)).await {
                tracing::debug!(%peer, "pipe ended: {e}");
            }
            tracing::info!(%peer, "pipe closed");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn str_(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u16).to_le_bytes());
        out.extend_from_slice(s);
    }

    /// A preamble laid out as rocketsmbd's `docs/IPC-PIPES.md` says.
    fn preamble(flags: u16, user_sid: &str, groups: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&flags.to_le_bytes());
        body.extend_from_slice(&0x0311u16.to_le_bytes());
        str_(&mut body, b"samr");
        str_(&mut body, &[0xab; 16]);
        str_(&mut body, b"administrator@IRON.LO");
        str_(&mut body, b"IRON");
        str_(&mut body, user_sid.as_bytes());
        body.extend_from_slice(&(groups.len() as u16).to_le_bytes());
        for g in groups {
            str_(&mut body, g.as_bytes());
        }
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    const DOM: &str = "S-1-5-21-1-2-3";

    fn parse(bytes: &[u8]) -> Result<PipeIdentity, PreambleError> {
        let header: [u8; 16] = bytes[..16].try_into().unwrap();
        let len = parse_header(&header)?;
        assert_eq!(len as usize, bytes.len() - 16);
        parse_body(&bytes[16..])
    }

    #[test]
    fn parses_rocketsmbd_layout() {
        let id = parse(&preamble(FLAG_SIGNED | FLAG_KERBEROS, "S-1-5-21-1-2-3-1104", &["S-1-5-21-1-2-3-513", "S-1-5-21-1-2-3-512"])).unwrap();
        assert_eq!(id.pipe, "samr");
        assert_eq!(id.dialect, 0x0311);
        assert_eq!(id.session_key, vec![0xab; 16]);
        assert_eq!(id.user, "administrator@IRON.LO");
        assert_eq!(id.domain, "IRON");
        assert_eq!(id.groups.len(), 2);
        let dom = Sid::parse(DOM).unwrap();
        assert!(id.is_domain_admin(&dom)); // member of 512
        assert!(!id.is_domain_admin(&Sid::parse("S-1-5-21-9-9-9").unwrap()));
    }

    #[test]
    fn domain_admin_needs_kerberos_and_the_right_sid() {
        let dom = Sid::parse(DOM).unwrap();
        assert!(parse(&preamble(FLAG_KERBEROS, "S-1-5-21-1-2-3-500", &[])).unwrap().is_domain_admin(&dom));
        assert!(!parse(&preamble(FLAG_KERBEROS, "S-1-5-21-1-2-3-1104", &["S-1-5-21-1-2-3-513"])).unwrap().is_domain_admin(&dom));
        // NTLM (no 0x4): never, whatever it claims.
        assert!(!parse(&preamble(FLAG_SIGNED, "S-1-5-21-1-2-3-500", &["S-1-5-21-1-2-3-512"])).unwrap().is_domain_admin(&dom));
        // No PAC: empty SID strings.
        let id = parse(&preamble(FLAG_SIGNED, "", &[])).unwrap();
        assert_eq!(id.user_sid, None);
        assert!(!id.is_domain_admin(&dom));
    }

    #[test]
    fn refuses_malformed_preambles() {
        let good = preamble(FLAG_KERBEROS, "S-1-5-21-1-2-3-500", &[]);
        let mut bad = good.clone();
        bad[0] = b'X';
        assert_eq!(parse(&bad), Err(PreambleError::Magic));
        let mut bad = good.clone();
        bad[8] = 2;
        assert_eq!(parse(&bad), Err(PreambleError::Version(2)));
        assert_eq!(parse_body(&good[16..good.len() - 1]), Err(PreambleError::Truncated));
        let mut long = good[16..].to_vec();
        long.push(0);
        assert_eq!(parse_body(&long), Err(PreambleError::Trailing(1)));
        let mut header: [u8; 16] = good[..16].try_into().unwrap();
        header[12..16].copy_from_slice(&(MAX_BODY + 1).to_le_bytes());
        assert_eq!(parse_header(&header), Err(PreambleError::Length(MAX_BODY + 1)));
        assert!(matches!(parse(&preamble(FLAG_KERBEROS, "not-a-sid", &[])), Err(PreambleError::Sid(_))));
    }

    #[tokio::test]
    async fn reads_a_preamble_from_a_stream_and_leaves_the_rest() {
        let mut bytes = preamble(FLAG_KERBEROS, "S-1-5-21-1-2-3-500", &[]);
        bytes.extend_from_slice(b"\x05\x00rest");
        let mut stream = &bytes[..];
        let id = read_preamble(&mut stream).await.unwrap().unwrap();
        assert_eq!(id.pipe, "samr");
        assert_eq!(stream, b"\x05\x00rest");
    }
}
