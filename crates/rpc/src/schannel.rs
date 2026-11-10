//! Netlogon secure channel as an RPC security provider ("Schannel",
//! `auth_type` 68, MS-NRPC 3.3) -- AES only (#20).
//!
//! After `NetrServerAuthenticate3` (see [`crate::netlogon`]) both ends
//! hold a 16-byte session key. A client then binds with `auth_type` 68 and
//! an `NL_AUTH_MESSAGE` naming its computer, and every request/response on
//! that binding carries an `NL_AUTH_SHA2_SIGNATURE` (MS-NRPC 2.2.1.3.3):
//! signed at `PKT_INTEGRITY`, signed and sealed at `PKT_PRIVACY`.
//!
//! MS-NRPC 3.3.4.2.1, AES variant:
//! - the signature header is `SignatureAlgorithm` 0x0013 (HMAC-SHA256),
//!   `SealAlgorithm` 0x001A (AES-128) or 0xFFFF (not sealed), `Pad` 0xFFFF,
//!   `Flags` 0;
//! - the 8-byte sequence number is the counter's low 32 bits then its high
//!   32 bits, both big-endian, with 0x80 set in byte 4 when the *client*
//!   sends;
//! - `Checksum` = HMAC-SHA256(SK, header || plaintext confounder (sealed
//!   only) || plaintext data)[..8];
//! - sealing: AES-128-CFB8 under SK XOR 0xF0.., IV = seq || seq, one stream
//!   over the confounder then the data;
//! - the sequence number goes on the wire AES-128-CFB8 encrypted under SK,
//!   IV = checksum || checksum.
//!
//! The data signed or sealed is the stub plus its auth padding, not the
//! PDU header (Samba's and impacket's schannel do the same).
//!
//! One counter per binding, shared by both directions (Samba's
//! `schannel_state.seq_num`, impacket's `__sequence`): request N, response
//! N+1, request N+2, ... Every primitive here is FIPS-approved
//! (HMAC-SHA256, AES-CFB8) and goes through [`FipsContext`].

use iron_crypto::FipsContext;

/// `RPC_C_AUTHN_NETLOGON`.
pub const AUTH_TYPE_NETLOGON: u8 = 0x44;
pub const AUTH_LEVEL_INTEGRITY: u8 = 5;
pub const AUTH_LEVEL_PRIVACY: u8 = 6;

const SIGNATURE_HMAC_SHA256: u16 = 0x0013;
const SEAL_AES128: u16 = 0x001A;
const SEAL_NONE: u16 = 0xFFFF;
/// `NL_AUTH_SHA2_SIGNATURE`: header 8, sequence 8, checksum 8,
/// confounder 8, reserved 24. impacket omits the confounder field when it
/// only signs (48 bytes); Samba always sends 56. Both are accepted; this
/// side always sends 56.
pub const SIGNATURE_LEN: usize = 56;
const MIN_SIGNATURE_LEN: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SchannelError {
    #[error("signature is {0} bytes, too short")]
    Short(usize),
    #[error("signature algorithm 0x{0:04x} is not HMAC-SHA256")]
    SignatureAlgorithm(u16),
    #[error("seal algorithm 0x{found:04x}, expected 0x{expected:04x}")]
    SealAlgorithm { found: u16, expected: u16 },
    #[error("sequence number does not match the expected one (replayed or reordered)")]
    Sequence,
    #[error("checksum does not match")]
    Checksum,
    #[error("crypto: {0}")]
    Crypto(String),
}

impl From<iron_crypto::Error> for SchannelError {
    fn from(e: iron_crypto::Error) -> Self {
        SchannelError::Crypto(e.to_string())
    }
}

/// MS-NRPC 3.3.4.2.1 step 5.
pub fn derive_sequence(seq: u64, client_sends: bool) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(seq as u32).to_be_bytes());
    out[4..].copy_from_slice(&((seq >> 32) as u32).to_be_bytes());
    if client_sends {
        out[4] |= 0x80;
    }
    out
}

fn header(seal: bool) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[..2].copy_from_slice(&SIGNATURE_HMAC_SHA256.to_le_bytes());
    h[2..4].copy_from_slice(&(if seal { SEAL_AES128 } else { SEAL_NONE }).to_le_bytes());
    h[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    h
}

fn checksum(fips: &FipsContext, key: &[u8; 16], header: &[u8; 8], confounder: Option<&[u8]>, data: &[u8]) -> Result<[u8; 8], SchannelError> {
    let mut msg = Vec::with_capacity(16 + data.len());
    msg.extend_from_slice(header);
    if let Some(c) = confounder {
        msg.extend_from_slice(c);
    }
    msg.extend_from_slice(data);
    let mac = iron_crypto::hmac::hmac_sha256(fips, key, &msg)?;
    Ok(mac[..8].try_into().unwrap())
}

fn seal_key(key: &[u8; 16]) -> [u8; 16] {
    key.map(|b| b ^ 0xF0)
}

fn doubled(eight: &[u8; 8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(eight);
    iv[8..].copy_from_slice(eight);
    iv
}

/// Signs (and, with `confounder`, seals) `data` as sequence `seq`. Returns
/// the data to put on the wire (sealed, or `data` unchanged) and the
/// 56-byte signature.
pub fn protect(fips: &FipsContext, key: &[u8; 16], seq: u64, client_sends: bool, confounder: Option<[u8; 8]>, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SchannelError> {
    let seal = confounder.is_some();
    let hdr = header(seal);
    let sum = checksum(fips, key, &hdr, confounder.as_ref().map(|c| &c[..]), data)?;
    let seq_bytes = derive_sequence(seq, client_sends);

    let mut sig = Vec::with_capacity(SIGNATURE_LEN);
    sig.extend_from_slice(&hdr);
    sig.extend_from_slice(&iron_crypto::aead::aes128_cfb8(fips, key, &doubled(&sum), &seq_bytes, true)?);
    sig.extend_from_slice(&sum);
    let out = match confounder {
        Some(c) => {
            let mut plain = c.to_vec();
            plain.extend_from_slice(data);
            let sealed = iron_crypto::aead::aes128_cfb8(fips, &seal_key(key), &doubled(&seq_bytes), &plain, true)?;
            sig.extend_from_slice(&sealed[..8]);
            sealed[8..].to_vec()
        }
        None => {
            sig.extend_from_slice(&[0u8; 8]);
            data.to_vec()
        }
    };
    sig.extend_from_slice(&[0u8; 24]);
    Ok((out, sig))
}

/// Checks (and, when `sealed`, unseals) `data` against `signature`, which
/// must carry sequence `seq` from the given direction. Returns the
/// plaintext.
pub fn unprotect(fips: &FipsContext, key: &[u8; 16], seq: u64, client_sent: bool, sealed: bool, data: &[u8], signature: &[u8]) -> Result<Vec<u8>, SchannelError> {
    if signature.len() < MIN_SIGNATURE_LEN {
        return Err(SchannelError::Short(signature.len()));
    }
    let hdr: [u8; 8] = signature[..8].try_into().unwrap();
    let alg = u16::from_le_bytes([hdr[0], hdr[1]]);
    if alg != SIGNATURE_HMAC_SHA256 {
        return Err(SchannelError::SignatureAlgorithm(alg));
    }
    let seal_alg = u16::from_le_bytes([hdr[2], hdr[3]]);
    let expected = if sealed { SEAL_AES128 } else { SEAL_NONE };
    if seal_alg != expected {
        return Err(SchannelError::SealAlgorithm { found: seal_alg, expected });
    }
    let enc_seq = &signature[8..16];
    let sum: [u8; 8] = signature[16..24].try_into().unwrap();
    let seq_bytes = iron_crypto::aead::aes128_cfb8(fips, key, &doubled(&sum), enc_seq, false)?;
    if seq_bytes != derive_sequence(seq, client_sent) {
        return Err(SchannelError::Sequence);
    }
    let (confounder, plain) = if sealed {
        let mut wire = signature[24..32].to_vec();
        wire.extend_from_slice(data);
        let seq8: [u8; 8] = seq_bytes[..].try_into().unwrap();
        let mut plain = iron_crypto::aead::aes128_cfb8(fips, &seal_key(key), &doubled(&seq8), &wire, false)?;
        let data = plain.split_off(8);
        (Some(plain), data)
    } else {
        (None, data.to_vec())
    };
    let expected_sum = checksum(fips, key, &hdr, confounder.as_deref(), &plain)?;
    if !constant_time_eq(&expected_sum, &sum) {
        return Err(SchannelError::Checksum);
    }
    Ok(plain)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The computer name an `NL_AUTH_MESSAGE` request (MS-NRPC 2.2.1.3.1)
/// names: its NetBIOS computer name (flag 0x2, OEM), else its UTF-8 one
/// (flag 0x10). Fields come in flag order: NetBIOS domain (0x1, OEM
/// NUL-terminated), NetBIOS computer (0x2, OEM), DNS domain (0x4,
/// compressed UTF-8, RFC 1035 labels), DNS host (0x8, same), NetBIOS
/// computer (0x10, compressed UTF-8).
pub fn auth_message_computer(msg: &[u8]) -> Option<String> {
    if msg.len() < 8 || u32::from_le_bytes(msg[..4].try_into().ok()?) != 0 {
        return None; // not a NEGOTIATE request
    }
    let flags = u32::from_le_bytes(msg[4..8].try_into().ok()?);
    let buf = &msg[8..];
    let mut pos = 0;
    let cstr = |pos: &mut usize| -> Option<String> {
        let end = buf[*pos..].iter().position(|&b| b == 0)? + *pos;
        let s = String::from_utf8_lossy(&buf[*pos..end]).into_owned();
        *pos = end + 1;
        Some(s)
    };
    if flags & 0x1 != 0 {
        cstr(&mut pos)?;
    }
    if flags & 0x2 != 0 {
        return cstr(&mut pos).filter(|s| !s.is_empty());
    }
    for bit in [0x4, 0x8] {
        if flags & bit != 0 {
            dns_name(buf, &mut pos)?;
        }
    }
    if flags & 0x10 != 0 {
        return dns_name(buf, &mut pos).filter(|s| !s.is_empty());
    }
    None
}

/// An RFC 1035 name at `*pos` (labels, or a 0xC0 pointer), advancing past it.
fn dns_name(buf: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut at = *pos;
    let mut jumped = false;
    for _ in 0..64 {
        let len = *buf.get(at)? as usize;
        if len & 0xC0 == 0xC0 {
            let target = ((len & 0x3F) << 8) | *buf.get(at + 1)? as usize;
            if !jumped {
                *pos = at + 2;
                jumped = true;
            }
            at = target;
            continue;
        }
        if len == 0 {
            if !jumped {
                *pos = at + 1;
            }
            return Some(labels.join("."));
        }
        labels.push(String::from_utf8_lossy(buf.get(at + 1..at + 1 + len)?).into_owned());
        at += 1 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn key() -> [u8; 16] {
        core::array::from_fn(|i| i as u8)
    }

    fn data() -> Vec<u8> {
        (0x40..0x54).collect()
    }

    // impacket 0.13.1: nrpc.SIGN(data, b'', 5, key, aes=True) -- the client
    // signing request 5 (48 bytes: impacket omits the confounder field).
    #[test]
    fn sign_matches_impacket() {
        let fips = FipsContext::new().unwrap();
        let (out, sig) = protect(&fips, &key(), 5, true, None, &data()).unwrap();
        assert_eq!(out, data());
        let imp = hex("1300ffffffff000081fcc5de2d0103b534903e19c85e4db1000000000000000000000000000000000000000000000000");
        assert_eq!(&sig[..24], &imp[..24]);
        assert_eq!(unprotect(&fips, &key(), 5, true, false, &data(), &imp).unwrap(), data());
    }

    // impacket 0.13.1: nrpc.SEAL(data, b'12345678', 7, key, aes=True).
    #[test]
    fn seal_matches_impacket() {
        let fips = FipsContext::new().unwrap();
        let (out, sig) = protect(&fips, &key(), 7, true, Some(*b"12345678"), &data()).unwrap();
        let imp_sig = hex("13001a00ffff00000ff094484ee1674cf44a9cd47684f4316c023465eadeeb39000000000000000000000000000000000000000000000000");
        let imp_data = hex("3d6b0883abd4624b84bbd9d8f817995ac9b4621e");
        assert_eq!(out, imp_data);
        assert_eq!(sig, imp_sig);
        assert_eq!(unprotect(&fips, &key(), 7, true, true, &imp_data, &imp_sig).unwrap(), data());
    }

    #[test]
    fn wrong_sequence_direction_tamper_are_refused() {
        let fips = FipsContext::new().unwrap();
        let (out, sig) = protect(&fips, &key(), 3, false, Some([9; 8]), &data()).unwrap();
        assert_eq!(unprotect(&fips, &key(), 3, false, true, &out, &sig).unwrap(), data());
        assert_eq!(unprotect(&fips, &key(), 4, false, true, &out, &sig), Err(SchannelError::Sequence));
        assert_eq!(unprotect(&fips, &key(), 3, true, true, &out, &sig), Err(SchannelError::Sequence));
        let mut bad = out.clone();
        bad[0] ^= 1;
        assert_eq!(unprotect(&fips, &key(), 3, false, true, &bad, &sig), Err(SchannelError::Checksum));
        assert!(matches!(unprotect(&fips, &key(), 3, false, false, &out, &sig), Err(SchannelError::SealAlgorithm { .. })));
    }

    #[test]
    fn auth_message_names() {
        // impacket getSSPType1('WS1', 'DOM'): NETBIOS_DOMAIN | NETBIOS_HOST.
        let mut m = vec![0, 0, 0, 0, 3, 0, 0, 0];
        m.extend_from_slice(b"DOM\0WS1\0");
        assert_eq!(auth_message_computer(&m).as_deref(), Some("WS1"));
        // Windows: DNS domain + DNS host + UTF-8 NetBIOS host.
        let mut m = vec![0, 0, 0, 0, 0x1c, 0, 0, 0];
        m.extend_from_slice(b"\x03dom\x02lo\x00\x03ws1\xc0\x00\x03WS1\x00");
        assert_eq!(auth_message_computer(&m).as_deref(), Some("WS1"));
        assert_eq!(auth_message_computer(&[1, 0, 0, 0, 2, 0, 0, 0, b'X', 0]), None);
    }
}
