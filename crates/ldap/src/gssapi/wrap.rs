//! RFC 4121 §4.2.6.2 Wrap tokens, without confidentiality only
//! (`GSS_Wrap` with `conf_flag=FALSE`) -- sufficient for RFC 4752's
//! SASL/GSSAPI security-layer negotiation, the only use this
//! implementation has for Wrap tokens.
//!
//! Full per-message confidentiality/integrity protection of LDAP
//! traffic after bind (RFC 4752's integrity/confidentiality security
//! layers) is NOT implemented -- iron-ldap always advertises and
//! negotiates "no security layer" and expects StartTLS/LDAPS for
//! transport security instead, which it already supports.
//!
//! No replay protection: the sequence-number field is always zero.
//! Real GSSAPI tracks a per-context sequence number across many Wrap/MIC
//! calls; this implementation only ever sends/verifies exactly one Wrap
//! message in each direction (the security-layer negotiation itself),
//! so there's nothing to replay-protect against within a single bind --
//! same posture as `iron-kdc`'s documented no-replay-cache simplification.

use iron_crypto::kerberos::{self, Enctype};
use iron_crypto::FipsContext;

use super::token::TOK_ID_WRAP;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("truncated Wrap token")]
    Truncated,
    #[error("wrong TOK_ID for a Wrap token")]
    WrongTokId,
    #[error("Wrap token requests confidentiality, which this implementation does not support")]
    ConfidentialityUnsupported,
    #[error("checksum verification failed")]
    BadChecksum,
    #[error("crypto error: {0}")]
    Crypto(#[from] iron_crypto::Error),
}

const SENT_BY_ACCEPTOR: u8 = 0x01;
const SEALED: u8 = 0x02;

/// Builds a Wrap token without confidentiality, as the context acceptor
/// -- iron-ldap never initiates a GSS context, only accepts inbound LDAP
/// binds, so `SentByAcceptor` is always set here.
pub fn wrap(ctx: &FipsContext, enctype: Enctype, session_key: &[u8], key_usage: u32, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let checksum_len = enctype.hmac_len();
    let mut header = [0u8; 16];
    header[0..2].copy_from_slice(&TOK_ID_WRAP);
    header[2] = SENT_BY_ACCEPTOR;
    header[3] = 0xFF;
    header[4..6].copy_from_slice(&(checksum_len as u16).to_be_bytes()); // EC: checksum trailer length
    // header[6..8] RRC = 0 (no rotation needed for a freshly-built token)
    // header[8..16] SND_SEQ = 0 (see module docs)

    // RFC 4121 4.2.4: "Both the EC field and the RRC field in the token
    // header SHALL be filled with zeroes for the purpose of calculating
    // the checksum" -- the OUTPUT header keeps the real EC value (set
    // above); only the checksum INPUT uses a zeroed copy.
    let mut header_for_checksum = header;
    header_for_checksum[4..6].copy_from_slice(&[0, 0]);
    let mic = kerberos::checksum(ctx, enctype, session_key, key_usage, &sign_input(plaintext, &header_for_checksum))?;

    let mut out = Vec::with_capacity(16 + plaintext.len() + mic.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(plaintext);
    out.extend_from_slice(&mic);
    Ok(out)
}

/// Unwraps and verifies a Wrap token without confidentiality (rejects
/// one with the `Sealed` flag set). Undoes any right-rotation (RRC)
/// before parsing, since the RFC requires acceptors to handle whatever
/// rotation a sender chose.
pub fn unwrap(ctx: &FipsContext, enctype: Enctype, session_key: &[u8], key_usage: u32, token: &[u8]) -> Result<Vec<u8>, Error> {
    if token.len() < 16 {
        return Err(Error::Truncated);
    }
    if token[0..2] != TOK_ID_WRAP {
        return Err(Error::WrongTokId);
    }
    if token[2] & SEALED != 0 {
        return Err(Error::ConfidentialityUnsupported);
    }
    let rrc = u16::from_be_bytes([token[6], token[7]]) as usize;

    let rest = &token[16..];
    let n = rest.len();
    let rrc = if n == 0 { 0 } else { rrc % n };
    let mut unrotated = Vec::with_capacity(n);
    unrotated.extend_from_slice(&rest[rrc..]);
    unrotated.extend_from_slice(&rest[..rrc]);

    let checksum_len = enctype.hmac_len();
    if unrotated.len() < checksum_len {
        return Err(Error::Truncated);
    }
    let (plaintext, mic) = unrotated.split_at(unrotated.len() - checksum_len);

    let mut header_for_checksum = [0u8; 16];
    header_for_checksum.copy_from_slice(&token[0..16]);
    header_for_checksum[4..6].copy_from_slice(&[0, 0]); // EC zeroed for the checksum calc
    header_for_checksum[6..8].copy_from_slice(&[0, 0]); // RRC zeroed for the checksum calc

    let expected_mic = kerberos::checksum(ctx, enctype, session_key, key_usage, &sign_input(plaintext, &header_for_checksum))?;
    if !constant_time_eq(&expected_mic, mic) {
        return Err(Error::BadChecksum);
    }
    Ok(plaintext.to_vec())
}

/// RFC 4121 §4.2.4: "the checksum SHALL be calculated first over the
/// to-be-signed plaintext data, and then over the ... header" -- i.e.
/// over the concatenation `plaintext || header`.
fn sign_input(plaintext: &[u8], header: &[u8; 16]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(plaintext.len() + 16);
    buf.extend_from_slice(plaintext);
    buf.extend_from_slice(header);
    buf
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use iron_crypto::kerberos as krb;
    use iron_crypto::FipsContext;

    #[test]
    fn wrap_unwrap_roundtrip_all_enctypes() {
        let ctx = FipsContext::new().unwrap();
        for enctype in [
            Enctype::Aes128CtsHmacSha1_96,
            Enctype::Aes256CtsHmacSha1_96,
            Enctype::Aes128CtsHmacSha256_128,
            Enctype::Aes256CtsHmacSha384_192,
        ] {
            let key = krb::random_bytes(&ctx, enctype.key_len()).unwrap();
            let plaintext = [0x01u8, 0x00, 0x00, 0x00]; // "no security layer", 0 max buffer
            let wrapped = wrap(&ctx, enctype, &key, 22, &plaintext).unwrap();
            let unwrapped = unwrap(&ctx, enctype, &key, 22, &wrapped).unwrap();
            assert_eq!(unwrapped, plaintext, "roundtrip mismatch for {enctype:?}");
        }
    }

    #[test]
    fn unwrap_rejects_tampered_token() {
        let ctx = FipsContext::new().unwrap();
        let enctype = Enctype::Aes256CtsHmacSha384_192;
        let key = krb::random_bytes(&ctx, enctype.key_len()).unwrap();
        let mut wrapped = wrap(&ctx, enctype, &key, 22, &[1, 0, 0, 0]).unwrap();
        *wrapped.last_mut().unwrap() ^= 0xFF;
        assert!(unwrap(&ctx, enctype, &key, 22, &wrapped).is_err());
    }

    #[test]
    fn unwrap_handles_nonzero_rrc() {
        let ctx = FipsContext::new().unwrap();
        let enctype = Enctype::Aes256CtsHmacSha1_96;
        let key = krb::random_bytes(&ctx, enctype.key_len()).unwrap();
        let plaintext = [1u8, 0, 0, 0];
        let mut wrapped = wrap(&ctx, enctype, &key, 22, &plaintext).unwrap();

        // Manually right-rotate the post-header bytes by 3 and set RRC=3,
        // simulating a sender that rotates in place (RFC 4121 4.2.5).
        let rrc: usize = 3;
        wrapped[6..8].copy_from_slice(&(rrc as u16).to_be_bytes());
        let rest = wrapped[16..].to_vec();
        let n = rest.len();
        let mut rotated = vec![0u8; n];
        for (i, b) in rest.iter().enumerate() {
            rotated[(i + rrc) % n] = *b;
        }
        wrapped[16..].copy_from_slice(&rotated);

        let unwrapped = unwrap(&ctx, enctype, &key, 22, &wrapped).unwrap();
        assert_eq!(unwrapped, plaintext);
    }
}
