//! GSS-API token framing (RFC 2743 §3.1) for the Kerberos V5 mechanism
//! (RFC 4121). Hand-rolled: this is a small, fixed byte-level format,
//! not a general ASN.1 structure `rasn` can decode against a schema
//! (the mechanism-specific inner token isn't required to be ASN.1 at
//! all per RFC 2743's own text) -- verified against RFC 2743's
//! byte-by-byte description of the tag/length/OID encoding.

/// DER encoding of the Kerberos V5 GSS-API mechanism OID
/// (1.2.840.113554.1.2.2), tag+length+content (`06 09 2a 86 48 86 f7 12
/// 01 02 02`) -- this exact byte sequence is reproduced verbatim across
/// Kerberos/GSSAPI implementations and RFC 4121's own examples; derived
/// here from first principles (base-128 OID component encoding) and
/// cross-checked against that well-known constant.
const KRB5_MECH_OID_DER: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

pub const TOK_ID_AP_REQ: [u8; 2] = [0x01, 0x00];
pub const TOK_ID_AP_REP: [u8; 2] = [0x02, 0x00];
pub const TOK_ID_WRAP: [u8; 2] = [0x05, 0x04];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("empty GSS token")]
    Empty,
    #[error("not an Initial Context Token (expected tag 0x60)")]
    NotInitialToken,
    #[error("truncated GSS token")]
    Truncated,
    #[error("unrecognized mechanism OID (only Kerberos V5 is supported)")]
    UnknownMechanism,
    #[error("unexpected TOK_ID {found:02x?}, expected {expected:02x?}")]
    WrongTokId { found: [u8; 2], expected: [u8; 2] },
}

/// Reads a BER length (short or long form) starting at `buf[*pos]`,
/// advancing `*pos` past it.
fn read_ber_length(buf: &[u8], pos: &mut usize) -> Result<usize, Error> {
    let first = *buf.get(*pos).ok_or(Error::Truncated)?;
    *pos += 1;
    if first & 0x80 == 0 {
        Ok(first as usize)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() {
            return Err(Error::Truncated);
        }
        let bytes = buf.get(*pos..*pos + n).ok_or(Error::Truncated)?;
        *pos += n;
        Ok(bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize))
    }
}

fn write_ber_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        let content = &bytes[first_nonzero..];
        out.push(0x80 | content.len() as u8);
        out.extend_from_slice(content);
    }
}

/// Parses an RFC 2743 §3.1 Initial Context Token, verifying the
/// mechanism is Kerberos V5, and returns the inner mechanism-specific
/// token (TOK_ID + Kerberos message).
pub fn parse_initial_context_token(buf: &[u8]) -> Result<&[u8], Error> {
    if buf.is_empty() {
        return Err(Error::Empty);
    }
    if buf[0] != 0x60 {
        return Err(Error::NotInitialToken);
    }
    let mut pos = 1;
    let len = read_ber_length(buf, &mut pos)?;
    let body = buf.get(pos..pos + len).ok_or(Error::Truncated)?;
    if !body.starts_with(KRB5_MECH_OID_DER) {
        return Err(Error::UnknownMechanism);
    }
    Ok(&body[KRB5_MECH_OID_DER.len()..])
}

/// Builds an RFC 2743 §3.1 Initial Context Token wrapping `inner`
/// (TOK_ID + Kerberos message) for the Kerberos V5 mechanism. RFC 2743
/// itself only requires this framing for the *initial* token, but RFC
/// 4121 §4.1 overrides that for its mechanism specifically: "All context
/// establishment tokens emitted by the Kerberos Version 5 GSS-API
/// mechanism SHALL have [this] framing" -- so the acceptor's AP-REP
/// response gets it too, not just the initiator's AP-REQ.
pub fn build_initial_context_token(inner: &[u8]) -> Vec<u8> {
    let body_len = KRB5_MECH_OID_DER.len() + inner.len();
    let mut out = Vec::with_capacity(2 + body_len);
    out.push(0x60);
    write_ber_length(&mut out, body_len);
    out.extend_from_slice(KRB5_MECH_OID_DER);
    out.extend_from_slice(inner);
    out
}

/// Splits a mechanism-specific token into its 2-byte TOK_ID and payload,
/// checking the TOK_ID matches `expected`.
pub fn split_tok_id(buf: &[u8], expected: [u8; 2]) -> Result<&[u8], Error> {
    let tok_id: [u8; 2] = buf.get(0..2).ok_or(Error::Truncated)?.try_into().unwrap();
    if tok_id != expected {
        return Err(Error::WrongTokId { found: tok_id, expected });
    }
    Ok(&buf[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_context_token_roundtrip() {
        let inner = [0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let token = build_initial_context_token(&inner);
        let parsed = parse_initial_context_token(&token).unwrap();
        assert_eq!(parsed, &inner);
    }

    #[test]
    fn rejects_non_krb5_mechanism() {
        // 0x60 <len=7> 06 03 2a 03 04 (a made-up, non-krb5 OID) AA BB
        let token = [0x60, 0x07, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xAA, 0xBB];
        assert_eq!(parse_initial_context_token(&token), Err(Error::UnknownMechanism));
    }

    #[test]
    fn split_tok_id_checks_value() {
        let buf = [0x01, 0x00, 0x99];
        let payload = split_tok_id(&buf, TOK_ID_AP_REQ).unwrap();
        assert_eq!(payload, &[0x99]);
        assert!(split_tok_id(&buf, TOK_ID_AP_REP).is_err());
    }

    #[test]
    fn long_form_length() {
        // A 200-byte body needs a long-form length (0x81 0xC8).
        let inner = vec![0xAB; 200 - KRB5_MECH_OID_DER.len()];
        let token = build_initial_context_token(&inner);
        assert_eq!(&token[1..3], &[0x81, 0xC8]);
        let parsed = parse_initial_context_token(&token).unwrap();
        assert_eq!(parsed, inner.as_slice());
    }
}
