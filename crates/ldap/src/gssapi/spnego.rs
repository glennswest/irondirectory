//! SPNEGO (RFC 4178) for the GSS-SPNEGO SASL bind (#88): the token
//! framing only, hand-rolled DER like `token`. The mechanism under it is
//! always Kerberos V5 (`accept`); NTLM is never negotiated (D4).
//!
//! The one exchange served is the one Windows and MIT initiators make when
//! Kerberos is their preferred mechanism: a `negTokenInit` whose first
//! `mechType` is Kerberos (Microsoft's 1.2.840.48018.1.2.2 or
//! 1.2.840.113554.1.2.2) and whose optimistic `mechToken` is the AP-REQ,
//! answered by one `negTokenResp` with `accept-completed`, the initiator's
//! own OID echoed as `supportedMech`, the AP-REP as `responseToken` and a
//! `mechListMIC` over the initiator's `mechTypes` (RFC 4178 §5: optional
//! when the preferred mechanism is chosen; AD and Samba send it, and the
//! initiator verifies it). An initiator that prefers another mechanism
//! would need further round trips (choose Kerberos, then a mandatory MIC
//! exchange): refused, naming why.
//!
//! ```text
//! InitialContextToken ::= [APPLICATION 0] { thisMech OID 1.3.6.1.5.5.2, NegotiationToken }
//! NegotiationToken ::= CHOICE { negTokenInit [0] NegTokenInit, negTokenResp [1] NegTokenResp }
//! NegTokenInit ::= SEQUENCE { mechTypes [0] MechTypeList, reqFlags [1] ContextFlags OPTIONAL,
//!                             mechToken [2] OCTET STRING OPTIONAL, mechListMIC [3] OCTET STRING OPTIONAL }
//! NegTokenResp ::= SEQUENCE { negState [0] ENUMERATED OPTIONAL, supportedMech [1] MechType OPTIONAL,
//!                             responseToken [2] OCTET STRING OPTIONAL, mechListMIC [3] OCTET STRING OPTIONAL }
//! ```

use super::token::{KRB5_MECH_OID_DER, MS_KRB5_MECH_OID_DER};

/// DER of SPNEGO's OID, 1.3.6.1.5.5.2.
const SPNEGO_OID_DER: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// NTLMSSP's OID, 1.3.6.1.4.1.311.2.2.10 -- named in a refusal only.
const NTLMSSP_OID_DER: &[u8] = &[0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed SPNEGO token: {0}")]
    Malformed(&'static str),
    #[error("not a SPNEGO initial token (a negTokenResp continuing another exchange is not supported)")]
    NotInit,
    #[error("the client offers no Kerberos mechanism (NTLM is not supported, D4)")]
    NoKerberos,
    #[error("the client prefers {0} over Kerberos; only a Kerberos-first negotiation is supported")]
    KerberosNotPreferred(&'static str),
    #[error("no optimistic Kerberos token in the negTokenInit")]
    NoMechToken,
}

/// What a `negTokenInit` carries that the bind needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegTokenInit {
    /// The `mechTypes` SEQUENCE exactly as sent (tag, length, OIDs): what
    /// the mechListMIC covers (RFC 4178 §5).
    pub mech_types_der: Vec<u8>,
    /// Each offered OID, as its full DER TLV, in the client's order.
    pub mech_types: Vec<Vec<u8>>,
    pub mech_token: Option<Vec<u8>>,
}

/// One DER TLV at `buf[pos..]`: (tag, content, position after it).
fn tlv(buf: &[u8], pos: usize) -> Result<(u8, &[u8], usize), Error> {
    let tag = *buf.get(pos).ok_or(Error::Malformed("truncated tag"))?;
    let first = *buf.get(pos + 1).ok_or(Error::Malformed("truncated length"))?;
    let (len, hdr) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(Error::Malformed("unsupported length form"));
        }
        let bytes = buf.get(pos + 2..pos + 2 + n).ok_or(Error::Malformed("truncated length"))?;
        (bytes.iter().fold(0usize, |a, &b| (a << 8) | b as usize), 2 + n)
    };
    let start = pos + hdr;
    let content = buf.get(start..start + len).ok_or(Error::Malformed("truncated content"))?;
    Ok((tag, content, start + len))
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let b = (n as u32).to_be_bytes();
        let skip = b.iter().position(|&x| x != 0).unwrap_or(3);
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&b[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn is_kerberos(oid_der: &[u8]) -> bool {
    oid_der == KRB5_MECH_OID_DER || oid_der == MS_KRB5_MECH_OID_DER
}

fn mech_name(oid_der: &[u8]) -> &'static str {
    if oid_der == NTLMSSP_OID_DER {
        "NTLMSSP"
    } else {
        "another mechanism"
    }
}

/// Parses the client's initial SPNEGO token.
pub fn parse_init(buf: &[u8]) -> Result<NegTokenInit, Error> {
    let (tag, body, _) = tlv(buf, 0)?;
    if tag != 0x60 {
        return Err(Error::NotInit);
    }
    if !body.starts_with(SPNEGO_OID_DER) {
        return Err(Error::Malformed("thisMech is not SPNEGO"));
    }
    let (tag, init, _) = tlv(body, SPNEGO_OID_DER.len())?;
    if tag != 0xa0 {
        return Err(Error::NotInit);
    }
    let (tag, seq, _) = tlv(init, 0)?;
    if tag != 0x30 {
        return Err(Error::Malformed("NegTokenInit is not a SEQUENCE"));
    }
    let (mut mech_types_der, mut mech_types, mut mech_token) = (None, Vec::new(), None);
    let mut pos = 0;
    while pos < seq.len() {
        let (tag, content, next) = tlv(seq, pos)?;
        match tag {
            0xa0 => {
                let (t, list, _) = tlv(content, 0)?;
                if t != 0x30 {
                    return Err(Error::Malformed("mechTypes is not a SEQUENCE"));
                }
                let mut p = 0;
                while p < list.len() {
                    let (t, _, n) = tlv(list, p)?;
                    if t != 0x06 {
                        return Err(Error::Malformed("a mechType is not an OID"));
                    }
                    mech_types.push(list[p..n].to_vec());
                    p = n;
                }
                mech_types_der = Some(content.to_vec());
            }
            0xa2 => {
                let (t, tok, _) = tlv(content, 0)?;
                if t != 0x04 {
                    return Err(Error::Malformed("mechToken is not an OCTET STRING"));
                }
                mech_token = Some(tok.to_vec());
            }
            _ => {} // reqFlags, mechListMIC (not needed for a Kerberos-first init)
        }
        pos = next;
    }
    let mech_types_der = mech_types_der.ok_or(Error::Malformed("no mechTypes"))?;
    Ok(NegTokenInit { mech_types_der, mech_types, mech_token })
}

impl NegTokenInit {
    /// The Kerberos OID the client prefers (its first mechType), and the
    /// optimistic AP-REQ token -- or why this negotiation is refused.
    pub fn kerberos_first(&self) -> Result<(&[u8], &[u8]), Error> {
        let first = self.mech_types.first().ok_or(Error::Malformed("empty mechTypes"))?;
        if !is_kerberos(first) {
            if self.mech_types.iter().any(|m| is_kerberos(m)) {
                return Err(Error::KerberosNotPreferred(mech_name(first)));
            }
            return Err(Error::NoKerberos);
        }
        let token = self.mech_token.as_deref().ok_or(Error::NoMechToken)?;
        Ok((first, token))
    }
}

/// negState values (RFC 4178 §4.2.2).
pub const ACCEPT_COMPLETED: u8 = 0;

/// The acceptor's `negTokenResp` (not wrapped in an InitialContextToken:
/// only the initiator's first token is).
pub fn build_resp(neg_state: u8, supported_mech: Option<&[u8]>, response_token: Option<&[u8]>, mech_list_mic: Option<&[u8]>) -> Vec<u8> {
    let mut seq = der(0xa0, &der(0x0a, &[neg_state]));
    if let Some(m) = supported_mech {
        seq.extend(der(0xa1, m));
    }
    if let Some(t) = response_token {
        seq.extend(der(0xa2, &der(0x04, t)));
    }
    if let Some(m) = mech_list_mic {
        seq.extend(der(0xa3, &der(0x04, m)));
    }
    der(0xa1, &der(0x30, &seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A negTokenInit as Windows sends it: MS-KRB5, KRB5, NTLMSSP, reqFlags, mechToken.
    fn windows_init(mech_token: &[u8]) -> Vec<u8> {
        let mut list = Vec::new();
        list.extend_from_slice(MS_KRB5_MECH_OID_DER);
        list.extend_from_slice(KRB5_MECH_OID_DER);
        list.extend_from_slice(NTLMSSP_OID_DER);
        let mut seq = der(0xa0, &der(0x30, &list));
        seq.extend(der(0xa1, &[0x03, 0x02, 0x00, 0x00]));
        seq.extend(der(0xa2, &der(0x04, mech_token)));
        let mut body = SPNEGO_OID_DER.to_vec();
        body.extend(der(0xa0, &der(0x30, &seq)));
        der(0x60, &body)
    }

    #[test]
    fn a_windows_init_parses_with_mechtypes_kept_verbatim() {
        let tok = vec![0x60; 300]; // long enough for a long-form length
        let init = parse_init(&windows_init(&tok)).unwrap();
        assert_eq!(init.mech_types.len(), 3);
        assert_eq!(init.mech_types[0], MS_KRB5_MECH_OID_DER);
        assert_eq!(init.mech_types_der[0], 0x30);
        assert_eq!(init.mech_types_der.len(), 2 + 11 + 11 + 12);
        let (mech, token) = init.kerberos_first().unwrap();
        assert_eq!(mech, MS_KRB5_MECH_OID_DER);
        assert_eq!(token, tok.as_slice());
    }

    #[test]
    fn ntlm_first_or_ntlm_only_is_refused_by_name() {
        let mut list = NTLMSSP_OID_DER.to_vec();
        let only_ntlm = NegTokenInit { mech_types_der: der(0x30, &list), mech_types: vec![NTLMSSP_OID_DER.to_vec()], mech_token: Some(vec![1]) };
        assert_eq!(only_ntlm.kerberos_first(), Err(Error::NoKerberos));
        list.extend_from_slice(KRB5_MECH_OID_DER);
        let ntlm_first = NegTokenInit {
            mech_types_der: der(0x30, &list),
            mech_types: vec![NTLMSSP_OID_DER.to_vec(), KRB5_MECH_OID_DER.to_vec()],
            mech_token: Some(vec![1]),
        };
        assert_eq!(ntlm_first.kerberos_first(), Err(Error::KerberosNotPreferred("NTLMSSP")));
        let no_token = NegTokenInit { mech_types_der: vec![], mech_types: vec![KRB5_MECH_OID_DER.to_vec()], mech_token: None };
        assert_eq!(no_token.kerberos_first(), Err(Error::NoMechToken));
    }

    #[test]
    fn a_resp_is_the_rfc_4178_shape() {
        let r = build_resp(ACCEPT_COMPLETED, Some(MS_KRB5_MECH_OID_DER), Some(&[0xAA; 3]), Some(&[0xBB; 2]));
        let mut want = vec![0xa1, 0x21, 0x30, 0x1f, 0xa0, 0x03, 0x0a, 0x01, 0x00, 0xa1, 0x0b];
        want.extend_from_slice(MS_KRB5_MECH_OID_DER);
        want.extend_from_slice(&[0xa2, 0x05, 0x04, 0x03, 0xAA, 0xAA, 0xAA, 0xa3, 0x04, 0x04, 0x02, 0xBB, 0xBB]);
        assert_eq!(r, want);
    }

    #[test]
    fn malformed_tokens_are_errors_not_panics() {
        for b in [&[][..], &[0x60], &[0x60, 0x05, 0x06], &[0xa1, 0x00], &[0x60, 0x84, 0xff, 0xff, 0xff, 0xff]] {
            assert!(parse_init(b).is_err(), "{b:02x?}");
        }
    }
}
