//! GSS-API "accept security context" for the Kerberos V5 mechanism (RFC
//! 4121) -- this is fundamentally the same operation `iron-kdc`'s
//! TGS-REQ handler already does (decrypt a Ticket, validate an
//! Authenticator), just from an application server's perspective
//! instead of a KDC's, with different key usage numbers (RFC 4120
//! §7.5.1: 11/12 here for the application AP-REQ/AP-REP, vs. TGS-REQ's
//! 2/7/8) and an extra GSS-specific checksum format in the Authenticator
//! (RFC 4121 §4.1.1).
//!
//! Not implemented, documented rather than silent: channel binding
//! verification (the `Bnd` field of the GSS checksum is read but never
//! checked against the actual transport), and delegation
//! (`GSS_C_DELEG_FLAG`/the `KRB_CRED` it would carry).

use iron_crypto::kerberos::{self, Enctype};
use iron_crypto::FipsContext;
use iron_kdc::principal::PrincipalKey;
use rasn_kerberos::{ApRep, ApReq, Authenticator, EncApRepPart, EncTicketPart, EncryptedData, PrincipalName};

use super::token;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("GSS token framing error: {0}")]
    Token(#[from] token::Error),
    #[error("DER decode failed: {0}")]
    Decode(#[from] rasn::error::DecodeError),
    #[error("DER encode failed: {0}")]
    Encode(#[from] rasn::error::EncodeError),
    #[error("no key for ticket issuer principal")]
    NoServiceKey,
    #[error("unsupported enctype {0}")]
    UnsupportedEnctype(i32),
    #[error("ticket decryption failed (wrong service key or corrupted ticket)")]
    TicketDecryptFailed,
    #[error("authenticator decryption failed")]
    AuthenticatorDecryptFailed,
    #[error("authenticator does not match ticket (crealm/cname mismatch)")]
    AuthenticatorMismatch,
    #[error("clock skew too great")]
    ClockSkew,
    #[error("ticket expired")]
    TicketExpired,
    #[error("missing or malformed GSS checksum (type must be 0x8003)")]
    MalformedGssChecksum,
    #[error("crypto error: {0}")]
    Crypto(#[from] iron_crypto::Error),
}

pub const CLOCK_SKEW_SECS: i64 = 300;
const GSS_CHECKSUM_TYPE: i32 = 0x8003;
pub const GSS_C_MUTUAL_FLAG: u32 = 2;

pub struct AcceptedContext {
    pub client_principal: String,
    pub session_key: Vec<u8>,
    pub enctype: Enctype,
    /// The GSS output token to return to the client (a mutual-auth
    /// AP-REP, wrapped per RFC 4121 §4.1), if mutual authentication was
    /// requested (`GSS_C_MUTUAL_FLAG` set in the Authenticator's GSS
    /// checksum -- real clients doing a SASL/GSSAPI LDAP bind always
    /// set this per RFC 4752 §3.1).
    pub output_token: Option<Vec<u8>>,
}

fn gss_checksum_flags(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() < 24 {
        return Err(Error::MalformedGssChecksum);
    }
    Ok(u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]))
}

/// Accepts a GSS-API initial context token carrying a Kerberos AP-REQ.
/// `lookup_key` resolves the target service principal's stored keys
/// (looked up from the presented ticket's own `sname`/`realm`, the same
/// issuer-driven approach `iron-kdc`'s TGS-REQ handler uses for
/// cross-realm-readiness) -- provided by the caller since this module
/// has no DIT access of its own (keeps it free of iron-store/tokio deps,
/// matching `iron_crypto::kerberos`'s own separation of protocol logic
/// from storage).
pub async fn accept<F, Fut>(ctx: &FipsContext, input_token: &[u8], lookup_key: F) -> Result<AcceptedContext, Error>
where
    F: FnOnce(PrincipalName, String) -> Fut,
    Fut: std::future::Future<Output = Option<Vec<PrincipalKey>>>,
{
    let inner = token::parse_initial_context_token(input_token)?;
    let ap_req_bytes = token::split_tok_id(inner, token::TOK_ID_AP_REQ)?;
    let ap_req: ApReq = rasn::der::decode(ap_req_bytes)?;

    let issuer_realm = iron_kdc::realm_to_string(&ap_req.ticket.realm);
    let service_keys = lookup_key(ap_req.ticket.sname.clone(), issuer_realm).await.ok_or(Error::NoServiceKey)?;

    let tkt_enctype =
        Enctype::try_from(ap_req.ticket.enc_part.etype).map_err(|_| Error::UnsupportedEnctype(ap_req.ticket.enc_part.etype))?;
    let service_key = service_keys.iter().find(|k| k.enctype == tkt_enctype).ok_or(Error::NoServiceKey)?;

    let enc_ticket_bytes = kerberos::decrypt(ctx, tkt_enctype, &service_key.key, 2, &ap_req.ticket.enc_part.cipher)
        .map_err(|_| Error::TicketDecryptFailed)?;
    let tgt: EncTicketPart = rasn::der::decode(&enc_ticket_bytes)?;

    let (now, _) = iron_kdc::time::now();
    if iron_kdc::time::diff_seconds(&tgt.end_time, &now) > 0 {
        return Err(Error::TicketExpired);
    }

    // Key usage 11: "AP-REQ Authenticator (includes application
    // authenticator subkey), encrypted with the application session
    // key" (RFC 4120 §7.5.1) -- distinct from TGS-REQ's usage 7, which
    // is for the Authenticator carried in a *TGS* request specifically.
    let ticket_session_key = tgt.key.value.to_vec();
    // The Authenticator itself is always encrypted with the *ticket's*
    // session key regardless of any subkey it goes on to assert (RFC
    // 4120 5.5.1) -- the subkey only takes over as the base key for
    // everything *after* this point.
    let auth_bytes = kerberos::decrypt(ctx, tkt_enctype, &ticket_session_key, 11, &ap_req.authenticator.cipher)
        .map_err(|_| Error::AuthenticatorDecryptFailed)?;
    let authenticator: Authenticator = rasn::der::decode(&auth_bytes)?;

    if authenticator.crealm != tgt.crealm || authenticator.cname != tgt.cname {
        return Err(Error::AuthenticatorMismatch);
    }
    if iron_kdc::time::diff_seconds(&authenticator.ctime, &now).abs() > CLOCK_SKEW_SECS {
        return Err(Error::ClockSkew);
    }
    let cksum = authenticator.cksum.as_ref().ok_or(Error::MalformedGssChecksum)?;
    if cksum.r#type != GSS_CHECKSUM_TYPE {
        return Err(Error::MalformedGssChecksum);
    }
    let gss_flags = gss_checksum_flags(&cksum.checksum)?;

    // RFC 4121 §2: "if the initiator asserts a subkey in the AP-REQ
    // message, the base key is this subkey; if the initiator does not
    // assert a subkey, the base key is the session key in the service
    // ticket." (We never assert our own acceptor subkey, so the other
    // branch -- "if the acceptor asserts a subkey" -- never applies
    // here.) This base key is what every *subsequent* Wrap/Unwrap uses
    // (RFC 4121's own per-message-token key derivation) -- but NOT the
    // AP-REP itself: RFC 4120 §3.2.5 is explicit that "for encrypting
    // the KRB_AP_REP message, the sub-session key is not used, even if
    // it is present in the Authenticat[or]" -- easy to conflate the two
    // since they're adjacent steps in the same exchange, but they use
    // different keys.
    let session_key = authenticator.subkey.as_ref().map(|k| k.value.to_vec()).unwrap_or_else(|| ticket_session_key.clone());

    let output_token = if gss_flags & GSS_C_MUTUAL_FLAG != 0 {
        // RFC 4120 §3.2.4: "The timestamp and microsecond field used in
        // the reply MUST be the client's timestamp and microsecond field
        // (as provided in the authenticator)" -- not a freshly-generated
        // one; the client checks these back against what it sent.
        let enc_ap_rep_part =
            EncApRepPart { ctime: authenticator.ctime.clone(), cusec: authenticator.cusec.clone(), subkey: None, seq_number: None };
        let enc_bytes = rasn::der::encode(&enc_ap_rep_part)?;
        // Key usage 12, encrypted under the *ticket* session key (RFC
        // 4120 §3.2.5), not the subkey-derived base key.
        let cipher = kerberos::encrypt(ctx, tkt_enctype, &ticket_session_key, 12, &enc_bytes)?;
        let ap_rep = ApRep {
            pvno: 5.into(),
            msg_type: 15.into(),
            enc_part: EncryptedData { etype: tkt_enctype.etype_number(), kvno: None, cipher: cipher.into() },
        };
        let ap_rep_bytes = rasn::der::encode(&ap_rep)?;
        let mut inner_out = Vec::with_capacity(2 + ap_rep_bytes.len());
        inner_out.extend_from_slice(&token::TOK_ID_AP_REP);
        inner_out.extend_from_slice(&ap_rep_bytes);
        Some(token::build_initial_context_token(&inner_out))
    } else {
        None
    };

    Ok(AcceptedContext {
        client_principal: format!("{}@{}", iron_kdc::principal_name_to_string(&tgt.cname), iron_kdc::realm_to_string(&tgt.crealm)),
        session_key,
        enctype: tkt_enctype,
        output_token,
    })
}
