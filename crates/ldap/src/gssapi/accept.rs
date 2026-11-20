//! GSS-API "accept security context" for the Kerberos V5 mechanism (RFC
//! 4121) -- this is fundamentally the same operation `iron-kdc`'s
//! TGS-REQ handler already does (decrypt a Ticket, validate an
//! Authenticator), just from an application server's perspective
//! instead of a KDC's, with different key usage numbers (RFC 4120
//! §7.5.1: 11/12 here for the application AP-REQ/AP-REP, vs. TGS-REQ's
//! 2/7/8) and an extra GSS-specific checksum format in the Authenticator
//! (RFC 4121 §4.1.1).
//!
//! Channel bindings (#65) are checked the way Active Directory's "LDAP
//! channel binding" does (ADV190023): the `Bnd` field of the GSS checksum
//! (RFC 4121 §4.1.1.2) is the MD5 of the channel bindings the client saw.
//! A zero `Bnd` means the client supplied none and is accepted (AD's "When
//! supported"), unless [`ChannelBindingPolicy::Always`] requires them on a
//! TLS connection. A non-zero `Bnd` must equal the MD5 of this
//! connection's own bindings -- RFC 5929 `tls-server-end-point` of our
//! certificate on LDAPS/StartTLS -- and is refused on plain LDAP, which
//! has no channel to bind to. A TLS-terminating relay presents its own
//! certificate, so a bind relayed through it no longer matches.
//!
//! Delegation is declined, as RFC 4121 §4.1.1.1 lets an acceptor do: a
//! directory server has no use for a client's forwarded TGT, so a
//! `GSS_C_DELEG_FLAG` and the `KRB_CRED` after the checksum's flags are
//! ignored and the credential is never decrypted or kept.

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
    #[error("channel bindings do not match this TLS connection (tls-server-end-point)")]
    ChannelBindingMismatch,
    #[error("channel bindings supplied on a connection without TLS")]
    ChannelBindingWithoutTls,
    #[error("channel bindings required on this TLS connection, client supplied none")]
    ChannelBindingRequired,
    #[error("crypto error: {0}")]
    Crypto(#[from] iron_crypto::Error),
}

pub const CLOCK_SKEW_SECS: i64 = 300;
const GSS_CHECKSUM_TYPE: i32 = 0x8003;
pub const GSS_C_MUTUAL_FLAG: u32 = 2;

/// When a GSSAPI bind over TLS must carry channel bindings -- AD's "LDAP
/// server channel binding token requirements" (`LdapEnforceChannelBinding`).
/// Set with `IRON_LDAP_CHANNEL_BINDING` (see iron-ldapd).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChannelBindingPolicy {
    /// AD's "When supported" (1): bindings a client sends are verified, a
    /// client that sends none is accepted.
    #[default]
    WhenSupported,
    /// AD's "Always" (2): over TLS, a bind without bindings is refused too.
    Always,
}

impl std::str::FromStr for ChannelBindingPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "when-supported" => Ok(Self::WhenSupported),
            "always" => Ok(Self::Always),
            other => Err(format!("unknown channel binding policy {other:?} (when-supported or always)")),
        }
    }
}

/// What the connection a bind arrived on can bind to.
#[derive(Debug, Clone, Copy)]
pub struct Channel<'a> {
    /// The `application_data` of this connection's channel bindings:
    /// `tls-server-end-point:` + the RFC 5929 hash of our certificate
    /// (`crate::tls::server_end_point`), or `None` on plain LDAP.
    pub tls_binding: Option<&'a [u8]>,
    pub policy: ChannelBindingPolicy,
}

/// The 16-byte `Bnd` an initiator computes for `application_data` (RFC
/// 4121 §4.1.1.2, RFC 1964 §1.1.1; MIT `kg_checksum_channel_bindings`):
/// MD5 over the flattened `gss_channel_bindings_struct` -- each address
/// type and length a 4-byte little-endian integer -- with no initiator
/// or acceptor address, as LDAP clients (OpenLDAP, Windows) send them.
pub fn channel_bindings_hash(application_data: &[u8]) -> [u8; 16] {
    let mut flat = Vec::with_capacity(20 + application_data.len());
    flat.extend_from_slice(&[0u8; 16]); // initiator addrtype + length, acceptor addrtype + length
    flat.extend_from_slice(&(application_data.len() as u32).to_le_bytes());
    flat.extend_from_slice(application_data);
    iron_crypto::md5::md5(&flat)
}

/// Checks the checksum's `Bnd` (bytes 4..20) against `channel`. Returns
/// whether the context is bound to the channel.
fn check_channel_binding(cksum: &[u8], channel: Channel<'_>) -> Result<bool, Error> {
    let bnd = cksum.get(4..20).ok_or(Error::MalformedGssChecksum)?;
    let supplied = bnd.iter().any(|&b| b != 0);
    match (supplied, channel.tls_binding) {
        (false, Some(_)) if channel.policy == ChannelBindingPolicy::Always => Err(Error::ChannelBindingRequired),
        (false, _) => Ok(false),
        (true, None) => Err(Error::ChannelBindingWithoutTls),
        (true, Some(app_data)) if channel_bindings_hash(app_data) == bnd => Ok(true),
        (true, Some(_)) => Err(Error::ChannelBindingMismatch),
    }
}

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
    /// Whether the client's channel bindings were checked and matched
    /// this TLS connection (`false`: it sent none).
    pub channel_bound: bool,
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
///
/// `channel` is what the connection can bind to; see the module doc.
pub async fn accept<F, Fut>(ctx: &FipsContext, input_token: &[u8], channel: Channel<'_>, lookup_key: F) -> Result<AcceptedContext, Error>
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
    let channel_bound = check_channel_binding(&cksum.checksum, channel)?;

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
        channel_bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_DATA: &[u8] = b"tls-server-end-point:0123456789abcdef0123456789abcdef";

    fn checksum(bnd: [u8; 16]) -> Vec<u8> {
        let mut c = 16u32.to_le_bytes().to_vec();
        c.extend_from_slice(&bnd);
        c.extend_from_slice(&GSS_C_MUTUAL_FLAG.to_le_bytes());
        c
    }

    fn tls(policy: ChannelBindingPolicy) -> Channel<'static> {
        Channel { tls_binding: Some(APP_DATA), policy }
    }

    const PLAIN: Channel<'static> = Channel { tls_binding: None, policy: ChannelBindingPolicy::WhenSupported };

    // The expected value is Python's hashlib.md5 over the struct flattened
    // independently (b"\0" * 16 + struct.pack("<I", len) + APP_DATA); real
    // MIT/OpenLDAP clients are checked by test/ldap-channel-binding-e2e.sh.
    #[test]
    fn bnd_matches_the_flattened_struct() {
        let mut flat = vec![0u8; 16];
        flat.extend_from_slice(&(APP_DATA.len() as u32).to_le_bytes());
        flat.extend_from_slice(APP_DATA);
        assert_eq!(channel_bindings_hash(APP_DATA), iron_crypto::md5::md5(&flat));
        let hex: String = channel_bindings_hash(APP_DATA).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "5eda5394c965f26697e73da2828a7ad0");
    }

    #[test]
    fn matching_bindings_over_tls_bind_the_context() {
        let c = checksum(channel_bindings_hash(APP_DATA));
        assert!(check_channel_binding(&c, tls(ChannelBindingPolicy::WhenSupported)).unwrap());
        assert!(check_channel_binding(&c, tls(ChannelBindingPolicy::Always)).unwrap());
    }

    #[test]
    fn bindings_of_another_certificate_are_refused() {
        let c = checksum(channel_bindings_hash(b"tls-server-end-point:a relay's certificate hash"));
        assert!(matches!(check_channel_binding(&c, tls(ChannelBindingPolicy::WhenSupported)), Err(Error::ChannelBindingMismatch)));
    }

    #[test]
    fn bindings_on_plain_ldap_are_refused() {
        let c = checksum(channel_bindings_hash(APP_DATA));
        assert!(matches!(check_channel_binding(&c, PLAIN), Err(Error::ChannelBindingWithoutTls)));
    }

    #[test]
    fn no_bindings_are_accepted_unless_always_over_tls() {
        let c = checksum([0; 16]);
        assert!(!check_channel_binding(&c, PLAIN).unwrap());
        assert!(!check_channel_binding(&c, tls(ChannelBindingPolicy::WhenSupported)).unwrap());
        assert!(matches!(check_channel_binding(&c, tls(ChannelBindingPolicy::Always)), Err(Error::ChannelBindingRequired)));
        let always_plain = Channel { policy: ChannelBindingPolicy::Always, ..PLAIN };
        assert!(!check_channel_binding(&c, always_plain).unwrap());
    }

    #[test]
    fn policy_parses() {
        assert_eq!("always".parse::<ChannelBindingPolicy>().unwrap(), ChannelBindingPolicy::Always);
        assert_eq!("when-supported".parse::<ChannelBindingPolicy>().unwrap(), ChannelBindingPolicy::WhenSupported);
        assert!("never".parse::<ChannelBindingPolicy>().is_err());
    }
}
