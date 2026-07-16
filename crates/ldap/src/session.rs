//! Per-connection LDAP session: reads framed `LdapMessage`s and dispatches
//! bind/search/add/delete/modify/compare (the operations implemented so
//! far -- see crate docs).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use iron_crypto::kerberos::Enctype;
use iron_partition::Dn;
use iron_store::model::Entry;
use iron_store::store::Store;
use openssl::ssl::SslAcceptor;
use rasn::types::{OctetString, SetOf};
use rasn::Decoder as _;
use rasn_kerberos::PrincipalName;
use rasn_ldap::{
    AddRequest, AddResponse, Attribute, AuthenticationChoice, BindRequest, BindResponse,
    ChangeOperation, CompareRequest, CompareResponse, DelRequest, DelResponse, ExtendedResponse,
    LdapMessage, LdapResult, ModifyDnRequest, ModifyDnResponse, ModifyRequest, ModifyResponse,
    PartialAttribute, ProtocolOp, ResultCode, SaslCredentials, SearchRequest, SearchRequestScope,
    SearchResultDone, SearchResultEntry,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::conn::Conn;
use crate::framing::{read_message, read_sized_buffer, write_message, write_sized_buffer};
use crate::{filter, rootdse, AppState};

/// LDAP attribute holding the PBKDF2-hashed password (D4). Lowercase to
/// match `Entry`'s case-folded storage.
const USER_PASSWORD_ATTR: &str = "userpassword";

/// RFC 4511 §4.14.1 -- the well-known OID for the StartTLS extended
/// operation.
const STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

/// RFC 4532 §1.1 -- the well-known OID for the "Who am I?" extended
/// operation.
const WHOAMI_OID: &[u8] = b"1.3.6.1.4.1.4203.1.11.3";

/// RFC 3062 -- the well-known OID for the Password Modify extended
/// operation. Found live testing a real macOS `dsconfigad` join (#20):
/// with no SAMR/SMB reachable, the computer account's initial Kerberos
/// key gets set entirely over LDAP via this extended op, not
/// `SamrSetInformationUser2`/NETLOGON at all.
const PASSWORD_MODIFY_OID: &[u8] = b"1.3.6.1.4.1.4203.1.11.1";

/// RFC 3062 §4's request value:
/// ```text
/// PasswdModifyRequestValue ::= SEQUENCE {
///    userIdentity    [0]  OCTET STRING OPTIONAL
///    oldPasswd       [1]  OCTET STRING OPTIONAL
///    newPasswd       [2]  OCTET STRING OPTIONAL }
/// ```
#[derive(rasn::AsnType, rasn::Decode, Default)]
struct PasswdModifyRequestValue {
    #[rasn(tag(context, 0))]
    user_identity: Option<OctetString>,
    #[allow(dead_code)] // part of RFC 3062's shape; no client here needs old-password verification yet
    #[rasn(tag(context, 1))]
    old_passwd: Option<OctetString>,
    #[rasn(tag(context, 2))]
    new_passwd: Option<OctetString>,
}

/// Per-connection SASL/GSSAPI negotiation state (RFC 4752), threaded
/// through successive `BindRequest`s on the *same* connection -- unlike
/// simple bind, a GSSAPI bind is a multi-message exchange (AP-REQ ->
/// mutual-auth AP-REP -> ack -> security-layer negotiation -> success).
#[derive(Default)]
enum SaslState {
    #[default]
    None,
    /// Sent a mutual-auth AP-REP; waiting for the client's
    /// empty-credentials acknowledgment before starting the security-layer
    /// negotiation.
    AwaitingApRepAck { session_key: Vec<u8>, enctype: Enctype, client_principal: String },
    /// Sent the security-layer negotiation challenge; waiting for the
    /// client's chosen layer.
    AwaitingSecurityLayerAck { session_key: Vec<u8>, enctype: Enctype, client_principal: String },
    /// Bind completed with the client selecting a security layer (RFC
    /// 4752 §3.4, integrity or confidentiality) -- every subsequent LDAP
    /// message on this connection is a GSS Wrap token inside a 4-octet
    /// length prefix, not a bare BER `LdapMessage`. `sealed` records
    /// which: `false` for integrity-only, `true` for confidentiality.
    /// Found live testing a real macOS `dsconfigad` join (#20): it
    /// rejects a bind that only ever offers "no security layer" with
    /// `GSS_S_BAD_QOP`, unlike MIT krb5's `ldapsearch` (used for every
    /// earlier SASL/GSSAPI verification), which accepts it -- and it
    /// separately requires confidentiality specifically to write the new
    /// computer account's Kerberos key, failing integrity-only binds the
    /// same way once it gets past the bind itself.
    ///
    /// `send_seq` is the acceptor's next outgoing Wrap-token sequence
    /// number (RFC 4121 §4.2.6.2 SND_SEQ). The security-layer challenge
    /// is the acceptor's *first* wrap token (seq 0, hardcoded in
    /// `security_layer_challenge`), so this starts at 1 and increments on
    /// every wrapped response -- a strict initiator (Heimdal / macOS
    /// `dsconfigad`) drops a token whose sequence number doesn't advance
    /// as a replay. `Cell` gives interior mutability so `send_response`
    /// can bump it while holding only `&SaslState`.
    SecurityLayerActive { session_key: Vec<u8>, enctype: Enctype, sealed: bool, send_seq: AtomicU64 },
}

// Manual `Clone` (rather than derived) because `AtomicU64` isn't `Clone`:
// snapshots the current sequence value into a fresh atomic. Used only to
// capture the pre-bind send state (see `handle_connection`'s bind arm);
// the clone and the original never send concurrently, so the snapshot is
// race-free in practice.
impl Clone for SaslState {
    fn clone(&self) -> Self {
        match self {
            SaslState::None => SaslState::None,
            SaslState::AwaitingApRepAck { session_key, enctype, client_principal } => {
                SaslState::AwaitingApRepAck { session_key: session_key.clone(), enctype: *enctype, client_principal: client_principal.clone() }
            }
            SaslState::AwaitingSecurityLayerAck { session_key, enctype, client_principal } => {
                SaslState::AwaitingSecurityLayerAck { session_key: session_key.clone(), enctype: *enctype, client_principal: client_principal.clone() }
            }
            SaslState::SecurityLayerActive { session_key, enctype, sealed, send_seq } => SaslState::SecurityLayerActive {
                session_key: session_key.clone(),
                enctype: *enctype,
                sealed: *sealed,
                send_seq: AtomicU64::new(send_seq.load(Ordering::Relaxed)),
            },
        }
    }
}

/// Reads the next `LdapMessage`, transparently unwrapping it first if
/// `sasl_state` says the integrity security layer is active on this
/// connection (see `SaslState::SecurityLayerActive`'s doc comment).
/// `Err(())` on any framing/GSS-unwrap failure -- the caller just closes
/// the connection either way, so the distinction isn't worth carrying.
async fn read_next_message<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    buf: &mut Vec<u8>,
    fips: Option<&iron_crypto::FipsContext>,
    sasl_state: &SaslState,
) -> Result<Option<LdapMessage>, ()> {
    match sasl_state {
        SaslState::SecurityLayerActive { session_key, enctype, .. } => {
            let fips = fips.ok_or(())?;
            let wrapped = match read_sized_buffer(conn, buf).await {
                Ok(Some(w)) => w,
                Ok(None) => return Ok(None),
                Err(_) => return Err(()),
            };
            // Key usage 24: KG-USAGE-INITIATOR-SEAL -- unwrapping a
            // token the client (the GSS initiator) sent. `unwrap`
            // dispatches on the token's own Sealed bit, so it doesn't
            // matter here which layer was negotiated.
            let plain = crate::gssapi::wrap::unwrap(fips, *enctype, session_key, 24, &wrapped).map_err(|_| ())?;
            rasn::ber::decode(&plain).map(Some).map_err(|_| ())
        }
        _ => read_message(conn, buf).await.map_err(|_| ()),
    }
}

/// Writes an `LdapMessage`, transparently GSS-wrapping it first under
/// the same condition `read_next_message` unwraps under.
async fn send_response<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    fips: Option<&iron_crypto::FipsContext>,
    sasl_state: &SaslState,
    msg: &LdapMessage,
) -> Result<(), ()> {
    match sasl_state {
        SaslState::SecurityLayerActive { session_key, enctype, sealed, send_seq } => {
            let fips = fips.ok_or(())?;
            let plain = rasn::ber::encode(msg).map_err(|_| ())?;
            // Consume this token's SND_SEQ and advance the counter so the
            // next wrapped response uses the following value (RFC 4121
            // §4.2.6.2 -- see `SecurityLayerActive`'s doc comment).
            let seq = send_seq.fetch_add(1, Ordering::Relaxed);
            // Key usage 22: KG-USAGE-ACCEPTOR-SEAL -- we're the GSS acceptor.
            let wrapped = crate::gssapi::wrap::wrap(fips, *enctype, session_key, 22, *sealed, seq, &plain).map_err(|_| ())?;
            write_sized_buffer(conn, &wrapped).await.map_err(|_| ())
        }
        _ => write_message(conn, msg).await.map_err(|_| ()),
    }
}

/// Handles one LDAP client connection until it unbinds, disconnects, or a
/// framing error occurs. `tls_acceptor` enables StartTLS on this
/// connection when `Some` -- pass `None` from `serve_ldaps` (StartTLS
/// over an already-implicit-TLS LDAPS connection is meaningless) and
/// `Some` from the plaintext `serve` listener when LDAPS/TLS is
/// configured at all.
pub async fn handle_connection<S>(stream: S, app: Arc<AppState>, tls_acceptor: Option<Arc<SslAcceptor>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = Conn::Plain(stream);
    let mut buf = Vec::new();
    let mut sasl_state = SaslState::None;
    // RFC 4513 §3 authzId this connection is currently bound as -- `None`
    // for anonymous, `Some("dn:...")`/`Some("u:...")` otherwise. Updated
    // on every *terminal* bind outcome (success or failure, but not a
    // still-in-progress SASL step) so a later WhoAmI extended operation
    // (RFC 4532) can answer correctly; RFC 4513 also permits re-binding
    // on the same connection, so this can change (including back to
    // `None`) more than once per connection.
    let mut bound_identity: Option<String> = None;
    loop {
        let msg = match read_next_message(&mut conn, &mut buf, app.fips.as_ref(), &sasl_state).await {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(()) => {
                tracing::debug!("framing or GSS-unwrap error, closing connection");
                return;
            }
        };
        let message_id = msg.message_id;

        match msg.protocol_op {
            ProtocolOp::UnbindRequest(_) => return,
            ProtocolOp::BindRequest(req) => {
                // RFC 4752 §3.1: the negotiated security layer takes effect
                // on the *first octet following* the last authentication
                // response -- i.e. the bindResponse that completes the SASL
                // handshake is itself sent in the clear, and only messages
                // after it are Wrapped. `handle_bind` flips `sasl_state` to
                // `SecurityLayerActive` on that terminal success, so we must
                // send the response using the state as it was *before* this
                // request (found live via packet capture, #20: sealing the
                // success response made macOS's client report GSS_S_BAD_QOP).
                // For a re-bind arriving *through* an already-active layer,
                // this same pre-request state correctly keeps the response
                // Wrapped.
                let send_state = sasl_state.clone();
                let (resp, identity) = handle_bind(&mut *app.store.lock().await, app.fips.as_ref(), &req, &mut sasl_state).await;
                if resp.result_code != ResultCode::SaslBindInProgress {
                    bound_identity = identity;
                }
                let resp = LdapMessage::new(message_id, ProtocolOp::BindResponse(resp));
                if send_response(&mut conn, app.fips.as_ref(), &send_state, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::SearchRequest(req) => {
                let mut store = app.store.lock().await;
                let ops = handle_search(&mut store, &req, &app.referral_config(), app.fips.is_some()).await;
                drop(store);
                for op in ops {
                    let resp = LdapMessage::new(message_id, op);
                    if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                        return;
                    }
                }
            }
            ProtocolOp::AddRequest(req) => {
                let resp = handle_add(&mut *app.store.lock().await, app.fips.as_ref(), &req, &app.index_spec, &app.referral_config()).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::AddResponse(resp));
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::DelRequest(req) => {
                let resp = handle_delete(&mut *app.store.lock().await, &req, &app.index_spec, &app.referral_config()).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::DelResponse(resp));
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::ModifyRequest(req) => {
                let resp = handle_modify(&mut *app.store.lock().await, app.fips.as_ref(), &req, &app.index_spec, &app.referral_config()).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::ModifyResponse(resp));
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::CompareRequest(req) => {
                let resp = handle_compare(&mut *app.store.lock().await, &req, &app.referral_config()).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::CompareResponse(resp));
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::ModDnRequest(req) => {
                let resp = handle_moddn(&mut *app.store.lock().await, &req, &app.index_spec, &app.referral_config()).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::ModDnResponse(resp));
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::ExtendedReq(req) if req.request_name.as_ref() == STARTTLS_OID => {
                let (code, diagnostic) = match (&conn, &tls_acceptor) {
                    (Conn::Tls(_), _) => (ResultCode::OperationsError, "already TLS"),
                    (Conn::Plain(_), None) => (ResultCode::ProtocolError, "StartTLS is not configured (no TLS cert/key)"),
                    (Conn::Plain(_), Some(_)) => (ResultCode::Success, ""),
                };
                let resp = LdapMessage::new(
                    message_id,
                    ProtocolOp::ExtendedResp(ExtendedResponse {
                        result_code: code,
                        matched_dn: String::new().into(),
                        diagnostic_message: diagnostic.into(),
                        referral: None,
                        response_name: Some(STARTTLS_OID.to_vec().into()),
                        response_value: None,
                    }),
                );
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
                if code == ResultCode::Success {
                    let Some(acceptor) = &tls_acceptor else { unreachable!() };
                    conn = match conn.upgrade_to_tls(acceptor).await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("StartTLS handshake failed: {e}");
                            return;
                        }
                    };
                    buf.clear(); // any bytes buffered before the handshake were plaintext framing only
                }
            }
            // RFC 4532 "Who am I?" -- reports this connection's current
            // authzId (see `bound_identity`'s doc comment above), which
            // requires no store lookup at all: the identity was already
            // resolved and validated at bind time.
            ProtocolOp::ExtendedReq(req) if req.request_name.as_ref() == WHOAMI_OID => {
                let resp = LdapMessage::new(
                    message_id,
                    ProtocolOp::ExtendedResp(ExtendedResponse {
                        result_code: ResultCode::Success,
                        matched_dn: String::new().into(),
                        diagnostic_message: String::new().into(),
                        referral: None,
                        // RFC 4532 §2: no responseName on a WhoAmI response.
                        response_name: None,
                        // Always present per RFC 4532 §2, empty for an
                        // anonymous connection rather than the field
                        // being absent entirely.
                        response_value: Some(bound_identity.clone().unwrap_or_default().into_bytes().into()),
                    }),
                );
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
            }
            // RFC 3062 Password Modify -- see PASSWORD_MODIFY_OID's doc
            // comment for why this exists (#20: a real macOS domain
            // join, with no SAMR/SMB reachable, sets the new computer
            // account's Kerberos key entirely this way).
            ProtocolOp::ExtendedReq(req) if req.request_name.as_ref() == PASSWORD_MODIFY_OID => {
                let resp_value = handle_password_modify(
                    &mut *app.store.lock().await,
                    app.fips.as_ref(),
                    req.request_value.as_deref(),
                    bound_identity.as_deref(),
                    &app.index_spec,
                )
                .await;
                let (code, diagnostic) = match &resp_value {
                    Ok(_) => (ResultCode::Success, String::new()),
                    Err(e) => (e.code, e.message.clone()),
                };
                let resp = LdapMessage::new(
                    message_id,
                    ProtocolOp::ExtendedResp(ExtendedResponse {
                        result_code: code,
                        matched_dn: String::new().into(),
                        diagnostic_message: diagnostic.into(),
                        referral: None,
                        response_name: Some(PASSWORD_MODIFY_OID.to_vec().into()),
                        response_value: resp_value.ok().flatten(),
                    }),
                );
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
            }
            // Not yet implemented (#4 tracks the rest of the scope), but
            // every one of these has a defined response -- a client must
            // not be left hanging waiting for one that never comes.
            ProtocolOp::ExtendedReq(_) => {
                let resp = LdapMessage::new(
                    message_id,
                    ProtocolOp::ExtendedResp(ExtendedResponse {
                        result_code: ResultCode::ProtocolError,
                        matched_dn: String::new().into(),
                        diagnostic_message: "extended operations are not implemented yet".into(),
                        referral: None,
                        response_name: None,
                        response_value: None,
                    }),
                );
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
            }
            // Abandon has no response per RFC 4511 §4.11. IntermediateResponse
            // and any future/unknown op the client sends: nothing sensible to
            // reply with, so drop it rather than guess.
            _ => {}
        }
    }
}

fn unwilling(diagnostic: &str) -> LdapResult {
    LdapResult::new(
        ResultCode::UnwillingToPerform,
        String::new().into(),
        diagnostic.into(),
    )
}

fn success() -> LdapResult {
    LdapResult::new(ResultCode::Success, String::new().into(), String::new().into())
}

fn operations_error(diagnostic: &str) -> LdapResult {
    LdapResult::new(ResultCode::OperationsError, String::new().into(), diagnostic.into())
}

fn invalid_dn() -> LdapResult {
    LdapResult::new(ResultCode::InvalidDnSyntax, String::new().into(), "invalid DN".into())
}

/// Bundles the two referral sources consulted on an out-of-scope DN
/// (#9/#10): the persisted, authoritative forest topology (checked
/// first) and the static `IRON_LDAP_REFERRALS` fallback list (for
/// deployments with no configuration partition set up, e.g. the
/// standalone il1/il2/il3 replicas). A cheap, per-request bundle of
/// borrows -- see `AppState::referral_config`.
pub struct Referrals<'a> {
    pub topology: Option<&'a iron_partition::PartitionRegistry>,
    pub static_list: &'a [(Dn, String)],
    /// This instance's own partition id -- see `proactive_referral`.
    pub own_partition_id: Option<&'a iron_partition::PartitionId>,
}

/// A naming context this server doesn't host, if `dn` falls under a
/// partition known to `refs.topology` with an `ldap_url` set, or
/// (falling back) at or below one of `refs.static_list`'s configured
/// base DNs. Used for the `NoPartitionFor` case (a DN genuinely
/// unrelated to this server's own base DN) -- see `proactive_referral`
/// for the child-domain case, which this alone can't catch.
fn referral_for<'a>(refs: &Referrals<'a>, dn: &Dn) -> Option<&'a str> {
    if let Some(topology) = refs.topology {
        if let Some(url) = topology.resolve(dn).and_then(|p| p.ldap_url.as_deref()) {
            return Some(url);
        }
    }
    refs.static_list.iter().find(|(base, _)| dn.is_within(base)).map(|(_, url)| url.as_str())
}

/// If `refs.topology` resolves `dn` to a *different* partition than the
/// one this instance itself serves, builds a `Referral` immediately --
/// without ever attempting a local lookup. This is necessary, not just
/// an optimization: a child domain's base DN is *structurally* a
/// descendant of its parent's (`dc=emea,dc=g10,dc=lo` under
/// `dc=g10,dc=lo`), so the parent's own single-partition `Store` would
/// otherwise report `Ok(None)`/"no such object" for an entry that
/// genuinely exists, just on the child's cluster -- it never raises
/// `StoreError::NoPartitionFor`, so `referral_for` (reactive, keyed off
/// that error) never gets a chance to fire. Every read/write handler
/// calls this first, before touching `Store` at all.
fn proactive_referral(refs: &Referrals, dn: &Dn) -> Option<LdapResult> {
    let topology = refs.topology?;
    let own_id = refs.own_partition_id?;
    let owner = topology.resolve(dn)?;
    if &owner.id == own_id {
        return None; // genuinely ours -- proceed with the local lookup
    }
    let url = owner.ldap_url.as_deref()?;
    let uri = format!("{}/{}", url.trim_end_matches('/'), dn);
    let mut result = LdapResult::new(ResultCode::Referral, String::new().into(), String::new().into());
    result.referral = Some(vec![uri.into()]);
    Some(result)
}

/// Maps a `StoreError` to the LDAP result it should produce.
/// `NoPartitionFor` becomes a `Referral` (RFC 4511 §4.1.10) if `dn` falls
/// under a naming context `refs` knows how to reach, since that's a
/// real, client-actionable answer ("ask over there instead") rather than
/// a generic server error.
fn store_error_result(e: &iron_store::StoreError, refs: &Referrals<'_>, dn: &Dn) -> LdapResult {
    if matches!(e, iron_store::StoreError::NoPartitionFor(_)) {
        if let Some(url) = referral_for(refs, dn) {
            let uri = format!("{}/{}", url.trim_end_matches('/'), dn);
            let mut result = LdapResult::new(ResultCode::Referral, String::new().into(), String::new().into());
            result.referral = Some(vec![uri.into()]);
            return result;
        }
    }
    operations_error(&e.to_string())
}

/// Handles a `BindRequest`, returning the response alongside the RFC
/// 4513 §3 authzId it establishes (`None` for anonymous, a failure, or
/// an unrecognized auth choice) -- the caller threads this into
/// `bound_identity` for a later WhoAmI (RFC 4532) to answer, but only
/// once the bind is *terminal* (checked by the caller via
/// `resp.result_code`), since a SASL exchange returns
/// `SaslBindInProgress` for every non-final step and this function
/// always returns `None` for those regardless.
async fn handle_bind(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    req: &BindRequest,
    sasl_state: &mut SaslState,
) -> (BindResponse, Option<String>) {
    if req.version != 3 {
        *sasl_state = SaslState::None;
        return (BindResponse::new(ResultCode::ProtocolError, String::new().into(), "only LDAPv3 is supported".into(), None, None), None);
    }
    match &req.authentication {
        AuthenticationChoice::Simple(password) if req.name.is_empty() && password.is_empty() => {
            *sasl_state = SaslState::None;
            (BindResponse::new(ResultCode::Success, String::new().into(), String::new().into(), None, None), None)
        }
        AuthenticationChoice::Simple(password) => {
            *sasl_state = SaslState::None;
            let code = authenticate_simple(store, fips, &req.name, password).await;
            let identity = (code == ResultCode::Success).then(|| format!("dn:{}", req.name.as_str()));
            (BindResponse::new(code, String::new().into(), String::new().into(), None, None), identity)
        }
        AuthenticationChoice::Sasl(creds) => handle_sasl_bind(store, fips, creds, sasl_state).await,
        _ => {
            *sasl_state = SaslState::None;
            (BindResponse::new(ResultCode::AuthMethodNotSupported, String::new().into(), "unrecognized authentication choice".into(), None, None), None)
        }
    }
}

/// RFC 4752 SASL/GSSAPI bind, over the Kerberos V5 GSS mechanism (RFC
/// 4121). Only the "GSSAPI" mechanism is supported, and only the "no
/// security layer" option (clients requesting integrity/confidentiality
/// get told only "no protection" is on offer -- use StartTLS/LDAPS for
/// transport security, which iron-ldap already supports).
async fn handle_sasl_bind(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    creds: &SaslCredentials,
    sasl_state: &mut SaslState,
) -> (BindResponse, Option<String>) {
    if creds.mechanism.as_str() != "GSSAPI" {
        *sasl_state = SaslState::None;
        return (BindResponse::new(ResultCode::AuthMethodNotSupported, String::new().into(), "only the GSSAPI SASL mechanism is supported".into(), None, None), None);
    }
    let Some(fips) = fips else {
        *sasl_state = SaslState::None;
        return (BindResponse::new(ResultCode::UnwillingToPerform, String::new().into(), "FIPS provider not active -- SASL/GSSAPI unavailable".into(), None, None), None);
    };

    let resp = match std::mem::take(sasl_state) {
        SaslState::None => {
            let Some(input_token) = &creds.credentials else {
                return (BindResponse::new(ResultCode::AuthMethodNotSupported, String::new().into(), "GSSAPI bind requires an initial token".into(), None, None), None);
            };
            // Any DN within the (single) served partition works here --
            // lookup_by_index only uses it to resolve which cluster to
            // query, not as a search filter.
            let Some(any_dn) = store.registry().iter().next().map(|p| p.base_dn.clone()) else {
                return (BindResponse::new(ResultCode::Other, String::new().into(), "no partition configured".into(), None, None), None);
            };
            let lookup = move |sname: PrincipalName, realm: String| async move {
                let principal_fqn = format!("{}@{realm}", iron_kdc::principal_name_to_string(&sname));
                let dns = store.lookup_by_index(&any_dn, iron_kdc::principal::ATTR_PRINCIPAL_NAME, &principal_fqn).await.ok()?;
                let dn = dns.into_iter().next()?;
                let entry = store.get_entry(&dn).await.ok()??;
                iron_kdc::principal::keys(&entry).ok()
            };
            match crate::gssapi::accept::accept(fips, input_token, lookup).await {
                Ok(accepted) => match accepted.output_token {
                    Some(tok) => {
                        *sasl_state = SaslState::AwaitingApRepAck {
                            session_key: accepted.session_key,
                            enctype: accepted.enctype,
                            client_principal: accepted.client_principal,
                        };
                        BindResponse::new(ResultCode::SaslBindInProgress, String::new().into(), String::new().into(), None, Some(tok.into()))
                    }
                    None => match security_layer_challenge(fips, accepted.enctype, &accepted.session_key) {
                        Ok(challenge) => {
                            *sasl_state = SaslState::AwaitingSecurityLayerAck {
                                session_key: accepted.session_key,
                                enctype: accepted.enctype,
                                client_principal: accepted.client_principal,
                            };
                            BindResponse::new(ResultCode::SaslBindInProgress, String::new().into(), String::new().into(), None, Some(challenge.into()))
                        }
                        Err(e) => BindResponse::new(ResultCode::OperationsError, String::new().into(), e.to_string().into(), None, None),
                    },
                },
                Err(e) => BindResponse::new(ResultCode::InvalidCredentials, String::new().into(), e.to_string().into(), None, None),
            }
        }
        SaslState::AwaitingApRepAck { session_key, enctype, client_principal } => match security_layer_challenge(fips, enctype, &session_key) {
            Ok(challenge) => {
                *sasl_state = SaslState::AwaitingSecurityLayerAck { session_key, enctype, client_principal };
                BindResponse::new(ResultCode::SaslBindInProgress, String::new().into(), String::new().into(), None, Some(challenge.into()))
            }
            Err(e) => BindResponse::new(ResultCode::OperationsError, String::new().into(), e.to_string().into(), None, None),
        },
        SaslState::AwaitingSecurityLayerAck { session_key, enctype, client_principal } => {
            let Some(response) = &creds.credentials else {
                return (BindResponse::new(ResultCode::ProtocolError, String::new().into(), "missing security-layer response".into(), None, None), None);
            };
            // Key usage 24: KG-USAGE-INITIATOR-SEAL (RFC 4121 §2) -- the
            // client is the GSS initiator, so its Wrap tokens use the
            // initiator-seal usage, not our own acceptor-seal (22).
            match crate::gssapi::wrap::unwrap(fips, enctype, &session_key, 24, response) {
                // Bit 0: no security layer -- bind succeeds, connection
                // stays plain BER framing (sasl_state already reset to
                // `None` by the `mem::take` at the top of this function).
                Ok(plain) if plain.first() == Some(&0x01) => {
                    tracing::info!(%client_principal, "GSSAPI bind succeeded (no security layer)");
                    return (BindResponse::new(ResultCode::Success, String::new().into(), String::new().into(), None, None), Some(format!("u:{client_principal}")));
                }
                // Bit 1: integrity -- bind succeeds, but every later
                // message on this connection must be a Wrap token (see
                // `SaslState::SecurityLayerActive`'s doc comment).
                Ok(plain) if plain.first() == Some(&0x02) => {
                    tracing::info!(%client_principal, "GSSAPI bind succeeded (integrity security layer active)");
                    // send_seq starts at 1: the challenge already consumed
                    // the acceptor's seq 0 (see `security_layer_challenge`).
                    *sasl_state = SaslState::SecurityLayerActive { session_key, enctype, sealed: false, send_seq: AtomicU64::new(1) };
                    return (BindResponse::new(ResultCode::Success, String::new().into(), String::new().into(), None, None), Some(format!("u:{client_principal}")));
                }
                // Bit 2: confidentiality -- found live (#20) that macOS's
                // `dsconfigad` needs this specifically to write the new
                // computer account's Kerberos key over LDAP; it accepts
                // the bind with only integrity offered, then fails
                // locally (`GSS_S_BAD_QOP`) the moment it tries to seal
                // that write.
                Ok(plain) if plain.first() == Some(&0x04) => {
                    tracing::info!(%client_principal, "GSSAPI bind succeeded (confidentiality security layer active)");
                    // send_seq starts at 1: the challenge already consumed
                    // the acceptor's seq 0 (see `security_layer_challenge`).
                    *sasl_state = SaslState::SecurityLayerActive { session_key, enctype, sealed: true, send_seq: AtomicU64::new(1) };
                    return (BindResponse::new(ResultCode::Success, String::new().into(), String::new().into(), None, None), Some(format!("u:{client_principal}")));
                }
                Ok(_) => BindResponse::new(ResultCode::UnwillingToPerform, String::new().into(), "client selected an unsupported security layer".into(), None, None),
                Err(e) => BindResponse::new(ResultCode::InvalidCredentials, String::new().into(), e.to_string().into(), None, None),
            }
        }
        // A `BindRequest` while a security layer is already active (a
        // re-bind, RFC 4513 §3) -- not supported yet, and the request
        // itself would need to have arrived *through* the active layer
        // for this state to even be reachable correctly. Fail rather
        // than silently drop back to an unprotected connection.
        active @ SaslState::SecurityLayerActive { .. } => {
            *sasl_state = active;
            BindResponse::new(ResultCode::UnwillingToPerform, String::new().into(), "re-bind on a connection with an active security layer is not supported".into(), None, None)
        }
    };
    (resp, None)
}

/// Builds the RFC 4752 §3.2 security-layer negotiation challenge: 4
/// octets (bitmask of offered layers + max buffer size), Wrapped without
/// confidentiality using KG-USAGE-ACCEPTOR-SEAL (22) -- we're the GSS
/// acceptor. Offers all three layers: bit 0 ("no security layer"), bit 1
/// ("integrity"), bit 2 ("confidentiality"/privacy). Originally only bit
/// 0 was offered, on the theory that StartTLS/LDAPS already covers
/// transport security -- found live (#20) that macOS's `dsconfigad`
/// rejects a bind offering *only* "no security layer" outright
/// (`GSS_S_BAD_QOP`), unlike MIT krb5's `ldapsearch`, which accepts it.
/// Adding integrity fixed the bind itself, but `dsconfigad` then failed
/// the same way the moment it tried to write the new computer account's
/// Kerberos key over the connection -- that write specifically needs
/// confidentiality, not just integrity, so bit 2 has to be offered too.
///
/// This is always the acceptor's *first* Wrap token on the connection, so
/// it takes SND_SEQ 0 (integrity-only, never sealed); `SecurityLayerActive`
/// then continues the acceptor's send sequence from 1.
fn security_layer_challenge(fips: &iron_crypto::FipsContext, enctype: Enctype, session_key: &[u8]) -> Result<Vec<u8>, crate::gssapi::wrap::Error> {
    const OFFERED_LAYERS: u8 = 0x01 | 0x02 | 0x04;
    const MAX_BUFFER: u32 = 0x00FF_FFFF; // 3-octet field -- largest representable value
    let mut challenge = [0u8; 4];
    challenge[0] = OFFERED_LAYERS;
    challenge[1..4].copy_from_slice(&MAX_BUFFER.to_be_bytes()[1..4]);
    crate::gssapi::wrap::wrap(fips, enctype, session_key, 22, false, 0, &challenge)
}

/// Verifies a non-empty simple bind against the target entry's
/// `userPassword` (D4: PBKDF2 via the OpenSSL FIPS provider).
///
/// Every failure path (bad DN, no such entry, no `userPassword` set,
/// wrong password, FIPS unavailable) returns the same `InvalidCredentials`
/// -- distinguishing them would let a client enumerate valid usernames.
async fn authenticate_simple(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    name: &str,
    password: &[u8],
) -> ResultCode {
    let Some(fips) = fips else {
        return ResultCode::InvalidCredentials;
    };
    let Ok(dn) = Dn::parse(name) else {
        return ResultCode::InvalidCredentials;
    };
    let Ok(Some(entry)) = store.get_entry(&dn).await else {
        return ResultCode::InvalidCredentials;
    };
    let Some(stored) = entry.get(USER_PASSWORD_ATTR).and_then(|v| v.first()) else {
        return ResultCode::InvalidCredentials;
    };
    match iron_crypto::pbkdf2::verify_password(fips, password, stored) {
        Ok(true) => ResultCode::Success,
        _ => ResultCode::InvalidCredentials,
    }
}

fn done(code: ResultCode, diagnostic: &str) -> Vec<ProtocolOp> {
    vec![ProtocolOp::SearchResDone(SearchResultDone(LdapResult::new(
        code,
        String::new().into(),
        diagnostic.into(),
    )))]
}

fn done_store_error(e: &iron_store::StoreError, referrals: &Referrals<'_>, dn: &Dn) -> Vec<ProtocolOp> {
    vec![ProtocolOp::SearchResDone(SearchResultDone(store_error_result(e, referrals, dn)))]
}

fn done_result(result: LdapResult) -> Vec<ProtocolOp> {
    vec![ProtocolOp::SearchResDone(SearchResultDone(result))]
}

/// Builds an `Entry` from an LDAP attribute list, hashing `userPassword`
/// values (D4) rather than storing them as the client sent them. Returns
/// `Err` if the request tries to set a password while the FIPS provider
/// isn't active -- fails closed rather than ever storing a plaintext
/// password.
/// `Attribute` (used by `AddRequest`) and `PartialAttribute` (used by
/// `ModifyRequestChanges`/search results) have identical shapes but are
/// distinct generated types -- this lets `entry_from_attributes` accept
/// either.
trait AttrLike {
    fn type_name(&self) -> &str;
    fn values(&self) -> Vec<&OctetString>;
}
impl AttrLike for &Attribute {
    fn type_name(&self) -> &str {
        self.r#type.as_str()
    }
    fn values(&self) -> Vec<&OctetString> {
        self.vals.to_vec()
    }
}
impl AttrLike for &PartialAttribute {
    fn type_name(&self) -> &str {
        self.r#type.as_str()
    }
    fn values(&self) -> Vec<&OctetString> {
        self.vals.to_vec()
    }
}

/// Maps an `iron_crypto::Error` from hashing a `userPassword` value to the
/// LDAP result it should produce -- `ConstraintViolation` (a real,
/// client-fixable constraint: pick a longer password) is a materially
/// different situation from `UnwillingToPerform` (a server-side
/// precondition, the FIPS provider isn't active).
fn password_error_result(e: &iron_crypto::Error) -> LdapResult {
    match e {
        iron_crypto::Error::PasswordTooShort { min, actual } => LdapResult::new(
            ResultCode::ConstraintViolation,
            String::new().into(),
            format!("password is {actual} bytes, shorter than the required minimum of {min}").into(),
        ),
        iron_crypto::Error::FipsProviderNotActive => {
            unwilling("FIPS provider not active -- cannot hash userPassword")
        }
        _ => unwilling("failed to hash userPassword"),
    }
}

fn hash_password_values(
    fips: Option<&iron_crypto::FipsContext>,
    values: &[String],
) -> Result<Vec<String>, iron_crypto::Error> {
    let Some(fips) = fips else {
        return Err(iron_crypto::Error::FipsProviderNotActive);
    };
    values
        .iter()
        .map(|v| iron_crypto::pbkdf2::hash_password(fips, v.as_bytes()))
        .collect()
}

fn entry_from_attributes<A: AttrLike>(
    attrs: impl IntoIterator<Item = A>,
    fips: Option<&iron_crypto::FipsContext>,
) -> Result<Entry, iron_crypto::Error> {
    let mut entry = Entry::new();
    for a in attrs {
        let values: Vec<String> = a
            .values()
            .into_iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect();
        if a.type_name().eq_ignore_ascii_case(USER_PASSWORD_ATTR) {
            entry.set(a.type_name(), hash_password_values(fips, &values)?);
        } else {
            entry.set(a.type_name(), values);
        }
    }
    Ok(entry)
}

async fn handle_add(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    req: &AddRequest,
    spec: &iron_store::index::IndexSpec,
    referrals: &Referrals<'_>,
) -> AddResponse {
    let dn = match Dn::parse(&req.entry) {
        Ok(dn) => dn,
        Err(_) => return AddResponse(invalid_dn()),
    };
    if let Some(result) = proactive_referral(referrals, &dn) {
        return AddResponse(result);
    }
    let mut entry = match entry_from_attributes(&req.attributes, fips) {
        Ok(e) => e,
        Err(e) => return AddResponse(password_error_result(&e)),
    };
    if let Err(msg) = crate::schema::validate(&entry) {
        return AddResponse(LdapResult::new(ResultCode::ObjectClassViolation, String::new().into(), msg.into()));
    }
    // #17: a user/computer/group entry gets an objectSid + default
    // nTSecurityDescriptor auto-assigned here, exactly like a real DC
    // does at object creation -- a no-op if the partition has no
    // domain SID provisioned yet (see `security` module docs).
    if let Err(e) = crate::security::stamp_security_principal(store, referrals.topology, &dn, &mut entry).await {
        return AddResponse(store_error_result(&e, referrals, &dn));
    }

    let result = match store.put_entry(&dn, &entry, spec).await {
        Ok(()) => success(),
        Err(e) => store_error_result(&e, referrals, &dn),
    };
    AddResponse(result)
}

async fn handle_delete(
    store: &mut Store,
    req: &DelRequest,
    spec: &iron_store::index::IndexSpec,
    referrals: &Referrals<'_>,
) -> DelResponse {
    let dn = match Dn::parse(&req.0) {
        Ok(dn) => dn,
        Err(_) => return DelResponse(invalid_dn()),
    };
    if let Some(result) = proactive_referral(referrals, &dn) {
        return DelResponse(result);
    }
    let result = match store.delete_entry(&dn, spec).await {
        Ok(()) => success(),
        Err(e) => store_error_result(&e, referrals, &dn),
    };
    DelResponse(result)
}

struct PasswordModifyError {
    code: ResultCode,
    message: String,
}
impl PasswordModifyError {
    fn new(code: ResultCode, message: impl Into<String>) -> Self {
        PasswordModifyError { code, message: message.into() }
    }
}

/// Resolves an RFC 3062 `userIdentity` value to the target `Dn`. In
/// practice this is either a bare DN string or an RFC 4513 `dn:`-prefixed
/// authzId -- both accepted here since real clients (macOS's
/// `dsconfigad`, found live in #20) aren't guaranteed to use the exact
/// same form.
fn resolve_password_target(identity: &str) -> Result<Dn, PasswordModifyError> {
    let dn_str = identity.strip_prefix("dn:").unwrap_or(identity);
    Dn::parse(dn_str).map_err(|_| PasswordModifyError::new(ResultCode::InvalidDnSyntax, "userIdentity is not a valid DN"))
}

/// The Kerberos principal name to derive keys under for an entry that
/// doesn't have one yet -- `<sAMAccountName>@<REALM>` (matching real
/// AD's convention for computer accounts, whose `sAMAccountName` already
/// carries the trailing `$`) if `sAMAccountName` is set, else falling
/// back to `<cn>@<REALM>`.
fn principal_fqn_for(entry: &Entry, realm: &str) -> Option<String> {
    if let Ok(existing) = iron_kdc::principal::principal_name(entry) {
        return Some(existing.to_string());
    }
    let name = entry.get("samaccountname").and_then(|v| v.first()).or_else(|| entry.get("cn").and_then(|v| v.first()))?;
    Some(format!("{name}@{realm}"))
}

/// RFC 3062 Password Modify -- see `PASSWORD_MODIFY_OID`'s doc comment.
/// Sets the target entry's Kerberos keys (`iron_kdc::principal::set_password`)
/// from `newPasswd`, deriving a `krbPrincipalName` from `sAMAccountName`/`cn`
/// if the entry doesn't already have one (a fresh computer account created
/// by an `AddRequest` won't). No fine-grained ACL check yet (D8/#4 scope) --
/// any authenticated bind may reset any entry's password, matching this
/// project's current single-tier trust model.
async fn handle_password_modify(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    request_value: Option<&[u8]>,
    bound_identity: Option<&str>,
    spec: &iron_store::index::IndexSpec,
) -> Result<Option<OctetString>, PasswordModifyError> {
    let Some(fips) = fips else {
        return Err(PasswordModifyError::new(ResultCode::UnwillingToPerform, "FIPS provider not active -- cannot set a Kerberos key"));
    };
    let Some(bytes) = request_value else {
        return Err(PasswordModifyError::new(ResultCode::ProtocolError, "missing request value"));
    };
    let req: PasswdModifyRequestValue =
        rasn::ber::decode(bytes).map_err(|e| PasswordModifyError::new(ResultCode::ProtocolError, format!("malformed PasswdModifyRequestValue: {e}")))?;
    let Some(new_passwd) = req.new_passwd else {
        // A server-generated random password (the no-newPasswd case) is
        // real RFC 3062 behavior, but nothing in this project's client
        // set needs it yet -- fail explicitly rather than silently
        // picking a password the caller never sees.
        return Err(PasswordModifyError::new(ResultCode::UnwillingToPerform, "server-generated passwords are not supported -- newPasswd is required"));
    };
    let identity = req
        .user_identity
        .map(|v| String::from_utf8_lossy(v.as_ref()).into_owned())
        .or_else(|| bound_identity.map(str::to_string))
        .ok_or_else(|| PasswordModifyError::new(ResultCode::ProtocolError, "no userIdentity and no bound identity to fall back to"))?;
    let dn = resolve_password_target(&identity)?;

    let Some(realm) = store.registry().iter().find_map(|p| p.realm.clone()) else {
        return Err(PasswordModifyError::new(ResultCode::Other, "no realm configured for this partition"));
    };
    let mut entry = match store.get_entry(&dn).await {
        Ok(Some(e)) => e,
        Ok(None) => return Err(PasswordModifyError::new(ResultCode::NoSuchObject, "")),
        Err(e) => return Err(PasswordModifyError::new(ResultCode::OperationsError, e.to_string())),
    };
    let Some(principal_fqn) = principal_fqn_for(&entry, &realm) else {
        return Err(PasswordModifyError::new(ResultCode::UnwillingToPerform, "entry has no sAMAccountName/cn to derive a principal name from"));
    };
    iron_kdc::principal::set_password(fips, &mut entry, &principal_fqn, &new_passwd)
        .map_err(|e| PasswordModifyError::new(ResultCode::OperationsError, e.to_string()))?;
    store.put_entry(&dn, &entry, spec).await.map_err(|e| PasswordModifyError::new(ResultCode::OperationsError, e.to_string()))?;

    // RFC 3062 §4: genPasswd is only present when the server generated
    // the password itself -- not the case here (newPasswd was supplied),
    // so the response has no value at all.
    Ok(None)
}

async fn handle_modify(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    req: &ModifyRequest,
    spec: &iron_store::index::IndexSpec,
    referrals: &Referrals<'_>,
) -> ModifyResponse {
    let dn = match Dn::parse(&req.object) {
        Ok(dn) => dn,
        Err(_) => return ModifyResponse(invalid_dn()),
    };
    if let Some(result) = proactive_referral(referrals, &dn) {
        return ModifyResponse(result);
    }
    let mut entry = match store.get_entry(&dn).await {
        Ok(Some(e)) => e,
        Ok(None) => return ModifyResponse(LdapResult::new(ResultCode::NoSuchObject, String::new().into(), "".into())),
        Err(e) => return ModifyResponse(store_error_result(&e, referrals, &dn)),
    };

    for change in &req.changes {
        let attr = change.modification.r#type.as_str();
        let values: Vec<String> = change
            .modification
            .vals
            .to_vec()
            .into_iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect();
        match change.operation {
            ChangeOperation::Add => {
                if attr.eq_ignore_ascii_case(USER_PASSWORD_ATTR) {
                    match hash_password_values(fips, &values) {
                        Ok(h) => entry.add_values(attr, h),
                        Err(e) => return ModifyResponse(password_error_result(&e)),
                    }
                } else {
                    entry.add_values(attr, values);
                }
            }
            ChangeOperation::Delete => entry.delete_values(attr, &values),
            ChangeOperation::Replace => {
                if values.is_empty() {
                    entry.delete_values(attr, &[]);
                } else if attr.eq_ignore_ascii_case(USER_PASSWORD_ATTR) {
                    match hash_password_values(fips, &values) {
                        Ok(h) => entry.set(attr, h),
                        Err(e) => return ModifyResponse(password_error_result(&e)),
                    }
                } else {
                    entry.set(attr, values);
                }
            }
        }
    }

    if let Err(msg) = crate::schema::validate(&entry) {
        return ModifyResponse(LdapResult::new(ResultCode::ObjectClassViolation, String::new().into(), msg.into()));
    }

    let result = match store.put_entry(&dn, &entry, spec).await {
        Ok(()) => success(),
        Err(e) => store_error_result(&e, referrals, &dn),
    };
    ModifyResponse(result)
}

async fn handle_compare(store: &mut Store, req: &CompareRequest, referrals: &Referrals<'_>) -> CompareResponse {
    let dn = match Dn::parse(&req.entry) {
        Ok(dn) => dn,
        Err(_) => return CompareResponse(invalid_dn()),
    };
    if let Some(result) = proactive_referral(referrals, &dn) {
        return CompareResponse(result);
    }
    let entry = match store.get_entry(&dn).await {
        Ok(Some(e)) => e,
        Ok(None) => return CompareResponse(LdapResult::new(ResultCode::NoSuchObject, String::new().into(), "".into())),
        Err(e) => return CompareResponse(store_error_result(&e, referrals, &dn)),
    };
    let want = String::from_utf8_lossy(&req.ava.assertion_value);
    let matched = entry
        .get(req.ava.attribute_desc.as_str())
        .is_some_and(|vals| vals.iter().any(|v| v.eq_ignore_ascii_case(&want)));
    let code = if matched { ResultCode::CompareTrue } else { ResultCode::CompareFalse };
    CompareResponse(LdapResult::new(code, String::new().into(), String::new().into()))
}

/// Renames and/or moves a **leaf** entry. Subtree rename (moving a
/// non-leaf entry, dragging its descendants along) is not implemented --
/// this is standards-sanctioned, not a stub: RFC 4511 lets a server that
/// doesn't support it return `NotAllowedOnNonLeaf`, which is exactly what
/// this does after confirming (via `scan_subtree`) that the entry really
/// has no children.
///
/// The move itself is **not atomic across the old/new keys**: it puts the
/// entry at the new DN first, then deletes the old one. A crash between
/// those two steps leaves the entry readable at both DNs rather than
/// losing it -- documented as a known limitation, same posture as
/// `iron-store`'s other cross-key simplifications.
async fn handle_moddn(
    store: &mut Store,
    req: &ModifyDnRequest,
    spec: &iron_store::index::IndexSpec,
    referrals: &Referrals<'_>,
) -> ModifyDnResponse {
    let old_dn = match Dn::parse(&req.entry) {
        Ok(dn) if !dn.is_empty() => dn,
        _ => return ModifyDnResponse(invalid_dn()),
    };
    if let Some(result) = proactive_referral(referrals, &old_dn) {
        return ModifyDnResponse(result);
    }
    let new_rdn_dn = match Dn::parse(&req.new_rdn) {
        Ok(dn) if dn.depth() == 1 => dn,
        _ => {
            return ModifyDnResponse(LdapResult::new(
                ResultCode::InvalidDnSyntax,
                String::new().into(),
                "newrdn must be exactly one RDN".into(),
            ))
        }
    };
    let new_rdn = &new_rdn_dn.rdns()[0];

    let new_parent = match &req.new_superior {
        Some(sup) => match Dn::parse(sup) {
            Ok(dn) => dn,
            Err(_) => return ModifyDnResponse(invalid_dn()),
        },
        None => old_dn.parent().unwrap_or_else(Dn::root),
    };
    let new_dn_str = if new_parent.is_empty() {
        req.new_rdn.as_str().to_string()
    } else {
        format!("{},{}", req.new_rdn.as_str(), new_parent)
    };
    let new_dn = match Dn::parse(&new_dn_str) {
        Ok(dn) => dn,
        Err(_) => return ModifyDnResponse(invalid_dn()),
    };

    // Refuse non-leaf moves (see doc comment above).
    match store.scan_subtree(&old_dn).await {
        Ok(rows) if rows.len() > 1 => {
            return ModifyDnResponse(LdapResult::new(
                ResultCode::NotAllowedOnNonLeaf,
                String::new().into(),
                "moving a non-leaf entry (subtree rename) is not supported yet".into(),
            ))
        }
        Ok(_) => {}
        Err(e) => return ModifyDnResponse(store_error_result(&e, referrals, &old_dn)),
    }

    let mut entry = match store.get_entry(&old_dn).await {
        Ok(Some(e)) => e,
        Ok(None) => return ModifyDnResponse(LdapResult::new(ResultCode::NoSuchObject, String::new().into(), "".into())),
        Err(e) => return ModifyDnResponse(store_error_result(&e, referrals, &old_dn)),
    };

    // The new RDN's attribute values become part of the entry (RFC 4511:
    // "Attribute values of the new RDN not matching any attribute value
    // of the entry are added"). If deleteoldrdn is set, the old RDN's
    // values are removed -- unless the new RDN also uses them (e.g.
    // renaming cn=alice+sn=x to cn=alice+sn=y shouldn't drop cn=alice).
    for ava in new_rdn.avas() {
        entry.add_values(ava.attr(), [ava.value().to_string()]);
    }
    if req.delete_old_rdn {
        for ava in old_dn.rdns()[0].avas() {
            let still_wanted = new_rdn
                .avas()
                .iter()
                .any(|a| a.attr() == ava.attr() && a.value().eq_ignore_ascii_case(ava.value()));
            if !still_wanted {
                entry.delete_values(ava.attr(), &[ava.value().to_string()]);
            }
        }
    }

    if let Err(e) = store.put_entry(&new_dn, &entry, spec).await {
        return ModifyDnResponse(store_error_result(&e, referrals, &new_dn));
    }
    if old_dn != new_dn {
        if let Err(e) = store.delete_entry(&old_dn, spec).await {
            return ModifyDnResponse(operations_error(&format!(
                "entry moved to the new DN but the old DN could not be removed: {e}"
            )));
        }
    }
    ModifyDnResponse(success())
}

async fn handle_search(store: &mut Store, req: &SearchRequest, referrals: &Referrals<'_>, fips_active: bool) -> Vec<ProtocolOp> {
    let base_dn = match Dn::parse(&req.base_object) {
        Ok(dn) => dn,
        Err(_) => return done(ResultCode::InvalidDnSyntax, "invalid base DN"),
    };

    if base_dn.is_empty() && req.scope == SearchRequestScope::BaseObject {
        // Found live during #17's verification: this used to always
        // pass `store.registry()` -- the *local*, single-partition
        // registry `Store` uses purely for DN-to-cluster routing, never
        // the full forest topology (`AppState::topology`, #9/#10).
        // `configurationNamingContext`/`schemaNamingContext` could
        // therefore never appear for a real multi-partition forest,
        // even once config/schema partitions were actually provisioned
        // (#9/#17) -- the registry rootDSE was built from simply never
        // had them in it. Prefer the loaded topology when one is
        // configured; fall back to the local registry (still correct
        // for a deployment with no configuration partition set up,
        // e.g. the standalone il1/il2/il3 replicas).
        let registry = referrals.topology.unwrap_or_else(|| store.registry());
        let entry_op = ProtocolOp::SearchResEntry(rootdse::build(registry, fips_active));
        let mut ops = vec![entry_op];
        ops.extend(done(ResultCode::Success, ""));
        return ops;
    }
    if let Some(result) = proactive_referral(referrals, &base_dn) {
        return done_result(result);
    }

    let candidates: Vec<(Dn, Entry)> = match req.scope {
        SearchRequestScope::BaseObject => match store.get_entry(&base_dn).await {
            Ok(Some(e)) => vec![(base_dn.clone(), e)],
            Ok(None) => return done(ResultCode::NoSuchObject, ""),
            Err(e) => return done_store_error(&e, referrals, &base_dn),
        },
        SearchRequestScope::SingleLevel | SearchRequestScope::WholeSubtree => {
            match store.scan_subtree(&base_dn).await {
                Ok(rows) => {
                    if req.scope == SearchRequestScope::SingleLevel {
                        let child_depth = base_dn.depth() + 1;
                        rows.into_iter()
                            .filter(|(dn, _)| dn.depth() == child_depth)
                            .collect()
                    } else {
                        rows
                    }
                }
                Err(e) => return done_store_error(&e, referrals, &base_dn),
            }
        }
        _ => return done(ResultCode::ProtocolError, "unrecognized search scope"),
    };

    let mut ops = Vec::new();
    let limit = if req.size_limit == 0 {
        usize::MAX
    } else {
        req.size_limit as usize
    };
    for (dn, entry) in candidates.into_iter().take(limit) {
        if !filter::matches(&entry, &req.filter) {
            continue;
        }
        ops.push(ProtocolOp::SearchResEntry(SearchResultEntry::new(
            dn.to_string().into(),
            project_attributes(&entry, &req.attributes, req.types_only),
        )));
    }
    ops.extend(done(ResultCode::Success, ""));
    ops
}

fn project_attributes(
    entry: &Entry,
    requested: &[rasn_ldap::LdapString],
    types_only: bool,
) -> Vec<PartialAttribute> {
    let want_all = requested.is_empty() || requested.iter().any(|a| a.as_str() == "*");
    let explicitly_requested =
        |name: &str| requested.iter().any(|a| a.eq_ignore_ascii_case(name));
    entry
        .attr_names()
        // userPassword is write-only by convention: never returned by a
        // wildcard/all-attributes request, only if named explicitly (and
        // even then it's the PBKDF2 hash, never plaintext).
        .filter(|name| {
            if name.eq_ignore_ascii_case(USER_PASSWORD_ATTR) {
                explicitly_requested(name)
            } else {
                want_all || explicitly_requested(name)
            }
        })
        .map(|name| {
            let values: Vec<Vec<u8>> = if types_only {
                Vec::new()
            } else {
                entry
                    .get(name)
                    .map(|vs| {
                        // objectSid/nTSecurityDescriptor (#17) are stored
                        // as base64 text (Entry's values are UTF-8-string
                        // only); decode back to real binary here, at the
                        // wire boundary, rather than returning the
                        // base64 text itself as if it were the value.
                        if crate::security::is_binary_attr(name) {
                            vs.iter().map(|v| crate::security::decode_binary_attr(v)).collect()
                        } else {
                            vs.iter().map(|v| v.clone().into_bytes()).collect()
                        }
                    })
                    .unwrap_or_default()
            };
            PartialAttribute::new(
                name.into(),
                SetOf::from_vec(values.into_iter().map(Into::into).collect()),
            )
        })
        .collect()
}

#[cfg(test)]
mod referral_tests {
    use iron_partition::{ClusterRef, ForestId, Partition, PartitionId, PartitionRegistry};

    use super::*;

    fn dn(s: &str) -> Dn {
        Dn::parse(s).unwrap()
    }

    fn registry_with_child(child_ldap_url: Option<&str>) -> PartitionRegistry {
        let forest = ForestId::new("acme").unwrap();
        let cluster = ClusterRef::plaintext(["http://127.0.0.1:2379"]);
        let parent = Partition::domain("g10", forest.clone(), dn("dc=g10,dc=lo"), cluster.clone()).unwrap();
        let mut child = Partition::domain("g10-emea", forest, dn("dc=emea,dc=g10,dc=lo"), cluster).unwrap();
        if let Some(url) = child_ldap_url {
            child = child.with_ldap_url(url);
        }
        PartitionRegistry::from_partitions([parent, child]).unwrap()
    }

    #[test]
    fn topology_referral_takes_priority_over_static_list() {
        let registry = registry_with_child(Some("ldap://child.example.com"));
        let static_list = [(dn("dc=emea,dc=g10,dc=lo"), "ldap://stale-static.example.com".to_string())];
        let refs = Referrals { topology: Some(&registry), static_list: &static_list, own_partition_id: None };
        let url = referral_for(&refs, &dn("cn=alice,dc=emea,dc=g10,dc=lo")).unwrap();
        assert_eq!(url, "ldap://child.example.com");
    }

    #[test]
    fn falls_back_to_static_list_when_topology_partition_has_no_ldap_url() {
        let registry = registry_with_child(None); // registered, but no ldap_url set yet
        let static_list = [(dn("dc=emea,dc=g10,dc=lo"), "ldap://static-fallback.example.com".to_string())];
        let refs = Referrals { topology: Some(&registry), static_list: &static_list, own_partition_id: None };
        let url = referral_for(&refs, &dn("cn=alice,dc=emea,dc=g10,dc=lo")).unwrap();
        assert_eq!(url, "ldap://static-fallback.example.com");
    }

    #[test]
    fn falls_back_to_static_list_when_no_topology_configured() {
        let static_list = [(dn("dc=emea,dc=g10,dc=lo"), "ldap://static-only.example.com".to_string())];
        let refs = Referrals { topology: None, static_list: &static_list, own_partition_id: None };
        let url = referral_for(&refs, &dn("cn=alice,dc=emea,dc=g10,dc=lo")).unwrap();
        assert_eq!(url, "ldap://static-only.example.com");
    }

    #[test]
    fn no_match_in_either_source_is_none() {
        let registry = registry_with_child(Some("ldap://child.example.com"));
        let refs = Referrals { topology: Some(&registry), static_list: &[], own_partition_id: None };
        assert!(referral_for(&refs, &dn("dc=totally,dc=unrelated")).is_none());
    }

    #[test]
    fn store_error_result_builds_a_real_referral_uri() {
        let registry = registry_with_child(Some("ldap://child.example.com"));
        let refs = Referrals { topology: Some(&registry), static_list: &[], own_partition_id: None };
        let target = dn("cn=alice,dc=emea,dc=g10,dc=lo");
        let err = iron_store::StoreError::NoPartitionFor(target.to_string());
        let result = store_error_result(&err, &refs, &target);
        assert_eq!(result.result_code, ResultCode::Referral);
        let referral = result.referral.unwrap();
        assert_eq!(referral[0].as_str(), "ldap://child.example.com/cn=alice,dc=emea,dc=g10,dc=lo");
    }

    #[test]
    fn store_error_result_falls_back_to_operations_error_with_no_match() {
        let refs = Referrals { topology: None, static_list: &[], own_partition_id: None };
        let target = dn("dc=totally,dc=unrelated");
        let err = iron_store::StoreError::NoPartitionFor(target.to_string());
        let result = store_error_result(&err, &refs, &target);
        assert_eq!(result.result_code, ResultCode::OperationsError);
    }

    // proactive_referral: the real bug this session found live -- a
    // child domain's DN is *structurally* a descendant of its parent's,
    // so the reactive NoPartitionFor path (referral_for/store_error_result,
    // tested above) never fires for it; only a check against the actual
    // partition topology, run BEFORE any local lookup, catches it.

    #[test]
    fn proactive_referral_fires_for_a_dn_owned_by_a_different_partition() {
        let registry = registry_with_child(Some("ldap://child.example.com"));
        let own_id = PartitionId::new("g10").unwrap();
        let refs = Referrals { topology: Some(&registry), static_list: &[], own_partition_id: Some(&own_id) };
        let result = proactive_referral(&refs, &dn("cn=alice,dc=emea,dc=g10,dc=lo")).unwrap();
        assert_eq!(result.result_code, ResultCode::Referral);
        assert_eq!(result.referral.unwrap()[0].as_str(), "ldap://child.example.com/cn=alice,dc=emea,dc=g10,dc=lo");
    }

    #[test]
    fn proactive_referral_is_none_for_a_dn_this_instance_itself_owns() {
        let registry = registry_with_child(Some("ldap://child.example.com"));
        let own_id = PartitionId::new("g10").unwrap();
        let refs = Referrals { topology: Some(&registry), static_list: &[], own_partition_id: Some(&own_id) };
        // Under the PARENT's own base DN, not the child's.
        assert!(proactive_referral(&refs, &dn("cn=bob,dc=g10,dc=lo")).is_none());
    }

    #[test]
    fn proactive_referral_is_none_when_own_partition_id_is_unset() {
        let registry = registry_with_child(Some("ldap://child.example.com"));
        let refs = Referrals { topology: Some(&registry), static_list: &[], own_partition_id: None };
        assert!(proactive_referral(&refs, &dn("cn=alice,dc=emea,dc=g10,dc=lo")).is_none());
    }

    #[test]
    fn proactive_referral_is_none_when_no_topology_configured() {
        let own_id = PartitionId::new("g10").unwrap();
        let refs = Referrals { topology: None, static_list: &[], own_partition_id: Some(&own_id) };
        assert!(proactive_referral(&refs, &dn("cn=alice,dc=emea,dc=g10,dc=lo")).is_none());
    }
}
