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

/// RFC 3909 §2 -- the well-known OID for the Cancel extended operation.
const CANCEL_OID: &[u8] = b"1.3.6.1.1.8";

/// RFC 3909 §2's request value: `cancelRequestValue ::= SEQUENCE {
/// cancelID MessageID }`.
#[derive(rasn::AsnType, rasn::Decode, rasn::Encode)]
struct CancelRequestValue {
    cancel_id: u32,
}

/// RFC 3909 §2 result codes. `rasn_ldap::ResultCode` stops at 80 (RFC
/// 4511's list), so a Cancel response is BER-encoded by hand
/// (`cancel_response_bytes`).
const RC_NO_SUCH_OPERATION: u8 = 119;
const RC_TOO_LATE: u8 = 120;
const RC_CANNOT_CANCEL: u8 = 121;

/// How many of a connection's most recent operations a Cancel can name
/// and be told `tooLate`/`cannotCancel` rather than `noSuchOperation`.
const OP_LOG_CAPACITY: usize = 1024;

/// The operations this connection has already answered, for Cancel (RFC
/// 3909). This server handles one connection's requests strictly in order,
/// so by the time a Cancel is read every earlier operation has completed:
/// a Cancel naming one is `tooLate` (or `cannotCancel` for the kinds §2
/// says cannot be cancelled), and one naming anything else is
/// `noSuchOperation`. Bounded to the last `OP_LOG_CAPACITY` operations.
#[derive(Default)]
struct OpLog {
    order: std::collections::VecDeque<u32>,
    cancelable: std::collections::HashMap<u32, bool>,
}

impl OpLog {
    fn record(&mut self, id: u32, cancelable: bool) {
        if self.cancelable.insert(id, cancelable).is_none() {
            self.order.push_back(id);
            while self.order.len() > OP_LOG_CAPACITY {
                let Some(old) = self.order.pop_front() else { break };
                self.cancelable.remove(&old);
            }
        }
    }

    /// RFC 3909 §2-§3: the result code and diagnostic for a Cancel
    /// carrying `value`.
    fn cancel(&self, value: Option<&[u8]>) -> (u8, String) {
        let Some(bytes) = value else {
            return (ResultCode::ProtocolError as u8, "cancel: missing cancelRequestValue".into());
        };
        let req: CancelRequestValue = match rasn::ber::decode(bytes) {
            Ok(r) => r,
            Err(e) => return (ResultCode::ProtocolError as u8, format!("cancel: malformed cancelRequestValue: {e}")),
        };
        match self.cancelable.get(&req.cancel_id) {
            None => (RC_NO_SUCH_OPERATION, format!("cancel: no outstanding operation {}", req.cancel_id)),
            Some(false) => (RC_CANNOT_CANCEL, format!("cancel: operation {} cannot be cancelled", req.cancel_id)),
            Some(true) => (RC_TOO_LATE, format!("cancel: operation {} has already completed", req.cancel_id)),
        }
    }
}

/// RFC 3909 §2: Abandon, Bind, Unbind, Cancel and StartTLS cannot be
/// cancelled.
fn is_cancelable(op: &ProtocolOp) -> bool {
    match op {
        ProtocolOp::BindRequest(_) | ProtocolOp::UnbindRequest(_) | ProtocolOp::AbandonRequest(_) => false,
        ProtocolOp::ExtendedReq(r) => r.request_name.as_ref() != STARTTLS_OID && r.request_name.as_ref() != CANCEL_OID,
        _ => true,
    }
}

fn ber_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let len = (n as u64).to_be_bytes();
        let skip = len.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&len[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// A Cancel's `ExtendedResponse` (RFC 3909 §2: no responseName, no
/// responseValue), BER-encoded by hand because its result codes are outside
/// `rasn_ldap::ResultCode`. Byte-identical to rasn's own encoding for any
/// code both can express (see the tests).
fn cancel_response_bytes(message_id: u32, code: u8, diagnostic: &str) -> Vec<u8> {
    let mut resp = ber_tlv(0x0a, &[code]); // resultCode ENUMERATED (every code here is < 128)
    resp.extend(ber_tlv(0x04, b"")); // matchedDN
    resp.extend(ber_tlv(0x04, diagnostic.as_bytes())); // diagnosticMessage
    let mut msg = rasn::ber::encode(&message_id).expect("an integer always encodes");
    msg.extend(ber_tlv(0x78, &resp)); // [APPLICATION 24] ExtendedResponse
    ber_tlv(0x30, &msg)
}

/// The `supportedExtension` values for rootDSE (RFC 4512 §5.1.4): only the
/// operations this connection can actually perform.
fn supported_extensions(fips_active: bool, starttls: bool) -> Vec<String> {
    let mut oids = Vec::new();
    if starttls {
        oids.push(STARTTLS_OID);
    }
    oids.push(WHOAMI_OID);
    if fips_active {
        oids.push(PASSWORD_MODIFY_OID);
    }
    oids.push(CANCEL_OID);
    oids.into_iter().map(|o| String::from_utf8_lossy(o).into_owned()).collect()
}

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
/// The security layer a finished negotiation installs is kept apart, in
/// [`SecurityLayer`], because a later bind on the same connection (a
/// re-bind, RFC 4513 §5.2.1.7 / RFC 4422 §3.8) runs a new negotiation
/// *through* the installed layer without disturbing it.
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
}

/// A SASL security layer in effect on the connection (RFC 4752 §3.4,
/// integrity or confidentiality) -- every LDAP message on this connection
/// is a GSS Wrap token inside a 4-octet length prefix, not a bare BER
/// `LdapMessage`. `sealed` records which: `false` for integrity-only,
/// `true` for confidentiality. Found live testing a real macOS
/// `dsconfigad` join (#20): it rejects a bind that only ever offers "no
/// security layer" with `GSS_S_BAD_QOP`, unlike MIT krb5's `ldapsearch`
/// (used for every earlier SASL/GSSAPI verification), which accepts it --
/// and it separately requires confidentiality specifically to write the
/// new computer account's Kerberos key, failing integrity-only binds the
/// same way once it gets past the bind itself.
///
/// Its lifetime follows RFC 4513 §5.2.1.4 and RFC 4422 §3.8: it stays in
/// effect until a later SASL bind installs a new layer (which replaces it)
/// or the connection closes. A failed bind, a simple or anonymous bind, or
/// a SASL bind that selects no layer leaves it in place.
///
/// `send_seq` is the acceptor's next outgoing Wrap-token sequence
/// number (RFC 4121 §4.2.6.2 SND_SEQ). The security-layer challenge
/// is the acceptor's *first* wrap token (seq 0, hardcoded in
/// `security_layer_challenge`), so this starts at 1 and increments on
/// every wrapped response -- a strict initiator (Heimdal / macOS
/// `dsconfigad`) drops a token whose sequence number doesn't advance
/// as a replay. Atomic for interior mutability, so `send_response` can
/// bump it while holding only `&SaslSession`.
struct SecurityLayer {
    session_key: Vec<u8>,
    enctype: Enctype,
    sealed: bool,
    send_seq: AtomicU64,
}

/// A connection's SASL state: the negotiation in progress (if any) and
/// the security layer in effect (if any). The two are independent -- see
/// [`SecurityLayer`].
#[derive(Default)]
struct SaslSession {
    negotiation: SaslState,
    layer: Option<SecurityLayer>,
}

/// Reads the next `LdapMessage`, transparently unwrapping it first if a
/// security layer is in effect on this connection (see [`SecurityLayer`]).
/// `Err(())` on any framing/GSS-unwrap failure -- the caller just closes
/// the connection either way, so the distinction isn't worth carrying.
async fn read_next_message<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    buf: &mut Vec<u8>,
    fips: Option<&iron_crypto::FipsContext>,
    sasl_state: &SaslSession,
) -> Result<Option<LdapMessage>, ()> {
    match &sasl_state.layer {
        Some(SecurityLayer { session_key, enctype, .. }) => {
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
        None => read_message(conn, buf).await.map_err(|_| ()),
    }
}

/// Writes an `LdapMessage`, transparently GSS-wrapping it first under
/// the same condition `read_next_message` unwraps under.
async fn send_response<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    fips: Option<&iron_crypto::FipsContext>,
    sasl_state: &SaslSession,
    msg: &LdapMessage,
) -> Result<(), ()> {
    match &sasl_state.layer {
        Some(_) => {
            let plain = rasn::ber::encode(msg).map_err(|_| ())?;
            send_encoded(conn, fips, sasl_state, &plain).await
        }
        None => write_message(conn, msg).await.map_err(|_| ()),
    }
}

/// Writes an already BER-encoded `LdapMessage` (one `rasn_ldap` cannot
/// express -- see `cancel_response_bytes`), GSS-wrapped like `send_response`.
async fn send_encoded<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    fips: Option<&iron_crypto::FipsContext>,
    sasl_state: &SaslSession,
    plain: &[u8],
) -> Result<(), ()> {
    use tokio::io::AsyncWriteExt;
    match &sasl_state.layer {
        Some(SecurityLayer { session_key, enctype, sealed, send_seq }) => {
            let fips = fips.ok_or(())?;
            // Consume this token's SND_SEQ and advance the counter so the
            // next wrapped response uses the following value (RFC 4121
            // §4.2.6.2 -- see `SecurityLayer`'s doc comment).
            let seq = send_seq.fetch_add(1, Ordering::Relaxed);
            // Key usage 22: KG-USAGE-ACCEPTOR-SEAL -- we're the GSS acceptor.
            let wrapped = crate::gssapi::wrap::wrap(fips, *enctype, session_key, 22, *sealed, seq, plain).map_err(|_| ())?;
            write_sized_buffer(conn, &wrapped).await.map_err(|_| ())
        }
        None => conn.write_all(plain).await.map_err(|_| ()),
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
    let mut sasl_state = SaslSession::default();
    // RFC 4513 §3 authzId this connection is currently bound as -- `None`
    // for anonymous, `Some("dn:...")`/`Some("u:...")` otherwise. Updated
    // on every *terminal* bind outcome (success or failure, but not a
    // still-in-progress SASL step) so a later WhoAmI extended operation
    // (RFC 4532) can answer correctly; RFC 4513 also permits re-binding
    // on the same connection, so this can change (including back to
    // `None`) more than once per connection.
    let mut bound_identity: Option<String> = None;
    let mut op_log = OpLog::default();
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
        let cancelable = is_cancelable(&msg.protocol_op);

        match msg.protocol_op {
            ProtocolOp::UnbindRequest(_) => return,
            ProtocolOp::BindRequest(req) => {
                // RFC 4752 §3.1 / RFC 4513 §5.2.1.4: a newly negotiated
                // security layer takes effect on the *first octet
                // following* the bindResponse that completes the SASL
                // handshake -- that response itself goes out under
                // whatever layer was in effect *before* this request (none
                // on a first bind; found live via packet capture, #20:
                // sealing the success response made macOS's client report
                // GSS_S_BAD_QOP). So `handle_bind` hands back the new
                // layer instead of installing it, and it replaces the old
                // one (RFC 4422 §3.8) only after the response is sent.
                let (resp, identity, new_layer) =
                    handle_bind(&mut *app.store.lock().await, app.fips.as_ref(), &req, &mut sasl_state.negotiation).await;
                if resp.result_code != ResultCode::SaslBindInProgress {
                    bound_identity = identity;
                }
                let resp = LdapMessage::new(message_id, ProtocolOp::BindResponse(resp));
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
                if let Some(layer) = new_layer {
                    sasl_state.layer = Some(layer);
                }
            }
            ProtocolOp::SearchRequest(req) => {
                let mut store = app.store.lock().await;
                let ops = handle_search(&mut store, &req, &app.referral_config(), app.fips.is_some(), tls_acceptor.is_some() && matches!(conn, Conn::Plain(_))).await;
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
            // RFC 3909 Cancel -- see `OpLog`.
            ProtocolOp::ExtendedReq(req) if req.request_name.as_ref() == CANCEL_OID => {
                let (code, diagnostic) = op_log.cancel(req.request_value.as_deref());
                let bytes = cancel_response_bytes(message_id, code, &diagnostic);
                if send_encoded(&mut conn, app.fips.as_ref(), &sasl_state, &bytes).await.is_err() {
                    return;
                }
            }
            // RFC 4511 §4.12: a request name the server does not recognize
            // is answered protocolError, with no responseName.
            ProtocolOp::ExtendedReq(req) => {
                let resp = unsupported_extended_response(message_id, req.request_name.as_ref());
                if send_response(&mut conn, app.fips.as_ref(), &sasl_state, &resp).await.is_err() {
                    return;
                }
            }
            // Abandon has no response per RFC 4511 §4.11. IntermediateResponse
            // and any future/unknown op the client sends: nothing sensible to
            // reply with, so drop it rather than guess.
            _ => {}
        }
        op_log.record(message_id, cancelable);
    }
}

fn unsupported_extended_response(message_id: u32, oid: &[u8]) -> LdapMessage {
    LdapMessage::new(
        message_id,
        ProtocolOp::ExtendedResp(ExtendedResponse {
            result_code: ResultCode::ProtocolError,
            matched_dn: String::new().into(),
            diagnostic_message: format!("unsupported extended operation {}", String::from_utf8_lossy(oid)).into(),
            referral: None,
            response_name: None,
            response_value: None,
        }),
    )
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
///
/// The third element is the security layer a GSSAPI bind that just
/// completed has negotiated, for the caller to install once this response
/// is sent (see [`SecurityLayer`]). Nothing here touches the layer already
/// in effect: per RFC 4513 §5.2.1.4 a failed or non-SASL bind leaves it in
/// place, and a SASL re-bind that selects no layer keeps it too (RFC 4422
/// §3.8). `negotiation` is reset by any non-SASL bind, which aborts a SASL
/// exchange in progress (RFC 4513 §5.2.1.2).
async fn handle_bind(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    req: &BindRequest,
    sasl_state: &mut SaslState,
) -> (BindResponse, Option<String>, Option<SecurityLayer>) {
    if req.version != 3 {
        *sasl_state = SaslState::None;
        return (BindResponse::new(ResultCode::ProtocolError, String::new().into(), "only LDAPv3 is supported".into(), None, None), None, None);
    }
    match &req.authentication {
        AuthenticationChoice::Simple(password) if req.name.is_empty() && password.is_empty() => {
            *sasl_state = SaslState::None;
            (BindResponse::new(ResultCode::Success, String::new().into(), String::new().into(), None, None), None, None)
        }
        AuthenticationChoice::Simple(password) => {
            *sasl_state = SaslState::None;
            let code = authenticate_simple(store, fips, &req.name, password).await;
            let identity = (code == ResultCode::Success).then(|| format!("dn:{}", req.name.as_str()));
            (BindResponse::new(code, String::new().into(), String::new().into(), None, None), identity, None)
        }
        AuthenticationChoice::Sasl(creds) => handle_sasl_bind(store, fips, creds, sasl_state).await,
        _ => {
            *sasl_state = SaslState::None;
            (BindResponse::new(ResultCode::AuthMethodNotSupported, String::new().into(), "unrecognized authentication choice".into(), None, None), None, None)
        }
    }
}

/// RFC 4752 SASL/GSSAPI bind, over the Kerberos V5 GSS mechanism (RFC
/// 4121). Only the "GSSAPI" mechanism is supported. All three security
/// layers are offered (see `security_layer_challenge`); a negotiated
/// integrity or confidentiality layer is returned for the caller to
/// install. Works the same as a re-bind through a layer already in effect:
/// the request arrived unwrapped by that layer, and this exchange's own
/// context and keys are independent of it.
async fn handle_sasl_bind(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    creds: &SaslCredentials,
    sasl_state: &mut SaslState,
) -> (BindResponse, Option<String>, Option<SecurityLayer>) {
    if creds.mechanism.as_str() != "GSSAPI" {
        *sasl_state = SaslState::None;
        return (BindResponse::new(ResultCode::AuthMethodNotSupported, String::new().into(), "only the GSSAPI SASL mechanism is supported".into(), None, None), None, None);
    }
    let Some(fips) = fips else {
        *sasl_state = SaslState::None;
        return (BindResponse::new(ResultCode::UnwillingToPerform, String::new().into(), "FIPS provider not active -- SASL/GSSAPI unavailable".into(), None, None), None, None);
    };

    let resp = match std::mem::take(sasl_state) {
        SaslState::None => {
            let Some(input_token) = &creds.credentials else {
                return (BindResponse::new(ResultCode::AuthMethodNotSupported, String::new().into(), "GSSAPI bind requires an initial token".into(), None, None), None, None);
            };
            // Any DN within the (single) served partition works here --
            // lookup_by_index only uses it to resolve which cluster to
            // query, not as a search filter.
            let Some(any_dn) = store.registry().iter().next().map(|p| p.base_dn.clone()) else {
                return (BindResponse::new(ResultCode::Other, String::new().into(), "no partition configured".into(), None, None), None, None);
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
                return (BindResponse::new(ResultCode::ProtocolError, String::new().into(), "missing security-layer response".into(), None, None), None, None);
            };
            // Key usage 24: KG-USAGE-INITIATOR-SEAL (RFC 4121 §2) -- the
            // client is the GSS initiator, so its Wrap tokens use the
            // initiator-seal usage, not our own acceptor-seal (22).
            match crate::gssapi::wrap::unwrap(fips, enctype, &session_key, 24, response) {
                // Bit 0: no security layer -- bind succeeds, and whatever
                // layer was already in effect (none on a first bind) stays
                // (RFC 4422 §3.8).
                Ok(plain) if plain.first() == Some(&0x01) => {
                    tracing::info!(%client_principal, "GSSAPI bind succeeded (no security layer)");
                    return (BindResponse::new(ResultCode::Success, String::new().into(), String::new().into(), None, None), Some(format!("u:{client_principal}")), None);
                }
                // Bit 1: integrity -- bind succeeds, but every later
                // message on this connection must be a Wrap token (see
                // `SecurityLayer`'s doc comment).
                Ok(plain) if plain.first() == Some(&0x02) => {
                    tracing::info!(%client_principal, "GSSAPI bind succeeded (integrity security layer active)");
                    // send_seq starts at 1: the challenge already consumed
                    // the acceptor's seq 0 (see `security_layer_challenge`).
                    let layer = SecurityLayer { session_key, enctype, sealed: false, send_seq: AtomicU64::new(1) };
                    return (BindResponse::new(ResultCode::Success, String::new().into(), String::new().into(), None, None), Some(format!("u:{client_principal}")), Some(layer));
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
                    let layer = SecurityLayer { session_key, enctype, sealed: true, send_seq: AtomicU64::new(1) };
                    return (BindResponse::new(ResultCode::Success, String::new().into(), String::new().into(), None, None), Some(format!("u:{client_principal}")), Some(layer));
                }
                Ok(_) => BindResponse::new(ResultCode::UnwillingToPerform, String::new().into(), "client selected an unsupported security layer".into(), None, None),
                Err(e) => BindResponse::new(ResultCode::InvalidCredentials, String::new().into(), e.to_string().into(), None, None),
            }
        }
    };
    (resp, None, None)
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
/// it takes SND_SEQ 0 (integrity-only, never sealed); `SecurityLayer`
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
/// by an `AddRequest` won't). Refused to an anonymous connection; no
/// fine-grained ACL check yet (D8/#4 scope) -- any authenticated bind may
/// reset any entry's password, matching this project's current
/// single-tier trust model.
async fn handle_password_modify(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    request_value: Option<&[u8]>,
    bound_identity: Option<&str>,
    spec: &iron_store::index::IndexSpec,
) -> Result<Option<OctetString>, PasswordModifyError> {
    // An anonymous connection may not set anyone's password (RFC 3062 §5
    // leaves the policy to the server; #45 tracks anonymous writes
    // generally).
    if bound_identity.is_none() {
        return Err(PasswordModifyError::new(ResultCode::InsufficientAccessRights, "password modify requires an authenticated bind"));
    }
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

/// Renames and/or moves an entry -- a leaf, or a whole subtree with its
/// descendants (RFC 4511 §4.9). Each descendant keeps its RDNs below the
/// renamed entry and takes the new DN as its suffix.
///
/// Refused, with the RFC 4511 result codes:
/// - `EntryAlreadyExists` if anything already exists at a target DN;
/// - `NoSuchObject` if `newSuperior` names an entry that does not exist;
/// - `UnwillingToPerform` if `newSuperior` is the entry or one of its own
///   descendants (the subtree would become its own parent);
/// - `AffectsMultipleDsas` if the new DN belongs to another naming context,
///   or the subtree holds another naming context's head (a child domain or
///   the configuration/schema NC): those live in other partitions, and the
///   partition registry names them by DN.
///
/// The move is **not atomic** across keys: every entry is created at its
/// new DN (parents first, each create-only), then the old entries are
/// deleted (deepest first). If a create finds its target taken, the
/// entries this call already created are deleted again before answering.
/// A crash between the creates and the deletes leaves the entries readable
/// at both DNs rather than losing any -- the same posture as `iron-store`'s
/// other cross-key operations.
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
    let new_dn = match Dn::parse(&join_dn(req.new_rdn.as_str(), &new_parent)) {
        Ok(dn) => dn,
        Err(_) => return ModifyDnResponse(invalid_dn()),
    };
    if new_parent.is_within(&old_dn) {
        return ModifyDnResponse(LdapResult::new(
            ResultCode::UnwillingToPerform,
            String::new().into(),
            "newSuperior is the entry itself or one of its descendants".into(),
        ));
    }
    let topology = referrals.topology.unwrap_or_else(|| store.registry());
    if let Some(result) = moddn_crosses_naming_contexts(topology, store.registry(), &old_dn, &new_dn) {
        return ModifyDnResponse(result);
    }
    if req.new_superior.is_some() && Some(&new_parent) != old_dn.parent().as_ref() {
        match store.get_entry(&new_parent).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return ModifyDnResponse(LdapResult::new(
                    ResultCode::NoSuchObject,
                    String::new().into(),
                    "newSuperior does not exist".into(),
                ))
            }
            Err(e) => return ModifyDnResponse(store_error_result(&e, referrals, &new_parent)),
        }
    }

    let mut subtree = match store.scan_subtree(&old_dn).await {
        Ok(rows) => rows,
        Err(e) => return ModifyDnResponse(store_error_result(&e, referrals, &old_dn)),
    };
    // The renamed entry itself is read by DN rather than taken from the
    // scan: the scan reconstructs DNs from storage keys (normalized case).
    let mut entry = match store.get_entry(&old_dn).await {
        Ok(Some(e)) => e,
        Ok(None) => return ModifyDnResponse(LdapResult::new(ResultCode::NoSuchObject, String::new().into(), "".into())),
        Err(e) => return ModifyDnResponse(store_error_result(&e, referrals, &old_dn)),
    };
    subtree.retain(|(dn, _)| dn != &old_dn);

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

    // Same DN (e.g. only deleteoldrdn/RDN-value changes): an in-place write.
    if old_dn == new_dn {
        return ModifyDnResponse(match store.put_entry(&new_dn, &entry, spec).await {
            Ok(()) => success(),
            Err(e) => store_error_result(&e, referrals, &new_dn),
        });
    }

    // (old DN, new DN, entry), parents before children.
    let mut moves = vec![(old_dn.clone(), new_dn.clone(), entry)];
    for (dn, e) in subtree {
        match rebase_dn(&dn, &old_dn, &new_dn) {
            Some(target) => moves.push((dn, target, e)),
            None => return ModifyDnResponse(operations_error(&format!("cannot rebase {dn} under {new_dn}"))),
        }
    }
    moves.sort_by_key(|(old, _, _)| old.depth());

    let mut created: Vec<&Dn> = Vec::new();
    for (_, target, e) in &moves {
        let outcome = match store.create_entry(target, e, spec).await {
            Ok(true) => None,
            Ok(false) => Some(LdapResult::new(ResultCode::EntryAlreadyExists, target.to_string().into(), String::new().into())),
            Err(err) => Some(store_error_result(&err, referrals, target)),
        };
        if let Some(result) = outcome {
            for dn in created.iter().rev() {
                if let Err(err) = store.delete_entry(dn, spec).await {
                    tracing::warn!(%dn, "modDN rollback could not delete a created entry: {err}");
                }
            }
            return ModifyDnResponse(result);
        }
        created.push(target);
    }
    for (old, _, _) in moves.iter().rev() {
        if let Err(e) = store.delete_entry(old, spec).await {
            return ModifyDnResponse(operations_error(&format!(
                "entries moved to the new DN but {old} could not be removed: {e}"
            )));
        }
    }
    ModifyDnResponse(success())
}

/// `rdn` under `parent`, as a DN string (`rdn` alone under the root).
fn join_dn(rdn: &str, parent: &Dn) -> String {
    if parent.is_empty() {
        rdn.to_string()
    } else {
        format!("{rdn},{parent}")
    }
}

/// `dn` (at or below `old_base`) with `old_base` replaced by `new_base`:
/// the RDNs below `old_base` are kept, in order.
fn rebase_dn(dn: &Dn, old_base: &Dn, new_base: &Dn) -> Option<Dn> {
    if !dn.is_within(old_base) {
        return None;
    }
    let keep = dn.depth() - old_base.depth();
    let mut parts: Vec<String> = dn.rdns()[..keep].iter().map(|r| r.to_string()).collect();
    if !new_base.is_empty() {
        parts.push(new_base.to_string());
    }
    Dn::parse(&parts.join(",")).ok()
}

/// `AffectsMultipleDsas` (RFC 4511 §4.9) if the move would leave this
/// entry's naming context: the new DN resolves to another partition, or
/// the subtree at `old_dn` is or holds the head of a naming context
/// (another partition's base DN, or this partition's own).
/// `topology` is the forest's registry (or the local one when no forest
/// is loaded); `local` is the store's own.
fn moddn_crosses_naming_contexts(
    topology: &iron_partition::PartitionRegistry,
    local: &iron_partition::PartitionRegistry,
    old_dn: &Dn,
    new_dn: &Dn,
) -> Option<LdapResult> {
    let registry = topology;
    let old_owner = registry.resolve(old_dn).map(|p| &p.id);
    let new_owner = registry.resolve(new_dn).map(|p| &p.id);
    let refuse = |why: String| Some(LdapResult::new(ResultCode::AffectsMultipleDsas, String::new().into(), why.into()));
    if old_owner != new_owner {
        return refuse(format!("{new_dn} is in another naming context"));
    }
    let heads: Vec<&Dn> = registry.iter().map(|p| &p.base_dn).chain(local.iter().map(|p| &p.base_dn)).collect();
    if let Some(head) = heads.into_iter().find(|b| b.is_within(old_dn)) {
        return refuse(format!("the subtree holds the naming context head {head}"));
    }
    None
}

async fn handle_search(store: &mut Store, req: &SearchRequest, referrals: &Referrals<'_>, fips_active: bool, starttls: bool) -> Vec<ProtocolOp> {
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
        // highestCommittedUSN: the store's current revision (#28).
        let own_base = store.registry().iter().next().map(|p| p.base_dn.clone());
        let usn = match own_base {
            Some(dn) => store.current_revision(&dn).await.ok(),
            None => None,
        };
        let registry = referrals.topology.unwrap_or_else(|| store.registry());
        let mut entry = rootdse::build(registry, fips_active, usn);
        entry.attributes.push(PartialAttribute::new(
            "supportedExtension".into(),
            SetOf::from_vec(supported_extensions(fips_active, starttls).into_iter().map(|v| v.into_bytes().into()).collect()),
        ));
        let entry_op = ProtocolOp::SearchResEntry(entry);
        let mut ops = vec![entry_op];
        ops.extend(done(ResultCode::Success, ""));
        return ops;
    }
    if let Some(result) = proactive_referral(referrals, &base_dn) {
        return done_result(result);
    }

    // Every candidate carries uSNCreated/uSNChanged from its etcd revisions
    // (D2's USN, #28), added before the filter so `(uSNChanged>=N)` -- how
    // AD clients poll for changes -- matches on them.
    let candidates: Vec<(Dn, Entry)> = match req.scope {
        SearchRequestScope::BaseObject => match store.get_entry_with_revisions(&base_dn).await {
            Ok(Some((e, revs))) => vec![(base_dn.clone(), with_usn(e, revs))],
            Ok(None) => return done(ResultCode::NoSuchObject, ""),
            Err(e) => return done_store_error(&e, referrals, &base_dn),
        },
        SearchRequestScope::SingleLevel | SearchRequestScope::WholeSubtree => {
            match store.scan_subtree_with_revisions(&base_dn).await {
                Ok(rows) => {
                    let child_depth = base_dn.depth() + 1;
                    rows.into_iter()
                        .filter(|(dn, _, _)| req.scope != SearchRequestScope::SingleLevel || dn.depth() == child_depth)
                        .map(|(dn, e, revs)| (dn, with_usn(e, revs)))
                        .collect()
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
    // The size limit counts entries returned, not candidates scanned
    // (#27: it used to cut the candidate list first, so a match past the
    // first N entries was dropped and the search still said Success).
    let mut sent = 0usize;
    for (dn, entry) in candidates {
        if !filter::matches(&entry, &req.filter) {
            continue;
        }
        if sent == limit {
            ops.extend(done(ResultCode::SizeLimitExceeded, ""));
            return ops;
        }
        sent += 1;
        ops.push(ProtocolOp::SearchResEntry(SearchResultEntry::new(
            dn.to_string().into(),
            project_attributes(&entry, &req.attributes, req.types_only),
        )));
    }
    ops.extend(done(ResultCode::Success, ""));
    ops
}

/// `entry` with AD's `uSNCreated`/`uSNChanged` set from its etcd
/// revisions (#28). Computed on every read, never stored: a client that
/// writes either attribute has it replaced here.
fn with_usn(mut entry: Entry, revs: iron_store::entry::Revisions) -> Entry {
    entry.set("uSNCreated", [revs.created.to_string()]);
    entry.set("uSNChanged", [revs.modified.to_string()]);
    entry
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
        // userPassword is write-only: never returned, named or not, to
        // anyone (#58; AD never returns unicodePwd). It used to come back
        // to any search that named it, anonymous included, handing out the
        // PBKDF2 hash for offline guessing. Binds check it server-side.
        .filter(|name| !name.eq_ignore_ascii_case(USER_PASSWORD_ATTR) && (want_all || explicitly_requested(name)))
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
mod projection_tests {
    use super::*;

    #[test]
    fn user_password_is_never_returned() {
        let mut e = Entry::new();
        e.set("uid", ["alice"]);
        e.set("userPassword", ["$pbkdf2-sha256$210000$aa$bb"]);
        let names = |req: &[&str]| -> Vec<String> {
            let req: Vec<rasn_ldap::LdapString> = req.iter().map(|a| (*a).into()).collect();
            project_attributes(&e, &req, false).iter().map(|a| a.r#type.as_str().to_ascii_lowercase()).collect()
        };
        assert_eq!(names(&[]), vec!["uid"]);
        assert_eq!(names(&["*"]), vec!["uid"]);
        assert_eq!(names(&["uid", "userPassword"]), vec!["uid"]);
        assert!(names(&["userpassword"]).is_empty());
    }

    #[test]
    fn usn_attributes_come_from_revisions_and_replace_written_ones() {
        let mut e = Entry::new();
        e.set("cn", ["alice"]);
        e.set("uSNChanged", ["999999"]); // a client-written value is replaced
        let e = with_usn(e, iron_store::entry::Revisions { created: 7, modified: 1500 });
        assert_eq!(e.get("usncreated"), Some(&["7".to_string()][..]));
        assert_eq!(e.get("usnchanged"), Some(&["1500".to_string()][..]));
    }
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

#[cfg(test)]
mod moddn_tests {
    use iron_partition::{ClusterRef, ForestId, Partition, PartitionRegistry};

    use super::*;

    fn dn(s: &str) -> Dn {
        Dn::parse(s).unwrap()
    }

    fn forest() -> PartitionRegistry {
        let forest = ForestId::new("acme").unwrap();
        let cluster = ClusterRef::plaintext(["http://127.0.0.1:2379"]);
        let parent = Partition::domain("g10", forest.clone(), dn("dc=g10,dc=lo"), cluster.clone()).unwrap();
        let child = Partition::domain("g10-emea", forest, dn("dc=emea,dc=g10,dc=lo"), cluster).unwrap();
        PartitionRegistry::from_partitions([parent, child]).unwrap()
    }

    fn local() -> PartitionRegistry {
        let forest = ForestId::new("acme").unwrap();
        let cluster = ClusterRef::plaintext(["http://127.0.0.1:2379"]);
        PartitionRegistry::from_partitions([Partition::domain("g10", forest, dn("dc=g10,dc=lo"), cluster).unwrap()]).unwrap()
    }

    #[test]
    fn rebase_keeps_the_rdns_below_the_moved_entry() {
        let old = dn("ou=eng,dc=g10,dc=lo");
        let new = dn("ou=engineering,ou=sales,dc=g10,dc=lo");
        assert_eq!(rebase_dn(&old, &old, &new), Some(new.clone()));
        assert_eq!(
            rebase_dn(&dn("cn=Carol Smith,ou=team,ou=eng,dc=g10,dc=lo"), &old, &new),
            Some(dn("cn=Carol Smith,ou=team,ou=engineering,ou=sales,dc=g10,dc=lo"))
        );
        // Values that need escaping survive the round trip.
        let carol = rebase_dn(&dn(r"cn=Smith\, Carol,ou=eng,dc=g10,dc=lo"), &old, &new).unwrap();
        assert_eq!(carol.rdns()[0].avas()[0].value(), "Smith, Carol");
        assert_eq!(rebase_dn(&dn("cn=x,ou=other,dc=g10,dc=lo"), &old, &new), None);
    }

    #[test]
    fn join_dn_under_root_and_parent() {
        assert_eq!(join_dn("ou=a", &Dn::root()), "ou=a");
        assert_eq!(join_dn("ou=a", &dn("dc=g10,dc=lo")), "ou=a,dc=g10,dc=lo");
    }

    #[test]
    fn a_move_inside_one_naming_context_is_allowed() {
        let (f, l) = (forest(), local());
        assert!(moddn_crosses_naming_contexts(&f, &l, &dn("ou=eng,dc=g10,dc=lo"), &dn("ou=eng,ou=sales,dc=g10,dc=lo")).is_none());
    }

    #[test]
    fn a_move_into_another_naming_context_affects_multiple_dsas() {
        let (f, l) = (forest(), local());
        let r = moddn_crosses_naming_contexts(&f, &l, &dn("ou=eng,dc=g10,dc=lo"), &dn("ou=eng,dc=emea,dc=g10,dc=lo")).unwrap();
        assert_eq!(r.result_code, ResultCode::AffectsMultipleDsas);
    }

    #[test]
    fn a_subtree_holding_a_naming_context_head_affects_multiple_dsas() {
        let (f, l) = (forest(), local());
        // The domain head itself (dc=emea, a child domain, also sits below it).
        let r = moddn_crosses_naming_contexts(&f, &l, &dn("dc=g10,dc=lo"), &dn("dc=g11,dc=lo")).unwrap();
        assert_eq!(r.result_code, ResultCode::AffectsMultipleDsas);
        // With only the local registry, the partition's own head still counts.
        let r = moddn_crosses_naming_contexts(&l, &l, &dn("dc=g10,dc=lo"), &dn("dc=x,dc=g10,dc=lo")).unwrap();
        assert_eq!(r.result_code, ResultCode::AffectsMultipleDsas);
    }
}

#[cfg(test)]
mod extended_op_tests {
    use rasn_ldap::ExtendedRequest;

    use super::*;

    fn cancel_value(id: u32) -> Vec<u8> {
        rasn::ber::encode(&CancelRequestValue { cancel_id: id }).unwrap()
    }

    #[test]
    fn cancel_of_an_unknown_operation_is_no_such_operation() {
        let log = OpLog::default();
        assert_eq!(log.cancel(Some(&cancel_value(7))).0, RC_NO_SUCH_OPERATION);
    }

    #[test]
    fn cancel_of_a_completed_operation_is_too_late() {
        let mut log = OpLog::default();
        log.record(3, true);
        assert_eq!(log.cancel(Some(&cancel_value(3))).0, RC_TOO_LATE);
    }

    #[test]
    fn cancel_of_bind_starttls_abandon_or_cancel_is_cannot_cancel() {
        let ext = |oid: &[u8]| ProtocolOp::ExtendedReq(ExtendedRequest { request_name: oid.to_vec().into(), request_value: None });
        assert!(!is_cancelable(&ProtocolOp::AbandonRequest(rasn_ldap::AbandonRequest(1))));
        assert!(!is_cancelable(&ext(STARTTLS_OID)));
        assert!(!is_cancelable(&ext(CANCEL_OID)));
        assert!(is_cancelable(&ext(WHOAMI_OID)));
        assert!(is_cancelable(&ext(PASSWORD_MODIFY_OID)));
        let mut log = OpLog::default();
        log.record(1, false);
        assert_eq!(log.cancel(Some(&cancel_value(1))).0, RC_CANNOT_CANCEL);
    }

    #[test]
    fn malformed_or_missing_cancel_value_is_protocol_error() {
        let log = OpLog::default();
        assert_eq!(log.cancel(None).0, ResultCode::ProtocolError as u8);
        assert_eq!(log.cancel(Some(b"\x04\x01x")).0, ResultCode::ProtocolError as u8);
    }

    #[test]
    fn op_log_is_bounded() {
        let mut log = OpLog::default();
        for id in 0..(OP_LOG_CAPACITY as u32 + 10) {
            log.record(id, true);
        }
        assert_eq!(log.cancelable.len(), OP_LOG_CAPACITY);
        assert_eq!(log.cancel(Some(&cancel_value(0))).0, RC_NO_SUCH_OPERATION);
        assert_eq!(log.cancel(Some(&cancel_value(OP_LOG_CAPACITY as u32 + 9))).0, RC_TOO_LATE);
    }

    /// The hand encoding matches rasn's for a code both can express, with a
    /// diagnostic long enough to need a long-form length.
    #[test]
    fn cancel_response_encoding_matches_rasn() {
        let diag = "x".repeat(300);
        for (id, code) in [(5u32, ResultCode::ProtocolError), (70000, ResultCode::Other)] {
            let msg = LdapMessage::new(
                id,
                ProtocolOp::ExtendedResp(ExtendedResponse {
                    result_code: code,
                    matched_dn: String::new().into(),
                    diagnostic_message: diag.clone().into(),
                    referral: None,
                    response_name: None,
                    response_value: None,
                }),
            );
            assert_eq!(cancel_response_bytes(id, code as u8, &diag), rasn::ber::encode(&msg).unwrap());
        }
        let b = cancel_response_bytes(9, RC_TOO_LATE, "");
        assert!(b.windows(3).any(|w| w == [0x0a, 0x01, 120]));
    }

    #[test]
    fn unknown_extended_operation_names_the_oid() {
        let msg = unsupported_extended_response(4, b"1.2.3.4");
        let ProtocolOp::ExtendedResp(r) = msg.protocol_op else { panic!() };
        assert_eq!(r.result_code, ResultCode::ProtocolError);
        assert_eq!(r.diagnostic_message.as_str(), "unsupported extended operation 1.2.3.4");
        assert!(r.response_name.is_none());
    }

    #[test]
    fn supported_extension_matches_capability() {
        let all = supported_extensions(true, true);
        assert_eq!(all, ["1.3.6.1.4.1.1466.20037", "1.3.6.1.4.1.4203.1.11.3", "1.3.6.1.4.1.4203.1.11.1", "1.3.6.1.1.8"]);
        assert_eq!(supported_extensions(false, false), ["1.3.6.1.4.1.4203.1.11.3", "1.3.6.1.1.8"]);
    }
}
