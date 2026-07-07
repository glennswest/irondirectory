//! Per-connection LDAP session: reads framed `LdapMessage`s and dispatches
//! bind/search/add/delete/modify/compare (the operations implemented so
//! far -- see crate docs).

use std::sync::Arc;

use iron_partition::Dn;
use iron_store::model::Entry;
use iron_store::store::Store;
use openssl::ssl::SslAcceptor;
use rasn::types::{OctetString, SetOf};
use rasn_ldap::{
    AddRequest, AddResponse, Attribute, AuthenticationChoice, BindRequest, BindResponse,
    ChangeOperation, CompareRequest, CompareResponse, DelRequest, DelResponse, ExtendedResponse,
    LdapMessage, LdapResult, ModifyDnRequest, ModifyDnResponse, ModifyRequest, ModifyResponse,
    PartialAttribute, ProtocolOp, ResultCode, SearchRequest, SearchRequestScope, SearchResultDone,
    SearchResultEntry,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::conn::Conn;
use crate::framing::{read_message, write_message};
use crate::{filter, rootdse, AppState};

/// LDAP attribute holding the PBKDF2-hashed password (D4). Lowercase to
/// match `Entry`'s case-folded storage.
const USER_PASSWORD_ATTR: &str = "userpassword";

/// RFC 4511 §4.14.1 -- the well-known OID for the StartTLS extended
/// operation.
const STARTTLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

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
    loop {
        let msg = match read_message(&mut conn, &mut buf).await {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(e) => {
                tracing::debug!("framing error, closing connection: {e}");
                return;
            }
        };
        let message_id = msg.message_id;

        match msg.protocol_op {
            ProtocolOp::UnbindRequest(_) => return,
            ProtocolOp::BindRequest(req) => {
                let resp = handle_bind(&mut *app.store.lock().await, app.fips.as_ref(), &req).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::BindResponse(resp));
                if write_message(&mut conn, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::SearchRequest(req) => {
                let mut store = app.store.lock().await;
                let ops = handle_search(&mut store, &req, &app.referrals).await;
                drop(store);
                for op in ops {
                    let resp = LdapMessage::new(message_id, op);
                    if write_message(&mut conn, &resp).await.is_err() {
                        return;
                    }
                }
            }
            ProtocolOp::AddRequest(req) => {
                let resp = handle_add(&mut *app.store.lock().await, app.fips.as_ref(), &req, &app.index_spec, &app.referrals).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::AddResponse(resp));
                if write_message(&mut conn, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::DelRequest(req) => {
                let resp = handle_delete(&mut *app.store.lock().await, &req, &app.index_spec, &app.referrals).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::DelResponse(resp));
                if write_message(&mut conn, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::ModifyRequest(req) => {
                let resp = handle_modify(&mut *app.store.lock().await, app.fips.as_ref(), &req, &app.index_spec, &app.referrals).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::ModifyResponse(resp));
                if write_message(&mut conn, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::CompareRequest(req) => {
                let resp = handle_compare(&mut *app.store.lock().await, &req, &app.referrals).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::CompareResponse(resp));
                if write_message(&mut conn, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::ModDnRequest(req) => {
                let resp = handle_moddn(&mut *app.store.lock().await, &req, &app.index_spec, &app.referrals).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::ModDnResponse(resp));
                if write_message(&mut conn, &resp).await.is_err() {
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
                if write_message(&mut conn, &resp).await.is_err() {
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
                if write_message(&mut conn, &resp).await.is_err() {
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

/// A naming context this server doesn't host, if `dn` falls at or below
/// one of `referrals`' configured base DNs.
fn referral_for<'a>(referrals: &'a [(Dn, String)], dn: &Dn) -> Option<&'a str> {
    referrals
        .iter()
        .find(|(base, _)| dn.is_within(base))
        .map(|(_, url)| url.as_str())
}

/// Maps a `StoreError` to the LDAP result it should produce.
/// `NoPartitionFor` becomes a `Referral` (RFC 4511 §4.1.10) if `dn` falls
/// under a configured referral naming context, since that's a real,
/// client-actionable answer ("ask over there instead") rather than a
/// generic server error.
fn store_error_result(e: &iron_store::StoreError, referrals: &[(Dn, String)], dn: &Dn) -> LdapResult {
    if matches!(e, iron_store::StoreError::NoPartitionFor(_)) {
        if let Some(url) = referral_for(referrals, dn) {
            let uri = format!("{}/{}", url.trim_end_matches('/'), dn);
            let mut result = LdapResult::new(ResultCode::Referral, String::new().into(), String::new().into());
            result.referral = Some(vec![uri.into()]);
            return result;
        }
    }
    operations_error(&e.to_string())
}

async fn handle_bind(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    req: &BindRequest,
) -> BindResponse {
    let (code, diagnostic) = if req.version != 3 {
        (ResultCode::ProtocolError, "only LDAPv3 is supported".to_string())
    } else {
        match &req.authentication {
            AuthenticationChoice::Simple(password) if req.name.is_empty() && password.is_empty() => {
                (ResultCode::Success, String::new())
            }
            AuthenticationChoice::Simple(password) => {
                (authenticate_simple(store, fips, &req.name, password).await, String::new())
            }
            AuthenticationChoice::Sasl(_) => (
                ResultCode::AuthMethodNotSupported,
                "SASL bind is not implemented yet".to_string(),
            ),
            _ => (
                ResultCode::AuthMethodNotSupported,
                "unrecognized authentication choice".to_string(),
            ),
        }
    };
    BindResponse::new(code, String::new().into(), diagnostic.into(), None, None)
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

fn done_store_error(e: &iron_store::StoreError, referrals: &[(Dn, String)], dn: &Dn) -> Vec<ProtocolOp> {
    vec![ProtocolOp::SearchResDone(SearchResultDone(store_error_result(e, referrals, dn)))]
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
    referrals: &[(Dn, String)],
) -> AddResponse {
    let dn = match Dn::parse(&req.entry) {
        Ok(dn) => dn,
        Err(_) => return AddResponse(invalid_dn()),
    };
    let entry = match entry_from_attributes(&req.attributes, fips) {
        Ok(e) => e,
        Err(e) => return AddResponse(password_error_result(&e)),
    };
    if let Err(msg) = crate::schema::validate(&entry) {
        return AddResponse(LdapResult::new(ResultCode::ObjectClassViolation, String::new().into(), msg.into()));
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
    referrals: &[(Dn, String)],
) -> DelResponse {
    let dn = match Dn::parse(&req.0) {
        Ok(dn) => dn,
        Err(_) => return DelResponse(invalid_dn()),
    };
    let result = match store.delete_entry(&dn, spec).await {
        Ok(()) => success(),
        Err(e) => store_error_result(&e, referrals, &dn),
    };
    DelResponse(result)
}

async fn handle_modify(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    req: &ModifyRequest,
    spec: &iron_store::index::IndexSpec,
    referrals: &[(Dn, String)],
) -> ModifyResponse {
    let dn = match Dn::parse(&req.object) {
        Ok(dn) => dn,
        Err(_) => return ModifyResponse(invalid_dn()),
    };
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

async fn handle_compare(store: &mut Store, req: &CompareRequest, referrals: &[(Dn, String)]) -> CompareResponse {
    let dn = match Dn::parse(&req.entry) {
        Ok(dn) => dn,
        Err(_) => return CompareResponse(invalid_dn()),
    };
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
    referrals: &[(Dn, String)],
) -> ModifyDnResponse {
    let old_dn = match Dn::parse(&req.entry) {
        Ok(dn) if !dn.is_empty() => dn,
        _ => return ModifyDnResponse(invalid_dn()),
    };
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

async fn handle_search(store: &mut Store, req: &SearchRequest, referrals: &[(Dn, String)]) -> Vec<ProtocolOp> {
    let base_dn = match Dn::parse(&req.base_object) {
        Ok(dn) => dn,
        Err(_) => return done(ResultCode::InvalidDnSyntax, "invalid base DN"),
    };

    if base_dn.is_empty() && req.scope == SearchRequestScope::BaseObject {
        let entry_op = ProtocolOp::SearchResEntry(rootdse::build(store.registry()));
        let mut ops = vec![entry_op];
        ops.extend(done(ResultCode::Success, ""));
        return ops;
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
                    .map(|vs| vs.iter().map(|v| v.clone().into_bytes()).collect())
                    .unwrap_or_default()
            };
            PartialAttribute::new(
                name.into(),
                SetOf::from_vec(values.into_iter().map(Into::into).collect()),
            )
        })
        .collect()
}
