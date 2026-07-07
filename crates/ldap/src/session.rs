//! Per-connection LDAP session: reads framed `LdapMessage`s and dispatches
//! bind/search/add/delete/modify/compare (the operations implemented so
//! far -- see crate docs).

use std::sync::Arc;

use iron_partition::Dn;
use iron_store::model::Entry;
use iron_store::store::Store;
use rasn::types::{OctetString, SetOf};
use rasn_ldap::{
    AddRequest, AddResponse, Attribute, AuthenticationChoice, BindRequest, BindResponse,
    ChangeOperation, CompareRequest, CompareResponse, DelRequest, DelResponse, ExtendedResponse,
    LdapMessage, LdapResult, ModifyDnResponse, ModifyRequest, ModifyResponse, PartialAttribute,
    ProtocolOp, ResultCode, SearchRequest, SearchRequestScope, SearchResultDone, SearchResultEntry,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::framing::{read_message, write_message};
use crate::{filter, rootdse, AppState};

/// LDAP attribute holding the PBKDF2-hashed password (D4). Lowercase to
/// match `Entry`'s case-folded storage.
const USER_PASSWORD_ATTR: &str = "userpassword";

/// Handles one LDAP client connection until it unbinds, disconnects, or a
/// framing error occurs.
pub async fn handle_connection<S>(mut stream: S, app: Arc<AppState>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::new();
    loop {
        let msg = match read_message(&mut stream, &mut buf).await {
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
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::SearchRequest(req) => {
                let mut store = app.store.lock().await;
                let ops = handle_search(&mut store, &req).await;
                drop(store);
                for op in ops {
                    let resp = LdapMessage::new(message_id, op);
                    if write_message(&mut stream, &resp).await.is_err() {
                        return;
                    }
                }
            }
            ProtocolOp::AddRequest(req) => {
                let resp = handle_add(&mut *app.store.lock().await, app.fips.as_ref(), &req, &app.index_spec).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::AddResponse(resp));
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::DelRequest(req) => {
                let resp = handle_delete(&mut *app.store.lock().await, &req, &app.index_spec).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::DelResponse(resp));
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::ModifyRequest(req) => {
                let resp = handle_modify(&mut *app.store.lock().await, app.fips.as_ref(), &req, &app.index_spec).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::ModifyResponse(resp));
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::CompareRequest(req) => {
                let resp = handle_compare(&mut *app.store.lock().await, &req).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::CompareResponse(resp));
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
            // Not yet implemented (#4 tracks the rest of the scope), but
            // every one of these has a defined response -- a client must
            // not be left hanging waiting for one that never comes.
            ProtocolOp::ModDnRequest(_) => {
                let resp = LdapMessage::new(
                    message_id,
                    ProtocolOp::ModDnResponse(ModifyDnResponse(unwilling(
                        "modify-DN is not implemented yet",
                    ))),
                );
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
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
                if write_message(&mut stream, &resp).await.is_err() {
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
) -> AddResponse {
    let dn = match Dn::parse(&req.entry) {
        Ok(dn) => dn,
        Err(_) => return AddResponse(invalid_dn()),
    };
    let entry = match entry_from_attributes(&req.attributes, fips) {
        Ok(e) => e,
        Err(e) => return AddResponse(password_error_result(&e)),
    };

    let result = match store.put_entry(&dn, &entry, spec).await {
        Ok(()) => success(),
        Err(e) => operations_error(&e.to_string()),
    };
    AddResponse(result)
}

async fn handle_delete(store: &mut Store, req: &DelRequest, spec: &iron_store::index::IndexSpec) -> DelResponse {
    let dn = match Dn::parse(&req.0) {
        Ok(dn) => dn,
        Err(_) => return DelResponse(invalid_dn()),
    };
    let result = match store.delete_entry(&dn, spec).await {
        Ok(()) => success(),
        Err(e) => operations_error(&e.to_string()),
    };
    DelResponse(result)
}

async fn handle_modify(
    store: &mut Store,
    fips: Option<&iron_crypto::FipsContext>,
    req: &ModifyRequest,
    spec: &iron_store::index::IndexSpec,
) -> ModifyResponse {
    let dn = match Dn::parse(&req.object) {
        Ok(dn) => dn,
        Err(_) => return ModifyResponse(invalid_dn()),
    };
    let mut entry = match store.get_entry(&dn).await {
        Ok(Some(e)) => e,
        Ok(None) => return ModifyResponse(LdapResult::new(ResultCode::NoSuchObject, String::new().into(), "".into())),
        Err(e) => return ModifyResponse(operations_error(&e.to_string())),
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

    let result = match store.put_entry(&dn, &entry, spec).await {
        Ok(()) => success(),
        Err(e) => operations_error(&e.to_string()),
    };
    ModifyResponse(result)
}

async fn handle_compare(store: &mut Store, req: &CompareRequest) -> CompareResponse {
    let dn = match Dn::parse(&req.entry) {
        Ok(dn) => dn,
        Err(_) => return CompareResponse(invalid_dn()),
    };
    let entry = match store.get_entry(&dn).await {
        Ok(Some(e)) => e,
        Ok(None) => return CompareResponse(LdapResult::new(ResultCode::NoSuchObject, String::new().into(), "".into())),
        Err(e) => return CompareResponse(operations_error(&e.to_string())),
    };
    let want = String::from_utf8_lossy(&req.ava.assertion_value);
    let matched = entry
        .get(req.ava.attribute_desc.as_str())
        .is_some_and(|vals| vals.iter().any(|v| v.eq_ignore_ascii_case(&want)));
    let code = if matched { ResultCode::CompareTrue } else { ResultCode::CompareFalse };
    CompareResponse(LdapResult::new(code, String::new().into(), String::new().into()))
}

async fn handle_search(store: &mut Store, req: &SearchRequest) -> Vec<ProtocolOp> {
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
            Err(e) => return done(ResultCode::OperationsError, &e.to_string()),
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
                Err(e) => return done(ResultCode::OperationsError, &e.to_string()),
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
