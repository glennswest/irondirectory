//! Per-connection LDAP session: reads framed `LdapMessage`s and dispatches
//! bind/search (the operations implemented so far -- see crate docs).

use std::sync::Arc;

use iron_partition::Dn;
use iron_store::index::IndexSpec;
use iron_store::model::Entry;
use iron_store::store::Store;
use rasn::types::SetOf;
use rasn_ldap::{
    AddRequest, AddResponse, AuthenticationChoice, BindRequest, BindResponse, CompareResponse,
    DelRequest, DelResponse, ExtendedResponse, LdapMessage, LdapResult, ModifyDnResponse,
    ModifyResponse, PartialAttribute, ProtocolOp, ResultCode, SearchRequest, SearchRequestScope,
    SearchResultDone, SearchResultEntry,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::framing::{read_message, write_message};
use crate::{filter, rootdse};

/// Handles one LDAP client connection until it unbinds, disconnects, or a
/// framing error occurs.
pub async fn handle_connection<S>(mut stream: S, store: Arc<Mutex<Store>>, index_spec: IndexSpec)
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
                let resp = LdapMessage::new(message_id, ProtocolOp::BindResponse(handle_bind(&req)));
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::SearchRequest(req) => {
                let mut store = store.lock().await;
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
                let resp = handle_add(&mut *store.lock().await, &req, &index_spec).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::AddResponse(resp));
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::DelRequest(req) => {
                let resp = handle_delete(&mut *store.lock().await, &req, &index_spec).await;
                let resp = LdapMessage::new(message_id, ProtocolOp::DelResponse(resp));
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
            // Not yet implemented (#4 tracks the rest of the scope), but
            // every one of these has a defined response -- a client must
            // not be left hanging waiting for one that never comes.
            ProtocolOp::ModifyRequest(_) => {
                let resp = LdapMessage::new(
                    message_id,
                    ProtocolOp::ModifyResponse(ModifyResponse(unwilling("modify is not implemented yet"))),
                );
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::CompareRequest(_) => {
                let resp = LdapMessage::new(
                    message_id,
                    ProtocolOp::CompareResponse(CompareResponse(unwilling(
                        "compare is not implemented yet",
                    ))),
                );
                if write_message(&mut stream, &resp).await.is_err() {
                    return;
                }
            }
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

fn handle_bind(req: &BindRequest) -> BindResponse {
    let (code, diagnostic) = if req.version != 3 {
        (ResultCode::ProtocolError, "only LDAPv3 is supported")
    } else {
        match &req.authentication {
            AuthenticationChoice::Simple(password) if req.name.is_empty() && password.is_empty() => {
                (ResultCode::Success, "")
            }
            AuthenticationChoice::Simple(_) => (
                ResultCode::InvalidCredentials,
                "authenticated simple bind is not implemented yet",
            ),
            AuthenticationChoice::Sasl(_) => (
                ResultCode::AuthMethodNotSupported,
                "SASL bind is not implemented yet",
            ),
            _ => (ResultCode::AuthMethodNotSupported, "unrecognized authentication choice"),
        }
    };
    BindResponse::new(code, String::new().into(), diagnostic.into(), None, None)
}

fn done(code: ResultCode, diagnostic: &str) -> Vec<ProtocolOp> {
    vec![ProtocolOp::SearchResDone(SearchResultDone(LdapResult::new(
        code,
        String::new().into(),
        diagnostic.into(),
    )))]
}

async fn handle_add(store: &mut Store, req: &AddRequest, spec: &IndexSpec) -> AddResponse {
    let dn = match Dn::parse(&req.entry) {
        Ok(dn) => dn,
        Err(_) => {
            return AddResponse(LdapResult::new(
                ResultCode::InvalidDnSyntax,
                String::new().into(),
                "invalid DN".into(),
            ))
        }
    };

    let mut entry = Entry::new();
    for a in &req.attributes {
        let values: Vec<String> = a
            .vals
            .to_vec()
            .into_iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect();
        entry.set(a.r#type.as_str(), values);
    }

    let result = match store.put_entry(&dn, &entry, spec).await {
        Ok(()) => LdapResult::new(ResultCode::Success, String::new().into(), String::new().into()),
        Err(e) => LdapResult::new(ResultCode::OperationsError, String::new().into(), e.to_string().into()),
    };
    AddResponse(result)
}

async fn handle_delete(store: &mut Store, req: &DelRequest, spec: &IndexSpec) -> DelResponse {
    let dn = match Dn::parse(&req.0) {
        Ok(dn) => dn,
        Err(_) => {
            return DelResponse(LdapResult::new(
                ResultCode::InvalidDnSyntax,
                String::new().into(),
                "invalid DN".into(),
            ))
        }
    };
    let result = match store.delete_entry(&dn, spec).await {
        Ok(()) => LdapResult::new(ResultCode::Success, String::new().into(), String::new().into()),
        Err(e) => LdapResult::new(ResultCode::OperationsError, String::new().into(), e.to_string().into()),
    };
    DelResponse(result)
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
    entry
        .attr_names()
        .filter(|name| want_all || requested.iter().any(|a| a.eq_ignore_ascii_case(name)))
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
