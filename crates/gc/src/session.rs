//! Minimal read-only connection handler for the Global Catalog listener
//! (#12): anonymous bind + search only, against the shared in-memory
//! [`crate::aggregate::Aggregate`] rather than a live `Store` -- there is
//! no add/delete/modify/compare/modify-DN surface here. The GC is fed
//! exclusively by watch streams (`crate::watch`), never written to
//! directly by a client.
//!
//! Simplifications, documented rather than silently absent: no
//! StartTLS (the plaintext/implicit-TLS port split, 3268/3269, already
//! covers the same need iron-ldap's StartTLS does, matching real AD's
//! GC convention); any request other than Bind/Search/Unbind is logged
//! and ignored rather than answered with a correctly-typed error
//! response for every possible `ProtocolOp` variant -- disproportionate
//! effort for a port well-behaved clients only ever Bind+Search against.

use std::sync::Arc;

use iron_partition::Dn;
use iron_store::model::Entry;
use rasn::types::SetOf;
use rasn_ldap::{
    AuthenticationChoice, BindRequest, BindResponse, LdapMessage, LdapResult, PartialAttribute, ProtocolOp,
    ResultCode, SearchRequest, SearchRequestScope, SearchResultDone, SearchResultEntry,
};
use tokio::io::{AsyncRead, AsyncWrite};

use iron_ldap::conn::Conn;
use iron_ldap::filter;
use iron_ldap::framing::{read_message, write_message};

use crate::AppState;

pub async fn handle_connection<S>(stream: S, app: Arc<AppState>)
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
                let resp = handle_bind(&req);
                let resp = LdapMessage::new(message_id, ProtocolOp::BindResponse(resp));
                if write_message(&mut conn, &resp).await.is_err() {
                    return;
                }
            }
            ProtocolOp::SearchRequest(req) => {
                let ops = handle_search(&app, &req);
                for op in ops {
                    let resp = LdapMessage::new(message_id, op);
                    if write_message(&mut conn, &resp).await.is_err() {
                        return;
                    }
                }
            }
            other => {
                tracing::debug!(?other, "ignoring unsupported operation on the read-only GC listener");
            }
        }
    }
}

fn handle_bind(req: &BindRequest) -> BindResponse {
    if req.version != 3 {
        return BindResponse::new(ResultCode::ProtocolError, String::new().into(), "only LDAPv3 is supported".into(), None, None);
    }
    match &req.authentication {
        AuthenticationChoice::Simple(password) if req.name.is_empty() && password.is_empty() => {
            BindResponse::new(ResultCode::Success, String::new().into(), String::new().into(), None, None)
        }
        _ => BindResponse::new(
            ResultCode::AuthMethodNotSupported,
            String::new().into(),
            "the Global Catalog listener only supports anonymous bind (#12's happy-path scope)".into(),
            None,
            None,
        ),
    }
}

fn done(code: ResultCode, msg: &str) -> Vec<ProtocolOp> {
    vec![ProtocolOp::SearchResDone(SearchResultDone(LdapResult::new(code, String::new().into(), msg.into())))]
}

fn handle_search(app: &AppState, req: &SearchRequest) -> Vec<ProtocolOp> {
    let base_dn = match Dn::parse(&req.base_object) {
        Ok(dn) => dn,
        Err(_) => return done(ResultCode::InvalidDnSyntax, "invalid base DN"),
    };

    if base_dn.is_empty() && req.scope == SearchRequestScope::BaseObject {
        let entry_op = ProtocolOp::SearchResEntry(iron_ldap::rootdse::build(&app.registry));
        let mut ops = vec![entry_op];
        ops.extend(done(ResultCode::Success, ""));
        return ops;
    }

    let candidates: Vec<(Dn, Entry)> = match req.scope {
        SearchRequestScope::BaseObject => match app.aggregate.get(&base_dn) {
            Some(e) => vec![(base_dn.clone(), e)],
            None => return done(ResultCode::NoSuchObject, ""),
        },
        SearchRequestScope::SingleLevel | SearchRequestScope::WholeSubtree => {
            let child_depth = base_dn.depth() + 1;
            app.aggregate
                .snapshot()
                .into_iter()
                .filter(|(dn, _)| dn.is_within(&base_dn))
                .filter(|(dn, _)| req.scope != SearchRequestScope::SingleLevel || dn.depth() == child_depth)
                .collect()
        }
        _ => return done(ResultCode::ProtocolError, "unrecognized search scope"),
    };

    let mut ops = Vec::new();
    let limit = if req.size_limit == 0 { usize::MAX } else { req.size_limit as usize };
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

/// Projects `entry`'s attributes for the wire response, honoring the
/// client's requested attribute list. No `userPassword`-style carve-out
/// is needed here (unlike `iron_ldap::session`'s version): the
/// aggregate never holds it at all, since `crate::aggregate::project`
/// already dropped anything outside the ingest-time whitelist before
/// this entry ever entered the replica.
fn project_attributes(entry: &Entry, requested: &[rasn_ldap::LdapString], types_only: bool) -> Vec<PartialAttribute> {
    let want_all = requested.is_empty() || requested.iter().any(|a| a.as_str() == "*");
    entry
        .attr_names()
        .filter(|name| want_all || requested.iter().any(|a| a.eq_ignore_ascii_case(name)))
        .map(|name| {
            let values: Vec<Vec<u8>> = if types_only {
                Vec::new()
            } else {
                entry.get(name).map(|vs| vs.iter().map(|v| v.clone().into_bytes()).collect()).unwrap_or_default()
            };
            PartialAttribute::new(name.into(), SetOf::from_vec(values.into_iter().map(Into::into).collect()))
        })
        .collect()
}
