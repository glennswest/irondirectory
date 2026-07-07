//! iron-ldap: LDAP v3 server over the iron-store DIT (#4).
//!
//! Implemented so far: rootDSE, anonymous simple bind, search (base/one/
//! subtree scope, core filter kinds), add, delete. Not yet: authenticated
//! bind (needs a real user/credential model), modify, compare, modify-DN,
//! extended ops, cross-NC referrals, AD-shaped schema, RFC 2307 posix
//! attrs, LDAPS/StartTLS.

pub mod filter;
pub mod framing;
pub mod rootdse;
pub mod session;

use std::sync::Arc;

use iron_store::index::IndexSpec;
use iron_store::store::Store;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Accepts connections on `listener` and serves each on its own task,
/// until the listener errors. `index_spec` names the attributes that get
/// a secondary index on `AddRequest`/write paths.
pub async fn serve(
    listener: TcpListener,
    store: Arc<Mutex<Store>>,
    index_spec: IndexSpec,
) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(%peer, "accepted LDAP connection");
        let store = store.clone();
        let index_spec = index_spec.clone();
        tokio::spawn(async move {
            session::handle_connection(stream, store, index_spec).await;
            tracing::info!(%peer, "LDAP connection closed");
        });
    }
}
