//! iron-ldap: LDAP v3 server over the iron-store DIT (#4).
//!
//! Implemented so far: rootDSE, anonymous simple bind, search (base/one/
//! subtree scope, core filter kinds), add, delete, LDAPS. Not yet:
//! authenticated bind (needs a real user/credential model), modify,
//! compare, modify-DN, extended ops, StartTLS, cross-NC referrals,
//! AD-shaped schema, RFC 2307 posix attrs.

pub mod filter;
pub mod framing;
pub mod rootdse;
pub mod session;
pub mod tls;

use std::pin::Pin;
use std::sync::Arc;

use iron_store::index::IndexSpec;
use iron_store::store::Store;
use openssl::ssl::{Ssl, SslAcceptor};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Accepts plaintext connections on `listener` and serves each on its own
/// task, until the listener errors. `index_spec` names the attributes
/// that get a secondary index on `AddRequest`/write paths.
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

/// Accepts LDAPS (implicit TLS) connections on `listener`, terminating
/// TLS via `acceptor` (see [`tls::build_acceptor`]) before handing the
/// stream to the same session handler `serve` uses.
pub async fn serve_ldaps(
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
    store: Arc<Mutex<Store>>,
    index_spec: IndexSpec,
) -> std::io::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        tracing::info!(%peer, "accepted LDAPS connection");
        let store = store.clone();
        let index_spec = index_spec.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let ssl = match Ssl::new(acceptor.context()) {
                Ok(ssl) => ssl,
                Err(e) => {
                    tracing::warn!(%peer, "failed to create SSL session: {e}");
                    return;
                }
            };
            let mut stream = match tokio_openssl::SslStream::new(ssl, tcp) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(%peer, "failed to wrap TCP stream: {e}");
                    return;
                }
            };
            if let Err(e) = Pin::new(&mut stream).accept().await {
                tracing::warn!(%peer, "TLS handshake failed: {e}");
                return;
            }
            session::handle_connection(stream, store, index_spec).await;
            tracing::info!(%peer, "LDAPS connection closed");
        });
    }
}
