//! iron-ldap: LDAP v3 server over the iron-store DIT (#4).
//!
//! Implemented: rootDSE, anonymous + authenticated simple bind (PBKDF2
//! via `iron-crypto`, D4), search (base/one/subtree scope, core filter
//! kinds), add, delete, modify, compare, modify-DN (leaf entries only),
//! StartTLS, LDAPS, cross-NC referrals (`AppState::referrals`), and
//! built-in AD-shaped + RFC 2307 posix schema validation (`schema`
//! module) on add/modify. Not yet: subtree rename, extended ops besides
//! StartTLS, full schema-subentry publishing (`cn=subschema`).

pub mod conn;
pub mod filter;
pub mod framing;
pub mod gssapi;
pub mod health;
pub mod rootdse;
pub mod schema;
pub mod session;
pub mod tls;

use std::pin::Pin;
use std::sync::Arc;

use iron_crypto::FipsContext;
use iron_partition::Dn;
use iron_store::index::IndexSpec;
use iron_store::store::Store;
use openssl::ssl::{Ssl, SslAcceptor};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Shared server state handed to every connection.
pub struct AppState {
    pub store: Mutex<Store>,
    pub index_spec: IndexSpec,
    /// FIPS crypto context for password hashing/verification (D4). `None`
    /// if the FIPS provider isn't active on this host -- authenticated
    /// bind and password-setting then fail closed (see `session::handle_bind`)
    /// rather than falling back to storing/checking plaintext.
    pub fips: Option<FipsContext>,
    /// TLS acceptor for StartTLS on the plaintext listener. `None` if no
    /// TLS cert/key is configured at all (StartTLS then reports
    /// `ProtocolError` rather than attempting a handshake). The same
    /// acceptor `serve_ldaps` uses for implicit TLS, if that's enabled too.
    pub tls_acceptor: Option<Arc<SslAcceptor>>,
    /// Naming contexts not hosted by this `Store` (its `PartitionRegistry`
    /// only knows about locally-connected partitions today -- there's no
    /// "referral-only, no cluster" partition kind yet), paired with the
    /// LDAP URL to send clients to instead. Checked whenever an operation
    /// resolves to `StoreError::NoPartitionFor` (see `session::referral_for`).
    pub referrals: Vec<(Dn, String)>,
}

impl AppState {
    pub fn new(
        store: Store,
        index_spec: IndexSpec,
        tls_acceptor: Option<Arc<SslAcceptor>>,
        referrals: Vec<(Dn, String)>,
    ) -> Arc<Self> {
        let fips = match FipsContext::new() {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::warn!(
                    "FIPS provider not active ({e}) -- authenticated bind and \
                     password-setting are disabled until it is; anonymous \
                     bind, search, add, delete, modify, compare still work"
                );
                None
            }
        };
        Arc::new(AppState {
            store: Mutex::new(store),
            index_spec,
            fips,
            tls_acceptor,
            referrals,
        })
    }
}

/// Accepts plaintext connections on `listener` and serves each on its own
/// task, until the listener errors. StartTLS is available on these
/// connections whenever `app.tls_acceptor` is set.
pub async fn serve(listener: TcpListener, app: Arc<AppState>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(%peer, "accepted LDAP connection");
        let app = app.clone();
        let tls_acceptor = app.tls_acceptor.clone();
        tokio::spawn(async move {
            session::handle_connection(stream, app, tls_acceptor).await;
            tracing::info!(%peer, "LDAP connection closed");
        });
    }
}

/// Accepts LDAPS (implicit TLS) connections on `listener`, terminating
/// TLS via `acceptor` (see [`tls::build_acceptor`]) before handing the
/// stream to the same session handler `serve` uses. StartTLS is not
/// offered on these connections (`None`) -- meaningless over a
/// connection that's already TLS from the first byte.
pub async fn serve_ldaps(
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
    app: Arc<AppState>,
) -> std::io::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        tracing::info!(%peer, "accepted LDAPS connection");
        let app = app.clone();
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
            session::handle_connection(stream, app, None).await;
            tracing::info!(%peer, "LDAPS connection closed");
        });
    }
}
