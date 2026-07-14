//! iron-ldap: LDAP v3 server over the iron-store DIT (#4).
//!
//! Implemented: rootDSE, anonymous + authenticated simple bind (PBKDF2
//! via `iron-crypto`, D4), search (base/one/subtree scope, core filter
//! kinds), add, delete, modify, compare, modify-DN (leaf entries only),
//! StartTLS, LDAPS, cross-NC referrals (`AppState::topology`, the
//! persisted forest registry from #9, falling back to the static
//! `AppState::referrals` list; chased one hop end-to-end, #10), built-in
//! AD-shaped + RFC 2307 posix schema validation (`schema` module) on
//! add/modify, the RFC 4532 WhoAmI extended operation (reports the
//! connection's current bind identity -- `dn:...` for simple bind,
//! `u:<principal>` for GSSAPI, empty for anonymous), and SID/RID
//! allocation + a default `nTSecurityDescriptor` auto-stamped onto
//! newly-added `user`/`computer`/`group` entries when their partition
//! has a provisioned domain SID (`security` module, #17). Not yet:
//! subtree rename, other extended ops, full schema-subentry publishing
//! (`cn=subschema`), ACE-based authorization enforcement (the
//! descriptor is stored, not yet evaluated to gate anything).

pub mod conn;
pub mod filter;
pub mod framing;
pub mod gssapi;
pub mod health;
pub mod rootdse;
pub mod schema;
pub mod security;
pub mod session;
pub mod tls;

use std::pin::Pin;
use std::sync::Arc;

use iron_crypto::FipsContext;
use iron_partition::{Dn, PartitionRegistry};
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
    /// resolves to `StoreError::NoPartitionFor` (see `session::referral_for`),
    /// as a fallback when `topology` is unset or doesn't have a match --
    /// kept for deployments with no configuration partition set up (#9)
    /// yet, e.g. the standalone il1/il2/il3 replicas.
    pub referrals: Vec<(Dn, String)>,
    /// The forest-wide partition topology (#9/#10), loaded once at
    /// startup from the persisted configuration partition if
    /// `IRON_LDAP_CONFIG_*` env vars are set -- a real, authoritative
    /// view of every partition and its `ldap_url`, not a hand-maintained
    /// list. Consulted before `referrals` when generating a referral, so
    /// sibling/child/parent partitions created via `iron-config-ctl` are
    /// referred to automatically. `None` if no configuration partition
    /// is configured (falls back to `referrals` alone). A snapshot, not
    /// watched -- refreshing it if the topology changes while this
    /// process is running is a later issue, not #10's happy-path scope.
    pub topology: Option<PartitionRegistry>,
    /// This instance's own partition id, needed to tell "topology says
    /// this DN is mine" apart from "topology says it belongs to someone
    /// else" -- a child domain's base DN is *structurally* a descendant
    /// of its parent's, so the parent's own single-partition `Store`
    /// would otherwise "successfully" resolve a child DN (finding no
    /// entry, not a `StoreError`) rather than ever reaching the
    /// `NoPartitionFor` path `session::referral_for` checks. See
    /// `session::proactive_referral`, checked before any local lookup.
    pub own_partition_id: Option<iron_partition::PartitionId>,
}

impl AppState {
    pub fn new(
        store: Store,
        index_spec: IndexSpec,
        tls_acceptor: Option<Arc<SslAcceptor>>,
        referrals: Vec<(Dn, String)>,
        topology: Option<PartitionRegistry>,
        own_partition_id: Option<iron_partition::PartitionId>,
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
            topology,
            own_partition_id,
        })
    }

    /// Bundles this instance's referral sources for a single request
    /// (see `session::Referrals`) -- cheap, just borrows.
    pub fn referral_config(&self) -> session::Referrals<'_> {
        session::Referrals {
            topology: self.topology.as_ref(),
            static_list: &self.referrals,
            own_partition_id: self.own_partition_id.as_ref(),
        }
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
