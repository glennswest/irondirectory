//! iron-gc: watch-fed Global Catalog / federated GAL aggregator
//! (#12/#13), ports 3268/3269.
//!
//! Subscribes to every `Domain`-kind partition across one or more
//! forests' `PartitionRegistry` (the same #9-persisted registry
//! `iron-ldapd`/`iron-kdcd` load a one-time snapshot of), maintaining a
//! live, continuously-updated, attribute-whitelisted partial replica
//! (`aggregate::Aggregate`) in memory -- and serves anonymous bind +
//! read-only search against it over a small LDAP-shaped protocol
//! surface reusing `iron_ldap`'s wire framing, filter matching, and
//! rootDSE builder. The library here is deliberately forest-agnostic --
//! `watch::run` takes a single `Partition` and doesn't care which forest
//! it came from -- so the SAME engine serves two deployment roles
//! (`iron-gcd`'s doc comment has the operational details): a single
//! forest's own internal Global Catalog (#12), or the D9 federated GAL
//! aggregating several forests behind a stricter attribute whitelist
//! (#13). Multi-forest bootstrap (loading N config partitions instead
//! of one) and merging their registries lives entirely in the binary,
//! not here.
//!
//! Happy-path scope (D10): the topology itself (which partitions/forests
//! exist) is a startup snapshot, not watched -- a new child domain, or a
//! whole new forest, added after a process starts requires a restart to
//! pick up, matching every other daemon's `AppState::topology`
//! limitation in this codebase. Multi-thousand-partition/many-forest
//! scale and staleness-bound proving are explicitly deferred (D10), not
//! this crate's scope.

pub mod aggregate;
pub mod session;
pub mod watch;

use std::sync::Arc;

use iron_partition::PartitionRegistry;
use openssl::ssl::{Ssl, SslAcceptor};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use aggregate::Aggregate;

/// Shared server state handed to every connection and every watcher task.
pub struct AppState {
    pub aggregate: Arc<Aggregate>,
    /// The forest's partition registry, kept around only for
    /// `rootDSE`'s `namingContexts` -- actual data lookups go through
    /// `aggregate`, never through this registry's clusters directly.
    pub registry: PartitionRegistry,
    /// How many domain partitions this process spawned a watcher for --
    /// the denominator the health check compares `aggregate.ready_count()`
    /// against.
    pub expected_partitions: usize,
}

/// Accepts plaintext connections on `listener`, serving each on its own
/// task, until the listener errors.
pub async fn serve(listener: TcpListener, app: Arc<AppState>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(%peer, "accepted GC connection");
        let app = app.clone();
        tokio::spawn(async move {
            session::handle_connection(stream, app).await;
            tracing::info!(%peer, "GC connection closed");
        });
    }
}

/// Accepts LDAPS (implicit TLS) connections on `listener`, terminating
/// TLS via `acceptor` before handing the stream to the same session
/// handler `serve` uses.
pub async fn serve_ldaps(listener: TcpListener, acceptor: Arc<SslAcceptor>, app: Arc<AppState>) -> std::io::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        tracing::info!(%peer, "accepted GC LDAPS connection");
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
            if let Err(e) = std::pin::Pin::new(&mut stream).accept().await {
                tracing::warn!(%peer, "TLS handshake failed: {e}");
                return;
            }
            session::handle_connection(stream, app).await;
            tracing::info!(%peer, "GC LDAPS connection closed");
        });
    }
}

/// HTTP `/health` for LB probes -- a real bootstrap-completeness check
/// (every expected partition's initial watch load has finished, per
/// `Aggregate::ready_count`) rather than just accepting the TCP
/// connection, mirroring `iron_ldap::health`'s reasoning. Deliberately
/// NOT `aggregate.len() > 0` -- a genuinely empty domain partition is a
/// valid, fully-loaded state, not an unready one.
pub mod health {
    use super::*;

    pub async fn serve(listener: TcpListener, app: Arc<AppState>) -> std::io::Result<()> {
        loop {
            let (mut stream, _peer) = listener.accept().await?;
            let app = app.clone();
            tokio::spawn(async move {
                let ready = app.aggregate.ready_count();
                let ok = ready >= app.expected_partitions;
                let body = format!(
                    "{{\"health\":{ok},\"ready_partitions\":{ready},\"expected_partitions\":{},\"entries\":{}}}",
                    app.expected_partitions,
                    app.aggregate.len()
                );
                let status = if ok { "200 OK" } else { "503 Service Unavailable" };
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}
