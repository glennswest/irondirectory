//! iron-ldapd: LDAP v3 daemon serving one partition's DIT over
//! plaintext/LDAPS, backed by fastetcd. Deployable (rpm + systemd unit,
//! see deploy/), configured entirely via environment variables so
//! systemd's EnvironmentFile= just works, matching fastetcd's own
//! convention.
//!
//! Not the eventual multi-service `crates/server` binary (which doesn't
//! exist yet and will wire up ldap+kdc+dns+oidc together) -- this is a
//! real, deployable single-service daemon for LDAP specifically.
//!
//! Required:
//!   IRON_LDAP_FASTETCD_ENDPOINT   e.g. http://etcd.g8.lo:2379
//!   IRON_LDAP_PARTITION_ID        e.g. g10
//!   IRON_LDAP_BASE_DN             e.g. dc=g10,dc=lo
//! Optional (defaults shown):
//!   IRON_LDAP_LISTEN=0.0.0.0:389
//!   IRON_LDAP_HEALTH_LISTEN=0.0.0.0:8080
//!   IRON_LDAP_LDAPS_LISTEN=       (unset = LDAPS disabled)
//!   IRON_LDAP_TLS_CERT=           (required if IRON_LDAP_LDAPS_LISTEN set)
//!   IRON_LDAP_TLS_KEY=            (required if IRON_LDAP_LDAPS_LISTEN set)

use std::sync::Arc;

use iron_partition::{ClusterRef, ForestId, Partition, PartitionRegistry};
use iron_store::index::IndexSpec;
use iron_store::store::Store;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn require_env(name: &str) -> anyhow::Result<String> {
    env(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let endpoint = require_env("IRON_LDAP_FASTETCD_ENDPOINT")?;
    let pid = require_env("IRON_LDAP_PARTITION_ID")?;
    let base_dn = require_env("IRON_LDAP_BASE_DN")?;
    let listen_addr = env("IRON_LDAP_LISTEN").unwrap_or_else(|| "0.0.0.0:389".to_string());
    let health_addr = env("IRON_LDAP_HEALTH_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".to_string());
    let ldaps_addr = env("IRON_LDAP_LDAPS_LISTEN");
    let tls_cert = env("IRON_LDAP_TLS_CERT");
    let tls_key = env("IRON_LDAP_TLS_KEY");

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?;
    let partition = Partition::domain(pid, forest, iron_partition::Dn::parse(&base_dn)?, cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;

    let store = Arc::new(Mutex::new(Store::connect(registry).await?));
    let index_spec = IndexSpec::new(["cn", "mail", "uid"]);

    let mut tasks = Vec::new();

    let health_listener = TcpListener::bind(&health_addr).await?;
    tracing::info!(%health_addr, "iron-ldapd listening (health)");
    tasks.push(tokio::spawn(iron_ldap::health::serve(health_listener, store.clone())));

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(%listen_addr, "iron-ldapd listening (plaintext)");
    tasks.push(tokio::spawn(iron_ldap::serve(listener, store.clone(), index_spec.clone())));

    if let Some(ldaps_addr) = ldaps_addr {
        let cert = tls_cert.ok_or_else(|| anyhow::anyhow!("IRON_LDAP_TLS_CERT is required when IRON_LDAP_LDAPS_LISTEN is set"))?;
        let key = tls_key.ok_or_else(|| anyhow::anyhow!("IRON_LDAP_TLS_KEY is required when IRON_LDAP_LDAPS_LISTEN is set"))?;
        let acceptor = Arc::new(iron_ldap::tls::build_acceptor(
            std::path::Path::new(&cert),
            std::path::Path::new(&key),
        )?);
        let ldaps_listener = TcpListener::bind(&ldaps_addr).await?;
        tracing::info!(%ldaps_addr, "iron-ldapd listening (LDAPS)");
        tasks.push(tokio::spawn(iron_ldap::serve_ldaps(
            ldaps_listener,
            acceptor,
            store.clone(),
            index_spec.clone(),
        )));
    }

    // These are infinite accept loops; join_all waits for all of them
    // concurrently (not a sequential for-loop, which would block forever
    // on the first one) and returns only once one of them exits (i.e.
    // errors).
    for result in futures::future::join_all(tasks).await {
        result??;
    }
    Ok(())
}
