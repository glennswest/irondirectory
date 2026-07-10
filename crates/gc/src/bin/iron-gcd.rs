//! iron-gcd: watch-fed Global Catalog aggregator daemon (#12), serving a
//! read-only, attribute-whitelisted partial replica of every domain
//! partition in a forest over LDAP-shaped anonymous bind + search.
//! Deployable (rpm + systemd unit, see deploy/), configured entirely via
//! environment variables, matching iron-ldapd's/iron-kdcd's convention.
//!
//! Required (unlike iron-ldapd/iron-kdcd, where the equivalent
//! `*_CONFIG_*` trio is optional -- iron-gcd's entire purpose is
//! watching the forest topology, so it cannot run without it):
//!   IRON_GC_CONFIG_FASTETCD_ENDPOINT   e.g. http://etcd.g8.lo:2379
//!   IRON_GC_CONFIG_PARTITION_ID        e.g. g10-config
//!   IRON_GC_CONFIG_BASE_DN             e.g. cn=configuration,dc=g10,dc=lo
//! Optional (defaults shown):
//!   IRON_GC_LISTEN=0.0.0.0:3268
//!   IRON_GC_HEALTH_LISTEN=0.0.0.0:8080
//!   IRON_GC_LDAPS_LISTEN=      (unset = no implicit-TLS port)
//!   IRON_GC_TLS_CERT=          (required with IRON_GC_LDAPS_LISTEN)
//!   IRON_GC_TLS_KEY=           (required with IRON_GC_LDAPS_LISTEN)
//!   IRON_GC_ATTRIBUTES=        (comma-separated attribute whitelist;
//!                               unset = iron_gc::aggregate::DEFAULT_ATTRIBUTES)
//!
//! Loads the forest's persisted `PartitionRegistry` (#9, maintained by
//! `iron-config-ctl`) once at startup, spawns one watch task
//! (`iron_gc::watch::run`) per `Domain`-kind partition found, and serves
//! search against the resulting live aggregate. The topology itself
//! (which partitions exist) is a startup snapshot -- a child domain
//! added after this process starts needs a restart to be picked up,
//! same limitation as every other daemon's `AppState::topology` in this
//! codebase; the *data* within each already-known partition is
//! genuinely watch-fed, not a snapshot.

use std::sync::Arc;

use iron_partition::{ClusterRef, Dn, ForestId, Partition, PartitionKind, PartitionRegistry};
use iron_store::store::Store;
use tokio::net::TcpListener;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn require_env(name: &str) -> anyhow::Result<String> {
    env(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

/// Loads the forest's persisted `PartitionRegistry`, the same
/// bootstrap-then-load pattern `iron-ldapd`/`iron-kdcd` use for their
/// optional referral topology -- required here, not optional.
async fn load_topology() -> anyhow::Result<PartitionRegistry> {
    let endpoint = require_env("IRON_GC_CONFIG_FASTETCD_ENDPOINT")?;
    let pid = require_env("IRON_GC_CONFIG_PARTITION_ID")?;
    let base_dn = require_env("IRON_GC_CONFIG_BASE_DN")?;

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?; // placeholder, overwritten by the loaded record
    let config_dn = Dn::parse(&base_dn)?;
    let config_partition = Partition::configuration(pid, forest, config_dn.clone(), cluster)?;
    let mut bootstrap_registry = PartitionRegistry::new();
    bootstrap_registry.insert(config_partition)?;
    let mut store = Store::connect(bootstrap_registry).await?;

    let registry = iron_config::load_registry(&mut store, &config_dn).await?;
    tracing::info!(partitions = registry.len(), "loaded forest topology");
    Ok(registry)
}

fn attribute_whitelist() -> Vec<String> {
    match env("IRON_GC_ATTRIBUTES") {
        Some(raw) => raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        None => iron_gc::aggregate::DEFAULT_ATTRIBUTES.iter().map(|s| s.to_string()).collect(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let listen_addr = env("IRON_GC_LISTEN").unwrap_or_else(|| "0.0.0.0:3268".to_string());
    let health_addr = env("IRON_GC_HEALTH_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".to_string());
    let ldaps_addr = env("IRON_GC_LDAPS_LISTEN");
    let tls_cert = env("IRON_GC_TLS_CERT");
    let tls_key = env("IRON_GC_TLS_KEY");

    let registry = load_topology().await?;
    let domain_partitions: Vec<Partition> = registry.iter().filter(|p| p.kind == PartitionKind::Domain).cloned().collect();
    if domain_partitions.is_empty() {
        tracing::warn!("forest topology has no domain partitions -- nothing to watch");
    }

    let aggregate = Arc::new(iron_gc::aggregate::Aggregate::new());
    let whitelist = Arc::new(attribute_whitelist());
    for partition in &domain_partitions {
        let aggregate = aggregate.clone();
        let whitelist = whitelist.clone();
        let partition = partition.clone();
        tokio::spawn(async move {
            iron_gc::watch::run(partition, aggregate, whitelist).await;
        });
    }

    let app = Arc::new(iron_gc::AppState { aggregate, registry, expected_partitions: domain_partitions.len() });

    let mut tasks = Vec::new();

    let health_listener = TcpListener::bind(&health_addr).await?;
    tracing::info!(%health_addr, "iron-gcd listening (health)");
    tasks.push(tokio::spawn(iron_gc::health::serve(health_listener, app.clone())));

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(%listen_addr, "iron-gcd listening (plaintext GC)");
    tasks.push(tokio::spawn(iron_gc::serve(listener, app.clone())));

    if let Some(ldaps_addr) = ldaps_addr {
        let (Some(cert), Some(key)) = (&tls_cert, &tls_key) else {
            anyhow::bail!("IRON_GC_TLS_CERT and IRON_GC_TLS_KEY are required when IRON_GC_LDAPS_LISTEN is set");
        };
        let acceptor = Arc::new(iron_ldap::tls::build_acceptor(std::path::Path::new(cert), std::path::Path::new(key))?);
        let ldaps_listener = TcpListener::bind(&ldaps_addr).await?;
        tracing::info!(%ldaps_addr, "iron-gcd listening (GC LDAPS)");
        tasks.push(tokio::spawn(iron_gc::serve_ldaps(ldaps_listener, acceptor, app.clone())));
    }

    for result in futures::future::join_all(tasks).await {
        result??;
    }
    Ok(())
}
