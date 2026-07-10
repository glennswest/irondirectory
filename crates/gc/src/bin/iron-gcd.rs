//! iron-gcd: watch-fed Global Catalog aggregator daemon (#12), serving a
//! read-only, attribute-whitelisted partial replica of every domain
//! partition across one OR MORE forests over LDAP-shaped anonymous
//! bind + search. Deployable (rpm + systemd unit, see deploy/),
//! configured entirely via environment variables, matching
//! iron-ldapd's/iron-kdcd's convention.
//!
//! At least one forest must be configured, via either or both of:
//!   IRON_GC_CONFIG_FASTETCD_ENDPOINT   e.g. http://etcd.g8.lo:2379
//!   IRON_GC_CONFIG_PARTITION_ID        e.g. g10-config
//!   IRON_GC_CONFIG_BASE_DN             e.g. cn=configuration,dc=g10,dc=lo
//!   IRON_GC_FORESTS                    `;`-separated additional forests,
//!                                       each `endpoint|partition-id|base-dn`
//!                                       (`|`, not `=`, since a DN is
//!                                       itself full of `=` signs -- same
//!                                       convention as IRON_LDAP_REFERRALS)
//! Optional (defaults shown):
//!   IRON_GC_LISTEN=0.0.0.0:3268
//!   IRON_GC_HEALTH_LISTEN=0.0.0.0:8080
//!   IRON_GC_LDAPS_LISTEN=      (unset = no implicit-TLS port)
//!   IRON_GC_TLS_CERT=          (required with IRON_GC_LDAPS_LISTEN)
//!   IRON_GC_TLS_KEY=           (required with IRON_GC_LDAPS_LISTEN)
//!   IRON_GC_ATTRIBUTES=        (comma-separated attribute whitelist;
//!                               unset = iron_gc::aggregate::DEFAULT_ATTRIBUTES)
//!
//! Same engine, two deployment roles (#12/#13, D8/D9): point this daemon
//! at exactly one forest's config partition for that forest's own
//! internal Global Catalog (#12's original scope); point it at several
//! (via IRON_GC_FORESTS) for the D9 federated GAL, the thin,
//! centrally-operated cross-forest address book -- typically with a
//! stricter IRON_GC_ATTRIBUTES than a single forest's own GC would use,
//! since crossing a forest boundary is crossing a security boundary
//! (D9: "no directory-content leakage"). There is no separate
//! GAL-specific whitelist knob; it's the same `IRON_GC_ATTRIBUTES`,
//! just configured differently per deployment.
//!
//! Loads each configured forest's persisted `PartitionRegistry` (#9,
//! maintained by `iron-config-ctl`) once at startup, spawns one watch
//! task (`iron_gc::watch::run`) per `Domain`-kind partition found across
//! all of them, and serves search against the resulting single, shared,
//! live aggregate -- entries from every forest land in the same
//! `Aggregate`, indistinguishable to a search beyond their attributes
//! and DN. The topology itself (which partitions/forests exist) is a
//! startup snapshot -- a child domain, or a whole new forest, added
//! after this process starts needs a restart to be picked up, same
//! limitation as every other daemon's `AppState::topology` in this
//! codebase; the *data* within each already-known partition is
//! genuinely watch-fed, not a snapshot.
//!
//! Two independent forests choosing the same partition id would collide
//! when merged for rootDSE's `namingContexts` -- `PartitionRegistry::insert`
//! rejects the duplicate and this process refuses to start rather than
//! silently dropping one forest's naming contexts. Not a concern for the
//! happy path (independent organizations' domain names are naturally
//! globally distinct in practice), but worth failing loudly on rather
//! than silently mishandling.

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

/// One forest's config-partition bootstrap coordinates.
struct ForestSpec {
    endpoint: String,
    partition_id: String,
    base_dn: String,
}

/// Every configured forest: the classic single trio, if set, plus every
/// entry in `IRON_GC_FORESTS`, if set. Errors if neither yields any
/// forest at all -- this daemon has nothing to do without at least one.
fn forest_specs() -> anyhow::Result<Vec<ForestSpec>> {
    let mut specs = Vec::new();

    if let Some(endpoint) = env("IRON_GC_CONFIG_FASTETCD_ENDPOINT") {
        let partition_id = require_env("IRON_GC_CONFIG_PARTITION_ID")?;
        let base_dn = require_env("IRON_GC_CONFIG_BASE_DN")?;
        specs.push(ForestSpec { endpoint, partition_id, base_dn });
    }

    if let Some(raw) = env("IRON_GC_FORESTS") {
        for entry in raw.split(';').filter(|s| !s.trim().is_empty()) {
            let mut parts = entry.splitn(3, '|');
            let (Some(endpoint), Some(partition_id), Some(base_dn)) = (parts.next(), parts.next(), parts.next()) else {
                anyhow::bail!("malformed IRON_GC_FORESTS entry {entry:?}, expected endpoint|partition-id|base-dn");
            };
            specs.push(ForestSpec { endpoint: endpoint.trim().to_string(), partition_id: partition_id.trim().to_string(), base_dn: base_dn.trim().to_string() });
        }
    }

    if specs.is_empty() {
        anyhow::bail!(
            "no forest configured -- set IRON_GC_CONFIG_FASTETCD_ENDPOINT/_PARTITION_ID/_BASE_DN, IRON_GC_FORESTS, or both"
        );
    }
    Ok(specs)
}

/// Loads one forest's persisted `PartitionRegistry`, the same
/// bootstrap-then-load pattern `iron-ldapd`/`iron-kdcd` use for their
/// optional referral topology -- required here, not optional.
async fn load_forest(spec: &ForestSpec) -> anyhow::Result<PartitionRegistry> {
    let cluster = ClusterRef::plaintext([spec.endpoint.clone()]);
    let forest = ForestId::new(spec.partition_id.clone())?; // placeholder, overwritten by the loaded record
    let config_dn = Dn::parse(&spec.base_dn)?;
    let config_partition = Partition::configuration(spec.partition_id.clone(), forest, config_dn.clone(), cluster)?;
    let mut bootstrap_registry = PartitionRegistry::new();
    bootstrap_registry.insert(config_partition)?;
    let mut store = Store::connect(bootstrap_registry).await?;

    let registry = iron_config::load_registry(&mut store, &config_dn).await?;
    tracing::info!(partitions = registry.len(), endpoint = %spec.endpoint, "loaded forest topology");
    Ok(registry)
}

/// Loads every configured forest and merges them into one registry (for
/// rootDSE's `namingContexts`) -- see the module doc for the
/// duplicate-partition-id failure mode this can hit.
async fn load_topology() -> anyhow::Result<PartitionRegistry> {
    let specs = forest_specs()?;
    let mut merged = PartitionRegistry::new();
    for spec in &specs {
        let registry = load_forest(spec).await?;
        for partition in registry.iter() {
            merged.insert(partition.clone()).map_err(|e| {
                anyhow::anyhow!("{e} -- two configured forests produced the same partition id, refusing to start")
            })?;
        }
    }
    Ok(merged)
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
