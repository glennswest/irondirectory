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
//!   IRON_LDAP_LDAPS_LISTEN=       (unset = no dedicated implicit-TLS port)
//!   IRON_LDAP_TLS_CERT=           (must be set with IRON_LDAP_TLS_KEY)
//!   IRON_LDAP_TLS_KEY=            (must be set with IRON_LDAP_TLS_CERT)
//!
//! Setting IRON_LDAP_TLS_CERT/_KEY alone (without IRON_LDAP_LDAPS_LISTEN)
//! enables StartTLS on the plaintext listener without opening a second
//! port; setting IRON_LDAP_LDAPS_LISTEN too additionally opens a
//! dedicated implicit-TLS (ldaps://) port using the same cert/key.
//!
//!   IRON_LDAP_REFERRALS=          (unset = no referrals)
//!
//! Naming contexts this instance doesn't host, for cross-NC referrals
//! (RFC 4511 §4.1.10): `;`-separated `base-dn|ldap-url` pairs (`|`, not
//! `=`, since a DN is itself full of `=` signs), e.g.
//! `dc=g11,dc=lo|ldap://ldap.g11.lo;dc=other,dc=lo|ldap://other.example.com`.
//! An operation whose target DN falls at or below one of these base DNs
//! gets a `Referral` result pointing at the paired URL instead of
//! `NoSuchObject`/`OperationsError`.
//!
//! Authenticated simple bind (D4: PBKDF2 via the OpenSSL FIPS provider)
//! needs OPENSSL_CONF pointing at a config that activates fips.so (see
//! docs/FIPS.md) -- without it, iron-ldapd still starts and serves
//! anonymous bind/search/add/delete/modify/compare, just logs a warning
//! and fails authenticated bind/password-setting closed.

use std::sync::Arc;

use iron_ldap::AppState;
use iron_partition::{ClusterRef, ForestId, Partition, PartitionRegistry};
use iron_store::index::IndexSpec;
use iron_store::store::Store;
use tokio::net::TcpListener;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn require_env(name: &str) -> anyhow::Result<String> {
    env(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

fn parse_referrals(raw: &str) -> anyhow::Result<Vec<(iron_partition::Dn, String)>> {
    raw.split(';')
        .filter(|s| !s.trim().is_empty())
        .map(|pair| {
            let (base_dn, url) = pair
                .split_once('|')
                .ok_or_else(|| anyhow::anyhow!("malformed IRON_LDAP_REFERRALS entry {pair:?}, expected base-dn|url"))?;
            Ok((iron_partition::Dn::parse(base_dn.trim())?, url.trim().to_string()))
        })
        .collect()
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
    let referrals = match env("IRON_LDAP_REFERRALS") {
        Some(raw) => parse_referrals(&raw)?,
        None => Vec::new(),
    };

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?;
    let partition = Partition::domain(pid, forest, iron_partition::Dn::parse(&base_dn)?, cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;

    let store = Store::connect(registry).await?;
    let index_spec = IndexSpec::new(["cn", "mail", "uid"]);

    // Built whenever cert/key are configured, independent of whether a
    // dedicated LDAPS port is also enabled -- this is what makes StartTLS
    // available on the plaintext listener even without IRON_LDAP_LDAPS_LISTEN.
    let tls_acceptor = match (&tls_cert, &tls_key) {
        (Some(cert), Some(key)) => Some(Arc::new(iron_ldap::tls::build_acceptor(
            std::path::Path::new(cert),
            std::path::Path::new(key),
        )?)),
        (None, None) => None,
        _ => anyhow::bail!("IRON_LDAP_TLS_CERT and IRON_LDAP_TLS_KEY must be set together"),
    };
    let app = AppState::new(store, index_spec, tls_acceptor.clone(), referrals);

    let mut tasks = Vec::new();

    let health_listener = TcpListener::bind(&health_addr).await?;
    tracing::info!(%health_addr, "iron-ldapd listening (health)");
    tasks.push(tokio::spawn(iron_ldap::health::serve(health_listener, app.clone())));

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(%listen_addr, starttls = tls_acceptor.is_some(), "iron-ldapd listening (plaintext)");
    tasks.push(tokio::spawn(iron_ldap::serve(listener, app.clone())));

    if let Some(ldaps_addr) = ldaps_addr {
        let acceptor = tls_acceptor
            .ok_or_else(|| anyhow::anyhow!("IRON_LDAP_TLS_CERT/IRON_LDAP_TLS_KEY are required when IRON_LDAP_LDAPS_LISTEN is set"))?;
        let ldaps_listener = TcpListener::bind(&ldaps_addr).await?;
        tracing::info!(%ldaps_addr, "iron-ldapd listening (LDAPS)");
        tasks.push(tokio::spawn(iron_ldap::serve_ldaps(
            ldaps_listener,
            acceptor,
            app.clone(),
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
