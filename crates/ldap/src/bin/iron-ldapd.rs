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
//!   IRON_LDAP_CHANNEL_BINDING=when-supported   (or `always`)
//!
//! GSSAPI channel bindings (#65), as Active Directory's LDAP channel
//! binding: the RFC 5929 tls-server-end-point bindings a client sends with
//! a SASL/GSSAPI bind are always checked against the LDAPS/StartTLS
//! connection, and refused on plain LDAP. `when-supported` accepts a bind
//! that carries none; `always` refuses one over TLS.
//!
//!   IRON_LDAP_REFERRALS=          (unset = no referrals)
//!
//! Naming contexts this instance doesn't host, for cross-NC referrals
//! (RFC 4511 §4.1.10): `;`-separated `base-dn|ldap-url` pairs (`|`, not
//! `=`, since a DN is itself full of `=` signs), e.g.
//! `dc=g11,dc=lo|ldap://ldap.g11.lo;dc=other,dc=lo|ldap://other.example.com`.
//! An operation whose target DN falls at or below one of these base DNs
//! gets a `Referral` result pointing at the paired URL instead of
//! `NoSuchObject`/`OperationsError`. This is a fallback used when the
//! registry-driven path below doesn't have a match (or isn't
//! configured) -- for a deployment with no configuration partition set
//! up (#9), e.g. the standalone il1/il2/il3 replicas.
//!
//!   IRON_LDAP_CONFIG_FASTETCD_ENDPOINT=  (unset = registry-driven referrals off)
//!   IRON_LDAP_CONFIG_PARTITION_ID=
//!   IRON_LDAP_CONFIG_BASE_DN=
//!
//! If all three are set, the forest's persisted `PartitionRegistry`
//! (#9/#10, maintained by `iron-config-ctl`) is loaded once at startup
//! and consulted *before* `IRON_LDAP_REFERRALS` when generating a
//! referral -- an operation whose target DN resolves to another
//! partition in the registry gets a `Referral` to that partition's
//! `ldap_url` (set via `iron-config-ctl create-child`/`set-ldap-url`)
//! automatically, no hand-maintained list to keep in sync as the
//! topology changes. A snapshot, not watched -- picking up a topology
//! change requires restarting this process (a later issue, not #10's
//! happy-path scope).
//!
//!   IRON_LDAP_CLDAP_LISTEN=       (unset = UDP on IRON_LDAP_LISTEN's address; `off` = none)
//!   IRON_LDAP_DC_HOSTNAME=        (unset = the kernel host name; no dot = a host in the domain)
//!   IRON_LDAP_DC_ADDRESS=         (unset = the address each ping reached)
//!
//! The LDAP ping (#52, MS-ADTS 6.3.3): how Windows finds a DC before it
//! joins. Answered on CLDAP (UDP, by default the same address and port as
//! the plaintext TCP listener, as AD serves CLDAP on UDP 389) and on TCP,
//! from this partition's record in the forest registry, so it needs
//! `IRON_LDAP_CONFIG_*` below and a record with a domain GUID
//! (`iron-bootstrap` fills one in). Without them iron-ldapd still starts,
//! warns, opens no CLDAP port and refuses a ping over TCP.
//! `IRON_LDAP_DC_HOSTNAME` is the DC's DNS name the ping answers with (and
//! rootDSE's `dnsHostName`); its first label is the DC's NetBIOS name.
//! `IRON_LDAP_DC_ADDRESS` is the IPv4 address a `_WITH_IP` answer carries.
//!
//! Authenticated simple bind (D4: PBKDF2 via the OpenSSL FIPS provider)
//! needs OPENSSL_CONF pointing at a config that activates fips.so (see
//! docs/FIPS.md) -- without it, iron-ldapd still starts and serves
//! anonymous bind/search/add/delete/modify/compare, just logs a warning
//! and fails authenticated bind/password-setting closed.

use std::sync::Arc;

use iron_ldap::AppState;
use iron_partition::{ForestId, Partition, PartitionRegistry};
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

/// Loads the forest's persisted `PartitionRegistry` (#9/#10) if
/// `IRON_LDAP_CONFIG_*` are all set, for registry-driven referrals.
/// `None` if they're unset -- an intentional, silent no-op, not an
/// error, since most deployments (e.g. il1/il2/il3) don't have a
/// configuration partition set up and rely solely on
/// `IRON_LDAP_REFERRALS`.
async fn load_topology() -> anyhow::Result<Option<PartitionRegistry>> {
    let (Some(endpoint), Some(pid), Some(base_dn)) =
        (env("IRON_LDAP_CONFIG_FASTETCD_ENDPOINT"), env("IRON_LDAP_CONFIG_PARTITION_ID"), env("IRON_LDAP_CONFIG_BASE_DN"))
    else {
        return Ok(None);
    };

    let cluster = iron_store::cluster_from_env(&endpoint, "IRON_LDAP_CONFIG_FASTETCD")?;
    let forest = ForestId::new(pid.clone())?; // placeholder, overwritten by the loaded record
    let config_dn = iron_partition::Dn::parse(&base_dn)?;
    let config_partition = Partition::configuration(pid, forest, config_dn.clone(), cluster)?;
    let mut bootstrap_registry = PartitionRegistry::new();
    bootstrap_registry.insert(config_partition)?;
    let mut store = Store::connect(bootstrap_registry).await?;

    let registry = iron_config::load_registry(&mut store, &config_dn).await?;
    tracing::info!(partitions = registry.len(), "loaded forest topology for registry-driven referrals");
    Ok(Some(registry))
}

/// What the LDAP ping answers with (#52), or `None` (warned about by the
/// caller) when there is no topology or this partition's record lacks
/// what the answer needs. A malformed `IRON_LDAP_DC_ADDRESS` is an error.
fn dc_info(topology: Option<&PartitionRegistry>, own: &iron_partition::PartitionId) -> anyhow::Result<Option<iron_ldap::cldap::DcInfo>> {
    let address = match env("IRON_LDAP_DC_ADDRESS") {
        Some(a) => Some(a.parse().map_err(|e| anyhow::anyhow!("IRON_LDAP_DC_ADDRESS {a:?}: {e}"))?),
        None => None,
    };
    let Some(topology) = topology else { return Ok(None) };
    let host = match env("IRON_LDAP_DC_HOSTNAME") {
        Some(h) => h,
        None => std::fs::read_to_string("/proc/sys/kernel/hostname").map(|h| h.trim().to_string()).unwrap_or_default(),
    };
    match iron_ldap::cldap::DcInfo::from_topology(topology, own, &host, address) {
        Ok(info) => Ok(Some(info)),
        Err(e) => {
            tracing::warn!("LDAP ping disabled: {e}");
            Ok(None)
        }
    }
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
    let channel_binding = match env("IRON_LDAP_CHANNEL_BINDING") {
        Some(v) => v.parse().map_err(|e: String| anyhow::anyhow!("IRON_LDAP_CHANNEL_BINDING: {e}"))?,
        None => iron_ldap::gssapi::accept::ChannelBindingPolicy::default(),
    };
    let referrals = match env("IRON_LDAP_REFERRALS") {
        Some(raw) => parse_referrals(&raw)?,
        None => Vec::new(),
    };

    let cluster = iron_store::cluster_from_env(&endpoint, "IRON_LDAP_FASTETCD")?;
    let forest = ForestId::new(pid.clone())?;
    let partition = Partition::domain(pid, forest, iron_partition::Dn::parse(&base_dn)?, cluster)?;
    let own_partition_id = partition.id.clone();
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;

    let store = Store::connect(registry).await?;
    // "member" (#18) lets iron-kdc's PAC generation efficiently reverse-look-up
    // a user's group memberships (groupOfNames entries whose "member" list
    // contains that user's DN) -- must match iron-kdc's own index_spec()
    // since indexing happens at write time, by whichever tool wrote the entry.
    // The KDC's spec: an entry iron-ldap writes (a computer account and
    // the key RFC 3062 sets on it, #20) must be findable by iron-kdcd's
    // `krbprincipalname`/`samaccountname` lookups.
    let index_spec = iron_kdc::index_spec();

    let topology = load_topology().await?;

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
    let dc_info = dc_info(topology.as_ref(), &own_partition_id)?;
    let cldap_addr = match env("IRON_LDAP_CLDAP_LISTEN").as_deref() {
        Some("off") => None,
        Some(a) => Some(a.to_string()),
        None => Some(listen_addr.clone()),
    };
    let app = AppState::new(store, index_spec, tls_acceptor.clone(), referrals, topology, Some(own_partition_id), channel_binding, dc_info);

    let mut tasks = Vec::new();

    let health_listener = TcpListener::bind(&health_addr).await?;
    tracing::info!(%health_addr, "iron-ldapd listening (health)");
    tasks.push(tokio::spawn(iron_ldap::health::serve(health_listener, app.clone())));

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(%listen_addr, starttls = tls_acceptor.is_some(), "iron-ldapd listening (plaintext)");
    tasks.push(tokio::spawn(iron_ldap::serve(listener, app.clone())));

    match (cldap_addr, &app.dc_info) {
        (Some(addr), Some(info)) => {
            let socket = tokio::net::UdpSocket::bind(&addr).await?;
            tracing::info!(cldap_addr = %addr, dc = %info.host_dns, domain = %info.domain_dns, "iron-ldapd listening (CLDAP, LDAP ping)");
            tasks.push(tokio::spawn(iron_ldap::cldap::serve(socket, app.clone())));
        }
        (Some(_), None) => tracing::warn!("no CLDAP listener: the LDAP ping needs IRON_LDAP_CONFIG_* and a domain record with a domain GUID (#52)"),
        (None, _) => {}
    }

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
