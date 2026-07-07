//! iron-kdcd: Kerberos 5 KDC daemon (#5), serving one realm/partition's
//! principals over UDP+TCP port 88. Deployable (rpm + systemd unit, see
//! deploy/), configured entirely via environment variables, matching
//! iron-ldapd's and fastetcd's convention.
//!
//! Required:
//!   IRON_KDC_FASTETCD_ENDPOINT   e.g. http://etcd.g8.lo:2379
//!   IRON_KDC_PARTITION_ID        e.g. g10
//!   IRON_KDC_BASE_DN             e.g. dc=g10,dc=lo
//!   IRON_KDC_REALM               e.g. IRON.LO
//! Optional (defaults shown):
//!   IRON_KDC_LISTEN=0.0.0.0:88   (both UDP and TCP bind here)
//!
//! Needs OPENSSL_CONF pointing at a config that activates fips.so (see
//! docs/FIPS.md) -- unlike iron-ldapd, this daemon refuses to start at
//! all without the FIPS provider active, since a KDC that can't do
//! Kerberos crypto can't do anything useful.
//!
//! Principals are provisioned via `iron-kdc-ctl`, not this daemon.

use iron_partition::{ClusterRef, Dn, ForestId, Partition, PartitionRegistry};
use iron_store::store::Store;
use tokio::net::{TcpListener, UdpSocket};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn require_env(name: &str) -> anyhow::Result<String> {
    env(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let endpoint = require_env("IRON_KDC_FASTETCD_ENDPOINT")?;
    let pid = require_env("IRON_KDC_PARTITION_ID")?;
    let base_dn = require_env("IRON_KDC_BASE_DN")?;
    let realm = require_env("IRON_KDC_REALM")?;
    let listen_addr = env("IRON_KDC_LISTEN").unwrap_or_else(|| "0.0.0.0:88".to_string());

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?;
    let base_dn_parsed = Dn::parse(&base_dn)?;
    let partition = Partition::domain(pid, forest, base_dn_parsed.clone(), cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;

    let store = Store::connect(registry).await?;
    let app = iron_kdc::AppState::new(store, base_dn_parsed, realm.clone())?;

    let udp = UdpSocket::bind(&listen_addr).await?;
    let tcp = TcpListener::bind(&listen_addr).await?;
    tracing::info!(%listen_addr, %realm, "iron-kdcd listening (UDP+TCP)");

    tokio::try_join!(
        iron_kdc::server::serve_udp(udp, app.clone()),
        iron_kdc::server::serve_tcp(tcp, app.clone()),
    )?;
    Ok(())
}
