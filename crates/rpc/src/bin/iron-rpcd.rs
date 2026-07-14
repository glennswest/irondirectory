//! iron-rpcd: a minimal `ncacn_ip_tcp` DCE/RPC daemon serving SAMR,
//! LSARPC, and NETLOGON (#19) -- see `iron_rpc`'s crate docs for scope
//! (unauthenticated, no `ncacn_np`/SMB transport, no
//! `SamrSetInformationUser2` password-setting).
//!
//! Required:
//!   IRON_RPC_FASTETCD_ENDPOINT   e.g. http://etcd.g8.lo:2379
//!   IRON_RPC_PARTITION_ID        e.g. g19rpc
//!   IRON_RPC_BASE_DN             e.g. dc=g19rpc,dc=lo
//!   IRON_RPC_DOMAIN_SID          e.g. S-1-5-21-...  (see iron-config-ctl show)
//!   IRON_RPC_NETBIOS_NAME        e.g. G19RPC
//!   IRON_RPC_DNS_DOMAIN          e.g. g19rpc.lo
//! Optional:
//!   IRON_RPC_LISTEN=0.0.0.0:445  (bind address; 445 needs root, use a
//!                                 high port for testing, e.g. 13445)
//!
//! Needs OPENSSL_CONF pointing at a config that activates fips.so (see
//! docs/FIPS.md) -- NETLOGON's session-key/credential crypto refuses to
//! start without it, same posture as iron-kdcd.

use iron_partition::{ClusterRef, Dn, ForestId, Partition, PartitionRegistry, Sid};
use iron_rpc::server::{AppState, DomainInfo};
use iron_rpc::{netlogon, samr};
use iron_store::index::IndexSpec;
use iron_store::store::Store;
use tokio::net::TcpListener;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}
fn require_env(name: &str) -> anyhow::Result<String> {
    env(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let endpoint = require_env("IRON_RPC_FASTETCD_ENDPOINT")?;
    let pid = require_env("IRON_RPC_PARTITION_ID")?;
    let base_dn = require_env("IRON_RPC_BASE_DN")?;
    let domain_sid = Sid::parse(&require_env("IRON_RPC_DOMAIN_SID")?).ok_or_else(|| anyhow::anyhow!("IRON_RPC_DOMAIN_SID is not a valid SID"))?;
    let netbios_name = require_env("IRON_RPC_NETBIOS_NAME")?;
    let dns_domain = require_env("IRON_RPC_DNS_DOMAIN")?;
    let listen_addr = env("IRON_RPC_LISTEN").unwrap_or_else(|| "0.0.0.0:445".to_string());

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?;
    let base_dn_parsed = Dn::parse(&base_dn)?;
    let partition = Partition::domain(pid, forest, base_dn_parsed.clone(), cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;

    let index_spec = IndexSpec::new(["cn", "member"]);
    let store_for_samr = Store::connect(registry.clone()).await?;
    let store_for_netlogon = Store::connect(registry).await?;
    let fips = iron_crypto::FipsContext::new()?;

    let app = std::sync::Arc::new(AppState {
        domain_info: DomainInfo { netbios_name, dns_domain_name: dns_domain.clone(), dns_forest_name: dns_domain, domain_sid },
        samr: samr::SamrState { store: tokio::sync::Mutex::new(store_for_samr), base_dn: base_dn_parsed.clone(), index_spec },
        netlogon: netlogon::NetlogonState { store: tokio::sync::Mutex::new(store_for_netlogon), base_dn: base_dn_parsed, fips },
    });

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(%listen_addr, "iron-rpcd listening (ncacn_ip_tcp: SAMR/LSARPC/NETLOGON)");
    iron_rpc::server::serve(listener, app).await?;
    Ok(())
}
