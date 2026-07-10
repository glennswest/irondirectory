//! iron-oidcd: FIPS OAuth2/OpenID Connect authorization server daemon
//! (#15), serving one directory partition's users over the standard
//! discovery/authorize/token/userinfo endpoint set. Deployable (rpm +
//! systemd unit, see deploy/), configured entirely via environment
//! variables, matching iron-ldapd's/iron-kdcd's/iron-gcd's convention.
//!
//! Required:
//!   IRON_OIDC_FASTETCD_ENDPOINT   e.g. http://etcd.g8.lo:2379
//!   IRON_OIDC_PARTITION_ID        e.g. g10
//!   IRON_OIDC_BASE_DN             e.g. dc=g10,dc=lo
//!   IRON_OIDC_ISSUER              e.g. https://oidc.g10.lo -- this
//!                                 process's own external base URL,
//!                                 used as the `iss` claim and to build
//!                                 every discovery-document URL. Must be
//!                                 exactly what clients will use to reach
//!                                 this server (scheme+host+port), since
//!                                 OIDC discovery URLs are absolute.
//!   IRON_OIDC_CLIENTS             `;`-separated `client_id|client_secret|
//!                                 redirect_uri` (see `clients.rs`)
//! Optional (defaults shown):
//!   IRON_OIDC_LISTEN=0.0.0.0:8080
//!   IRON_OIDC_LOGIN_ATTRIBUTE=uid
//!   IRON_OIDC_CODE_TTL_SECS=60
//!   IRON_OIDC_TOKEN_TTL_SECS=3600
//!
//! No built-in TLS termination -- unlike iron-ldapd/iron-gcd's
//! StartTLS/LDAPS support, this is a plain HTTP service, deliberately:
//! OpenShift (this issue's primary consumer) natively fronts internal
//! services with edge/reencrypt-TLS Routes, and that's the more correct
//! place to terminate TLS for an HTTP-shaped service in that
//! environment anyway, not a gap. A non-OpenShift deployment should put
//! any standard reverse proxy in front of this.
//!
//! Needs OPENSSL_CONF pointing at a config that activates fips.so (see
//! docs/FIPS.md) -- like iron-kdcd, this daemon refuses to start at all
//! without the FIPS provider active, since it can't verify passwords or
//! sign tokens without it.

use std::sync::Arc;
use std::time::Duration;

use iron_crypto::sign::EcKeyPair;
use iron_crypto::FipsContext;
use iron_oidc::clients::ClientRegistry;
use iron_oidc::codes::CodeStore;
use iron_oidc::AppState;
use iron_partition::{ClusterRef, Dn, ForestId, Partition, PartitionRegistry};
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

    let endpoint = require_env("IRON_OIDC_FASTETCD_ENDPOINT")?;
    let pid = require_env("IRON_OIDC_PARTITION_ID")?;
    let base_dn_str = require_env("IRON_OIDC_BASE_DN")?;
    let issuer = require_env("IRON_OIDC_ISSUER")?;
    let clients_raw = require_env("IRON_OIDC_CLIENTS")?;
    let listen_addr = env("IRON_OIDC_LISTEN").unwrap_or_else(|| "0.0.0.0:8080".to_string());
    let login_attribute = env("IRON_OIDC_LOGIN_ATTRIBUTE").unwrap_or_else(|| "uid".to_string());
    let code_ttl_secs: u64 = env("IRON_OIDC_CODE_TTL_SECS").and_then(|v| v.parse().ok()).unwrap_or(60);
    let token_ttl_secs: u64 = env("IRON_OIDC_TOKEN_TTL_SECS").and_then(|v| v.parse().ok()).unwrap_or(3600);

    let fips = FipsContext::new()?;
    let signing_key = EcKeyPair::generate(&fips)?;
    let clients = ClientRegistry::parse(&clients_raw)?;

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?;
    let base_dn = Dn::parse(&base_dn_str)?;
    let partition = Partition::domain(pid, forest, base_dn.clone(), cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;
    let store = Store::connect(registry).await?;

    let app = Arc::new(AppState {
        issuer,
        store: Mutex::new(store),
        base_dn,
        login_attribute,
        fips,
        signing_key: Mutex::new(signing_key),
        clients,
        codes: CodeStore::new(),
        code_ttl: Duration::from_secs(code_ttl_secs),
        token_ttl: Duration::from_secs(token_ttl_secs),
    });

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(%listen_addr, issuer = %app.issuer, "iron-oidcd listening");
    axum::serve(listener, iron_oidc::router(app)).await?;
    Ok(())
}
