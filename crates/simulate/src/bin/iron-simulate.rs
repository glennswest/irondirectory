//! iron-simulate: drives N concurrent simulated domain joins and/or
//! ordinary logins against a real iron-ldapd/iron-kdcd/iron-rpcd stack
//! (#23), for scale testing and quick end-to-end verification.
//!
//! Usage:
//!   iron-simulate join <count> [name-prefix]
//!   iron-simulate login <count> <username> <password>
//!
//! Required env: IRON_SIM_RPC_ADDR (e.g. 127.0.0.1:13445),
//! IRON_SIM_KDC_ADDR (e.g. 127.0.0.1:8888), IRON_SIM_BASE_DN,
//! IRON_SIM_REALM, IRON_SIM_FASTETCD_ENDPOINT (direct store access for
//! provisioning -- see `join` module docs), IRON_SIM_SERVICE_PRINCIPAL
//! (a principal this harness provisions itself so it can decrypt
//! resulting service tickets to inspect their PAC).
//!
//! Needs OPENSSL_CONF pointing at a FIPS-activating config (see
//! docs/FIPS.md), same as every other Kerberos-touching binary here.

use std::time::Instant;

use iron_crypto::FipsContext;
use iron_simulate::join::{self, SimConfig};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}
fn require_env(name: &str) -> anyhow::Result<String> {
    env(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

fn build_config() -> anyhow::Result<SimConfig> {
    Ok(SimConfig {
        rpc_addr: require_env("IRON_SIM_RPC_ADDR")?,
        kdc_addr: require_env("IRON_SIM_KDC_ADDR")?,
        base_dn: require_env("IRON_SIM_BASE_DN")?,
        realm: require_env("IRON_SIM_REALM")?,
        service_principal: require_env("IRON_SIM_SERVICE_PRINCIPAL")?,
        service_password: b"iron-simulate-service-secret".to_vec(),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args: Vec<String> = std::env::args().collect();
    let Some(mode) = args.get(1) else {
        anyhow::bail!("usage: iron-simulate <join|login> ...");
    };

    let config = build_config()?;
    let fips = FipsContext::new()?;
    join::ensure_service_principal(&config, &fips).await?;

    match mode.as_str() {
        "join" => {
            let count: usize = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(1);
            let prefix = args.get(3).cloned().unwrap_or_else(|| "SIMPC".to_string());
            let start = Instant::now();
            let mut handles = Vec::with_capacity(count);
            for i in 0..count {
                let config = config.clone();
                let fips = FipsContext::new()?;
                let computer_name = format!("{prefix}{i:04}$");
                handles.push(tokio::spawn(async move {
                    let password = format!("sim-password-{i}");
                    let result = join::simulate_join(&config, &fips, &computer_name, password.as_bytes()).await;
                    (computer_name, result)
                }));
            }
            let mut ok = 0usize;
            let mut failed = 0usize;
            for h in handles {
                let (name, result) = h.await?;
                match result {
                    Ok(report) => {
                        ok += 1;
                        println!(
                            "OK   {name}: rid={} domain_sid={} pac_buffers={:?} elapsed={:?}",
                            report.rid, report.domain_sid, report.pac_buffer_types, report.elapsed
                        );
                    }
                    Err(e) => {
                        failed += 1;
                        println!("FAIL {name}: {e}");
                    }
                }
            }
            println!("--- {ok} succeeded, {failed} failed, total wall time {:?} ---", start.elapsed());
        }
        "login" => {
            let count: usize = args.get(2).map(|s| s.parse()).transpose()?.unwrap_or(1);
            let username = args.get(3).cloned().ok_or_else(|| anyhow::anyhow!("usage: iron-simulate login <count> <username> <password>"))?;
            let password = args.get(4).cloned().ok_or_else(|| anyhow::anyhow!("usage: iron-simulate login <count> <username> <password>"))?;
            let start = Instant::now();
            let mut handles = Vec::with_capacity(count);
            for _ in 0..count {
                let config = config.clone();
                let fips = FipsContext::new()?;
                let username = username.clone();
                let password = password.clone();
                handles.push(tokio::spawn(async move { join::simulate_login(&config, &fips, &username, password.as_bytes()).await }));
            }
            let mut ok = 0usize;
            let mut failed = 0usize;
            for h in handles {
                match h.await? {
                    Ok(report) => {
                        ok += 1;
                        println!("OK   {}: pac_buffers={:?} elapsed={:?}", report.username, report.pac_buffer_types, report.elapsed);
                    }
                    Err(e) => {
                        failed += 1;
                        println!("FAIL: {e}");
                    }
                }
            }
            println!("--- {ok} succeeded, {failed} failed, total wall time {:?} ---", start.elapsed());
        }
        other => anyhow::bail!("unknown mode {other:?}; expected join or login"),
    }

    Ok(())
}
