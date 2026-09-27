//! iron-bootstrap: provisions a new domain if it is missing, then stays
//! resident (#25). See the library docs for what it creates.
//!
//! It runs as a container in a pod whose `restartPolicy` is `Always`, so an
//! exit would loop it: after success it waits for SIGTERM/SIGINT and exits
//! 0. It exits non-zero only on failure, with the reason on stderr.
//!
//! Env: `IRON_BOOTSTRAP_FASTETCD_ENDPOINT`, `IRON_BOOTSTRAP_PARTITION_ID`,
//! `IRON_BOOTSTRAP_BASE_DN`, `IRON_BOOTSTRAP_REALM`,
//! `IRON_BOOTSTRAP_NETBIOS_NAME`, `IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE` (all
//! required), and `OPENSSL_CONF` activating the FIPS provider.
//! `IRON_BOOTSTRAP_ONESHOT=1` exits 0 after provisioning instead of staying
//! resident (for use outside a pod).

use std::time::Duration;

use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    if let Err(e) = run().await {
        eprintln!("iron-bootstrap: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let settings = iron_bootstrap::Settings::from_env()?;
    tracing::info!(partition = %settings.partition_id, base_dn = %settings.base_dn, realm = %settings.realm, "waiting for fastetcd");
    let mut store = iron_bootstrap::wait_for_store(&settings, Duration::from_secs(2)).await?;
    let report = iron_bootstrap::provision(&mut store, &settings).await?;
    if report.created.is_empty() {
        tracing::info!(domain_sid = %report.domain_sid, "already provisioned; nothing to do");
    } else {
        tracing::info!(domain_sid = %report.domain_sid, created = ?report.created, "provisioned");
    }
    drop(store);

    if std::env::var("IRON_BOOTSTRAP_ONESHOT").is_ok_and(|v| v == "1") {
        return Ok(());
    }
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tracing::info!("staying resident until SIGTERM");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    Ok(())
}
