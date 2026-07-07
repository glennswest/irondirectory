//! Spike server binary for #4: serves one partition's DIT over plaintext
//! LDAP and/or LDAPS, backed by the live fastetcd cluster. Not the
//! production entry point (that's `crates/server`, not yet built) --
//! just enough to run `ldapsearch`/`ldapadd`/`ldapdelete` against a real
//! backend for interop verification.
//!
//! Usage: iron-ldapd <listen addr:port> <fastetcd endpoint> <partition id> <base dn> [ldaps-listen cert.pem key.pem]
//! Example (plaintext only):
//!   iron-ldapd 127.0.0.1:3890 http://etcd.g8.lo:2379 g8spike4 dc=g8spike4,dc=lo
//! Example (plaintext + LDAPS):
//!   iron-ldapd 127.0.0.1:3890 http://etcd.g8.lo:2379 g8spike4 dc=g8spike4,dc=lo 127.0.0.1:6360 server.pem server-key.pem

use std::sync::Arc;

use iron_partition::{ClusterRef, ForestId, Partition, PartitionRegistry};
use iron_store::index::IndexSpec;
use iron_store::store::Store;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut args = std::env::args().skip(1);
    let listen_addr = args.next().expect("usage: iron-ldapd <listen> <endpoint> <pid> <base-dn> [ldaps-listen cert key]");
    let endpoint = args.next().expect("missing fastetcd endpoint");
    let pid = args.next().expect("missing partition id");
    let base_dn = args.next().expect("missing base DN");
    let ldaps: Option<(String, String, String)> = match (args.next(), args.next(), args.next()) {
        (Some(l), Some(c), Some(k)) => Some((l, c, k)),
        _ => None,
    };

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?;
    let partition = Partition::domain(pid, forest, iron_partition::Dn::parse(&base_dn)?, cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;

    let store = Arc::new(Mutex::new(Store::connect(registry).await?));
    let index_spec = IndexSpec::new(["cn", "mail", "uid"]);

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(%listen_addr, "iron-ldapd listening (plaintext)");
    let plaintext = tokio::spawn(iron_ldap::serve(listener, store.clone(), index_spec.clone()));

    if let Some((ldaps_addr, cert, key)) = ldaps {
        let acceptor = Arc::new(iron_ldap::tls::build_acceptor(
            std::path::Path::new(&cert),
            std::path::Path::new(&key),
        )?);
        let ldaps_listener = TcpListener::bind(&ldaps_addr).await?;
        tracing::info!(%ldaps_addr, "iron-ldapd listening (LDAPS)");
        let ldaps_task = tokio::spawn(iron_ldap::serve_ldaps(
            ldaps_listener,
            acceptor,
            store.clone(),
            index_spec.clone(),
        ));
        tokio::try_join!(flatten(plaintext), flatten(ldaps_task))?;
    } else {
        plaintext.await??;
    }
    Ok(())
}

async fn flatten(task: tokio::task::JoinHandle<std::io::Result<()>>) -> anyhow::Result<()> {
    Ok(task.await??)
}
