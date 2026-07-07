//! Spike server binary for #4: serves one partition's DIT over plaintext
//! LDAP, backed by the live fastetcd cluster. Not the production entry
//! point (that's `crates/server`, not yet built) -- just enough to run
//! `ldapsearch`/`ldapadd`/`ldapdelete` against a real backend for
//! interop verification.
//!
//! Usage: iron-ldapd <listen addr:port> <fastetcd endpoint> <partition id> <base dn>
//! Example: iron-ldapd 127.0.0.1:3890 http://etcd.g8.lo:2379 g8spike4 dc=g8spike4,dc=lo

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
    let listen_addr = args.next().expect("usage: iron-ldapd <listen> <endpoint> <pid> <base-dn>");
    let endpoint = args.next().expect("missing fastetcd endpoint");
    let pid = args.next().expect("missing partition id");
    let base_dn = args.next().expect("missing base DN");

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?;
    let partition = Partition::domain(pid, forest, iron_partition::Dn::parse(&base_dn)?, cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;

    let store = Store::connect(registry).await?;
    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(%listen_addr, "iron-ldapd listening");

    let index_spec = IndexSpec::new(["cn", "mail", "uid"]);
    iron_ldap::serve(listener, Arc::new(Mutex::new(store)), index_spec).await?;
    Ok(())
}
