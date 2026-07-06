//! iron-store: partition-scoped DIT over fastetcd (#2/#3).
//!
//! - [`connect`] turns a [`ClusterRef`] (D1: endpoints + optional mTLS
//!   identity) into a live `etcd_client::Client`.
//! - [`entry`] is raw partition-scoped put/get/scan/watch on
//!   `iron_partition`'s key encoding (D2/D8).
//! - [`model::Entry`] is the stored (multi-valued attribute map) format.
//! - [`index`] atomically maintains secondary indexes alongside entry
//!   writes via a single etcd transaction per write.
//! - [`store::Store`] is the multi-cluster connection registry (invariant
//!   #4): resolves a DN to its partition and the client for that
//!   partition's cluster.

pub mod entry;
pub mod index;
pub mod model;
pub mod store;

use etcd_client::{Certificate, Client, ConnectOptions, Error as EtcdError, Identity, TlsOptions};
use iron_partition::{ClusterRef, PartitionError, TlsRef};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("etcd client error: {0}")]
    Etcd(#[from] EtcdError),
    #[error("failed to read TLS material at {path}: {source}")]
    TlsFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to decode entry: {0}")]
    EntryDecode(#[from] serde_json::Error),
    #[error("DN error: {0}")]
    Partition(#[from] PartitionError),
    #[error("no partition covers DN {0}")]
    NoPartitionFor(String),
    #[error("not connected to the cluster for partition {0}")]
    NotConnected(String),
}

/// Connects to the fastetcd cluster described by `cluster`. Plaintext if
/// `cluster.tls` is `None` (test/dev only, per `ClusterRef::plaintext`'s
/// own doc comment); mTLS otherwise, using the referenced CA/cert/key
/// files.
pub async fn connect(cluster: &ClusterRef) -> Result<Client, StoreError> {
    let options = match &cluster.tls {
        None => None,
        Some(tls) => Some(ConnectOptions::new().with_tls(build_tls_options(tls)?)),
    };
    let client = Client::connect(&cluster.endpoints, options).await?;
    Ok(client)
}

fn build_tls_options(tls: &TlsRef) -> Result<TlsOptions, StoreError> {
    let ca = read(&tls.ca)?;
    let cert = read(&tls.cert)?;
    let key = read(&tls.key)?;
    Ok(TlsOptions::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key)))
}

fn read(path: &str) -> Result<Vec<u8>, StoreError> {
    std::fs::read(Path::new(path)).map_err(|source| StoreError::TlsFile {
        path: path.to_string(),
        source,
    })
}
