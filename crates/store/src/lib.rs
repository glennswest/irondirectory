//! iron-store <-> fastetcd connection harness (#2).
//!
//! Turns a [`ClusterRef`] (D1: endpoints + optional mTLS identity) into a
//! live `etcd_client::Client`, and provides partition-scoped entry/watch
//! operations built on `iron_partition`'s key encoding (D2/D8).

pub mod entry;

use etcd_client::{Certificate, Client, ConnectOptions, Error as EtcdError, Identity, TlsOptions};
use iron_partition::{ClusterRef, TlsRef};
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
