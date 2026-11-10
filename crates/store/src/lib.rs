//! iron-store: partition-scoped DIT over fastetcd (#2/#3).
//!
//! - [`connect`] turns a [`ClusterRef`] (D1: endpoints + optional mTLS
//!   identity) into a live `etcd_client::Client`.
//! - [`entry`] is raw partition-scoped put/get/scan/watch on
//!   `iron_partition`'s key encoding (D2/D8).
//! - [`model::Entry`] is the stored (multi-valued attribute map) format.
//! - [`index`] atomically maintains secondary indexes alongside entry
//!   writes via a single etcd transaction per write.
//! - [`ridpool`] allocates RIDs (#17) via a real etcd compare-and-swap
//!   loop, not `index`'s read-then-write-in-one-txn pattern -- a RID
//!   pool must stay correct even if a second, independent process
//!   touches the same partition.
//! - [`binary_attrs`] is the shared base64-in-`Entry` convention for
//!   MS-DTYP binary values (`objectSid`/`nTSecurityDescriptor`, #17),
//!   used by both `iron-ldap`'s wire projection and `iron-kdc`'s PAC
//!   generation (#18).
//! - [`store::Store`] is the multi-cluster connection registry (invariant
//!   #4): resolves a DN to its partition and the client for that
//!   partition's cluster.

pub mod binary_attrs;
pub mod entry;
pub mod index;
pub mod model;
pub mod ridpool;
pub mod store;

use etcd_client::{Certificate, Client, ConnectOptions, Error as EtcdError, GetOptions, GetResponse, Identity, TlsOptions};
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
    #[error("RID pool for partition {0} is corrupt: {1}")]
    RidPoolCorrupt(String, String),
    #[error("fastetcd TLS settings: {0}")]
    TlsSettings(String),
}

/// The [`ClusterRef`] a binary reaches fastetcd with (#26): `endpoint`
/// (several may be given, comma-separated), plus mTLS from the environment
/// variables `<prefix>_CA`, `<prefix>_CERT` and `<prefix>_KEY` (PEM file
/// paths) when they are set. For iron-ldapd, `prefix` is
/// `IRON_LDAP_FASTETCD`: `IRON_LDAP_FASTETCD_ENDPOINT` names the cluster
/// and `IRON_LDAP_FASTETCD_CA`/`_CERT`/`_KEY` its client identity.
pub fn cluster_from_env(endpoint: &str, prefix: &str) -> Result<ClusterRef, StoreError> {
    let var = |suffix: &str| std::env::var(format!("{prefix}_{suffix}")).ok().filter(|v| !v.is_empty());
    cluster_ref(endpoint, prefix, var("CA"), var("CERT"), var("KEY"))
}

/// [`cluster_from_env`] without the environment. All three of `ca`, `cert`
/// and `key`, or none: a client identity is what `--client-cert-auth`
/// requires, and half a setting is a mistake to report, not to guess
/// around. The scheme must agree: `https://` with TLS, `http://` without
/// -- otherwise a forgotten setting would silently mean plaintext, or a
/// TLS identity would be sent nowhere.
pub fn cluster_ref(endpoint: &str, prefix: &str, ca: Option<String>, cert: Option<String>, key: Option<String>) -> Result<ClusterRef, StoreError> {
    let endpoints: Vec<String> = endpoint.split(',').map(str::trim).filter(|e| !e.is_empty()).map(String::from).collect();
    if endpoints.is_empty() {
        return Err(StoreError::TlsSettings(format!("{prefix}_ENDPOINT is empty")));
    }
    let tls = match (ca, cert, key) {
        (Some(ca), Some(cert), Some(key)) => Some(TlsRef { ca, cert, key }),
        (None, None, None) => None,
        _ => return Err(StoreError::TlsSettings(format!("set all of {prefix}_CA, {prefix}_CERT and {prefix}_KEY, or none"))),
    };
    for e in &endpoints {
        match (&tls, e.starts_with("https://")) {
            (Some(_), false) => return Err(StoreError::TlsSettings(format!("{e}: {prefix}_CA/_CERT/_KEY are set, so the endpoint must be https://"))),
            (None, true) => return Err(StoreError::TlsSettings(format!("{e} is https://: set {prefix}_CA, {prefix}_CERT and {prefix}_KEY"))),
            _ => {}
        }
    }
    Ok(ClusterRef { endpoints, tls })
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

/// gRPC `UNAVAILABLE`.
const GRPC_UNAVAILABLE: i32 = 14;

/// Reads `key` (every key under it if `prefix`), retrying while fastetcd
/// answers `UNAVAILABLE`. A linearizable read's barrier gives up when the
/// leader can't confirm quorum in time (a leader change, a loaded member:
/// "linearizable read barrier: not enough for a quorum", seen under
/// `iron-simulate join 25`, #24). Go's clientv3 retries such reads;
/// `etcd-client` doesn't, so every read here does: up to 6 attempts over
/// about 1.5 s. Reads only -- a write that failed may still have committed.
pub(crate) async fn get(client: &mut Client, key: &str, prefix: bool) -> Result<GetResponse, EtcdError> {
    let mut delay = std::time::Duration::from_millis(50);
    for _ in 0..5 {
        let options = prefix.then(|| GetOptions::new().with_prefix());
        match client.get(key, options).await {
            Err(EtcdError::GRpcStatus(status)) if status.code() as i32 == GRPC_UNAVAILABLE => {
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            other => return other,
        }
    }
    client.get(key, prefix.then(|| GetOptions::new().with_prefix())).await
}

#[cfg(test)]
mod cluster_ref_tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn plaintext_without_tls_settings() {
        let c = cluster_ref("http://a:2379, http://b:2379", "P", None, None, None).unwrap();
        assert_eq!(c.endpoints, ["http://a:2379", "http://b:2379"]);
        assert!(c.tls.is_none());
    }

    #[test]
    fn mtls_with_all_three() {
        let c = cluster_ref("https://a:2379", "P", s("ca.pem"), s("c.pem"), s("c.key")).unwrap();
        let tls = c.tls.unwrap();
        assert_eq!((tls.ca.as_str(), tls.cert.as_str(), tls.key.as_str()), ("ca.pem", "c.pem", "c.key"));
    }

    #[test]
    fn half_settings_and_scheme_mismatches_are_refused() {
        assert!(cluster_ref("https://a:2379", "P", s("ca.pem"), None, None).is_err());
        assert!(cluster_ref("http://a:2379", "P", s("ca.pem"), s("c.pem"), s("c.key")).is_err());
        assert!(cluster_ref("https://a:2379", "P", None, None, None).is_err());
        assert!(cluster_ref(" , ", "P", None, None, None).is_err());
    }
}
