//! mTLS spike (#2): exercises `iron_store::connect()`'s TLS path against a
//! throwaway fastetcd instance configured with `--cert-file`/`--key-file`/
//! `--trusted-ca-file`/`--client-cert-auth`.
//!
//! Not run against the live dm1/dm2/dm3 cluster -- that cluster has no TLS
//! configured. `test/mtls-e2e.sh` makes throwaway certificates, starts a
//! single-node fastetcd with `--client-cert-auth`, and runs these (#32).
//!
//! The second test is the one fastetcd#6 failed: with `--client-cert-auth`,
//! a client that trusts the CA but has no certificate of its own must not
//! be able to write. fastetcd fixed that in v0.8.1.
//!
//! Ignored by default; set these env vars to run:
//!   IRON_STORE_MTLS_ENDPOINT (e.g. https://dev.g8.lo:23791)
//!   IRON_STORE_MTLS_CA / IRON_STORE_MTLS_CERT / IRON_STORE_MTLS_KEY (paths)
//!
//! cargo test -p iron-store --test mtls_spike -- --ignored

use iron_partition::{ClusterRef, Dn, PartitionId, TlsRef};

fn cluster_from_env() -> Option<ClusterRef> {
    let endpoint = std::env::var("IRON_STORE_MTLS_ENDPOINT").ok()?;
    let ca = std::env::var("IRON_STORE_MTLS_CA").ok()?;
    let cert = std::env::var("IRON_STORE_MTLS_CERT").ok()?;
    let key = std::env::var("IRON_STORE_MTLS_KEY").ok()?;
    Some(ClusterRef {
        endpoints: vec![endpoint],
        tls: Some(TlsRef { ca, cert, key }),
    })
}

#[tokio::test]
#[ignore]
async fn mtls_connect_and_roundtrip() {
    let cluster = cluster_from_env()
        .expect("set IRON_STORE_MTLS_ENDPOINT/_CA/_CERT/_KEY to run this spike");

    let mut client = iron_store::connect(&cluster)
        .await
        .expect("mTLS connect with a valid client identity should succeed");

    let pid = PartitionId::new("mtls-spike").unwrap();
    let dn = Dn::parse("cn=probe,dc=spike").unwrap();
    iron_store::entry::put_entry(&mut client, &pid, &dn, "mtls works")
        .await
        .unwrap();
    let got = iron_store::entry::get_entry(&mut client, &pid, &dn)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"mtls works");

    client
        .delete(
            iron_partition::key::partition_root(&pid),
            Some(etcd_client::DeleteOptions::new().with_prefix()),
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn mtls_refuses_a_client_without_a_certificate() {
    let endpoint = std::env::var("IRON_STORE_MTLS_ENDPOINT").expect("set IRON_STORE_MTLS_ENDPOINT/_CA to run this spike");
    let ca = std::fs::read(std::env::var("IRON_STORE_MTLS_CA").expect("set IRON_STORE_MTLS_CA")).unwrap();
    // Trusts the server, presents nothing.
    let options = etcd_client::ConnectOptions::new()
        .with_tls(etcd_client::TlsOptions::new().ca_certificate(etcd_client::Certificate::from_pem(ca)));
    let result = async {
        let mut client = etcd_client::Client::connect([endpoint], Some(options)).await?;
        client.put("/iron/mtls-spike/anonymous", "no client certificate", None).await
    }
    .await;
    assert!(result.is_err(), "fastetcd with --client-cert-auth took a write from a client with no certificate (fastetcd#6): {result:?}");
}
