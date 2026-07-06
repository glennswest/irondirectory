//! mTLS spike (#2): exercises `iron_store::connect()`'s TLS path against a
//! throwaway fastetcd instance configured with `--cert-file`/`--key-file`/
//! `--trusted-ca-file`/`--client-cert-auth`.
//!
//! Not run against the live dm1/dm2/dm3 cluster -- that cluster has no TLS
//! configured (see irondirectory#1's DNS-probe notes), and enabling it there
//! is a separate, bigger change. This spins up (by hand, see docs/FIPS.md's
//! sibling doc `docs/MTLS-SPIKE.md`) a single-node instance instead.
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
