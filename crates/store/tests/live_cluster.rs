//! Spike harness (#2): exercises the real dm1/dm2/dm3 fastetcd cluster at
//! `etcd.g8.lo:2379` (D1) with partition-scoped keys (D2/D8) and watch.
//!
//! Ignored by default -- needs network access to the live g8 cluster.
//! Run explicitly with:
//!   cargo test -p iron-store --test live_cluster -- --ignored --test-threads=1

use iron_partition::{ClusterRef, Dn, PartitionId};
use iron_store::entry::{get_entry, next_subtree_event, put_entry, scan_subtree, watch_subtree};

fn cluster() -> ClusterRef {
    ClusterRef::plaintext(["http://etcd.g8.lo:2379"])
}

fn test_pid() -> PartitionId {
    PartitionId::new("g8spike").unwrap()
}

#[tokio::test]
#[ignore]
async fn put_get_roundtrip_against_live_cluster() {
    let mut client = iron_store::connect(&cluster()).await.unwrap();
    let pid = test_pid();
    let dn = Dn::parse("cn=alice,ou=users,dc=g8,dc=lo").unwrap();

    put_entry(&mut client, &pid, &dn, "hello from iron-store")
        .await
        .unwrap();
    let got = get_entry(&mut client, &pid, &dn).await.unwrap().unwrap();
    assert_eq!(got, b"hello from iron-store");

    // cleanup
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
async fn subtree_scan_against_live_cluster() {
    let mut client = iron_store::connect(&cluster()).await.unwrap();
    let pid = test_pid();
    let base = Dn::parse("ou=users,dc=g8,dc=lo").unwrap();
    let alice = Dn::parse("cn=alice,ou=users,dc=g8,dc=lo").unwrap();
    let bob = Dn::parse("cn=bob,ou=users,dc=g8,dc=lo").unwrap();

    put_entry(&mut client, &pid, &base, "ou").await.unwrap();
    put_entry(&mut client, &pid, &alice, "alice").await.unwrap();
    put_entry(&mut client, &pid, &bob, "bob").await.unwrap();

    let rows = scan_subtree(&mut client, &pid, &base).await.unwrap();
    assert_eq!(rows.len(), 3, "expected base + 2 children, got {rows:?}");
    assert!(rows.iter().any(|(_, v)| v == b"ou"));
    assert!(rows.iter().any(|(_, v)| v == b"alice"));
    assert!(rows.iter().any(|(_, v)| v == b"bob"));

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
async fn watch_observes_puts_against_live_cluster() {
    let pid = test_pid();
    let base = Dn::parse("ou=watch,dc=g8,dc=lo").unwrap();
    let child = Dn::parse("cn=carol,ou=watch,dc=g8,dc=lo").unwrap();

    let mut watch_client = iron_store::connect(&cluster()).await.unwrap();
    let mut stream = watch_subtree(&mut watch_client, &pid, &base).await.unwrap();

    // First message is the watch-creation ack, not a data event.
    let created = stream.message().await.unwrap().unwrap();
    assert!(created.created());

    let mut write_client = iron_store::connect(&cluster()).await.unwrap();
    put_entry(&mut write_client, &pid, &child, "carol").await.unwrap();

    let event = next_subtree_event(&mut stream)
        .await
        .unwrap()
        .expect("expected a put event on the watched subtree");
    assert_eq!(event.value, b"carol");

    write_client
        .delete(
            iron_partition::key::partition_root(&pid),
            Some(etcd_client::DeleteOptions::new().with_prefix()),
        )
        .await
        .unwrap();
}
