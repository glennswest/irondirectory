//! Spike (#3): entry serialization + secondary indexes + the multi-cluster
//! `Store` type, against the real dm1/dm2/dm3 cluster at `etcd.g8.lo:2379`.
//!
//! Ignored by default -- needs network access to the live g8 cluster.
//! Run explicitly with:
//!   cargo test -p iron-store --test indexed_entries -- --ignored --test-threads=1

use iron_partition::{
    ClusterRef, Dn, ForestId, Partition, PartitionRegistry,
};
use iron_store::index::IndexSpec;
use iron_store::model::Entry;
use iron_store::store::Store;

fn cluster() -> ClusterRef {
    ClusterRef::plaintext(["http://etcd.g8.lo:2379"])
}

fn spec() -> IndexSpec {
    IndexSpec::new(["cn", "mail"])
}

fn base_dn() -> Dn {
    Dn::parse("dc=g8spike3,dc=lo").unwrap()
}

async fn store() -> Store {
    let forest = ForestId::new("g8spike3").unwrap();
    let partition =
        Partition::domain("g8spike3", forest, base_dn(), cluster()).unwrap();
    let mut registry = PartitionRegistry::new();
    registry.insert(partition).unwrap();
    Store::connect(registry).await.unwrap()
}

async fn cleanup(store: &mut Store) {
    let pid = store.registry().resolve(&base_dn()).unwrap().id.clone();
    // Reach through to the raw client to wipe the whole partition prefix --
    // simplest teardown for a spike test.
    let client = etcd_client::Client::connect(["http://etcd.g8.lo:2379"], None)
        .await
        .unwrap();
    let mut client = client;
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
async fn put_get_delete_roundtrip_via_store() {
    let mut store = store().await;
    let dn = Dn::parse("cn=alice,dc=g8spike3,dc=lo").unwrap();

    let mut entry = Entry::new();
    entry.set("cn", ["alice"]);
    entry.set("mail", ["alice@g8spike3.lo"]);

    store.put_entry(&dn, &entry, &spec()).await.unwrap();
    let got = store.get_entry(&dn).await.unwrap().unwrap();
    assert_eq!(got.get("cn"), Some(["alice".to_string()].as_slice()));

    store.delete_entry(&dn, &spec()).await.unwrap();
    assert!(store.get_entry(&dn).await.unwrap().is_none());

    cleanup(&mut store).await;
}

#[tokio::test]
#[ignore]
async fn secondary_index_tracks_attribute_changes() {
    let mut store = store().await;
    let dn = Dn::parse("cn=bob,dc=g8spike3,dc=lo").unwrap();

    let mut entry = Entry::new();
    entry.set("cn", ["bob"]);
    entry.set("mail", ["bob@old.example"]);
    store.put_entry(&dn, &entry, &spec()).await.unwrap();

    let hits = store
        .lookup_by_index(&dn, "mail", "bob@old.example")
        .await
        .unwrap();
    assert_eq!(hits, vec![dn.clone()]);

    // Change the indexed attribute -- old index entry must disappear.
    entry.set("mail", ["bob@new.example"]);
    store.put_entry(&dn, &entry, &spec()).await.unwrap();

    let stale = store
        .lookup_by_index(&dn, "mail", "bob@old.example")
        .await
        .unwrap();
    assert!(stale.is_empty(), "stale index entry should have been removed");

    let fresh = store
        .lookup_by_index(&dn, "mail", "bob@new.example")
        .await
        .unwrap();
    assert_eq!(fresh, vec![dn.clone()]);

    store.delete_entry(&dn, &spec()).await.unwrap();
    let after_delete = store
        .lookup_by_index(&dn, "mail", "bob@new.example")
        .await
        .unwrap();
    assert!(after_delete.is_empty(), "index entry should be gone after delete");

    cleanup(&mut store).await;
}

#[tokio::test]
#[ignore]
async fn watch_decodes_typed_entry_changes() {
    let dn = Dn::parse("cn=carol,ou=watch3,dc=g8spike3,dc=lo").unwrap();
    let watch_base = Dn::parse("ou=watch3,dc=g8spike3,dc=lo").unwrap();
    let pid = {
        let s = store().await;
        s.registry().resolve(&watch_base).unwrap().id.clone()
    };

    let mut watch_client =
        etcd_client::Client::connect(["http://etcd.g8.lo:2379"], None).await.unwrap();
    let mut stream = iron_store::entry::watch_subtree(&mut watch_client, &pid, &watch_base)
        .await
        .unwrap();
    let created = stream.message().await.unwrap().unwrap();
    assert!(created.created());

    let mut store = store().await;
    let mut entry = Entry::new();
    entry.set("cn", ["carol"]);
    store.put_entry(&dn, &entry, &spec()).await.unwrap();

    let change = iron_store::entry::next_entry_change(&mut stream)
        .await
        .unwrap()
        .expect("expected a Put change");
    match change {
        iron_store::entry::EntryChange::Put { entry, .. } => {
            assert_eq!(entry.get("cn"), Some(["carol".to_string()].as_slice()));
        }
        other => panic!("expected Put, got {other:?}"),
    }

    cleanup(&mut store).await;
}
