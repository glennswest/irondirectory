//! A subtree watch returns every event of a multi-event response (finding
//! f7d57dd68673).
//!
//! Needs a fastetcd/etcd endpoint of its own (it wipes its partition
//! prefix): `test/watch-batch-e2e.sh` starts a throwaway one and runs
//!   IRON_STORE_TEST_ENDPOINT=http://127.0.0.1:PORT \
//!     cargo test -p iron-store --test watch_batch -- --ignored --nocapture
//!
//! One etcd transaction that writes N entries under the watched subtree is
//! one revision, so its N events arrive in one WatchResponse. Every one must
//! come out of `next_entry_change`, then the N deletes of a second
//! transaction, then a lone write after them.

use std::time::Duration;

use etcd_client::{Client, DeleteOptions, Txn, TxnOp};
use iron_partition::{key, Dn, PartitionId};
use iron_store::entry::{dn_from_tree_key, next_entry_change, watch_subtree, EntryChange};
use iron_store::model::Entry;

const N: usize = 25;

fn endpoint() -> String {
    std::env::var("IRON_STORE_TEST_ENDPOINT").expect("set IRON_STORE_TEST_ENDPOINT (test/watch-batch-e2e.sh does)")
}

fn dn(i: usize) -> Dn {
    Dn::parse(&format!("cn=user{i:02},ou=batch,dc=watch,dc=lo")).unwrap()
}

fn entry(i: usize) -> Entry {
    let mut e = Entry::new();
    e.set("cn", [format!("user{i:02}")]);
    e
}

#[tokio::test]
#[ignore]
async fn every_event_of_a_multi_event_response_is_returned() {
    let pid = PartitionId::new("watchbatch").unwrap();
    let base = Dn::parse("ou=batch,dc=watch,dc=lo").unwrap();
    let mut c = Client::connect([endpoint()], None).await.unwrap();
    c.delete(key::partition_root(&pid), Some(DeleteOptions::new().with_prefix())).await.unwrap();

    let mut wc = Client::connect([endpoint()], None).await.unwrap();
    let mut watch = watch_subtree(&mut wc, &pid, &base).await.unwrap();
    let created = watch.message().await.unwrap().unwrap();
    assert!(created.created());

    // N puts in one transaction: one revision, one response.
    let puts: Vec<TxnOp> = (0..N).map(|i| TxnOp::put(key::entry_key(&pid, &dn(i)), entry(i).encode(), None)).collect();
    c.txn(Txn::new().and_then(puts)).await.unwrap();
    let deletes: Vec<TxnOp> = (0..N).map(|i| TxnOp::delete(key::entry_key(&pid, &dn(i)), None)).collect();
    c.txn(Txn::new().and_then(deletes)).await.unwrap();
    c.put(key::entry_key(&pid, &dn(99)), entry(99).encode(), None).await.unwrap();

    let mut puts_seen = Vec::new();
    let mut deletes_seen = Vec::new();
    let mut last = None;
    while last.is_none() {
        let change = tokio::time::timeout(Duration::from_secs(10), next_entry_change(&mut watch))
            .await
            .unwrap_or_else(|_| panic!("timed out after {} puts and {} deletes of {N} each", puts_seen.len(), deletes_seen.len()))
            .unwrap()
            .expect("watch stream ended");
        match change {
            EntryChange::Put { key, entry } => {
                let d = dn_from_tree_key(&pid, &key).unwrap();
                if d == dn(99) {
                    last = Some(entry);
                } else {
                    puts_seen.push(d);
                }
            }
            EntryChange::Delete { key } => deletes_seen.push(dn_from_tree_key(&pid, &key).unwrap()),
        }
    }
    println!("one {N}-put txn: {} put events; one {N}-delete txn: {} delete events; then the lone put", puts_seen.len(), deletes_seen.len());
    let want: Vec<Dn> = (0..N).map(dn).collect();
    puts_seen.sort_by_key(|d| d.to_string());
    deletes_seen.sort_by_key(|d| d.to_string());
    assert_eq!(puts_seen, want, "puts of one transaction were dropped");
    assert_eq!(deletes_seen, want, "deletes of one transaction were dropped");
    assert_eq!(last.unwrap().get("cn").unwrap()[0], "user99");

    c.delete(key::partition_root(&pid), Some(DeleteOptions::new().with_prefix())).await.unwrap();
}
