//! Concurrent writers keep secondary indexes consistent (finding
//! e925e45000f8): every update and delete is guarded on the entry it read.
//!
//! Needs a fastetcd/etcd endpoint of its own (it wipes its partition
//! prefix): `test/index-race-e2e.sh` starts a throwaway one and runs
//!   IRON_STORE_TEST_ENDPOINT=http://127.0.0.1:PORT \
//!     cargo test -p iron-store --test index_race -- --ignored --nocapture
//!
//! Each writer has its own etcd client, as two daemons would. After the
//! storm the index must name the DN under exactly the value(s) the final
//! entry holds, or under nothing if the entry is gone.

use etcd_client::{Client, DeleteOptions, GetOptions};
use iron_partition::{key, Dn, PartitionId};
use iron_store::index::{delete_entry_indexed, put_entry_indexed, IndexSpec};
use iron_store::model::Entry;

const WRITERS: usize = 16;
const ROUNDS: usize = 20;

fn endpoint() -> String {
    std::env::var("IRON_STORE_TEST_ENDPOINT").expect("set IRON_STORE_TEST_ENDPOINT (test/index-race-e2e.sh does)")
}

async fn client() -> Client {
    Client::connect([endpoint()], None).await.unwrap()
}

fn spec() -> IndexSpec {
    IndexSpec::new(["uid"])
}

fn entry(uid: &str) -> Entry {
    let mut e = Entry::new();
    e.set("cn", ["racer".to_string()]);
    e.set("uid", [uid.to_string()]);
    e
}

/// Every `uid` value the index files `dn` under.
async fn indexed_uids(c: &mut Client, pid: &PartitionId, dn: &Dn) -> Vec<String> {
    let prefix = format!("/iron/{pid}/idx/uid/");
    let resp = c.get(prefix.clone(), Some(GetOptions::new().with_prefix())).await.unwrap();
    resp.kvs()
        .iter()
        .filter(|kv| kv.value_str().unwrap() == dn.to_string())
        .map(|kv| kv.key_str().unwrap()[prefix.len()..].split('/').next().unwrap().to_string())
        .collect()
}

async fn final_uid(c: &mut Client, pid: &PartitionId, dn: &Dn) -> Option<String> {
    let resp = c.get(key::entry_key(pid, dn), None).await.unwrap();
    resp.kvs().first().map(|kv| Entry::decode(kv.value()).unwrap().get("uid").unwrap()[0].clone())
}

async fn wipe(c: &mut Client, pid: &PartitionId) {
    c.delete(key::partition_root(pid), Some(DeleteOptions::new().with_prefix())).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn concurrent_puts_leave_only_the_final_values_index() {
    let pid = PartitionId::new("idxrace1").unwrap();
    let dn = Dn::parse("cn=racer,dc=race,dc=lo").unwrap();
    let mut c = client().await;
    wipe(&mut c, &pid).await;

    let mut tasks = Vec::new();
    for w in 0..WRITERS {
        let (pid, dn) = (pid.clone(), dn.clone());
        tasks.push(tokio::spawn(async move {
            let mut c = client().await;
            for r in 0..ROUNDS {
                put_entry_indexed(&mut c, &pid, &dn, &entry(&format!("w{w}r{r}")), &spec()).await.unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    let fin = final_uid(&mut c, &pid, &dn).await.expect("the entry exists");
    let idx = indexed_uids(&mut c, &pid, &dn).await;
    println!("{} puts by {WRITERS} writers: entry uid={fin}, index {idx:?}", WRITERS * ROUNDS);
    assert_eq!(idx, vec![fin], "stale index entries survived concurrent puts");
    wipe(&mut c, &pid).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn puts_racing_deletes_leave_index_and_entry_in_agreement() {
    let pid = PartitionId::new("idxrace2").unwrap();
    let dn = Dn::parse("cn=racer,dc=race,dc=lo").unwrap();
    let mut c = client().await;
    for trial in 0..5 {
        wipe(&mut c, &pid).await;
        let mut tasks = Vec::new();
        for w in 0..WRITERS {
            let (pid, dn) = (pid.clone(), dn.clone());
            tasks.push(tokio::spawn(async move {
                let mut c = client().await;
                for r in 0..ROUNDS / 2 {
                    if w % 2 == 0 {
                        put_entry_indexed(&mut c, &pid, &dn, &entry(&format!("t{trial}w{w}r{r}")), &spec()).await.unwrap();
                    } else {
                        delete_entry_indexed(&mut c, &pid, &dn, &spec()).await.unwrap();
                    }
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let fin = final_uid(&mut c, &pid, &dn).await;
        let idx = indexed_uids(&mut c, &pid, &dn).await;
        println!("trial {trial}: entry uid={fin:?}, index {idx:?}");
        assert_eq!(idx, fin.into_iter().collect::<Vec<_>>(), "index and entry disagree after puts racing deletes");
    }
    wipe(&mut c, &pid).await;
}
