//! Secondary-index maintenance: keeps `/iron/<pid>/idx/<attr>/<value>/<dn>`
//! entries (D2) consistent with `/iron/<pid>/tree/<dn>` via a single etcd
//! transaction per write, so a crash never leaves a stale index behind.
//!
//! Which index keys a write removes depends on the entry it replaces, read
//! just before. Every update and delete transaction is guarded on that
//! read still being current -- the entry key's `mod_revision`, or its
//! absence (`version == 0`) -- and on a failed guard the read and the
//! transaction are redone (finding e925e45000f8). Without the guard two
//! writers (two daemons, or two connections of one) that both read value A
//! and then wrote B and C left the entry at C with B's index behind, and a
//! delete racing a write removed the indexes of a stale value.

use etcd_client::{Client, Compare, CompareOp, Txn, TxnOp};
use iron_partition::{key, Dn, PartitionId};

use crate::model::Entry;
use crate::StoreError;

/// Which attributes get a secondary index, within a partition.
#[derive(Debug, Clone)]
pub struct IndexSpec(Vec<String>);

impl IndexSpec {
    pub fn new(attrs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        IndexSpec(attrs.into_iter().map(|a| a.into().to_ascii_lowercase()).collect())
    }
}

fn index_keys_for(pid: &PartitionId, dn: &Dn, entry: &Entry, spec: &IndexSpec) -> Vec<String> {
    let mut keys = Vec::new();
    for attr in &spec.0 {
        if let Some(values) = entry.get(attr) {
            for v in values {
                keys.push(key::index_key(pid, attr, v, dn));
            }
        }
    }
    keys
}

/// How many times a guarded write is redone after losing a race before
/// [`StoreError::Contended`]. Each retry follows a concurrent write that
/// committed, so this many in a row means sustained contention on one DN.
const MAX_ATTEMPTS: u32 = 64;

/// The entry at `dn` and the `mod_revision` it was read at.
async fn read_entry(client: &mut Client, pid: &PartitionId, dn: &Dn) -> Result<Option<(Entry, i64)>, StoreError> {
    let resp = crate::get(client, &key::entry_key(pid, dn), false).await?;
    resp.kvs().first().map(|kv| Ok((Entry::decode(kv.value())?, kv.mod_revision()))).transpose()
}

/// The guard that the entry key is still as it was read.
fn unchanged_since(entry_key: &str, read: Option<i64>) -> Compare {
    match read {
        Some(rev) => Compare::mod_revision(entry_key, CompareOp::Equal, rev),
        None => Compare::version(entry_key, CompareOp::Equal, 0),
    }
}

/// A short, growing pause between attempts, so racing writers spread out.
async fn back_off(attempt: u32) {
    let micros = 200u64 << attempt.min(6);
    tokio::time::sleep(std::time::Duration::from_micros(micros)).await;
}

/// Atomically writes `entry` at `dn` and updates its secondary indexes,
/// removing any index entries left over from a prior value at the same DN.
/// Guarded on that prior value still being current, and redone if it is not
/// (module docs).
pub async fn put_entry_indexed(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
    entry: &Entry,
    spec: &IndexSpec,
) -> Result<(), StoreError> {
    let entry_key = key::entry_key(pid, dn);
    let new_keys = index_keys_for(pid, dn, entry, spec);
    for attempt in 0..MAX_ATTEMPTS {
        let old = read_entry(client, pid, dn).await?;
        let old_keys = old.as_ref().map(|(e, _)| index_keys_for(pid, dn, e, spec)).unwrap_or_default();

        let mut ops = Vec::new();
        for k in &old_keys {
            if !new_keys.contains(k) {
                ops.push(TxnOp::delete(k.clone(), None));
            }
        }
        ops.push(TxnOp::put(entry_key.clone(), entry.encode(), None));
        for k in &new_keys {
            ops.push(TxnOp::put(k.clone(), dn.to_string(), None));
        }

        let guard = unchanged_since(&entry_key, old.as_ref().map(|(_, rev)| *rev));
        if client.txn(Txn::new().when([guard]).and_then(ops)).await?.succeeded() {
            return Ok(());
        }
        back_off(attempt).await;
    }
    Err(StoreError::Contended(dn.to_string()))
}

/// Writes `entry` at `dn` with its secondary indexes only if nothing exists
/// at `dn` yet, in one etcd transaction guarded on the entry key's version
/// being 0. Returns whether this call created it. Unlike a read-then-write,
/// two writers racing to create the same DN can't both win -- which
/// `iron-bootstrap` relies on when several members of one directory
/// provision it at once (#25).
pub async fn create_entry_indexed(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
    entry: &Entry,
    spec: &IndexSpec,
) -> Result<bool, StoreError> {
    let entry_key = key::entry_key(pid, dn);
    let mut ops = vec![TxnOp::put(entry_key.clone(), entry.encode(), None)];
    for k in index_keys_for(pid, dn, entry, spec) {
        ops.push(TxnOp::put(k, dn.to_string(), None));
    }
    let txn = Txn::new().when([Compare::version(entry_key, CompareOp::Equal, 0)]).and_then(ops);
    Ok(client.txn(txn).await?.succeeded())
}

/// Atomically deletes the entry at `dn` and every secondary index entry it
/// had. A no-op (not an error) if the entry doesn't exist. Guarded on the
/// entry still being the one read, and redone if it is not (module docs).
pub async fn delete_entry_indexed(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
    spec: &IndexSpec,
) -> Result<(), StoreError> {
    let entry_key = key::entry_key(pid, dn);
    for attempt in 0..MAX_ATTEMPTS {
        let Some((old, rev)) = read_entry(client, pid, dn).await? else {
            return Ok(());
        };
        let mut ops = vec![TxnOp::delete(entry_key.clone(), None)];
        for k in index_keys_for(pid, dn, &old, spec) {
            ops.push(TxnOp::delete(k, None));
        }
        let guard = unchanged_since(&entry_key, Some(rev));
        if client.txn(Txn::new().when([guard]).and_then(ops)).await?.succeeded() {
            return Ok(());
        }
        back_off(attempt).await;
    }
    Err(StoreError::Contended(dn.to_string()))
}

/// Every DN indexed under `(attr, value)` within partition `pid`.
pub async fn lookup_by_index(
    client: &mut Client,
    pid: &PartitionId,
    attr: &str,
    value: &str,
) -> Result<Vec<Dn>, StoreError> {
    let prefix = key::index_prefix(pid, attr, value);
    let resp = crate::get(client, &prefix, true).await?;
    resp.kvs()
        .iter()
        .map(|kv| {
            let s = kv.value_str().map_err(StoreError::Etcd)?;
            Dn::parse(s).map_err(StoreError::Partition)
        })
        .collect()
}
