//! Secondary-index maintenance: keeps `/iron/<pid>/idx/<attr>/<value>/<dn>`
//! entries (D2) consistent with `/iron/<pid>/tree/<dn>` via a single etcd
//! transaction per write, so a crash never leaves a stale index behind.

use etcd_client::{Client, GetOptions, Txn, TxnOp};
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

async fn read_entry(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
) -> Result<Option<Entry>, StoreError> {
    let resp = client.get(key::entry_key(pid, dn), None).await?;
    resp.kvs()
        .first()
        .map(|kv| Entry::decode(kv.value()))
        .transpose()
}

/// Atomically writes `entry` at `dn` and updates its secondary indexes,
/// removing any index entries left over from a prior value at the same DN.
pub async fn put_entry_indexed(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
    entry: &Entry,
    spec: &IndexSpec,
) -> Result<(), StoreError> {
    let old = read_entry(client, pid, dn).await?;
    let new_keys = index_keys_for(pid, dn, entry, spec);
    let old_keys = old
        .as_ref()
        .map(|e| index_keys_for(pid, dn, e, spec))
        .unwrap_or_default();

    let mut ops = Vec::new();
    for k in &old_keys {
        if !new_keys.contains(k) {
            ops.push(TxnOp::delete(k.clone(), None));
        }
    }
    ops.push(TxnOp::put(key::entry_key(pid, dn), entry.encode(), None));
    for k in &new_keys {
        ops.push(TxnOp::put(k.clone(), dn.to_string(), None));
    }

    client.txn(Txn::new().and_then(ops)).await?;
    Ok(())
}

/// Atomically deletes the entry at `dn` and every secondary index entry it
/// had. A no-op (not an error) if the entry doesn't exist.
pub async fn delete_entry_indexed(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
    spec: &IndexSpec,
) -> Result<(), StoreError> {
    let Some(old) = read_entry(client, pid, dn).await? else {
        return Ok(());
    };
    let old_keys = index_keys_for(pid, dn, &old, spec);

    let mut ops = vec![TxnOp::delete(key::entry_key(pid, dn), None)];
    for k in old_keys {
        ops.push(TxnOp::delete(k, None));
    }
    client.txn(Txn::new().and_then(ops)).await?;
    Ok(())
}

/// Every DN indexed under `(attr, value)` within partition `pid`.
pub async fn lookup_by_index(
    client: &mut Client,
    pid: &PartitionId,
    attr: &str,
    value: &str,
) -> Result<Vec<Dn>, StoreError> {
    let prefix = key::index_prefix(pid, attr, value);
    let resp = client
        .get(prefix, Some(GetOptions::new().with_prefix()))
        .await?;
    resp.kvs()
        .iter()
        .map(|kv| {
            let s = kv.value_str().map_err(StoreError::Etcd)?;
            Dn::parse(s).map_err(StoreError::Partition)
        })
        .collect()
}
