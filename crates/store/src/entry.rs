//! Partition-scoped entry put/get/watch, built on `iron_partition::key`'s
//! encoding (D2: `/iron/<pid>/tree/<reversed-rdn-path>`).

use crate::StoreError;
use etcd_client::{Client, EventType, GetOptions, WatchOptions};
use iron_partition::{key, Dn, PartitionError, PartitionId};

/// Reconstructs a [`Dn`] from a raw fastetcd key under a partition's tree
/// (as returned by [`scan_subtree`]).
///
/// Storage keys are case-normalized (see `iron_partition::dn`'s module
/// docs: attribute values are case-folded for the key, not display case),
/// so the returned `Dn`'s components may not match the original entry's
/// display case. Fine for routing/equality; a follow-up (stash an exact-
/// case `entryDN` pseudo-attribute on write) would fix display fidelity.
pub fn dn_from_tree_key(pid: &PartitionId, raw_key: &str) -> Result<Dn, StoreError> {
    let root = key::tree_root(pid);
    let suffix = raw_key.strip_prefix(&root).ok_or_else(|| {
        StoreError::Partition(PartitionError::InvalidDn {
            input: raw_key.to_string(),
            reason: "key is not under this partition's tree root".into(),
        })
    })?;
    let comma_form: String = suffix.split('/').rev().collect::<Vec<_>>().join(",");
    Dn::parse(&comma_form).map_err(StoreError::Partition)
}

/// Writes the raw entry value at `dn` within partition `pid`.
pub async fn put_entry(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
    value: impl Into<Vec<u8>>,
) -> Result<(), StoreError> {
    client.put(key::entry_key(pid, dn), value.into(), None).await?;
    Ok(())
}

/// Reads the raw entry value at `dn` within partition `pid`, if present.
pub async fn get_entry(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
) -> Result<Option<Vec<u8>>, StoreError> {
    let resp = client.get(key::entry_key(pid, dn), None).await?;
    Ok(resp.kvs().first().map(|kv| kv.value().to_vec()))
}

/// Range-scans every entry in the subtree rooted at `dn` (inclusive of
/// `dn` itself), within partition `pid`. Returns `(dn_suffix, value)`
/// pairs in lexicographic key order.
pub async fn scan_subtree(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
    let base = key::entry_key(pid, dn);
    let prefix = key::subtree_prefix(pid, dn);
    let resp = client
        .get(prefix.clone(), Some(GetOptions::new().with_prefix()))
        .await?;
    let mut out: Vec<(String, Vec<u8>)> = resp
        .kvs()
        .iter()
        .map(|kv| (kv.key_str().unwrap_or_default().to_string(), kv.value().to_vec()))
        .collect();
    // The base entry itself doesn't match the `<prefix>/` scan; fetch it
    // separately so callers get the whole subtree, not just descendants.
    if let Some(v) = get_entry(client, pid, dn).await? {
        out.insert(0, (base, v));
    }
    Ok(out)
}

/// One observed change under a watched subtree.
#[derive(Debug)]
pub struct SubtreeEvent {
    pub key: String,
    pub kind: EventType,
    pub value: Vec<u8>,
}

/// Watches every key change under the subtree rooted at `dn` (inclusive),
/// within partition `pid`. Returns the raw watch stream's first (creation)
/// response consumed internally; call `.message()` on the returned stream
/// for subsequent events, or use [`next_subtree_event`] for a
/// higher-level poll.
pub async fn watch_subtree(
    client: &mut Client,
    pid: &PartitionId,
    dn: &Dn,
) -> Result<etcd_client::WatchStream, StoreError> {
    let prefix = key::subtree_prefix(pid, dn);
    let stream = client
        .watch(prefix, Some(WatchOptions::new().with_prefix()))
        .await?;
    Ok(stream)
}

/// Pulls the next data event (put/delete) off a subtree watch stream,
/// skipping bookkeeping-only responses (creation acks, progress notifies).
pub async fn next_subtree_event(
    stream: &mut etcd_client::WatchStream,
) -> Result<Option<SubtreeEvent>, StoreError> {
    while let Some(resp) = stream.message().await? {
        if let Some(event) = resp.events().first() {
            if let Some(kv) = event.kv() {
                return Ok(Some(SubtreeEvent {
                    key: kv.key_str().unwrap_or_default().to_string(),
                    kind: event.event_type(),
                    value: kv.value().to_vec(),
                }));
            }
        }
    }
    Ok(None)
}

/// A watched change, decoded into an [`crate::model::Entry`] on `Put`.
#[derive(Debug)]
pub enum EntryChange {
    Put { key: String, entry: crate::model::Entry },
    Delete { key: String },
}

/// Like [`next_subtree_event`], but decodes `Put` values as
/// [`crate::model::Entry`] rather than raw bytes.
pub async fn next_entry_change(
    stream: &mut etcd_client::WatchStream,
) -> Result<Option<EntryChange>, StoreError> {
    let Some(event) = next_subtree_event(stream).await? else {
        return Ok(None);
    };
    Ok(Some(match event.kind {
        EventType::Delete => EntryChange::Delete { key: event.key },
        EventType::Put => EntryChange::Put {
            key: event.key,
            entry: crate::model::Entry::decode(&event.value)?,
        },
    }))
}
