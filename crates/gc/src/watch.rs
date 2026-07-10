//! Per-partition watch subscription (#12): connects to a domain
//! partition's own cluster, subscribes to its subtree, does the initial
//! bootstrap scan, then loops forever applying `Put`/`Delete` events to
//! the shared [`Aggregate`].
//!
//! Subscribes *before* scanning, deliberately: a write landing between
//! "scan" and "watch subscribed" would otherwise be missed forever
//! (until something else touches the same DN). Subscribing first means
//! such a write is applied twice -- once via the scan, once via the
//! replayed watch event -- which is harmless, since re-applying the
//! same entry to the aggregate is idempotent. The alternative (scan
//! first) trades a permanent gap for a slightly simpler ordering
//! argument; not worth it.

use std::sync::Arc;
use std::time::Duration;

use iron_partition::Partition;
use iron_store::entry::{dn_from_tree_key, next_entry_change, scan_subtree, watch_subtree, EntryChange};
use iron_store::model::Entry;

use crate::aggregate::{project, Aggregate};

/// Watches one domain partition for as long as the process runs,
/// reconnecting on any error. A dead/reconnecting watcher just means
/// that partition's slice of the aggregate goes stale (D8: "Eventual
/// (staleness OK)"), not a process crash -- so this never returns.
pub async fn run(partition: Partition, aggregate: Arc<Aggregate>, whitelist: Arc<Vec<String>>) {
    loop {
        if let Err(e) = watch_once(&partition, &aggregate, &whitelist).await {
            tracing::warn!(partition = %partition.id, error = %e, "watch stream ended, reconnecting in 5s");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn watch_once(partition: &Partition, aggregate: &Aggregate, whitelist: &[String]) -> anyhow::Result<()> {
    let mut client = iron_store::connect(&partition.cluster).await?;

    let mut stream = watch_subtree(&mut client, &partition.id, &partition.base_dn).await?;

    let rows = scan_subtree(&mut client, &partition.id, &partition.base_dn).await?;
    for (key, value) in rows {
        if let Err(e) = apply_put(partition, aggregate, whitelist, &key, &value) {
            tracing::warn!(%key, error = %e, "failed to apply scanned entry");
        }
    }
    aggregate.mark_ready(partition.id.clone());
    tracing::info!(partition = %partition.id, entries = aggregate.len(), "initial load complete");

    while let Some(change) = next_entry_change(&mut stream).await? {
        match change {
            EntryChange::Put { key, entry } => {
                if let Err(e) = apply_entry(partition, aggregate, whitelist, &key, entry) {
                    tracing::warn!(%key, error = %e, "failed to apply watched put");
                }
            }
            EntryChange::Delete { key } => match dn_from_tree_key(&partition.id, &key) {
                Ok(dn) => aggregate.remove(&dn),
                Err(e) => tracing::warn!(%key, error = %e, "failed to decode watched key as a DN"),
            },
        }
    }
    anyhow::bail!("watch stream ended")
}

fn apply_put(partition: &Partition, aggregate: &Aggregate, whitelist: &[String], key: &str, value: &[u8]) -> anyhow::Result<()> {
    let entry = Entry::decode(value)?;
    apply_entry(partition, aggregate, whitelist, key, entry)
}

fn apply_entry(partition: &Partition, aggregate: &Aggregate, whitelist: &[String], key: &str, entry: Entry) -> anyhow::Result<()> {
    let dn = dn_from_tree_key(&partition.id, key)?;
    aggregate.upsert(dn, project(&entry, whitelist));
    Ok(())
}
