//! Multi-cluster connection registry (invariant #4): resolves a DN to its
//! partition (D8) and holds one connected `etcd_client::Client` per
//! partition, since partitions may live on different fastetcd clusters.

use std::collections::HashMap;

use etcd_client::Client;
use iron_partition::{Dn, Partition, PartitionId, PartitionRegistry};

use crate::index::IndexSpec;
use crate::model::Entry;
use crate::StoreError;

pub struct Store {
    registry: PartitionRegistry,
    clients: HashMap<PartitionId, Client>,
}

impl Store {
    /// Connects to every partition's cluster up front.
    pub async fn connect(registry: PartitionRegistry) -> Result<Self, StoreError> {
        let mut clients = HashMap::new();
        for partition in registry.iter() {
            let client = crate::connect(&partition.cluster).await?;
            clients.insert(partition.id.clone(), client);
        }
        Ok(Store { registry, clients })
    }

    pub fn registry(&self) -> &PartitionRegistry {
        &self.registry
    }

    fn resolve(&self, dn: &Dn) -> Result<&Partition, StoreError> {
        self.registry
            .resolve(dn)
            .ok_or_else(|| StoreError::NoPartitionFor(dn.to_string()))
    }

    fn client_mut(&mut self, pid: &PartitionId) -> Result<&mut Client, StoreError> {
        self.clients
            .get_mut(pid)
            .ok_or_else(|| StoreError::NotConnected(pid.as_str().to_string()))
    }

    /// Writes `entry` at `dn`, on whichever cluster hosts `dn`'s partition,
    /// maintaining the secondary indexes in `spec`.
    pub async fn put_entry(
        &mut self,
        dn: &Dn,
        entry: &Entry,
        spec: &IndexSpec,
    ) -> Result<(), StoreError> {
        let pid = self.resolve(dn)?.id.clone();
        let client = self.client_mut(&pid)?;
        crate::index::put_entry_indexed(client, &pid, dn, entry, spec).await
    }

    /// Reads the entry at `dn`, if present.
    pub async fn get_entry(&mut self, dn: &Dn) -> Result<Option<Entry>, StoreError> {
        let pid = self.resolve(dn)?.id.clone();
        let client = self.client_mut(&pid)?;
        let bytes = crate::entry::get_entry(client, &pid, dn).await?;
        bytes.map(|b| Entry::decode(&b)).transpose()
    }

    /// Deletes the entry at `dn` and its secondary indexes.
    pub async fn delete_entry(&mut self, dn: &Dn, spec: &IndexSpec) -> Result<(), StoreError> {
        let pid = self.resolve(dn)?.id.clone();
        let client = self.client_mut(&pid)?;
        crate::index::delete_entry_indexed(client, &pid, dn, spec).await
    }

    /// Every DN indexed under `(attr, value)` within `dn`'s partition.
    pub async fn lookup_by_index(
        &mut self,
        dn_in_partition: &Dn,
        attr: &str,
        value: &str,
    ) -> Result<Vec<Dn>, StoreError> {
        let pid = self.resolve(dn_in_partition)?.id.clone();
        let client = self.client_mut(&pid)?;
        crate::index::lookup_by_index(client, &pid, attr, value).await
    }

    /// Every entry in the subtree rooted at `dn` (inclusive), decoded.
    /// DNs are reconstructed from storage keys, so their case may be
    /// normalized rather than the original display case (see
    /// [`crate::entry::dn_from_tree_key`]).
    pub async fn scan_subtree(&mut self, dn: &Dn) -> Result<Vec<(Dn, Entry)>, StoreError> {
        let pid = self.resolve(dn)?.id.clone();
        let client = self.client_mut(&pid)?;
        let rows = crate::entry::scan_subtree(client, &pid, dn).await?;
        rows.into_iter()
            .map(|(k, v)| {
                let dn = crate::entry::dn_from_tree_key(&pid, &k)?;
                let entry = Entry::decode(&v)?;
                Ok((dn, entry))
            })
            .collect()
    }
}
