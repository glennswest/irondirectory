//! Persists the [`PartitionRegistry`] (crossRef-equivalent records, one
//! per naming context) in the forest **configuration partition** (#9).
//!
//! `iron-partition`'s own doc comment describes this crate's job
//! precisely: "The registry is itself persisted in the forest
//! configuration partition; a small bootstrap config points at that
//! partition's cluster. (That wiring lands with `iron-store`; this crate
//! provides the in-memory model and its serialized form.)" -- the model
//! (`Partition`, already `Serialize`/`Deserialize`) and the config/domain
//! partition kinds already existed; this crate is the missing wiring.
//!
//! Storage shape: each partition's record lives at `cn=<id>,<config_dn>`
//! within the configuration partition's own DIT, its full JSON
//! serialization in one `partitiondata` attribute -- simplest possible
//! mapping, and `Partition`'s serde roundtrip is already unit-tested in
//! `iron-partition`, so there's no new encode/decode logic to get wrong.
//! This mirrors Active Directory's `CN=Partitions,CN=Configuration,...`
//! crossRef objects, minus the extra `CN=Partitions` container (not
//! needed yet -- nothing else lives in the configuration partition).
//!
//! `iron-config-ctl` (the child-domain provisioning tool) is the only
//! consumer for now; `iron-ldapd`/`iron-kdcd` still take a single
//! statically-configured partition via env vars (multi-partition-aware
//! daemons are a later issue, not this one -- #9's scope is "create a
//! partition, register it, wire superior/subordinate refs").

use iron_partition::{Dn, Partition, PartitionError, PartitionId, PartitionRegistry};
use iron_store::model::Entry;
use iron_store::store::Store;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("store error: {0}")]
    Store(#[from] iron_store::StoreError),
    #[error("partition error: {0}")]
    Partition(#[from] PartitionError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("entry at {0} has no partitiondata attribute")]
    MissingPartitionData(Dn),
    #[error("registry error: {0}")]
    Registry(String),
}

/// Attribute holding a partition record's full JSON serialization.
pub const ATTR_PARTITION_DATA: &str = "partitiondata";

/// The DN a partition's record lives at within the configuration
/// partition's own DIT.
pub fn record_dn(config_dn: &Dn, id: &PartitionId) -> Result<Dn, Error> {
    Ok(Dn::parse(&format!("cn={},{config_dn}", id.as_str()))?)
}

/// Builds the DIT entry for a partition record.
pub fn partition_to_entry(p: &Partition) -> Result<Entry, Error> {
    let mut entry = Entry::new();
    entry.set("objectclass", ["top".to_string()]);
    entry.set("cn", [p.id.to_string()]);
    entry.set(ATTR_PARTITION_DATA, [serde_json::to_string(p)?]);
    Ok(entry)
}

/// The inverse of [`partition_to_entry`].
pub fn entry_to_partition(dn: &Dn, entry: &Entry) -> Result<Partition, Error> {
    let raw = entry.get(ATTR_PARTITION_DATA).and_then(|v| v.first()).ok_or_else(|| Error::MissingPartitionData(dn.clone()))?;
    Ok(serde_json::from_str(raw)?)
}

/// Loads every partition record from the configuration partition's DIT
/// into a fresh [`PartitionRegistry`].
pub async fn load_registry(store: &mut Store, config_dn: &Dn) -> Result<PartitionRegistry, Error> {
    let entries = store.scan_subtree(config_dn).await?;
    let mut partitions = Vec::with_capacity(entries.len());
    for (dn, entry) in entries {
        // The configuration partition's own base entry (config_dn itself,
        // before any records are written under it) has no partitiondata
        // -- skip rather than error, so an empty/freshly-created config
        // partition loads as an empty registry instead of failing.
        if dn == *config_dn && entry.get(ATTR_PARTITION_DATA).is_none() {
            continue;
        }
        partitions.push(entry_to_partition(&dn, &entry)?);
    }
    PartitionRegistry::from_partitions(partitions).map_err(|e| Error::Registry(e.to_string()))
}

/// Writes (or overwrites) one partition's record in the configuration
/// partition's DIT.
pub async fn put_partition(store: &mut Store, config_dn: &Dn, index_spec: &iron_store::index::IndexSpec, p: &Partition) -> Result<(), Error> {
    let dn = record_dn(config_dn, &p.id)?;
    let entry = partition_to_entry(p)?;
    store.put_entry(&dn, &entry, index_spec).await?;
    Ok(())
}

/// Index spec for the configuration partition (just `cn`, matching every
/// other partition's minimal indexing convention).
pub fn index_spec() -> iron_store::index::IndexSpec {
    iron_store::index::IndexSpec::new(["cn"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use iron_partition::{ClusterRef, ForestId};

    fn forest() -> ForestId {
        ForestId::new("acme").unwrap()
    }

    #[test]
    fn partition_entry_roundtrip() {
        let p = Partition::domain("g10", forest(), Dn::parse("dc=g10,dc=lo").unwrap(), ClusterRef::plaintext(["http://127.0.0.1:2379"]))
            .unwrap();
        let entry = partition_to_entry(&p).unwrap();
        let dn = Dn::parse("cn=g10,cn=configuration,dc=lo").unwrap();
        let back = entry_to_partition(&dn, &entry).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn missing_partitiondata_is_an_error() {
        let mut entry = Entry::new();
        entry.set("cn", ["g10".to_string()]);
        let dn = Dn::parse("cn=g10,cn=configuration,dc=lo").unwrap();
        assert!(matches!(entry_to_partition(&dn, &entry), Err(Error::MissingPartitionData(_))));
    }

    #[test]
    fn record_dn_is_child_of_config_dn() {
        let config_dn = Dn::parse("cn=configuration,dc=lo").unwrap();
        let id = PartitionId::new("g10").unwrap();
        let dn = record_dn(&config_dn, &id).unwrap();
        assert_eq!(dn.to_string(), "cn=g10,cn=configuration,dc=lo");
    }
}
