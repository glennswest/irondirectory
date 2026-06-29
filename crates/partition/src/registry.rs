//! The partition registry — irondirectory's equivalent of AD's crossRef
//! objects in `CN=Partitions,CN=Configuration`.
//!
//! It holds the global view of every naming context: where each lives (which
//! fastetcd cluster), its Kerberos realm, and its parent/child relationships.
//! Routing a DN means finding the partition whose base DN is the **longest
//! suffix** of that DN ([`PartitionRegistry::resolve`]).
//!
//! The registry is itself persisted in the forest configuration partition; a
//! small bootstrap config points at that partition's cluster. (That wiring
//! lands with `iron-store`; this crate provides the in-memory model and its
//! serialized form.)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::dn::Dn;
use crate::error::PartitionError;
use crate::partition::{ForestId, Partition, PartitionId, PartitionKind};

/// In-memory, serializable view of all partitions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PartitionRegistry {
    partitions: BTreeMap<PartitionId, Partition>,
}

impl PartitionRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a list of partitions, rejecting duplicate ids.
    pub fn from_partitions(
        parts: impl IntoIterator<Item = Partition>,
    ) -> Result<Self, PartitionError> {
        let mut reg = PartitionRegistry::new();
        for p in parts {
            reg.insert(p)?;
        }
        Ok(reg)
    }

    /// Insert a partition, rejecting a duplicate id.
    pub fn insert(&mut self, p: Partition) -> Result<(), PartitionError> {
        if self.partitions.contains_key(&p.id) {
            return Err(PartitionError::DuplicateId(p.id.to_string()));
        }
        self.partitions.insert(p.id.clone(), p);
        Ok(())
    }

    /// Number of partitions.
    pub fn len(&self) -> usize {
        self.partitions.len()
    }
    /// True if there are no partitions.
    pub fn is_empty(&self) -> bool {
        self.partitions.is_empty()
    }

    /// Look up a partition by id.
    pub fn get(&self, id: &PartitionId) -> Option<&Partition> {
        self.partitions.get(id)
    }

    /// Iterate over all partitions.
    pub fn iter(&self) -> impl Iterator<Item = &Partition> {
        self.partitions.values()
    }

    /// Route a DN to the naming context that owns it: the partition whose base
    /// DN is the longest suffix of `dn`. `None` if no partition contains it.
    pub fn resolve(&self, dn: &Dn) -> Option<&Partition> {
        self.partitions
            .values()
            .filter(|p| dn.is_within(&p.base_dn))
            .max_by_key(|p| p.base_dn.depth())
    }

    /// Like [`resolve`](Self::resolve) but returns a descriptive error.
    pub fn resolve_or_err(&self, dn: &Dn) -> Result<&Partition, PartitionError> {
        self.resolve(dn)
            .ok_or_else(|| PartitionError::NoOwningPartition(dn.to_string()))
    }

    /// The superior (parent) partition of `id`, if recorded and present.
    pub fn superior_of(&self, id: &PartitionId) -> Option<&Partition> {
        self.get(id)
            .and_then(|p| p.superior.as_ref())
            .and_then(|sid| self.get(sid))
    }

    /// The subordinate (child) partitions of `id` that are present.
    pub fn subordinates_of(&self, id: &PartitionId) -> Vec<&Partition> {
        let Some(p) = self.get(id) else {
            return Vec::new();
        };
        p.subordinates.iter().filter_map(|c| self.get(c)).collect()
    }

    /// All partitions in a forest.
    pub fn forest_partitions(&self, forest: &ForestId) -> Vec<&Partition> {
        self.partitions
            .values()
            .filter(|p| &p.forest == forest)
            .collect()
    }

    /// The single partition of `kind` in `forest` (e.g. the schema or
    /// configuration NC), if exactly one exists.
    pub fn partition_of_kind(&self, forest: &ForestId, kind: PartitionKind) -> Option<&Partition> {
        let mut found = self
            .partitions
            .values()
            .filter(|p| &p.forest == forest && p.kind == kind);
        let first = found.next()?;
        match found.next() {
            None => Some(first),
            Some(_) => None, // ambiguous
        }
    }

    /// The configuration naming context for a forest.
    pub fn config_partition(&self, forest: &ForestId) -> Option<&Partition> {
        self.partition_of_kind(forest, PartitionKind::Configuration)
    }

    /// The schema naming context for a forest.
    pub fn schema_partition(&self, forest: &ForestId) -> Option<&Partition> {
        self.partition_of_kind(forest, PartitionKind::Schema)
    }

    /// Base DNs of all naming contexts — used to populate the rootDSE
    /// `namingContexts` attribute.
    pub fn naming_contexts(&self) -> Vec<&Dn> {
        self.partitions.values().map(|p| &p.base_dn).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partition::ClusterRef;

    fn dn(s: &str) -> Dn {
        Dn::parse(s).unwrap()
    }
    fn forest() -> ForestId {
        ForestId::new("acme").unwrap()
    }
    fn cluster(port: u16) -> ClusterRef {
        ClusterRef::plaintext([format!("http://127.0.0.1:{port}")])
    }

    fn sample_registry() -> PartitionRegistry {
        // Two domains in a tree: parent dc=g10,dc=lo and child dc=emea,dc=g10,dc=lo,
        // each on its own cluster (D8).
        let parent = Partition::domain("g10", forest(), dn("dc=g10,dc=lo"), cluster(2379)).unwrap();
        let mut child = Partition::domain(
            "g10-emea",
            forest(),
            dn("dc=emea,dc=g10,dc=lo"),
            cluster(2479),
        )
        .unwrap()
        .with_superior(PartitionId::new("g10").unwrap());
        child.subordinates = vec![];
        let mut parent = parent;
        parent.subordinates = vec![PartitionId::new("g10-emea").unwrap()];
        PartitionRegistry::from_partitions([parent, child]).unwrap()
    }

    #[test]
    fn duplicate_id_rejected() {
        let p = Partition::domain("g10", forest(), dn("dc=g10,dc=lo"), cluster(2379)).unwrap();
        let dup = Partition::domain("g10", forest(), dn("dc=x,dc=lo"), cluster(2380)).unwrap();
        let mut reg = PartitionRegistry::new();
        reg.insert(p).unwrap();
        assert!(matches!(
            reg.insert(dup),
            Err(PartitionError::DuplicateId(_))
        ));
    }

    #[test]
    fn resolve_picks_longest_suffix() {
        let reg = sample_registry();
        // A DN under the child resolves to the child, not the parent.
        let p = reg
            .resolve(&dn("cn=alice,ou=users,dc=emea,dc=g10,dc=lo"))
            .unwrap();
        assert_eq!(p.id.as_str(), "g10-emea");
        // A DN under only the parent resolves to the parent.
        let p = reg.resolve(&dn("cn=bob,ou=users,dc=g10,dc=lo")).unwrap();
        assert_eq!(p.id.as_str(), "g10");
        // Outside every NC: no owner.
        assert!(reg.resolve(&dn("dc=other,dc=net")).is_none());
    }

    #[test]
    fn superior_and_subordinate_navigation() {
        let reg = sample_registry();
        let child = PartitionId::new("g10-emea").unwrap();
        let parent = PartitionId::new("g10").unwrap();
        assert_eq!(reg.superior_of(&child).unwrap().id, parent);
        let subs = reg.subordinates_of(&parent);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].id, child);
    }

    #[test]
    fn resolve_or_err_reports_dn() {
        let reg = sample_registry();
        let err = reg.resolve_or_err(&dn("dc=other,dc=net")).unwrap_err();
        assert!(matches!(err, PartitionError::NoOwningPartition(_)));
    }

    #[test]
    fn registry_serde_roundtrip() {
        let reg = sample_registry();
        let j = serde_json::to_string_pretty(&reg).unwrap();
        let back: PartitionRegistry = serde_json::from_str(&j).unwrap();
        assert_eq!(reg, back);
    }

    #[test]
    fn naming_contexts_lists_all_bases() {
        let reg = sample_registry();
        let ncs = reg.naming_contexts();
        assert_eq!(ncs.len(), 2);
    }
}
