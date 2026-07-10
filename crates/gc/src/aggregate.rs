//! In-memory partial-replica cache fed by per-partition watch streams
//! (#12): the "read-only partial replica" the Global Catalog design
//! (D8) and later the federated GAL (D9) both build on top of.
//!
//! Keyed by the DN's normalized string form rather than `Dn` itself --
//! `Dn` doesn't implement `Hash` -- storing the parsed `Dn` alongside the
//! entry so scope-matching (`is_within`/`depth`) doesn't need to
//! re-parse the key on every search.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use iron_partition::{Dn, PartitionId};
use iron_store::model::Entry;

/// Attributes retained in the aggregate -- the "partial" in partial
/// replica. Applied at ingest, not at read time (unlike iron-ldap's
/// per-request attribute projection): once an attribute is dropped
/// here, it never enters the replica at all, the stricter reading of
/// D9's "no directory-content leakage" requirement this same engine
/// will need once #13 configures it for the cross-forest GAL. A
/// conservative starting default for the in-forest case (#12); tune via
/// `IRON_GC_ATTRIBUTES`.
pub const DEFAULT_ATTRIBUTES: &[&str] =
    &["objectclass", "cn", "uid", "mail", "displayname", "sn", "givenname", "uidnumber", "gidnumber"];

/// Drops every attribute not in `whitelist` (case-insensitive), keeping
/// the rest of the entry as-is.
pub fn project(entry: &Entry, whitelist: &[String]) -> Entry {
    let mut projected = Entry::new();
    for name in entry.attr_names() {
        if whitelist.iter().any(|w| w.eq_ignore_ascii_case(name)) {
            if let Some(values) = entry.get(name) {
                projected.set(name, values.iter().cloned());
            }
        }
    }
    projected
}

/// The aggregated partial replica: DN string -> (parsed DN, projected
/// entry). A plain `RwLock`, not `iron_store::store::Store`'s
/// `tokio::sync::Mutex` -- reads/writes here are synchronous in-memory
/// map operations, never an await point, so a std lock is the right
/// tool and can't deadlock against the watch tasks' own async work.
#[derive(Default)]
pub struct Aggregate {
    entries: RwLock<HashMap<String, (Dn, Entry)>>,
    /// Partitions whose initial bootstrap scan (`crate::watch`) has
    /// completed at least once -- distinct from `entries` being
    /// non-empty, since a genuinely empty domain partition is a valid,
    /// fully-loaded state, not an unready one. Used by the health check
    /// to answer "has this process finished bootstrapping" rather than
    /// "does it happen to hold any data right now."
    ready: RwLock<HashSet<PartitionId>>,
}

impl Aggregate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_ready(&self, pid: PartitionId) {
        self.ready.write().unwrap().insert(pid);
    }

    pub fn ready_count(&self) -> usize {
        self.ready.read().unwrap().len()
    }

    pub fn upsert(&self, dn: Dn, entry: Entry) {
        self.entries.write().unwrap().insert(dn.to_string(), (dn, entry));
    }

    pub fn remove(&self, dn: &Dn) {
        self.entries.write().unwrap().remove(&dn.to_string());
    }

    pub fn get(&self, dn: &Dn) -> Option<Entry> {
        self.entries.read().unwrap().get(&dn.to_string()).map(|(_, e)| e.clone())
    }

    /// Every `(Dn, Entry)` pair currently held -- a cloned snapshot, not
    /// a live view, so a search can filter/iterate without holding the
    /// lock for the whole response.
    pub fn snapshot(&self) -> Vec<(Dn, Entry)> {
        self.entries.read().unwrap().values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whitelist() -> Vec<String> {
        DEFAULT_ATTRIBUTES.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn project_drops_attributes_not_in_the_whitelist() {
        let mut e = Entry::new();
        e.set("cn", ["alice"]);
        e.set("userpassword", ["should-never-leave-the-partition"]);
        let projected = project(&e, &whitelist());
        assert_eq!(projected.get("cn"), Some(&["alice".to_string()][..]));
        assert_eq!(projected.get("userpassword"), None);
    }

    #[test]
    fn project_is_case_insensitive_against_the_whitelist() {
        let mut e = Entry::new();
        e.set("CN", ["alice"]);
        let projected = project(&e, &whitelist());
        assert_eq!(projected.get("cn"), Some(&["alice".to_string()][..]));
    }

    #[test]
    fn aggregate_upsert_get_remove_roundtrip() {
        let agg = Aggregate::new();
        let dn = Dn::parse("cn=alice,dc=g10,dc=lo").unwrap();
        let mut e = Entry::new();
        e.set("cn", ["alice"]);
        agg.upsert(dn.clone(), e.clone());
        assert_eq!(agg.get(&dn), Some(e));
        assert_eq!(agg.len(), 1);
        agg.remove(&dn);
        assert_eq!(agg.get(&dn), None);
        assert_eq!(agg.len(), 0);
    }

    #[test]
    fn ready_count_tracks_distinct_partitions_not_entry_count() {
        let agg = Aggregate::new();
        assert_eq!(agg.ready_count(), 0);
        agg.mark_ready(iron_partition::PartitionId::new("g12gc").unwrap());
        // A partition with zero entries is still a fully-loaded, ready
        // partition -- readiness must not be inferred from `len()`.
        assert_eq!(agg.len(), 0);
        assert_eq!(agg.ready_count(), 1);
        agg.mark_ready(iron_partition::PartitionId::new("g12gc").unwrap());
        assert_eq!(agg.ready_count(), 1, "marking the same partition ready twice must be idempotent");
    }

    #[test]
    fn snapshot_reflects_multiple_partitions_worth_of_entries() {
        let agg = Aggregate::new();
        let a = Dn::parse("cn=alice,dc=g10,dc=lo").unwrap();
        let b = Dn::parse("cn=bob,dc=emea,dc=g10,dc=lo").unwrap();
        agg.upsert(a, Entry::new());
        agg.upsert(b, Entry::new());
        assert_eq!(agg.snapshot().len(), 2);
    }
}
