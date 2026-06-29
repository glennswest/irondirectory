//! Partition-scoped key encoding for the fastetcd backend.
//!
//! Every key is rooted under a partition id so partitions are disjoint and may
//! live on different clusters (D8): `/iron/<pid>/…`. The directory tree uses
//! reverse-ordered, normalized RDN components so that a subtree is a key prefix
//! and a range scan over that prefix returns the subtree.
//!
//! Layout:
//! - entry:        `/iron/<pid>/tree/<dc=lo/dc=g10/ou=users/cn=alice>`
//! - subtree scan: prefix `/iron/<pid>/tree/<…base…>/`
//! - index:        `/iron/<pid>/idx/<attr>/<value>/<dn>`

use crate::dn::Dn;
use crate::partition::PartitionId;

/// Root prefix for all of a partition's keys (`/iron/<pid>/`).
pub fn partition_root(pid: &PartitionId) -> String {
    format!("/iron/{pid}/")
}

/// Prefix for a partition's directory tree (`/iron/<pid>/tree/`).
pub fn tree_root(pid: &PartitionId) -> String {
    format!("/iron/{pid}/tree/")
}

/// Storage key for the entry at `dn` within partition `pid`. The base DN of the
/// partition need not be stripped — the full reversed path is used, which keeps
/// keys self-describing and lets the same encoding serve every naming context.
pub fn entry_key(pid: &PartitionId, dn: &Dn) -> String {
    let mut k = tree_root(pid);
    k.push_str(&dn.reversed_components().join("/"));
    k
}

/// Prefix that matches every entry strictly below `dn` (the children subtree).
/// To scan an inclusive subtree, read [`entry_key`] and then range-scan this
/// prefix.
pub fn subtree_prefix(pid: &PartitionId, dn: &Dn) -> String {
    let mut k = entry_key(pid, dn);
    k.push('/');
    k
}

/// Index key for an equality/presence lookup: maps `(attr, value)` to the DN
/// that has it. `value` and `dn` are escaped so `/` cannot break the key.
pub fn index_key(pid: &PartitionId, attr: &str, value: &str, dn: &Dn) -> String {
    format!(
        "/iron/{pid}/idx/{}/{}/{}",
        escape_segment(&attr.to_ascii_lowercase()),
        escape_segment(value),
        escape_segment(&dn.to_string()),
    )
}

/// Prefix matching every DN indexed under `(attr, value)`.
pub fn index_prefix(pid: &PartitionId, attr: &str, value: &str) -> String {
    format!(
        "/iron/{pid}/idx/{}/{}/",
        escape_segment(&attr.to_ascii_lowercase()),
        escape_segment(value),
    )
}

/// Percent-escape `%` and `/` so a value never collides with the key delimiter.
fn escape_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            '/' => out.push_str("%2F"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid() -> PartitionId {
        PartitionId::new("g10").unwrap()
    }

    #[test]
    fn entry_key_is_reverse_ordered() {
        let dn = Dn::parse("cn=alice,ou=users,dc=g10,dc=lo").unwrap();
        assert_eq!(
            entry_key(&pid(), &dn),
            "/iron/g10/tree/dc=lo/dc=g10/ou=users/cn=alice"
        );
    }

    #[test]
    fn subtree_prefix_contains_descendant_keys() {
        let base = Dn::parse("dc=g10,dc=lo").unwrap();
        let child = Dn::parse("cn=alice,ou=users,dc=g10,dc=lo").unwrap();
        let prefix = subtree_prefix(&pid(), &base);
        assert_eq!(prefix, "/iron/g10/tree/dc=lo/dc=g10/");
        assert!(entry_key(&pid(), &child).starts_with(&prefix));
    }

    #[test]
    fn base_entry_is_just_below_root() {
        let base = Dn::parse("dc=g10,dc=lo").unwrap();
        assert_eq!(entry_key(&pid(), &base), "/iron/g10/tree/dc=lo/dc=g10");
    }

    #[test]
    fn index_key_escapes_slashes() {
        let dn = Dn::parse("cn=alice,dc=g10,dc=lo").unwrap();
        let k = index_key(&pid(), "mail", "a/b@g10.lo", &dn);
        assert!(k.starts_with("/iron/g10/idx/mail/a%2Fb@g10.lo/"));
        assert!(k.contains("cn=alice"));
    }
}
