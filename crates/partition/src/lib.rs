//! `iron-partition` — the foundational naming-context / partition model for
//! irondirectory.
//!
//! Per decision **D8**, the directory is never a monolithic tree: it is a set of
//! partitions (naming contexts), each mapped to its own strongly-consistent
//! fastetcd Raft cluster, federated by trust + referrals + watch-fed
//! aggregation. This crate makes that structure load-bearing from the first
//! commit so it never has to be retrofitted.
//!
//! It provides:
//! - [`Dn`] — RFC 4514 distinguished names, with suffix-containment routing.
//! - [`Partition`] / [`PartitionKind`] / [`PartitionId`] / [`ForestId`] /
//!   [`ClusterRef`] — the naming-context model (D8/D9).
//! - [`PartitionRegistry`] — the crossRef-equivalent global view; routes a DN to
//!   the partition whose base DN is its longest suffix.
//! - [`key`] — partition-scoped fastetcd key encoding (`/iron/<pid>/…`), where a
//!   subtree is a key prefix.
//!
//! Everything else in irondirectory (`iron-store`, `iron-ldap`, `iron-kdc`, …)
//! depends on these types.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod dn;
pub mod error;
pub mod key;
pub mod partition;
pub mod registry;

pub use dn::{Ava, Dn, Rdn};
pub use error::{PartitionError, Result};
pub use partition::{
    realm_from_dn, ClusterRef, ForestId, Partition, PartitionId, PartitionKind, TlsRef,
};
pub use registry::PartitionRegistry;
