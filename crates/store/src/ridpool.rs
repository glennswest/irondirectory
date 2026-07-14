//! RID (relative identifier) pool allocation (#17): a monotonic,
//! compare-and-swap-guarded counter per partition, the same primitive
//! real AD uses to hand out the trailing sub-authority of every object
//! SID it creates (`domain_sid`-`rid` = object SID, see
//! `iron_partition::sid::Sid::with_sub_authority`).
//!
//! Lives at a dedicated key outside the entry tree and secondary-index
//! namespaces (`/iron/<pid>/ridpool/next`, distinct from
//! `/iron/<pid>/tree/…`/`/iron/<pid>/idx/…`), guarded by an etcd
//! compare-and-swap loop rather than `index.rs`'s read-then-write-in-one-
//! txn pattern -- that pattern is safe only because this project's
//! `Store` serializes all operations behind one `tokio::sync::Mutex`
//! per process; a RID pool must also stay correct if a *second*,
//! independent process (e.g. a future SAMR service, #19) touches the
//! same partition's pool concurrently, so it gets a real
//! read-compare-write retry loop instead.

use etcd_client::{Client, Compare, CompareOp, Txn, TxnOp};
use iron_partition::PartitionId;

use crate::StoreError;

/// RIDs below this are the well-known range real AD reserves (500
/// Administrator, 512 Domain Admins, 513 Domain Users, ... ) --
/// allocation starts just above it, matching AD's own convention.
pub const FIRST_ALLOCATABLE_RID: u32 = 1000;

fn pool_key(pid: &PartitionId) -> String {
    format!("/iron/{pid}/ridpool/next")
}

/// Allocates and returns the next RID for `pid`'s domain partition,
/// retrying under contention. Never returns the same RID twice for a
/// given partition (even across process restarts -- the counter is
/// durable in fastetcd, not in-memory).
pub async fn allocate_rid(client: &mut Client, pid: &PartitionId) -> Result<u32, StoreError> {
    let key = pool_key(pid);
    loop {
        let resp = client.get(key.clone(), None).await?;
        let (current, compare) = match resp.kvs().first() {
            Some(kv) => {
                let s = kv.value_str().map_err(StoreError::Etcd)?;
                let n: u32 = s
                    .parse()
                    .map_err(|_| StoreError::RidPoolCorrupt(pid.to_string(), format!("non-numeric value {s:?}")))?;
                (n, Compare::value(key.clone(), CompareOp::Equal, kv.value().to_vec()))
            }
            // Key doesn't exist yet: CAS on "still doesn't exist"
            // (create_revision == 0 is etcd's idiom for absence).
            None => (FIRST_ALLOCATABLE_RID, Compare::create_revision(key.clone(), CompareOp::Equal, 0)),
        };
        let next = current + 1;
        let txn = Txn::new().when(vec![compare]).and_then(vec![TxnOp::put(key.clone(), next.to_string(), None)]);
        let resp = client.txn(txn).await?;
        if resp.succeeded() {
            return Ok(current);
        }
        // Someone else won the race; retry with a fresh read.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_key_is_namespaced_under_the_partition_and_disjoint_from_tree_and_idx() {
        let pid = PartitionId::new("g10").unwrap();
        let key = pool_key(&pid);
        assert_eq!(key, "/iron/g10/ridpool/next");
        assert!(!key.starts_with("/iron/g10/tree/"));
        assert!(!key.starts_with("/iron/g10/idx/"));
    }
}
