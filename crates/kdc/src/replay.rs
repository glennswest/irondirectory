//! Replay cache for AP-REQ Authenticators (RFC 4120 §3.2.3, §10).
//!
//! A server accepting an AP-REQ must refuse a second one carrying the
//! same Authenticator while it would still pass the clock-skew check.
//! The cache key is the SHA-256 of the Authenticator's ciphertext (what
//! MIT krb5 keys its replay cache on since 1.18): it is unique per
//! request, since every Authenticator is freshly encrypted with a random
//! confounder, and an attacker can only replay it byte for byte.
//!
//! An Authenticator is accepted only when its `ctime` is within
//! [`CLOCK_SKEW_SECS`] of the server's clock, so one first seen at `t`
//! is refused by the skew check from `t + 2 * CLOCK_SKEW_SECS` on: that
//! is how long an entry is kept. Expired entries are dropped on insert.
//! The cache is in memory, per process: a restarted daemon starts empty,
//! and each kpasswd instance keeps its own (as MIT's per-host rcache).

use std::collections::HashMap;
use std::sync::Mutex;

use crate::CLOCK_SKEW_SECS;

/// How long an entry is remembered, in seconds.
pub const RETENTION_SECS: i64 = 2 * CLOCK_SKEW_SECS;

#[derive(Default)]
pub struct ReplayCache {
    /// Authenticator hash -> the time it was first seen (Unix seconds).
    seen: Mutex<HashMap<[u8; 32], i64>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `tag` as seen at `now` (Unix seconds). Returns `false` if
    /// it was already seen within [`RETENTION_SECS`]: a replay.
    pub fn check_and_insert(&self, tag: [u8; 32], now: i64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, first| now - *first < RETENTION_SECS);
        match seen.entry(tag) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(now);
                true
            }
        }
    }

    /// Entries currently held.
    pub fn len(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Unix seconds now.
pub fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_identical_authenticator_is_a_replay() {
        let c = ReplayCache::new();
        assert!(c.check_and_insert([1; 32], 1000));
        assert!(!c.check_and_insert([1; 32], 1001));
        assert!(c.check_and_insert([2; 32], 1001));
    }

    #[test]
    fn entries_expire_after_twice_the_skew() {
        let c = ReplayCache::new();
        assert!(c.check_and_insert([1; 32], 1000));
        assert!(!c.check_and_insert([1; 32], 1000 + RETENTION_SECS - 1));
        // Past retention the skew check refuses it anyway; the entry goes.
        assert!(c.check_and_insert([3; 32], 1000 + RETENTION_SECS));
        assert_eq!(c.len(), 1);
    }
}
