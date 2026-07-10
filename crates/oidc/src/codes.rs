//! In-memory, single-use authorization code store (RFC 6749 §4.1). Codes
//! are minted by `/authorize` on a successful login and redeemed exactly
//! once by `/token` -- `consume` removes the entry atomically so a
//! replayed code (the same value presented twice) always fails the
//! second time, independent of the TTL check.
//!
//! Process-local only (a `Mutex<HashMap>`, not backed by fastetcd): fine
//! for #15's single-replica happy path, but means this doesn't
//! horizontally scale past one `iron-oidcd` process yet -- a later
//! concern, not this issue's scope.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

pub struct IssuedCode {
    pub client_id: String,
    pub redirect_uri: String,
    /// The authenticated user's DN -- `/token` re-reads the entry fresh
    /// from the directory rather than caching claims here, so a
    /// password/attribute change between login and token exchange (a
    /// narrow window) is never a source of stale claims.
    pub subject_dn: String,
    pub nonce: Option<String>,
    pub scope: String,
    expires_at: Instant,
}

/// The caller-supplied half of an [`IssuedCode`] -- everything except
/// `expires_at`, which `CodeStore::issue` computes from `ttl`. A plain
/// struct rather than a long parameter list.
pub struct NewCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub subject_dn: String,
    pub nonce: Option<String>,
    pub scope: String,
}

#[derive(Default)]
pub struct CodeStore {
    codes: Mutex<HashMap<String, IssuedCode>>,
}

impl CodeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mints a fresh random code (32 bytes of FIPS DRBG output,
    /// base64url-encoded) and stores it, valid for `ttl`.
    pub async fn issue(&self, fips: &iron_crypto::FipsContext, new: NewCode, ttl: Duration) -> Result<String, iron_crypto::Error> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let raw = iron_crypto::kerberos::random_bytes(fips, 32)?;
        let code = URL_SAFE_NO_PAD.encode(raw);
        let entry = IssuedCode {
            client_id: new.client_id,
            redirect_uri: new.redirect_uri,
            subject_dn: new.subject_dn,
            nonce: new.nonce,
            scope: new.scope,
            expires_at: Instant::now() + ttl,
        };
        self.codes.lock().await.insert(code.clone(), entry);
        Ok(code)
    }

    /// Removes and returns the code's entry if it exists and hasn't
    /// expired -- `None` either way otherwise, so a caller can't tell
    /// "expired" from "never existed"/"already used" (no information
    /// that would help an attacker guess valid codes).
    pub async fn consume(&self, code: &str) -> Option<IssuedCode> {
        let entry = self.codes.lock().await.remove(code)?;
        if entry.expires_at < Instant::now() {
            return None;
        }
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iron_crypto::FipsContext;

    fn sample_code() -> NewCode {
        NewCode {
            client_id: "client".into(),
            redirect_uri: "https://example.com/cb".into(),
            subject_dn: "cn=alice,dc=g10,dc=lo".into(),
            nonce: None,
            scope: "openid".into(),
        }
    }

    #[tokio::test]
    async fn issued_code_is_consumed_exactly_once() {
        let fips = FipsContext::new().unwrap();
        let store = CodeStore::new();
        let code = store.issue(&fips, sample_code(), Duration::from_secs(60)).await.unwrap();
        let consumed = store.consume(&code).await;
        assert!(consumed.is_some());
        assert_eq!(consumed.unwrap().client_id, "client");
        assert!(store.consume(&code).await.is_none(), "a code must not be redeemable twice");
    }

    #[tokio::test]
    async fn expired_code_is_rejected() {
        let fips = FipsContext::new().unwrap();
        let store = CodeStore::new();
        let code = store.issue(&fips, sample_code(), Duration::from_millis(1)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(store.consume(&code).await.is_none());
    }

    #[tokio::test]
    async fn unknown_code_is_rejected() {
        let store = CodeStore::new();
        assert!(store.consume("nonexistent").await.is_none());
    }
}
