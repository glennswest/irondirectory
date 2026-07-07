//! Password storage KDF (D4: "FIPS-approved KDF (PBKDF2 via OpenSSL)").
//!
//! Stored format: `$pbkdf2-sha256$<iterations>$<salt-hex>$<hash-hex>` --
//! self-describing (iteration count travels with the hash, so it can be
//! bumped for new passwords without invalidating old ones) and trivially
//! parseable without a new dependency (hex, not base64).

use crate::{Error, FipsContext};
use ossl::derive::Pbkdf2Derive;
use ossl::digest::DigestAlg;
use ossl::rand::EvpRandCtx;

pub const DEFAULT_ITERATIONS: usize = 210_000; // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32; // SHA-256 output
const SCHEME: &str = "pbkdf2-sha256";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn derive(ctx: &FipsContext, password: &[u8], salt: &[u8], iterations: usize) -> Result<[u8; HASH_LEN], Error> {
    let mut kdf = Pbkdf2Derive::new(ctx.inner(), DigestAlg::Sha2_256)?;
    kdf.set_iterations(iterations);
    kdf.set_password(password);
    kdf.set_salt(salt);
    let mut out = [0u8; HASH_LEN];
    kdf.derive(&mut out)?;
    Ok(out)
}

/// Hashes `password` with a fresh random salt at [`DEFAULT_ITERATIONS`],
/// returning the self-describing stored form.
pub fn hash_password(ctx: &FipsContext, password: &[u8]) -> Result<String, Error> {
    let mut rng = EvpRandCtx::new_hmac_drbg(ctx.inner(), DigestAlg::Sha2_256, b"iron-crypto pbkdf2 salt")?;
    let mut salt = [0u8; SALT_LEN];
    rng.generate(&[], &mut salt)?;

    let hash = derive(ctx, password, &salt, DEFAULT_ITERATIONS)?;
    Ok(format!(
        "${SCHEME}${DEFAULT_ITERATIONS}${}${}",
        to_hex(&salt),
        to_hex(&hash)
    ))
}

/// Verifies `password` against a stored hash produced by [`hash_password`].
/// Constant-time comparison on the derived hash (not on the whole string --
/// the scheme/iteration/salt fields aren't secret).
pub fn verify_password(ctx: &FipsContext, password: &[u8], stored: &str) -> Result<bool, Error> {
    let mut parts = stored.split('$');
    let (Some(""), Some(scheme), Some(iter_str), Some(salt_hex), Some(hash_hex)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Ok(false);
    };
    if scheme != SCHEME || parts.next().is_some() {
        return Ok(false);
    }
    let Ok(iterations) = iter_str.parse::<usize>() else {
        return Ok(false);
    };
    let (Some(salt), Some(expected)) = (from_hex(salt_hex), from_hex(hash_hex)) else {
        return Ok(false);
    };
    if expected.len() != HASH_LEN {
        return Ok(false);
    }

    let computed = derive(ctx, password, &salt, iterations)?;
    let mut diff: u8 = 0;
    for (a, b) in computed.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    Ok(diff == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrip() {
        let ctx = FipsContext::new().unwrap();
        let stored = hash_password(&ctx, b"correct horse battery staple").unwrap();
        assert!(stored.starts_with("$pbkdf2-sha256$210000$"));
        assert!(verify_password(&ctx, b"correct horse battery staple", &stored).unwrap());
        assert!(!verify_password(&ctx, b"wrong password", &stored).unwrap());
    }

    #[test]
    fn different_salts_for_same_password() {
        let ctx = FipsContext::new().unwrap();
        let a = hash_password(&ctx, b"hunter2").unwrap();
        let b = hash_password(&ctx, b"hunter2").unwrap();
        assert_ne!(a, b, "salts should differ between calls");
    }

    #[test]
    fn rejects_malformed_stored_hash() {
        let ctx = FipsContext::new().unwrap();
        assert!(!verify_password(&ctx, b"x", "not-a-valid-format").unwrap());
        assert!(!verify_password(&ctx, b"x", "$pbkdf2-sha256$abc$deadbeef$deadbeef").unwrap());
    }
}
