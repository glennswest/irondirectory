//! JWT compact serialization for OIDC ID tokens and self-contained
//! access tokens (#15). Hand-rolled JOSE envelope (base64url header +
//! base64url payload + base64url ES256 signature) rather than a JWT
//! crate -- every JWT/JOSE crate (`jsonwebtoken`, `josekit`, ...) bundles
//! its own signing implementation (typically `ring`), which would bypass
//! `iron_crypto::sign` and the FIPS provider D4 requires end to end.
//! `base64` itself is just an encoding, not a crypto primitive, so using
//! it here doesn't have that problem.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use iron_crypto::sign::EcKeyPair;
use iron_crypto::FipsContext;
use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(#[from] iron_crypto::Error),
    #[error("malformed JWT: {0}")]
    Malformed(&'static str),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("signature verification failed")]
    BadSignature,
}

#[derive(serde::Serialize)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

/// Signs `claims` as a compact ES256 JWT, tagged with `kid` so a
/// verifier can pick the right key out of `crate::discovery`'s
/// published JWKS.
pub fn sign<T: Serialize>(ctx: &FipsContext, key: &mut EcKeyPair, kid: &str, claims: &T) -> Result<String, Error> {
    let header = Header { alg: "ES256", typ: "JWT", kid };
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = key.sign_es256(ctx, signing_input.as_bytes())?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verifies a compact ES256 JWT's signature and decodes its claims.
/// Deliberately does NOT check `exp`/`nbf`/`aud` -- what's valid differs
/// per caller (e.g. `/userinfo` doesn't care about `aud`, `/token`'s
/// client validation does), so those checks belong with whichever
/// claims struct the caller deserializes into, not here.
pub fn verify<T: DeserializeOwned>(ctx: &FipsContext, key: &mut EcKeyPair, token: &str) -> Result<T, Error> {
    let mut parts = token.splitn(3, '.');
    let (Some(header_b64), Some(claims_b64), Some(sig_b64)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::Malformed("expected three dot-separated parts"));
    };
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| Error::Malformed("signature is not valid base64url"))?;
    if !key.verify_es256(ctx, signing_input.as_bytes(), &sig)? {
        return Err(Error::BadSignature);
    }
    let claims_bytes = URL_SAFE_NO_PAD.decode(claims_b64).map_err(|_| Error::Malformed("claims are not valid base64url"))?;
    Ok(serde_json::from_slice(&claims_bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestClaims {
        sub: String,
        exp: u64,
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let ctx = FipsContext::new().unwrap();
        let mut key = EcKeyPair::generate(&ctx).unwrap();
        let claims = TestClaims { sub: "alice".into(), exp: 9999999999 };
        let token = sign(&ctx, &mut key, "kid-1", &claims).unwrap();
        assert_eq!(token.matches('.').count(), 2);
        let decoded: TestClaims = verify(&ctx, &mut key, &token).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let ctx = FipsContext::new().unwrap();
        let mut key = EcKeyPair::generate(&ctx).unwrap();
        let claims = TestClaims { sub: "alice".into(), exp: 100 };
        let token = sign(&ctx, &mut key, "kid-1", &claims).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        // Swap in a different payload claiming a different subject,
        // keeping the original (now-mismatched) signature.
        let tampered_claims = TestClaims { sub: "mallory".into(), exp: 100 };
        let tampered_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered_claims).unwrap());
        parts[1] = &tampered_b64;
        let tampered = parts.join(".");
        let result: Result<TestClaims, Error> = verify(&ctx, &mut key, &tampered);
        assert!(matches!(result, Err(Error::BadSignature)));
    }

    #[test]
    fn verify_rejects_malformed_token() {
        let ctx = FipsContext::new().unwrap();
        let mut key = EcKeyPair::generate(&ctx).unwrap();
        let result: Result<TestClaims, Error> = verify(&ctx, &mut key, "not-a-jwt");
        assert!(matches!(result, Err(Error::Malformed(_))));
    }
}
