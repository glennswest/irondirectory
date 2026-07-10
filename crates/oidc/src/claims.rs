//! Claim sets for the two token kinds this server issues (#15). Both are
//! plain JWTs (see `jwt.rs`) -- there's no opaque/introspection-based
//! access token here, since a self-contained signed token is sufficient
//! for a single-issuer server with no separate resource-server registry.

use serde::{Deserialize, Serialize};

/// RFC 7519 / OpenID Connect Core §2 standard + profile/email claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
}

/// This server's own access token claims -- not a standardized shape
/// (OAuth2 deliberately leaves the access token's format up to the
/// issuer), just enough for `/userinfo` to identify the subject and
/// confirm the token hasn't expired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub scope: String,
}

/// Seconds since the Unix epoch, right now.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
