//! OIDC discovery document (`/.well-known/openid-configuration`, OpenID
//! Connect Discovery §3) and JWKS (`/.well-known/jwks.json`, RFC 7517) --
//! the two endpoints an OIDC relying party (OpenShift's `oauth-server`,
//! or any other client) fetches once at startup to learn where
//! everything else lives and what key to verify ID tokens with.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

use crate::AppState;

/// The `kid` every token this process issues is signed with -- fixed
/// since there's exactly one active signing key per process (see
/// `AppState::signing_key`'s doc comment on key rotation being out of
/// scope for #15's first vertical slice).
pub const KEY_ID: &str = "iron-oidc-1";

pub fn openid_configuration(app: &AppState) -> Value {
    let issuer = &app.issuer;
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "name", "preferred_username"],
    })
}

pub async fn jwks(app: &AppState) -> Result<Value, iron_crypto::Error> {
    let key = app.signing_key.lock().await;
    let (x, y) = key.public_xy()?;
    Ok(json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": KEY_ID,
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        }]
    }))
}
