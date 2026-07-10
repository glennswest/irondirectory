//! `/userinfo` (OpenID Connect Core §5.3): `Authorization: Bearer
//! <access_token>` -> fresh claims re-read from the directory. Verifies
//! the access token's signature and expiry itself (self-contained JWT,
//! no separate token-introspection call) rather than trusting the
//! claims embedded at issuance time for anything but `sub` -- email/name
//! are re-read live so a directory change between token issuance and
//! this call is reflected, not stale.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use iron_partition::Dn;
use serde_json::{json, Value};

use crate::claims::{now_secs, AccessTokenClaims};
use crate::AppState;

pub async fn userinfo(State(app): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let unauthorized = |desc: &str| Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_token", "error_description": desc}))));

    let Some(auth) = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return unauthorized("missing Authorization header");
    };
    let Some(token) = auth.strip_prefix("Bearer ") else {
        return unauthorized("expected a Bearer token");
    };

    let claims: AccessTokenClaims = {
        let mut key = app.signing_key.lock().await;
        match crate::jwt::verify(&app.fips, &mut key, token) {
            Ok(c) => c,
            Err(_) => return unauthorized("token signature is invalid or malformed"),
        }
    };
    if claims.exp < now_secs() {
        return unauthorized("token has expired");
    }

    let Ok(subject_dn) = Dn::parse(&claims.sub) else {
        return unauthorized("token subject is malformed");
    };
    let entry = {
        let mut store = app.store.lock().await;
        store.get_entry(&subject_dn).await.ok().flatten()
    };
    let Some(entry) = entry else {
        return unauthorized("the token's subject no longer exists");
    };

    let scopes: Vec<&str> = claims.scope.split_whitespace().collect();
    let attr = |name: &str| entry.get(name).and_then(|v| v.first()).cloned();
    let mut body = json!({ "sub": claims.sub });
    if scopes.contains(&"email") {
        if let Some(email) = attr("mail") {
            body["email"] = json!(email);
        }
    }
    if scopes.contains(&"profile") {
        if let Some(name) = attr("cn") {
            body["name"] = json!(name);
        }
    }
    if let Some(uid) = attr("uid").or_else(|| attr("cn")) {
        body["preferred_username"] = json!(uid);
    }
    Ok(Json(body))
}
