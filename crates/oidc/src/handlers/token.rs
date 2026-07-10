//! `/token` (RFC 6749 §4.1.3/§4.1.4): exchanges a one-time authorization
//! code for a signed ID token + access token. Supports both client
//! authentication methods `openid-configuration` advertises --
//! `client_secret_basic` (an `Authorization: Basic` header) and
//! `client_secret_post` (`client_id`/`client_secret` form fields),
//! preferring the header if both happen to be present.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Form;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use iron_partition::Dn;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::claims::{now_secs, AccessTokenClaims, IdTokenClaims};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

fn error_response(status: StatusCode, error: &str, description: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"error": error, "error_description": description})))
}

/// Extracts `(client_id, client_secret)` from an `Authorization: Basic`
/// header, if present and well-formed.
fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

pub async fn token(State(app): State<Arc<AppState>>, headers: HeaderMap, Form(form): Form<TokenForm>) -> (StatusCode, Json<Value>) {
    let (client_id, client_secret) = match basic_auth(&headers) {
        Some(creds) => creds,
        None => match (form.client_id.clone(), form.client_secret.clone()) {
            (Some(id), Some(secret)) => (id, secret),
            _ => return error_response(StatusCode::UNAUTHORIZED, "invalid_client", "missing client credentials"),
        },
    };
    if !app.clients.authenticate(&client_id, &client_secret) {
        return error_response(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client or bad secret");
    }

    if form.grant_type != "authorization_code" {
        return error_response(StatusCode::BAD_REQUEST, "unsupported_grant_type", "only authorization_code is supported");
    }
    let (Some(code), Some(redirect_uri)) = (&form.code, &form.redirect_uri) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "code and redirect_uri are required");
    };

    let Some(issued) = app.codes.consume(code).await else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "code is unknown, expired, or already used");
    };
    if issued.client_id != client_id || &issued.redirect_uri != redirect_uri {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "code was not issued to this client/redirect_uri");
    }

    let Ok(subject_dn) = Dn::parse(&issued.subject_dn) else {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "stored subject DN is malformed");
    };
    let entry = {
        let mut store = app.store.lock().await;
        store.get_entry(&subject_dn).await.ok().flatten()
    };
    let Some(entry) = entry else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "the authenticated user no longer exists");
    };

    let scopes: Vec<&str> = issued.scope.split_whitespace().collect();
    let attr = |name: &str| entry.get(name).and_then(|v| v.first()).cloned();
    let email = scopes.contains(&"email").then(|| attr("mail")).flatten();
    let name = scopes.contains(&"profile").then(|| attr("cn")).flatten();
    let preferred_username = attr("uid").or_else(|| attr("cn"));

    let iat = now_secs();
    let exp = iat + app.token_ttl.as_secs();
    let id_claims = IdTokenClaims {
        iss: app.issuer.clone(),
        sub: issued.subject_dn.clone(),
        aud: client_id.clone(),
        exp,
        iat,
        nonce: issued.nonce.clone(),
        email,
        name,
        preferred_username,
    };
    let access_claims = AccessTokenClaims { iss: app.issuer.clone(), sub: issued.subject_dn.clone(), exp, iat, scope: issued.scope.clone() };

    let mut key = app.signing_key.lock().await;
    let id_token = match crate::jwt::sign(&app.fips, &mut key, crate::discovery::KEY_ID, &id_claims) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("failed to sign id_token: {e}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "failed to sign id_token");
        }
    };
    let access_token = match crate::jwt::sign(&app.fips, &mut key, crate::discovery::KEY_ID, &access_claims) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("failed to sign access_token: {e}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "failed to sign access_token");
        }
    };
    drop(key);

    (
        StatusCode::OK,
        Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": app.token_ttl.as_secs(),
            "id_token": id_token,
            "scope": issued.scope,
        })),
    )
}
