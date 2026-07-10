//! `/authorize` (RFC 6749 §4.1.1/§4.1.2): `GET` renders a login form,
//! `POST` checks the submitted credentials against the directory and
//! redirects to the client's `redirect_uri` with a one-time
//! authorization code on success.
//!
//! Security-load-bearing ordering: `client_id`/`redirect_uri` are
//! validated against the static registry *before* anything else,
//! including before deciding how to report any other error. Only once
//! `redirect_uri` is confirmed to belong to a real, registered client is
//! it safe to redirect errors back to it (RFC 6749 §4.1.2.1) -- an
//! unvalidated `redirect_uri` must never be redirected to, or this
//! becomes an open redirector.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

fn login_page(params: &AuthorizeParams, error: Option<&str>) -> Html<String> {
    let error_html = error.map(|e| format!("<p style=\"color:red\">{}</p>", html_escape(e))).unwrap_or_default();
    Html(format!(
        r#"<!doctype html>
<html><head><title>Sign in</title></head><body>
{error_html}
<form method="post" action="/authorize">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="nonce" value="{nonce}">
<label>Username <input type="text" name="username" autofocus></label><br>
<label>Password <input type="password" name="password"></label><br>
<button type="submit">Sign in</button>
</form>
</body></html>"#,
        error_html = error_html,
        client_id = html_escape(&params.client_id),
        redirect_uri = html_escape(&params.redirect_uri),
        scope = html_escape(&params.scope),
        state = html_escape(params.state.as_deref().unwrap_or("")),
        nonce = html_escape(params.nonce.as_deref().unwrap_or("")),
    ))
}

/// Validates `client_id`/`redirect_uri` together against the registry.
/// Both must match the SAME registered client -- a `redirect_uri` that
/// merely matches some other client's registration is not good enough
/// (that's exactly the open-redirect mistake this check exists to rule
/// out).
fn validate_client<'a>(app: &'a AppState, client_id: &str, redirect_uri: &str) -> Option<&'a crate::clients::Client> {
    let client = app.clients.get(client_id)?;
    (client.redirect_uri == redirect_uri).then_some(client)
}

pub async fn show_login(State(app): State<Arc<AppState>>, Query(params): Query<AuthorizeParams>) -> Response {
    if validate_client(&app, &params.client_id, &params.redirect_uri).is_none() {
        return (StatusCode::BAD_REQUEST, "unknown client_id or redirect_uri does not match registration").into_response();
    }
    if params.response_type != "code" {
        let mut redirect = format!("{}?error=unsupported_response_type", params.redirect_uri);
        if let Some(state) = &params.state {
            redirect.push_str("&state=");
            redirect.push_str(&urlencoding_encode(state));
        }
        return Redirect::to(&redirect).into_response();
    }
    login_page(&params, None).into_response()
}

pub async fn submit_login(State(app): State<Arc<AppState>>, Form(form): Form<LoginForm>) -> Response {
    let params = AuthorizeParams {
        response_type: "code".to_string(),
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        scope: form.scope.clone(),
        state: form.state.clone(),
        nonce: form.nonce.clone(),
    };
    if validate_client(&app, &params.client_id, &params.redirect_uri).is_none() {
        return (StatusCode::BAD_REQUEST, "unknown client_id or redirect_uri does not match registration").into_response();
    }

    let mut store = app.store.lock().await;
    let Some((dn, entry)) = crate::handlers::resolve_user(&mut store, &app.base_dn, &app.login_attribute, &form.username).await else {
        drop(store);
        return login_page(&params, Some("Invalid username or password")).into_response();
    };
    let Some(stored) = entry.get(super::USER_PASSWORD_ATTR).and_then(|v| v.first()) else {
        drop(store);
        return login_page(&params, Some("Invalid username or password")).into_response();
    };
    let ok = iron_crypto::pbkdf2::verify_password(&app.fips, form.password.as_bytes(), stored).unwrap_or(false);
    drop(store);
    if !ok {
        return login_page(&params, Some("Invalid username or password")).into_response();
    }

    let new_code = crate::codes::NewCode {
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        subject_dn: dn.to_string(),
        nonce: params.nonce.clone(),
        scope: params.scope.clone(),
    };
    let code = match app.codes.issue(&app.fips, new_code, app.code_ttl).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to issue authorization code: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "failed to issue authorization code").into_response();
        }
    };

    let mut redirect = format!("{}?code={}", params.redirect_uri, urlencoding_encode(&code));
    if let Some(state) = &params.state {
        redirect.push_str("&state=");
        redirect.push_str(&urlencoding_encode(state));
    }
    Redirect::to(&redirect).into_response()
}

/// Minimal percent-encoding for a query-string value -- no new
/// dependency for the handful of characters (`&`, `=`, `%`, space) that
/// would otherwise break the redirect URL.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
