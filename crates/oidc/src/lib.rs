//! iron-oidc: FIPS OAuth2/OpenID Connect authorization server (#15),
//! serving OpenShift's native OIDC identity provider and generic "modern
//! app" token SSO. Self-contained -- no external Keycloak/Dex runtime --
//! authenticating against the same LDAP directory `iron-ldap` serves
//! (reusing `iron_store::store::Store` + `iron_crypto::pbkdf2`, not a
//! second user database).
//!
//! Endpoints (RFC 6749 authorization code grant + OpenID Connect Core):
//! - `GET /.well-known/openid-configuration` -- discovery document.
//! - `GET /.well-known/jwks.json` -- this process's public signing key.
//! - `GET /authorize` -- renders a login form; `POST /authorize` checks
//!   the submitted credentials against the directory and, on success,
//!   redirects to the client's `redirect_uri` with a one-time
//!   authorization code.
//! - `POST /token` -- exchanges an authorization code for a signed ID
//!   token + access token (both ES256 JWTs, `jwt.rs`).
//! - `GET /userinfo` -- `Authorization: Bearer <access_token>` -> fresh
//!   claims re-read from the directory.
//!
//! ID tokens are signed with `iron_crypto::sign` (ES256/P-256 via the
//! OpenSSL FIPS provider, D4) -- never a JWT/JOSE crate, which would
//! bundle its own non-FIPS signing implementation.
//!
//! Happy-path scope (D10): single forest, single issuer, a fresh
//! signing keypair generated at every process start (no key
//! persistence -- previously-issued tokens and a previously-published
//! JWKS stop validating across a restart; documented, not silently
//! absent), authorization codes and the signing key held in memory only
//! (no cluster-wide state, so this doesn't horizontally scale past one
//! replica yet). The D9 cross-forest brokering hook is explicitly
//! deferred (D10) -- this is a single-forest IdP, not a broker.

pub mod claims;
pub mod clients;
pub mod codes;
pub mod discovery;
pub mod handlers;
pub mod jwt;

use std::sync::Arc;

use iron_crypto::sign::EcKeyPair;
use iron_crypto::FipsContext;
use iron_partition::Dn;
use iron_store::store::Store;
use tokio::sync::Mutex;

use clients::ClientRegistry;
use codes::CodeStore;

/// Shared server state handed to every request.
pub struct AppState {
    /// This server's own external base URL (e.g. `https://oidc.g10.lo`),
    /// used as the `iss` claim and to build every other endpoint URL in
    /// the discovery document.
    pub issuer: String,
    /// The directory backing user authentication (`/authorize`'s login
    /// form) and `/userinfo`'s claim lookups.
    pub store: Mutex<Store>,
    /// A DN within the served partition -- `Store::lookup_by_index` only
    /// uses this to resolve which cluster to query, not as a search
    /// filter, same as `iron-ldap`'s GSSAPI bind lookup.
    pub base_dn: Dn,
    /// Attribute this server resolves a submitted username against, via
    /// `Store::lookup_by_index` -- typically `uid`.
    pub login_attribute: String,
    pub fips: FipsContext,
    /// The ES256 keypair every token is signed with. A `Mutex` because
    /// `EcKeyPair::sign_es256`/`verify_es256` need `&mut self` (the
    /// underlying `ossl` signature context is stateful) -- see
    /// `iron_crypto::sign`'s doc comment on why there's no key
    /// persistence yet.
    pub signing_key: Mutex<EcKeyPair>,
    pub clients: ClientRegistry,
    pub codes: CodeStore,
    /// How long an issued authorization code stays valid before
    /// `CodeStore::consume` refuses it (RFC 6749 §4.1.2 recommends a
    /// short lifetime -- one-time use already limits replay, this bounds
    /// how long an intercepted-but-unused code stays dangerous).
    pub code_ttl: std::time::Duration,
    /// How long an issued ID/access token stays valid (the `exp` claim).
    pub token_ttl: std::time::Duration,
}

pub fn router(app: Arc<AppState>) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/.well-known/openid-configuration", get(handlers::discovery::openid_configuration))
        .route("/.well-known/jwks.json", get(handlers::discovery::jwks))
        .route("/authorize", get(handlers::authorize::show_login).post(handlers::authorize::submit_login))
        .route("/token", post(handlers::token::token))
        .route("/userinfo", get(handlers::userinfo::userinfo))
        .with_state(app)
}
