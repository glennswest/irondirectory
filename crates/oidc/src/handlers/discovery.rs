use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use crate::AppState;

pub async fn openid_configuration(State(app): State<Arc<AppState>>) -> Json<Value> {
    Json(crate::discovery::openid_configuration(&app))
}

pub async fn jwks(State(app): State<Arc<AppState>>) -> Result<Json<Value>, StatusCode> {
    crate::discovery::jwks(&app).await.map(Json).map_err(|e| {
        tracing::error!("failed to build JWKS: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}
