// =============================================================================
// api/routes/auth_token.rs — /v1/auth/token/* self-management endpoints
//
// Vault-compatible token self-service, authenticated by the X-Vault-Token
// header (the token authenticates itself — no master key needed):
//   GET  /v1/auth/token/lookup-self   metadata about the calling token
//   POST /v1/auth/token/revoke-self   revoke the calling token (204)
//   POST /v1/auth/token/renew-self    extend a renewable token's lifetime
// =============================================================================

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::api::response::VaultResponse;
use crate::error::AppError;
use crate::state::AppState;
use crate::tokens;

// ─────────────────────────────────────────────────────────────────────────────
// bearer
// Extract the X-Vault-Token header value, or 403 if absent/empty.
// ─────────────────────────────────────────────────────────────────────────────
fn bearer(headers: &HeaderMap) -> Result<String, AppError> {
    headers
        .get("x-vault-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or(AppError::Forbidden)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/auth/token/lookup-self
// Return metadata about the calling token (no secret material).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn lookup_self(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, AppError> {
    let raw = bearer(&headers)?;
    let info = tokens::lookup(&state.db, &raw).await?;
    Ok(Json(VaultResponse::new(json!({
        "id": info.token_id,
        "accessor": info.token_id,
        "display_name": info.display_name,
        "policies": info.allowed_paths,
        "ttl": info.ttl_seconds(),
        "renewable": info.renewable,
        "creation_time": info.created_at,
        "expire_time": info.expires_at.map(|e| e.to_rfc3339()),
        "meta": { "vault_id": info.vault_id, "allowed_ips": info.allowed_ips },
    })))
    .into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/auth/token/revoke-self
// Revoke the calling token (effective immediately); 204 on success.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn revoke_self(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, AppError> {
    let raw = bearer(&headers)?;
    tokens::revoke_self(&state.db, &raw).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Body for renew-self: optional lifetime increment in seconds.
#[derive(Debug, Default, Deserialize)]
pub struct RenewBody {
    pub increment: Option<i64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/auth/token/renew-self
// Extend a renewable token by `increment` seconds (or its stored renew period).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn renew_self(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<RenewBody>>,
) -> Result<Response, AppError> {
    let raw = bearer(&headers)?;
    let increment = body.and_then(|Json(b)| b.increment);
    let info = tokens::renew(&state.db, &raw, increment).await?;
    Ok(Json(VaultResponse::new(json!({
        "ttl": info.ttl_seconds(),
        "renewable": info.renewable,
        "expire_time": info.expires_at.map(|e| e.to_rfc3339()),
    })))
    .into_response())
}
