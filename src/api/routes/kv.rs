// =============================================================================
// api/routes/kv.rs — /v1/secret/* KV v2 API (token-authenticated)
//
// HashiCorp Vault–compatible KV v2 over the token path. The token determines
// the vault (one token = one vault); the URL path is the secret path within it.
//   GET    /v1/secret/data/{*path}        read latest version
//   POST   /v1/secret/data/{*path}        write a new version ({"data": {...}})
//   DELETE /v1/secret/data/{*path}        soft-delete latest version
//   GET    /v1/secret/metadata/{*path}    list paths under a prefix (?list=true)
//
// Auth: X-Vault-Token: ev.<base64url> (also accepts Vault's s. prefix). The
// instance must be unsealed (master_key reachable). IP ACL lands in a follow-up.
// =============================================================================

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::api::response::VaultResponse;
use crate::error::AppError;
use crate::state::AppState;
use crate::tokens::{self, TokenAuth};
use crate::{secrets, vault};

/// Query flags for the metadata endpoint (`?list=true`).
#[derive(Debug, Default, Deserialize)]
pub struct MetadataQuery {
    #[serde(default)]
    pub list: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// authorize
// Resolve + validate the request token and enforce the path ACL, yielding the
// token context (with the unwrapped vault key) on success.
// ─────────────────────────────────────────────────────────────────────────────
async fn authorize(state: &Arc<AppState>, headers: &HeaderMap, path: &str) -> Result<TokenAuth, AppError> {
    let master = state.master_key_bytes().await.ok_or(AppError::Sealed)?;
    let raw = headers
        .get("x-vault-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(AppError::Forbidden)?;

    let auth = tokens::authenticate_token(&state.db, &master, raw).await?;
    if !tokens::path_allowed(&auth.allowed_paths, path) {
        return Err(AppError::Forbidden);
    }
    Ok(auth)
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/secret/data/{*path}
// Read and decrypt the latest live version, in KV v2 envelope shape.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn read(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let auth = authorize(&state, &headers, &path).await?;
    match secrets::read_latest(&state.db, &auth.vault_id, &path, &auth.vault_key).await? {
        Some((version, value)) => Ok(Json(VaultResponse::new(json!({
            "data": value,
            "metadata": { "version": version, "destroyed": false }
        })))
        .into_response()),
        None => Err(AppError::NotFound),
    }
}

/// KV v2 write body: `{"data": { ... }}`.
#[derive(Debug, Deserialize)]
pub struct WriteBody {
    pub data: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/secret/data/{*path}
// Write a new version of the secret; returns the new version metadata.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn write(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    Json(body): Json<WriteBody>,
) -> Result<Response, AppError> {
    let auth = authorize(&state, &headers, &path).await?;
    let creator = auth.created_by.as_deref().ok_or_else(|| AppError::Internal("token has no owner".into()))?;
    let version = secrets::write(&state.db, &auth.vault_id, &path, &body.data, &auth.vault_key, creator).await?;
    Ok(Json(VaultResponse::new(json!({ "version": version, "destroyed": false }))).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /v1/secret/data/{*path}
// Soft-delete the latest version (recoverable); 204 on success.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let auth = authorize(&state, &headers, &path).await?;
    secrets::soft_delete(&state.db, &auth.vault_id, &path).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/secret/metadata/{*path}?list=true  and  /v1/secret/metadata
// List secret paths under a prefix (Vault directory listing); empty = root.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn metadata_list(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    Query(q): Query<MetadataQuery>,
) -> Result<Response, AppError> {
    metadata_list_inner(&state, &headers, &path, q.list).await
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /v1/secret/metadata (root prefix)
// Same as `metadata_list` but for the empty prefix, which the wildcard route
// cannot capture.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn metadata_list_root(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<MetadataQuery>,
) -> Result<Response, AppError> {
    metadata_list_inner(&state, &headers, "", q.list).await
}

// ─────────────────────────────────────────────────────────────────────────────
// metadata_list_inner
// Shared listing logic for both the prefixed and root metadata routes.
// ─────────────────────────────────────────────────────────────────────────────
async fn metadata_list_inner(state: &Arc<AppState>, headers: &HeaderMap, path: &str, list: bool) -> Result<Response, AppError> {
    let auth = authorize(state, headers, path).await?;
    if !list {
        return Err(AppError::BadRequest("only ?list=true is supported on metadata".into()));
    }
    let prefix = path.trim_end_matches('/');
    let keys: Vec<String> = secrets::list_paths(&state.db, &auth.vault_id)
        .await?
        .into_iter()
        .filter(|s| prefix.is_empty() || s.path == prefix || s.path.starts_with(&format!("{prefix}/")))
        .map(|s| s.path)
        .collect();
    Ok(Json(VaultResponse::new(json!({ "keys": keys }))).into_response())
}
