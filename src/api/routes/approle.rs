// =============================================================================
// api/routes/approle.rs — /v1/auth/approle/login
//
// Machine login: exchange a role_id + secret_id for a per-vault API token,
// returned in Vault's `auth` envelope. Roles/secret-ids are provisioned in the
// GUI; this is the only public AppRole endpoint. Requires an unsealed instance.
// =============================================================================

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::approle;
use crate::error::AppError;
use crate::state::AppState;

/// AppRole login body.
#[derive(Debug, Deserialize)]
pub struct LoginBody {
    pub role_id: String,
    pub secret_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /v1/auth/approle/login
// Validate role_id + secret_id and return a freshly minted token in the auth
// envelope (Vault-compatible shape).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn login(State(state): State<Arc<AppState>>, Json(body): Json<LoginBody>) -> Result<Response, AppError> {
    let master = state.master_key_bytes().await.ok_or(AppError::Sealed)?;
    let (token, policies, ttl) = approle::login(&state.db, &master, body.role_id.trim(), body.secret_id.trim()).await?;

    Ok(Json(json!({
        "request_id": Uuid::new_v4().to_string(),
        "lease_id": "",
        "renewable": false,
        "lease_duration": 0,
        "data": serde_json::Value::Null,
        "wrap_info": serde_json::Value::Null,
        "warnings": serde_json::Value::Null,
        "auth": {
            "client_token": token,
            "accessor": "",
            "policies": policies,
            "token_policies": policies,
            "lease_duration": ttl.unwrap_or(0),
            "renewable": ttl.is_some(),
        }
    }))
    .into_response())
}
