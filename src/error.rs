// =============================================================================
// error.rs — AppError and Vault-compatible error responses
//
// Every handler returns Result<_, AppError>. AppError renders to HashiCorp
// Vault's error envelope: {"errors": [..]} with a matching HTTP status code.
// =============================================================================

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Application-wide error type, mapped to Vault-style HTTP responses.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),

    #[error("permission denied")]
    Forbidden,

    #[error("not found")]
    NotFound,

    /// Returned (503) when the instance is sealed or a vault is locked.
    #[error("EasyVault is sealed")]
    Sealed,

    /// Returned (503) before the instance has been initialized.
    #[error("EasyVault is not initialized")]
    Uninitialized,

    /// Catch-all for unexpected internal failures (logged, not detailed to clients).
    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    // ─────────────────────────────────────────────────────────────────────────
    // AppError::status
    // Map each variant to the Vault-compatible HTTP status code.
    // ─────────────────────────────────────────────────────────────────────────
    fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::Sealed | AppError::Uninitialized => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AppError::client_message
    // The message safe to expose to clients (internal details are masked).
    // ─────────────────────────────────────────────────────────────────────────
    fn client_message(&self) -> String {
        match self {
            AppError::Internal(_) => "internal error".to_string(),
            other => other.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IntoResponse for AppError
// Render as {"errors": ["..."]} with the mapped status; log internals.
// ─────────────────────────────────────────────────────────────────────────────
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let AppError::Internal(detail) = &self {
            tracing::error!(error = %detail, "internal error");
        }
        let body = Json(json!({ "errors": [self.client_message()] }));
        (self.status(), body).into_response()
    }
}

/// Convert sqlx errors into opaque internal errors.
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.to_string())
    }
}
