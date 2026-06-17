// =============================================================================
// api/response.rs — the Vault-compatible response envelope
//
// All /v1/* success responses are wrapped in this envelope so HashiCorp Vault
// SDKs and CLIs can consume EasyVault unchanged.
// =============================================================================

use serde::Serialize;
use uuid::Uuid;

/// Vault-compatible response envelope wrapping a typed `data` payload.
#[derive(Debug, Serialize)]
pub struct VaultResponse<T: Serialize> {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: u64,
    pub data: T,
    pub wrap_info: Option<serde_json::Value>,
    pub warnings: Option<Vec<String>>,
    pub auth: Option<serde_json::Value>,
}

impl<T: Serialize> VaultResponse<T> {
    // ─────────────────────────────────────────────────────────────────────────
    // VaultResponse::new
    // Wrap `data` with a fresh request id and Vault's default envelope fields.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn new(data: T) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            lease_id: String::new(),
            renewable: false,
            lease_duration: 0,
            data,
            wrap_info: None,
            warnings: None,
            auth: None,
        }
    }
}
