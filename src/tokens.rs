// =============================================================================
// tokens.rs — per-vault API tokens (crypto Flows 7 & 8)
//
// A token is scoped to exactly one vault. Its vault_key is sealed under a
// per-token token_key, which is itself sealed under the master key. So reading
// via a token requires the instance unsealed (master_key in memory):
//   master_key -> token_key -> vault_key -> secret.
// The raw token is shown once at creation and only its SHA-256 is stored.
// =============================================================================

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, aes};
use crate::error::AppError;
use crate::vault;

/// Prefix on every EasyVault token (Vault uses `s.`; we also accept that).
const TOKEN_PREFIX: &str = "ev.";

/// A token row for management listings (no secret material).
#[derive(Debug, sqlx::FromRow)]
pub struct TokenListing {
    pub id: String,
    pub display_name: Option<String>,
    pub allowed_paths: String,
    pub allowed_ips: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked: bool,
    pub created_at: String,
}

/// Resolved token context after authentication (Flow 8), incl. the vault key.
pub struct TokenAuth {
    pub token_id: String,
    pub vault_id: String,
    pub created_by: Option<String>,
    pub allowed_paths: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub vault_key: Zeroizing<[u8; 32]>,
}

// ─────────────────────────────────────────────────────────────────────────────
// create_token — crypto Flow 7 (API Token Creation)
// Resolve the creator's vault_key, generate a token_key, seal vault_key under
// token_key and token_key under the master key, and store the token. Returns
// the raw token (shown once).
// ─────────────────────────────────────────────────────────────────────────────
#[allow(clippy::too_many_arguments)]
pub async fn create_token(
    db: &sqlx::SqlitePool,
    vault_id: &str,
    creator_id: &str,
    creator_private: &[u8; 32],
    master_key: &[u8; 32],
    display_name: &str,
    allowed_paths: &[String],
    allowed_ips: &[String],
    ttl_seconds: Option<i64>,
) -> Result<String, AppError> {
    // Proves the creator actually has access to this vault.
    let vault_key = vault::resolve_vault_key(db, vault_id, creator_id, creator_private).await?;

    let token_key = Zeroizing::new(crypto::random_key());
    let raw = format!("{TOKEN_PREFIX}{}", B64URL.encode(crypto::random_bytes::<32>()));
    let token_hash = crypto::sha256_hex(raw.as_bytes());

    let (vk_nonce, vault_key_enc) = aes::encrypt(&token_key, vault_key.as_ref())
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let (tk_nonce, token_key_enc) = aes::encrypt(master_key, token_key.as_ref())
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let paths_vec: Vec<String> = if allowed_paths.is_empty() { vec!["*".into()] } else { allowed_paths.to_vec() };
    let paths_json = serde_json::to_string(&paths_vec).unwrap_or_else(|_| "[\"*\"]".into());
    let ips_json = serde_json::to_string(allowed_ips).unwrap_or_else(|_| "[]".into());
    let expires_at: Option<DateTime<Utc>> = ttl_seconds.map(|s| Utc::now() + Duration::seconds(s));
    // Tokens with a TTL are renewable; renew-self extends them by `renew_period`.
    let renewable = ttl_seconds.is_some();

    sqlx::query(
        "INSERT INTO api_tokens \
         (id, vault_id, token_hash, display_name, vault_key_enc, vault_key_nonce, \
          token_key_enc, token_key_nonce, allowed_paths, allowed_ips, expires_at, \
          renewable, renew_period, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(vault_id)
    .bind(&token_hash)
    .bind(if display_name.trim().is_empty() { None } else { Some(display_name.trim()) })
    .bind(vault_key_enc)
    .bind(vk_nonce.to_vec())
    .bind(token_key_enc)
    .bind(tk_nonce.to_vec())
    .bind(paths_json)
    .bind(ips_json)
    .bind(expires_at)
    .bind(renewable)
    .bind(ttl_seconds)
    .bind(creator_id)
    .execute(db)
    .await?;

    tracing::info!(%vault_id, "API token created");
    Ok(raw)
}

// ─────────────────────────────────────────────────────────────────────────────
// authenticate_token — crypto Flow 8 (API Token Read)
// Look up a token by hash, validate revoked/expired, then unwrap
// master_key -> token_key -> vault_key. Path/IP ACL is enforced by the caller.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn authenticate_token(
    db: &sqlx::SqlitePool,
    master_key: &[u8; 32],
    raw_token: &str,
) -> Result<TokenAuth, AppError> {
    let token_hash = crypto::sha256_hex(raw_token.as_bytes());
    let row = sqlx::query_as::<_, (String, String, Option<String>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, String, Option<DateTime<Utc>>, bool)>(
        "SELECT id, vault_id, created_by, vault_key_enc, vault_key_nonce, token_key_enc, \
         token_key_nonce, allowed_paths, allowed_ips, expires_at, revoked \
         FROM api_tokens WHERE token_hash = ?",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await?
    .ok_or(AppError::Forbidden)?;

    let (token_id, vault_id, created_by, vk_enc, vk_nonce, tk_enc, tk_nonce, paths_json, ips_json, expires_at, revoked) = row;
    if revoked {
        return Err(AppError::Forbidden);
    }
    if let Some(exp) = expires_at {
        if exp <= Utc::now() {
            return Err(AppError::Forbidden);
        }
    }

    // Unwrap master_key -> token_key -> vault_key.
    let token_key = unwrap(master_key, &tk_nonce, &tk_enc)?;
    let vault_key = unwrap(&token_key, &vk_nonce, &vk_enc)?;

    let allowed_paths: Vec<String> = serde_json::from_str(&paths_json).unwrap_or_else(|_| vec!["*".into()]);
    let allowed_ips: Vec<String> = serde_json::from_str(&ips_json).unwrap_or_default();

    // Best-effort last-used timestamp.
    let _ = sqlx::query("UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(&token_id)
        .execute(db)
        .await;

    Ok(TokenAuth { token_id, vault_id, created_by, allowed_paths, allowed_ips, vault_key })
}

/// Token metadata for the `/v1/auth/token/*` self endpoints (no key material).
pub struct TokenInfo {
    pub token_id: String,
    pub vault_id: String,
    pub display_name: Option<String>,
    pub allowed_paths: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub renewable: bool,
    pub created_at: String,
}

impl TokenInfo {
    /// Seconds until expiry (0 if expired or never-expiring).
    pub fn ttl_seconds(&self) -> i64 {
        match self.expires_at {
            Some(exp) => (exp - Utc::now()).num_seconds().max(0),
            None => 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// lookup
// Validate a raw token (not revoked/expired) and return its metadata. No
// decryption — works regardless of seal state. (/v1/auth/token/lookup-self)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn lookup(db: &sqlx::SqlitePool, raw_token: &str) -> Result<TokenInfo, AppError> {
    let token_hash = crypto::sha256_hex(raw_token.as_bytes());
    let row = sqlx::query_as::<_, (String, String, Option<String>, String, String, Option<DateTime<Utc>>, bool, bool, String)>(
        "SELECT id, vault_id, display_name, allowed_paths, allowed_ips, expires_at, \
         renewable, revoked, created_at FROM api_tokens WHERE token_hash = ?",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await?
    .ok_or(AppError::Forbidden)?;

    let (token_id, vault_id, display_name, paths_json, ips_json, expires_at, renewable, revoked, created_at) = row;
    if revoked {
        return Err(AppError::Forbidden);
    }
    if let Some(exp) = expires_at {
        if exp <= Utc::now() {
            return Err(AppError::Forbidden);
        }
    }
    Ok(TokenInfo {
        token_id,
        vault_id,
        display_name,
        allowed_paths: serde_json::from_str(&paths_json).unwrap_or_else(|_| vec!["*".into()]),
        allowed_ips: serde_json::from_str(&ips_json).unwrap_or_default(),
        expires_at,
        renewable,
        created_at,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// revoke_self
// Revoke the token presented in the request. (/v1/auth/token/revoke-self)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn revoke_self(db: &sqlx::SqlitePool, raw_token: &str) -> Result<(), AppError> {
    let token_hash = crypto::sha256_hex(raw_token.as_bytes());
    let res = sqlx::query("UPDATE api_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0")
        .bind(&token_hash)
        .execute(db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// renew
// Extend a renewable token's lifetime by `increment` seconds (or its stored
// renew_period when no increment is given). (/v1/auth/token/renew-self)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn renew(db: &sqlx::SqlitePool, raw_token: &str, increment: Option<i64>) -> Result<TokenInfo, AppError> {
    let token_hash = crypto::sha256_hex(raw_token.as_bytes());
    let row = sqlx::query_as::<_, (String, bool, bool, Option<i64>, Option<DateTime<Utc>>)>(
        "SELECT id, renewable, revoked, renew_period, expires_at FROM api_tokens WHERE token_hash = ?",
    )
    .bind(&token_hash)
    .fetch_optional(db)
    .await?
    .ok_or(AppError::Forbidden)?;

    let (_id, renewable, revoked, renew_period, expires_at) = row;
    if revoked || expires_at.map(|e| e <= Utc::now()).unwrap_or(false) {
        return Err(AppError::Forbidden);
    }
    if !renewable {
        return Err(AppError::BadRequest("token is not renewable".into()));
    }
    let secs = increment.or(renew_period).unwrap_or(0);
    if secs <= 0 {
        return Err(AppError::BadRequest("nothing to renew".into()));
    }
    let new_expiry = Utc::now() + Duration::seconds(secs);
    sqlx::query("UPDATE api_tokens SET expires_at = ? WHERE token_hash = ?")
        .bind(new_expiry)
        .bind(&token_hash)
        .execute(db)
        .await?;

    lookup(db, raw_token).await
}

// ─────────────────────────────────────────────────────────────────────────────
// list_for_vault
// Tokens minted against a vault, newest first (no secret material).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn list_for_vault(db: &sqlx::SqlitePool, vault_id: &str) -> Result<Vec<TokenListing>, AppError> {
    let rows = sqlx::query_as::<_, TokenListing>(
        "SELECT id, display_name, allowed_paths, allowed_ips, expires_at, last_used_at, revoked, created_at \
         FROM api_tokens WHERE vault_id = ? ORDER BY created_at DESC",
    )
    .bind(vault_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// revoke_token
// Mark a token revoked (effective immediately on the next request).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn revoke_token(db: &sqlx::SqlitePool, vault_id: &str, token_id: &str) -> Result<(), AppError> {
    sqlx::query("UPDATE api_tokens SET revoked = 1 WHERE id = ? AND vault_id = ?")
        .bind(token_id)
        .bind(vault_id)
        .execute(db)
        .await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// path_allowed
// Whether `path` matches any allowed pattern. A trailing `*` is a prefix glob
// (`db/*` matches `db/pg`); `*` alone matches everything; otherwise exact.
// ─────────────────────────────────────────────────────────────────────────────
pub fn path_allowed(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|pat| match pat.strip_suffix('*') {
        Some(prefix) => path.starts_with(prefix),
        None => pat == path,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// unwrap
// Decrypt a wrapped 32-byte key, returning a zeroizing copy.
// ─────────────────────────────────────────────────────────────────────────────
fn unwrap(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
    if nonce.len() != crypto::NONCE_LEN {
        return Err(AppError::Internal("corrupt token nonce".into()));
    }
    let mut n = [0u8; crypto::NONCE_LEN];
    n.copy_from_slice(nonce);
    let plain = aes::decrypt(key, &n, ciphertext).map_err(|_| AppError::Forbidden)?;
    if plain.len() != 32 {
        return Err(AppError::Internal("corrupt token key".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plain);
    Ok(Zeroizing::new(out))
}
