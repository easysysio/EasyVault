// =============================================================================
// secrets.rs — versioned KV secret storage (crypto Flow 6)
//
// Secret values are JSON objects sealed with the vault_key. Writes are append-
// only: each write inserts a new version, never overwriting an earlier one.
// Reads decrypt the latest live version with the caller-resolved vault_key.
// =============================================================================

use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::{self, aes};
use crate::error::AppError;

/// One entry in a vault's secret listing (latest live version per path).
#[derive(Debug, sqlx::FromRow)]
pub struct SecretListing {
    pub path: String,
    pub version: i64,
    pub created_at: String,
}

/// Metadata for a single stored version of a secret path.
#[derive(Debug, sqlx::FromRow)]
pub struct SecretVersion {
    pub version: i64,
    pub created_at: String,
    pub deleted: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// write — crypto Flow 6 (Write a Secret)
// Seal the JSON value under the vault_key and insert it as the next version of
// `path`. Returns the new version number.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn write(
    db: &sqlx::SqlitePool,
    vault_id: &str,
    path: &str,
    value: &serde_json::Value,
    vault_key: &[u8; 32],
    created_by: &str,
) -> Result<i64, AppError> {
    let path = path.trim();
    if path.is_empty() {
        return Err(AppError::BadRequest("secret path is required".into()));
    }

    let mut json = serde_json::to_vec(value).map_err(|e| AppError::Internal(e.to_string()))?;
    let (nonce, value_enc) = aes::encrypt(vault_key, &json).map_err(|e| AppError::Internal(e.to_string()))?;
    json.zeroize();

    let next: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM secrets WHERE vault_id = ? AND path = ?",
    )
    .bind(vault_id)
    .bind(path)
    .fetch_one(db)
    .await?;

    sqlx::query(
        "INSERT INTO secrets (id, vault_id, path, version, value_enc, value_nonce, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(vault_id)
    .bind(path)
    .bind(next)
    .bind(value_enc)
    .bind(nonce.to_vec())
    .bind(created_by)
    .execute(db)
    .await?;

    Ok(next)
}

// ─────────────────────────────────────────────────────────────────────────────
// list_paths
// Latest live version per secret path in a vault, ordered by path.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn list_paths(db: &sqlx::SqlitePool, vault_id: &str) -> Result<Vec<SecretListing>, AppError> {
    let rows = sqlx::query_as::<_, SecretListing>(
        "SELECT path, MAX(version) AS version, MAX(created_at) AS created_at \
         FROM secrets WHERE vault_id = ? AND destroyed = 0 GROUP BY path ORDER BY path",
    )
    .bind(vault_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// versions
// All stored versions of a path (newest first), with their delete state.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn versions(db: &sqlx::SqlitePool, vault_id: &str, path: &str) -> Result<Vec<SecretVersion>, AppError> {
    let rows = sqlx::query_as::<_, SecretVersion>(
        "SELECT version, created_at, (deleted_at IS NOT NULL OR destroyed = 1) AS deleted \
         FROM secrets WHERE vault_id = ? AND path = ? ORDER BY version DESC",
    )
    .bind(vault_id)
    .bind(path)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// read_latest
// Decrypt the newest live version of `path`, returning (version, JSON value).
// Returns None when the path has no live version.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn read_latest(
    db: &sqlx::SqlitePool,
    vault_id: &str,
    path: &str,
    vault_key: &[u8; 32],
) -> Result<Option<(i64, serde_json::Value)>, AppError> {
    let row = sqlx::query_as::<_, (i64, Vec<u8>, Vec<u8>)>(
        "SELECT version, value_enc, value_nonce FROM secrets \
         WHERE vault_id = ? AND path = ? AND destroyed = 0 AND deleted_at IS NULL \
         ORDER BY version DESC LIMIT 1",
    )
    .bind(vault_id)
    .bind(path)
    .fetch_optional(db)
    .await?;

    let Some((version, value_enc, nonce_vec)) = row else {
        return Ok(None);
    };
    if nonce_vec.len() != crypto::NONCE_LEN {
        return Err(AppError::Internal("corrupt secret nonce".into()));
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&nonce_vec);

    let mut plain = aes::decrypt(vault_key, &nonce, &value_enc)
        .map_err(|_| AppError::Internal("failed to decrypt secret".into()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&plain).map_err(|e| AppError::Internal(e.to_string()))?;
    plain.zeroize();
    Ok(Some((version, value)))
}

// ─────────────────────────────────────────────────────────────────────────────
// soft_delete
// Mark the latest live version of `path` as deleted (recoverable; value kept).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn soft_delete(db: &sqlx::SqlitePool, vault_id: &str, path: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE secrets SET deleted_at = CURRENT_TIMESTAMP \
         WHERE id = (SELECT id FROM secrets WHERE vault_id = ? AND path = ? \
                     AND destroyed = 0 AND deleted_at IS NULL ORDER BY version DESC LIMIT 1)",
    )
    .bind(vault_id)
    .bind(path)
    .execute(db)
    .await?;
    Ok(())
}
