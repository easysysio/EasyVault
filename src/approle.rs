// =============================================================================
// approle.rs — AppRole auth (machine login → per-vault token)
//
// An AppRole binds a role_id + secret_id(s) to a vault and a path/IP/TTL policy.
// Roles and secret-ids are provisioned in the GUI (by editor+); the only public
// API surface is `login`, which validates role_id + secret_id and mints a token
// for the role's vault via the master escrow. Only SHA-256(secret_id) is stored.
// =============================================================================

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use uuid::Uuid;

use crate::crypto;
use crate::error::AppError;
use crate::tokens;

/// An AppRole row (no secret material).
#[derive(Debug, sqlx::FromRow)]
pub struct ApproleRow {
    pub id: String,
    pub name: String,
    pub vault_id: String,
    pub role_id: String,
    pub allowed_paths: String,
    pub allowed_ips: String,
    pub token_ttl: Option<i64>,
    pub writable: bool,
    pub created_by: Option<String>,
}

/// A role entry for management listings.
#[derive(Debug, sqlx::FromRow)]
pub struct ApproleListing {
    pub id: String,
    pub name: String,
    pub role_id: String,
    pub allowed_paths: String,
    pub token_ttl: Option<i64>,
    pub created_at: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// create_role
// Create a named AppRole on a vault with a fresh random role_id.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn create_role(
    db: &sqlx::SqlitePool,
    vault_id: &str,
    name: &str,
    allowed_paths: &[String],
    allowed_ips: &[String],
    token_ttl: Option<i64>,
    writable: bool,
    created_by: &str,
) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("role name is required".into()));
    }
    if get_by_name(db, name).await?.is_some() {
        return Err(AppError::BadRequest("a role with that name already exists".into()));
    }
    let id = Uuid::new_v4().to_string();
    let role_id = Uuid::new_v4().to_string();
    let paths_vec: Vec<String> = if allowed_paths.is_empty() { vec!["*".into()] } else { allowed_paths.to_vec() };

    sqlx::query(
        "INSERT INTO approles (id, name, vault_id, role_id, allowed_paths, allowed_ips, token_ttl, writable, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(vault_id)
    .bind(&role_id)
    .bind(serde_json::to_string(&paths_vec).unwrap_or_else(|_| "[\"*\"]".into()))
    .bind(serde_json::to_string(allowed_ips).unwrap_or_else(|_| "[]".into()))
    .bind(token_ttl)
    .bind(writable)
    .bind(created_by)
    .execute(db)
    .await?;

    tracing::info!(%vault_id, %name, "AppRole created");
    Ok(role_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// get_by_name / get_by_role_id
// ─────────────────────────────────────────────────────────────────────────────
pub async fn get_by_name(db: &sqlx::SqlitePool, name: &str) -> Result<Option<ApproleRow>, AppError> {
    Ok(sqlx::query_as::<_, ApproleRow>(
        "SELECT id, name, vault_id, role_id, allowed_paths, allowed_ips, token_ttl, writable, created_by FROM approles WHERE name = ?",
    )
    .bind(name)
    .fetch_optional(db)
    .await?)
}

pub async fn get_by_role_id(db: &sqlx::SqlitePool, role_id: &str) -> Result<Option<ApproleRow>, AppError> {
    Ok(sqlx::query_as::<_, ApproleRow>(
        "SELECT id, name, vault_id, role_id, allowed_paths, allowed_ips, token_ttl, writable, created_by FROM approles WHERE role_id = ?",
    )
    .bind(role_id)
    .fetch_optional(db)
    .await?)
}

// ─────────────────────────────────────────────────────────────────────────────
// list_for_vault
// AppRoles defined on a vault, newest first.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn list_for_vault(db: &sqlx::SqlitePool, vault_id: &str) -> Result<Vec<ApproleListing>, AppError> {
    Ok(sqlx::query_as::<_, ApproleListing>(
        "SELECT id, name, role_id, allowed_paths, token_ttl, created_at FROM approles \
         WHERE vault_id = ? ORDER BY created_at DESC",
    )
    .bind(vault_id)
    .fetch_all(db)
    .await?)
}

// ─────────────────────────────────────────────────────────────────────────────
// delete_role
// Remove an AppRole (and its secret-ids, via cascade) from a vault.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn delete_role(db: &sqlx::SqlitePool, vault_id: &str, role_internal_id: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM approles WHERE id = ? AND vault_id = ?")
        .bind(role_internal_id)
        .bind(vault_id)
        .execute(db)
        .await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// generate_secret_id
// Issue a new secret-id for a role (stored hashed; returned once).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn generate_secret_id(db: &sqlx::SqlitePool, approle_id: &str) -> Result<String, AppError> {
    let secret_id = B64URL.encode(crypto::random_bytes::<32>());
    let hash = crypto::sha256_hex(secret_id.as_bytes());
    sqlx::query("INSERT INTO approle_secrets (id, approle_id, secret_id_hash) VALUES (?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind(approle_id)
        .bind(&hash)
        .execute(db)
        .await?;
    Ok(secret_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// login — AppRole login (POST /v1/auth/approle/login)
// Validate role_id + secret_id and mint a per-vault token for the role.
// Returns (raw_token, policies, ttl_seconds).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn login(
    db: &sqlx::SqlitePool,
    master_key: &[u8; 32],
    role_id: &str,
    secret_id: &str,
) -> Result<(String, Vec<String>, Option<i64>), AppError> {
    let role = get_by_role_id(db, role_id).await?.ok_or(AppError::Forbidden)?;

    // Validate the secret-id against the role's stored hashes.
    let hash = crypto::sha256_hex(secret_id.as_bytes());
    let matched: Option<String> =
        sqlx::query_scalar("SELECT id FROM approle_secrets WHERE approle_id = ? AND secret_id_hash = ?")
            .bind(&role.id)
            .bind(&hash)
            .fetch_optional(db)
            .await?;
    let secret_row_id = matched.ok_or(AppError::Forbidden)?;
    let _ = sqlx::query("UPDATE approle_secrets SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(&secret_row_id)
        .execute(db)
        .await;

    let allowed_paths: Vec<String> = serde_json::from_str(&role.allowed_paths).unwrap_or_else(|_| vec!["*".into()]);
    let allowed_ips: Vec<String> = serde_json::from_str(&role.allowed_ips).unwrap_or_default();

    let raw = tokens::create_token_via_master(
        db,
        &role.vault_id,
        master_key,
        &role.name,
        &allowed_paths,
        &allowed_ips,
        role.token_ttl,
        role.writable,
        role.created_by.as_deref(),
    )
    .await?;

    tracing::info!(role = %role.name, "AppRole login");
    Ok((raw, allowed_paths, role.token_ttl))
}
