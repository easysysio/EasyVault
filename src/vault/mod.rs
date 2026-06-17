// =============================================================================
// vault/mod.rs — vault lifecycle and per-user vault-key distribution
//
// A vault has a single random vault_key, never stored in plaintext. It is
// wrapped per-user under an X25519 ECDH shared secret (crypto Flows 3–5) and
// re-wrapped when granted to another user (Flow 4). Secrets in the vault are
// encrypted with this vault_key.
// =============================================================================

use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, aes, ecdh};
use crate::error::AppError;

/// A vault row (metadata only — the key is never stored here).
#[derive(Debug, sqlx::FromRow)]
pub struct VaultRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub locked: bool,
    pub created_by: Option<String>,
}

/// Summary of a vault a user can access, for list views.
#[derive(Debug, sqlx::FromRow)]
pub struct VaultSummary {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

/// A member of a vault (someone with a wrapped vault key).
#[derive(Debug, sqlx::FromRow)]
pub struct VaultMember {
    pub user_id: String,
    pub username: String,
    pub granted_at: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// create_vault — crypto Flow 3 (Vault Creation)
// Generate a vault_key, wrap it for the creator via self-ECDH, and persist the
// vault plus the creator's vault_user_keys row. Returns the new vault id.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn create_vault(
    db: &sqlx::SqlitePool,
    name: &str,
    description: &str,
    creator_id: &str,
    creator_private: &[u8; 32],
    creator_public: &[u8; 32],
) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("vault name is required".into()));
    }
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM vaults WHERE name = ?")
        .bind(name)
        .fetch_optional(db)
        .await?;
    if exists.is_some() {
        return Err(AppError::BadRequest("a vault with that name already exists".into()));
    }

    let vault_key = Zeroizing::new(crypto::random_key());
    // Self-ECDH: the creator wraps the vault key to their own keypair.
    let shared = ecdh::shared_secret(creator_private, creator_public);
    let (nonce, vault_key_enc) = aes::encrypt(&shared, vault_key.as_ref())
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let vault_id = Uuid::new_v4().to_string();
    let mut tx = db.begin().await?;
    sqlx::query("INSERT INTO vaults (id, name, description, created_by) VALUES (?, ?, ?, ?)")
        .bind(&vault_id)
        .bind(name)
        .bind(if description.trim().is_empty() { None } else { Some(description.trim()) })
        .bind(creator_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO vault_user_keys \
         (vault_id, user_id, vault_key_enc, vault_key_nonce, granter_public_key, granted_by) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&vault_id)
    .bind(creator_id)
    .bind(vault_key_enc)
    .bind(nonce.to_vec())
    .bind(creator_public.to_vec())
    .bind(creator_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    tracing::info!(%name, vault_id = %vault_id, "vault created");
    Ok(vault_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// list_for_user
// Vaults the given user has a wrapped key for, ordered by name.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn list_for_user(db: &sqlx::SqlitePool, user_id: &str) -> Result<Vec<VaultSummary>, AppError> {
    let rows = sqlx::query_as::<_, VaultSummary>(
        "SELECT v.id, v.name, v.description FROM vaults v \
         JOIN vault_user_keys k ON k.vault_id = v.id \
         WHERE k.user_id = ? ORDER BY v.name",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// user_has_access
// Whether `user_id` holds a wrapped key for the vault (i.e. has access).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn user_has_access(db: &sqlx::SqlitePool, vault_id: &str, user_id: &str) -> Result<bool, AppError> {
    let row: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_user_keys WHERE vault_id = ? AND user_id = ?")
            .bind(vault_id)
            .bind(user_id)
            .fetch_optional(db)
            .await?;
    Ok(row.is_some())
}

// ─────────────────────────────────────────────────────────────────────────────
// get
// Fetch a vault's metadata by id.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn get(db: &sqlx::SqlitePool, vault_id: &str) -> Result<Option<VaultRow>, AppError> {
    let row = sqlx::query_as::<_, VaultRow>(
        "SELECT id, name, description, locked, created_by FROM vaults WHERE id = ?",
    )
    .bind(vault_id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

// ─────────────────────────────────────────────────────────────────────────────
// members
// List users who have access to a vault (joined to usernames).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn members(db: &sqlx::SqlitePool, vault_id: &str) -> Result<Vec<VaultMember>, AppError> {
    let rows = sqlx::query_as::<_, VaultMember>(
        "SELECT k.user_id, u.username, k.granted_at FROM vault_user_keys k \
         JOIN users u ON u.id = k.user_id WHERE k.vault_id = ? ORDER BY u.username",
    )
    .bind(vault_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// resolve_vault_key — crypto Flow 5 (Access Vault)
// Recover the vault_key for `user_id` by re-deriving their ECDH shared secret
// from the stored granter public key and decrypting their wrapped copy.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn resolve_vault_key(
    db: &sqlx::SqlitePool,
    vault_id: &str,
    user_id: &str,
    user_private: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, AppError> {
    let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT vault_key_enc, vault_key_nonce, granter_public_key \
         FROM vault_user_keys WHERE vault_id = ? AND user_id = ?",
    )
    .bind(vault_id)
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .ok_or(AppError::Forbidden)?;

    let (vk_enc, nonce_vec, granter_public) = row;
    if nonce_vec.len() != crypto::NONCE_LEN || granter_public.len() != 32 {
        return Err(AppError::Internal("corrupt vault key material".into()));
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&nonce_vec);
    let mut granter = [0u8; 32];
    granter.copy_from_slice(&granter_public);

    let shared = ecdh::shared_secret(user_private, &granter);
    let mut plain = aes::decrypt(&shared, &nonce, &vk_enc)
        .map_err(|_| AppError::Internal("failed to unwrap vault key".into()))?;
    if plain.len() != 32 {
        plain.zeroize();
        return Err(AppError::Internal("corrupt vault key".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plain);
    plain.zeroize();
    Ok(Zeroizing::new(key))
}

// ─────────────────────────────────────────────────────────────────────────────
// grant — crypto Flow 4 (Grant Vault Access)
// The granter unwraps the vault_key, re-wraps it under ECDH(granter, target),
// and inserts the target's vault_user_keys row.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn grant(
    db: &sqlx::SqlitePool,
    vault_id: &str,
    granter_id: &str,
    granter_private: &[u8; 32],
    granter_public: &[u8; 32],
    target_username: &str,
) -> Result<(), AppError> {
    let target = crate::users::get_by_username(db, target_username.trim())
        .await?
        .ok_or_else(|| AppError::BadRequest("no such user".into()))?;
    if target.id == granter_id {
        return Err(AppError::BadRequest("you already have access to this vault".into()));
    }
    let already: Option<String> =
        sqlx::query_scalar("SELECT user_id FROM vault_user_keys WHERE vault_id = ? AND user_id = ?")
            .bind(vault_id)
            .bind(&target.id)
            .fetch_optional(db)
            .await?;
    if already.is_some() {
        return Err(AppError::BadRequest("user already has access".into()));
    }

    // Unwrap the vault key via the granter's own ECDH path.
    let vault_key = resolve_vault_key(db, vault_id, granter_id, granter_private).await?;

    let mut target_public = [0u8; 32];
    if target.public_key.len() != 32 {
        return Err(AppError::Internal("corrupt target public key".into()));
    }
    target_public.copy_from_slice(&target.public_key);

    // Re-wrap under ECDH(granter_private, target_public); target recovers it
    // with ECDH(target_private, granter_public) — see Flow 5.
    let shared = ecdh::shared_secret(granter_private, &target_public);
    let (nonce, vk_enc) = aes::encrypt(&shared, vault_key.as_ref())
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO vault_user_keys \
         (vault_id, user_id, vault_key_enc, vault_key_nonce, granter_public_key, granted_by) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(vault_id)
    .bind(&target.id)
    .bind(vk_enc)
    .bind(nonce.to_vec())
    .bind(granter_public.to_vec())
    .bind(granter_id)
    .execute(db)
    .await?;

    tracing::info!(%vault_id, target = %target.username, "vault access granted");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// revoke
// Remove a user's wrapped vault key. NOTE: this does not yet rotate the vault
// key (crypto Flow 9) — a full re-encryption rotation is a planned follow-up.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn revoke(db: &sqlx::SqlitePool, vault_id: &str, user_id: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM vault_user_keys WHERE vault_id = ? AND user_id = ?")
        .bind(vault_id)
        .bind(user_id)
        .execute(db)
        .await?;
    tracing::info!(%vault_id, %user_id, "vault access revoked (key rotation pending)");
    Ok(())
}
