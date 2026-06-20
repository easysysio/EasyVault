// =============================================================================
// users.rs — user records and registration (crypto Flow 1)
//
// Creating a user generates an X25519 keypair and seals the private key under
// the user_key derived from their password. The user_key and plaintext private
// key are never stored — only password_hash, salt, public_key and the sealed
// private key persist.
// =============================================================================

use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::argon2::{self, SALT_LEN};
use crate::crypto::{self, aes, ecdh};
use crate::error::AppError;

/// A user row as stored in the `users` table.
#[derive(Debug, sqlx::FromRow)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub password_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub public_key: Vec<u8>,
    pub private_key_enc: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub is_master: bool,
    pub active: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// count_users
// Number of rows in `users` — used to detect the first-run setup state.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn count_users(db: &sqlx::SqlitePool) -> Result<i64, AppError> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(db).await?;
    Ok(n)
}

/// A compact user entry for management listings.
#[derive(Debug, sqlx::FromRow)]
pub struct UserListItem {
    pub id: String,
    pub username: String,
    pub is_master: bool,
    pub active: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// list_all
// All users (id, username, role, active state) ordered by username.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn list_all(db: &sqlx::SqlitePool) -> Result<Vec<UserListItem>, AppError> {
    let rows = sqlx::query_as::<_, UserListItem>(
        "SELECT id, username, is_master, active FROM users ORDER BY username",
    )
    .fetch_all(db)
    .await?;
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// get_by_id
// Fetch a single user by id, or None if absent.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn get_by_id(db: &sqlx::SqlitePool, id: &str) -> Result<Option<UserRow>, AppError> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, password_hash, salt, public_key, private_key_enc, \
         private_key_nonce, is_master, active FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

// ─────────────────────────────────────────────────────────────────────────────
// set_active
// Enable or disable a user. A disabled user cannot log in (existing sessions
// are dropped separately by the caller).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn set_active(db: &sqlx::SqlitePool, user_id: &str, active: bool) -> Result<(), AppError> {
    sqlx::query("UPDATE users SET active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(active)
        .bind(user_id)
        .execute(db)
        .await?;
    tracing::info!(%user_id, active, "user active state changed");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// change_password — crypto Flow 10 (Password Change)
// Verify the old password, re-derive the user_key to unlock the private key,
// then re-wrap it under a new salt+user_key. The vault_user_keys rows are
// untouched (they use ECDH shared secrets, not the user_key).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn change_password(
    db: &sqlx::SqlitePool,
    user_id: &str,
    old_password: &str,
    new_password: &str,
) -> Result<(), AppError> {
    let user = get_by_id(db, user_id).await?.ok_or(AppError::NotFound)?;
    if !argon2::verify_password(old_password.as_bytes(), &user.salt, &user.password_hash) {
        return Err(AppError::BadRequest("current password is incorrect".into()));
    }
    if new_password.len() < 8 {
        return Err(AppError::BadRequest("new password must be at least 8 characters".into()));
    }

    // Unlock the private key with the old user_key.
    let old_user_key = argon2::derive_user_key(old_password.as_bytes(), &user.salt)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if user.private_key_nonce.len() != crypto::NONCE_LEN {
        return Err(AppError::Internal("corrupt private-key nonce".into()));
    }
    let mut nonce = [0u8; crypto::NONCE_LEN];
    nonce.copy_from_slice(&user.private_key_nonce);
    let mut private_key = aes::decrypt(&old_user_key, &nonce, &user.private_key_enc)
        .map_err(|_| AppError::Internal("failed to decrypt private key".into()))?;

    // Re-wrap under a fresh salt + user_key.
    let new_salt = crypto::random_bytes::<SALT_LEN>();
    let new_pw_hash = argon2::password_hash(new_password.as_bytes(), &new_salt)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let new_user_key = argon2::derive_user_key(new_password.as_bytes(), &new_salt)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let (new_nonce, new_priv_enc) = aes::encrypt(&new_user_key, &private_key)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    private_key.zeroize();

    sqlx::query(
        "UPDATE users SET salt = ?, password_hash = ?, private_key_enc = ?, \
         private_key_nonce = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    )
    .bind(new_salt.to_vec())
    .bind(new_pw_hash.to_vec())
    .bind(new_priv_enc)
    .bind(new_nonce.to_vec())
    .bind(user_id)
    .execute(db)
    .await?;

    tracing::info!(%user_id, "user password changed");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// get_by_username
// Fetch a single user by username, or None if absent.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn get_by_username(db: &sqlx::SqlitePool, username: &str) -> Result<Option<UserRow>, AppError> {
    let row = sqlx::query_as::<_, UserRow>(
        "SELECT id, username, password_hash, salt, public_key, private_key_enc, \
         private_key_nonce, is_master, active FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

// ─────────────────────────────────────────────────────────────────────────────
// create_user — crypto Flow 1 (User Registration)
// Generate salt + keypair, derive user_key, seal the private key, and insert.
// Returns the new user id.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn create_user(
    db: &sqlx::SqlitePool,
    username: &str,
    password: &str,
    is_master: bool,
) -> Result<String, AppError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(AppError::BadRequest("username is required".into()));
    }
    if password.len() < 8 {
        return Err(AppError::BadRequest("password must be at least 8 characters".into()));
    }
    if get_by_username(db, username).await?.is_some() {
        return Err(AppError::BadRequest("username already exists".into()));
    }

    // 1. random per-user salt; 2/3. derive the login hash and user_key from it.
    let salt = crypto::random_bytes::<SALT_LEN>();
    let pw_hash = argon2::password_hash(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let user_key = argon2::derive_user_key(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // 4. fresh X25519 keypair; 5/6. seal the private key under the user_key.
    let keypair = ecdh::generate_keypair();
    let (nonce, private_key_enc) = aes::encrypt(&user_key, keypair.private.as_ref())
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users \
         (id, username, password_hash, salt, public_key, private_key_enc, private_key_nonce, is_master) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(username)
    .bind(pw_hash.to_vec())
    .bind(salt.to_vec())
    .bind(keypair.public.to_vec())
    .bind(private_key_enc)
    .bind(nonce.to_vec())
    .bind(is_master)
    .execute(db)
    .await?;

    tracing::info!(%username, is_master, "user created");
    Ok(id)
}
