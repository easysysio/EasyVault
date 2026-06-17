// =============================================================================
// auth/session.rs — GUI login, server-side sessions, and the session cookie
//
// Login (crypto Flow 2) verifies the password, derives the user_key, and
// decrypts the user's X25519 private key. The private key is stored only in the
// in-memory session map (AppState.sessions); the DB row in `gui_sessions`
// records the hashed token + expiry for audit/persistence.
// =============================================================================

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{Duration, Utc};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::argon2;
use crate::crypto::{self, aes};
use crate::error::AppError;
use crate::state::{AppState, SessionSecrets};
use crate::users;

/// Name of the GUI session cookie.
pub const SESSION_COOKIE: &str = "ev_session";

/// Lightweight identity snapshot returned from session lookups.
#[derive(Clone)]
pub struct SessionIdentity {
    pub user_id: String,
    pub username: String,
    pub is_master: bool,
}

/// Successful authentication result: the user plus their decrypted private key.
pub struct AuthOk {
    pub user_id: String,
    pub username: String,
    pub is_master: bool,
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

// ─────────────────────────────────────────────────────────────────────────────
// authenticate — crypto Flow 2 (User Login)
// Verify the password, derive the user_key, and decrypt the X25519 private key.
// Returns None for unknown/inactive users or a bad password (no detail leak).
// ─────────────────────────────────────────────────────────────────────────────
pub async fn authenticate(
    db: &sqlx::SqlitePool,
    username: &str,
    password: &str,
) -> Result<Option<AuthOk>, AppError> {
    let Some(user) = users::get_by_username(db, username).await? else {
        return Ok(None);
    };
    if !user.active {
        return Ok(None);
    }
    if !argon2::verify_password(password.as_bytes(), &user.salt, &user.password_hash) {
        return Ok(None);
    }

    let user_key = argon2::derive_user_key(password.as_bytes(), &user.salt)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let mut nonce = [0u8; crypto::NONCE_LEN];
    if user.private_key_nonce.len() != crypto::NONCE_LEN {
        return Err(AppError::Internal("corrupt private-key nonce".into()));
    }
    nonce.copy_from_slice(&user.private_key_nonce);

    let mut priv_vec = aes::decrypt(&user_key, &nonce, &user.private_key_enc)
        .map_err(|_| AppError::Internal("failed to decrypt private key".into()))?;
    if priv_vec.len() != 32 {
        priv_vec.zeroize();
        return Err(AppError::Internal("corrupt private key".into()));
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&priv_vec);
    priv_vec.zeroize();

    let mut public_key = [0u8; 32];
    if user.public_key.len() != 32 {
        return Err(AppError::Internal("corrupt public key".into()));
    }
    public_key.copy_from_slice(&user.public_key);

    Ok(Some(AuthOk {
        user_id: user.id,
        username: user.username,
        is_master: user.is_master,
        private_key,
        public_key,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// create_session
// Persist a hashed session token + expiry, hold the private key in memory, and
// return the raw token to place in the cookie.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn create_session(
    state: &Arc<AppState>,
    auth: AuthOk,
    ip: Option<String>,
) -> Result<String, AppError> {
    let raw_token = B64URL.encode(crypto::random_bytes::<32>());
    let session_hash = crypto::sha256_hex(raw_token.as_bytes());
    let ttl = Duration::hours(state.config.security.session_ttl_hours as i64);
    let expires_at = Utc::now() + ttl;

    sqlx::query(
        "INSERT INTO gui_sessions (id, user_id, session_hash, expires_at, ip_address) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&auth.user_id)
    .bind(&session_hash)
    .bind(expires_at)
    .bind(ip)
    .execute(&state.db)
    .await?;

    state.sessions.write().await.insert(
        session_hash,
        SessionSecrets {
            user_id: auth.user_id,
            username: auth.username,
            is_master: auth.is_master,
            private_key: auth.private_key,
            public_key: auth.public_key,
            expires_at,
        },
    );

    Ok(raw_token)
}

// ─────────────────────────────────────────────────────────────────────────────
// lookup
// Resolve a raw cookie token to a session identity, evicting it if expired.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn lookup(state: &Arc<AppState>, raw_token: &str) -> Option<SessionIdentity> {
    let hash = crypto::sha256_hex(raw_token.as_bytes());
    {
        let sessions = state.sessions.read().await;
        if let Some(s) = sessions.get(&hash) {
            if s.expires_at > Utc::now() {
                return Some(SessionIdentity {
                    user_id: s.user_id.clone(),
                    username: s.username.clone(),
                    is_master: s.is_master,
                });
            }
        } else {
            return None;
        }
    }
    // Expired: drop it from memory and DB.
    evict(state, &hash).await;
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// logout
// Remove the session for a raw cookie token from memory and the database.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn logout(state: &Arc<AppState>, raw_token: &str) {
    let hash = crypto::sha256_hex(raw_token.as_bytes());
    evict(state, &hash).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// evict
// Internal: delete a session (by hash) from the in-memory map and gui_sessions.
// ─────────────────────────────────────────────────────────────────────────────
async fn evict(state: &Arc<AppState>, session_hash: &str) {
    state.sessions.write().await.remove(session_hash);
    let _ = sqlx::query("DELETE FROM gui_sessions WHERE session_hash = ?")
        .bind(session_hash)
        .execute(&state.db)
        .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// build_cookie
// Construct the Set-Cookie value for a freshly issued session token.
// (Secure flag is added once TLS is enabled in a later increment.)
// ─────────────────────────────────────────────────────────────────────────────
pub fn build_cookie(token: &str, ttl_hours: u64) -> String {
    format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        ttl_hours * 3600
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// clear_cookie
// Construct the Set-Cookie value that expires the session cookie on logout.
// ─────────────────────────────────────────────────────────────────────────────
pub fn clear_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

// ─────────────────────────────────────────────────────────────────────────────
// token_from_cookie_header
// Extract the session token from a raw Cookie header value, if present.
// ─────────────────────────────────────────────────────────────────────────────
pub fn token_from_cookie_header(header: &str) -> Option<String> {
    for part in header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}
