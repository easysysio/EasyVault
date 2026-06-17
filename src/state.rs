// =============================================================================
// state.rs — AppState, the in-memory MasterKey, and unseal progress
//
// AppState is shared (Arc) across all handlers. It holds the SQLite pool, the
// loaded config, the master key (None while sealed), and the transient buffer
// of submitted unseal shares.
// =============================================================================

use std::sync::Arc;

use tokio::sync::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::Config;

/// The 256-bit master key, held only in memory and wiped on drop.
///
/// On Unix the backing bytes are best-effort `mlock`'d to keep them out of swap.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl MasterKey {
    // ─────────────────────────────────────────────────────────────────────────
    // MasterKey::new
    // Wrap 32 key bytes and attempt to mlock the page (ignored on failure).
    // ─────────────────────────────────────────────────────────────────────────
    pub fn new(bytes: [u8; 32]) -> Self {
        let key = Self { bytes };
        #[cfg(unix)]
        // SAFETY: locking the exact span of our owned array; failure is ignored.
        unsafe {
            let ret = libc::mlock(key.bytes.as_ptr() as *const libc::c_void, key.bytes.len());
            if ret != 0 {
                tracing::warn!("mlock of master key failed; key may be swappable");
            }
        }
        key
    }

    /// Borrow the raw key bytes for AES-GCM operations.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Shared application state handed to every Axum handler via `State`.
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub config: Config,
    /// `None` while sealed; `Some` once unsealed.
    pub master_key: RwLock<Option<MasterKey>>,
    /// Raw unseal share bytes submitted since the last successful unseal/reset.
    pub unseal_progress: RwLock<Vec<Vec<u8>>>,
}

impl AppState {
    // ─────────────────────────────────────────────────────────────────────────
    // AppState::new
    // Construct the shared state in the sealed/empty-progress starting position.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn new(db: sqlx::SqlitePool, config: Config) -> Arc<Self> {
        Arc::new(Self {
            db,
            config,
            master_key: RwLock::new(None),
            unseal_progress: RwLock::new(Vec::new()),
        })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AppState::is_sealed
    // True when the master key is not present in memory.
    // ─────────────────────────────────────────────────────────────────────────
    pub async fn is_sealed(&self) -> bool {
        self.master_key.read().await.is_none()
    }
}
