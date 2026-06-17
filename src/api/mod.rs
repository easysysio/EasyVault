// =============================================================================
// api/mod.rs — HTTP router assembly
//
// Builds the Axum router from the route handlers. This increment wires up the
// /v1/sys/* lifecycle endpoints; auth, KV, and GUI routes are added later.
// =============================================================================

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::state::AppState;

pub mod response;
pub mod routes;

// ─────────────────────────────────────────────────────────────────────────────
// build_router
// Assemble the application router with the shared AppState attached.
// ─────────────────────────────────────────────────────────────────────────────
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(routes::sys::index))
        .route("/v1/sys/init", post(routes::sys::init))
        .route("/v1/sys/unseal", post(routes::sys::unseal))
        .route("/v1/sys/seal-status", get(routes::sys::seal_status))
        .route("/v1/sys/health", get(routes::sys::health))
        .with_state(state)
}
