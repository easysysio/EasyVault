// =============================================================================
// api/mod.rs — HTTP router assembly
//
// Builds the Axum router from the route handlers: the /v1/sys/* lifecycle
// endpoints and the /gui/* management UI. KV/auth/token routes are added later.
// =============================================================================

use std::sync::Arc;

use axum::Router;
use axum::response::Redirect;
use axum::routing::{get, post};

use crate::state::AppState;

pub mod response;
pub mod routes;

// ─────────────────────────────────────────────────────────────────────────────
// build_router
// Assemble the application router (sys API + GUI) with shared AppState attached.
// ─────────────────────────────────────────────────────────────────────────────
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/gui/") }))
        .route("/v1/sys/init", post(routes::sys::init))
        .route("/v1/sys/unseal", post(routes::sys::unseal))
        .route("/v1/sys/seal-status", get(routes::sys::seal_status))
        .route("/v1/sys/health", get(routes::sys::health))
        .route(
            "/v1/secret/data/{*path}",
            get(routes::kv::read).post(routes::kv::write).delete(routes::kv::delete),
        )
        .route("/v1/secret/metadata", get(routes::kv::metadata_list_root))
        .route("/v1/secret/metadata/{*path}", get(routes::kv::metadata_list))
        .merge(crate::web::routes())
        .with_state(state)
}
