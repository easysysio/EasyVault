// =============================================================================
// web/mod.rs — management GUI routes (/gui/*)
//
// Server-rendered, cookie-session HTML for first-run setup, login/logout and
// the dashboard. Auth state is resolved per-request from the ev_session cookie;
// a dedicated middleware layer is introduced in a later increment.
// =============================================================================

use std::sync::Arc;

use axum::Router;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::auth::session::{self, SessionIdentity};
use crate::error::AppError;
use crate::state::AppState;
use crate::users;

pub mod pages;

/// Credentials submitted by the setup and login forms.
#[derive(Debug, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// routes
// The /gui/* router, returned without state so the caller attaches it once.
// ─────────────────────────────────────────────────────────────────────────────
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/gui", get(gui_root))
        .route("/gui/", get(gui_root))
        .route("/gui/setup", get(setup_form).post(setup_submit))
        .route("/gui/login", get(login_form).post(login_submit))
        .route("/gui/logout", post(logout))
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/ (and /gui)
// First-run → setup; unauthenticated → login; otherwise render the dashboard.
// ─────────────────────────────────────────────────────────────────────────────
async fn gui_root(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, AppError> {
    if users::count_users(&state.db).await? == 0 {
        return Ok(Redirect::to("/gui/setup").into_response());
    }
    let Some(id) = current_identity(&state, &headers).await else {
        return Ok(Redirect::to("/gui/login").into_response());
    };

    let sealed = state.is_sealed().await;
    let vault_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vaults").fetch_one(&state.db).await?;
    Ok(Html(pages::dashboard_page(&id.username, id.is_master, sealed, vault_count)).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/setup
// Render the first-run master-account form; redirect to login if users exist.
// ─────────────────────────────────────────────────────────────────────────────
async fn setup_form(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    if users::count_users(&state.db).await? > 0 {
        return Ok(Redirect::to("/gui/login").into_response());
    }
    Ok(Html(pages::setup_page(None)).into_response())
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/setup
// Create the master user (only when none exist), then auto-login.
// ─────────────────────────────────────────────────────────────────────────────
async fn setup_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<Credentials>,
) -> Result<Response, AppError> {
    if users::count_users(&state.db).await? > 0 {
        return Ok(Redirect::to("/gui/login").into_response());
    }
    if let Err(e) = users::create_user(&state.db, &form.username, &form.password, true).await {
        return match e {
            AppError::BadRequest(msg) => {
                Ok((StatusCode::BAD_REQUEST, Html(pages::setup_page(Some(&msg)))).into_response())
            }
            other => Err(other),
        };
    }
    issue_session(&state, &headers, &form).await
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /gui/login
// Render the login form.
// ─────────────────────────────────────────────────────────────────────────────
async fn login_form() -> Response {
    Html(pages::login_page(None)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/login
// Verify credentials with brute-force lockout, then issue a session.
// ─────────────────────────────────────────────────────────────────────────────
async fn login_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<Credentials>,
) -> Result<Response, AppError> {
    let key = form.username.trim().to_lowercase();

    if let Some(msg) = locked_message(&state, &key).await {
        return Ok((StatusCode::TOO_MANY_REQUESTS, Html(pages::login_page(Some(&msg)))).into_response());
    }

    match session::authenticate(&state.db, form.username.trim(), &form.password).await? {
        Some(auth) => {
            reset_throttle(&state, &key).await;
            let token = session::create_session(&state, auth, client_ip(&headers)).await?;
            Ok(redirect_with_cookie(
                "/gui/",
                &session::build_cookie(&token, state.config.security.session_ttl_hours),
            ))
        }
        None => {
            record_failure(&state, &key).await;
            Ok((
                StatusCode::UNAUTHORIZED,
                Html(pages::login_page(Some("Invalid username or password."))),
            )
                .into_response())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /gui/logout
// Drop the current session and clear the cookie.
// ─────────────────────────────────────────────────────────────────────────────
async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_token(&headers) {
        session::logout(&state, &token).await;
    }
    redirect_with_cookie("/gui/login", &session::clear_cookie())
}

// ─────────────────────────────────────────────────────────────────────────────
// issue_session
// Authenticate the just-submitted credentials and set the session cookie.
// ─────────────────────────────────────────────────────────────────────────────
async fn issue_session(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    form: &Credentials,
) -> Result<Response, AppError> {
    let auth = session::authenticate(&state.db, form.username.trim(), &form.password)
        .await?
        .ok_or_else(|| AppError::Internal("post-setup authentication failed".into()))?;
    let token = session::create_session(state, auth, client_ip(headers)).await?;
    Ok(redirect_with_cookie(
        "/gui/",
        &session::build_cookie(&token, state.config.security.session_ttl_hours),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// current_identity
// Resolve the ev_session cookie to a logged-in identity, if any.
// ─────────────────────────────────────────────────────────────────────────────
async fn current_identity(state: &Arc<AppState>, headers: &HeaderMap) -> Option<SessionIdentity> {
    let token = cookie_token(headers)?;
    session::lookup(state, &token).await
}

// ─────────────────────────────────────────────────────────────────────────────
// cookie_token
// Extract the raw session token from the request's Cookie header.
// ─────────────────────────────────────────────────────────────────────────────
fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    session::token_from_cookie_header(cookie)
}

// ─────────────────────────────────────────────────────────────────────────────
// client_ip
// Best-effort client IP from X-Forwarded-For (first hop), else None.
// ─────────────────────────────────────────────────────────────────────────────
fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ─────────────────────────────────────────────────────────────────────────────
// redirect_with_cookie
// Build a 303-style redirect response carrying a Set-Cookie header.
// ─────────────────────────────────────────────────────────────────────────────
fn redirect_with_cookie(location: &str, cookie: &str) -> Response {
    let mut resp = Redirect::to(location).into_response();
    if let Ok(value) = HeaderValue::from_str(cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, value);
    }
    resp
}

// ─────────────────────────────────────────────────────────────────────────────
// locked_message
// If the username is currently locked out, return a user-facing message.
// ─────────────────────────────────────────────────────────────────────────────
async fn locked_message(state: &Arc<AppState>, key: &str) -> Option<String> {
    let throttle = state.login_throttle.read().await;
    let entry = throttle.get(key)?;
    let until = entry.locked_until?;
    let remaining = until - Utc::now();
    if remaining > Duration::zero() {
        let mins = remaining.num_minutes() + 1;
        Some(format!("Too many failed attempts. Try again in about {mins} minute(s)."))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// record_failure
// Increment the failure counter and lock the account at the configured limit.
// ─────────────────────────────────────────────────────────────────────────────
async fn record_failure(state: &Arc<AppState>, key: &str) {
    let max = state.config.security.max_login_attempts;
    let lockout = state.config.security.lockout_minutes as i64;
    let mut throttle = state.login_throttle.write().await;
    let entry = throttle.entry(key.to_string()).or_default();
    entry.failures += 1;
    if entry.failures >= max {
        entry.locked_until = Some(Utc::now() + Duration::minutes(lockout));
        entry.failures = 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// reset_throttle
// Clear any failure/lockout state for a username after a successful login.
// ─────────────────────────────────────────────────────────────────────────────
async fn reset_throttle(state: &Arc<AppState>, key: &str) {
    state.login_throttle.write().await.remove(key);
}
