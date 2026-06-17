// =============================================================================
// auth/mod.rs — authentication and session management
//
// `session` holds the GUI login flow: password verification (crypto Flow 2),
// server-side session creation, lookup, and logout. Token/AppRole/policy auth
// arrive in later increments.
// =============================================================================

pub mod session;
