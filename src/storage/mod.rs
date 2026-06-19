// =============================================================================
// storage/mod.rs — storage backend wiring
//
// SQLite is the supported backend. Re-exports the pool constructor used at
// startup.
// =============================================================================

pub mod sqlite;

pub use sqlite::open_sqlite;
