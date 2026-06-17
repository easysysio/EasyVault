// =============================================================================
// storage/mod.rs — storage backend wiring
//
// Only SQLite is implemented in this increment; PostgreSQL is reserved for a
// later one. Re-exports the pool constructor used at startup.
// =============================================================================

pub mod sqlite;

pub use sqlite::open_sqlite;
