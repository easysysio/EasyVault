// =============================================================================
// storage/sqlite.rs — SQLite pool creation and migration runner
//
// Opens (creating if absent) the SQLite database at the configured path,
// enables foreign keys, and applies the embedded migrations in ./migrations.
// =============================================================================

use std::str::FromStr;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

// ─────────────────────────────────────────────────────────────────────────────
// open_sqlite
// Open/create the SQLite database, turn on foreign keys, run migrations, and
// return a ready connection pool.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn open_sqlite(path: &str) -> anyhow::Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{path}"))?
        .create_if_missing(true)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
