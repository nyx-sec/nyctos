//! Migration framework. Numbered SQL files under `migrations/` are
//! embedded into the binary via `sqlx::migrate!()`; running migrations is
//! idempotent because sqlx tracks applied versions in
//! `_sqlx_migrations`.

use sqlx::migrate::Migrator;
use sqlx::SqlitePool;

use crate::store::StoreError;

/// Highest schema version shipped by this build. Bump this number when
/// adding a new migration file (and only ever add - never edit a prior
/// migration).
pub const CURRENT_SCHEMA_VERSION: i64 = 8;

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Maximum applied migration version. Returns 0 if no migrations have
/// been applied yet (which would only happen if `Store::open` did not
/// run `MIGRATOR.run`, i.e. a misconfiguration).
pub async fn schema_version(pool: &SqlitePool) -> Result<i64, StoreError> {
    let row: (Option<i64>,) =
        sqlx::query_as("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await?;
    Ok(row.0.unwrap_or(0))
}
