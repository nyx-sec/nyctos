//! SQLite persistence layer for the agent.
//!
//! `Store::open` resolves a SQLite file under the configured state
//! directory (`~/.local/share/nyctos/state.db` by default), applies
//! every migration shipped under `migrations/`, sets WAL + the tuning
//! pragmas the plan specifies, and hands back a clonable pool wrapper.
//!
//! Per-table repository structs (`RepoStore`, `RunStore`, ...) are
//! returned by accessor methods on `Store`. Every repository borrows a
//! pool reference; cloning `Store` is cheap because `SqlitePool` is an
//! `Arc` internally.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{ConnectOptions, SqlitePool};
use thiserror::Error;

pub mod budget;
pub mod candidate;
pub mod chain;
pub mod feedback;
pub mod finding;
pub mod payload;
pub mod project;
pub mod repo;
pub mod repro;
pub mod run;
pub mod run_repo_outcome;
pub mod schedule;
pub mod schema;
pub mod spec;
pub mod trace;
pub mod webhook;

#[cfg(test)]
pub(crate) mod testutil;

pub use budget::{BudgetKind, BudgetRecord, BudgetStore};
pub use candidate::{CandidateFindingRecord, CandidateFindingStore, CandidateStatus};
pub use chain::{ChainRecord, ChainStore};
pub use feedback::{FeedbackRecord, FeedbackStore, OperatorVerdict};
pub use finding::{
    finding_id_hash, FindingFilter, FindingOrigin, FindingRecord, FindingStatus, FindingStore,
    TriageState,
};
pub use payload::{PayloadRecord, PayloadStore};
pub use project::{
    ProjectPatch, ProjectPatchOption, ProjectRecord, ProjectStore, DEFAULT_PROJECT_ID,
    DEFAULT_PROJECT_NAME,
};
pub use repo::{PatchOption, RepoPatch, RepoRecord, RepoStore, SourceKind};
pub use repro::{ReproBundleRecord, ReproBundleStore};
pub use run::{RunRecord, RunStatus, RunStore, TriggeredBy};
pub use run_repo_outcome::{RepoOutcomeLabel, RunRepoOutcomeRecord, RunRepoOutcomeStore};
pub use schedule::{ScheduleRecord, ScheduleStore};
pub use schema::{schema_version, CURRENT_SCHEMA_VERSION, MIGRATOR};
pub use spec::{HarnessSpecRecord, HarnessSpecStore};
pub use trace::{AgentTraceRecord, AgentTraceStore, TaskKind};
pub use webhook::{WebhookRecord, WebhookStore};

const DB_FILE_NAME: &str = "state.db";

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to open database at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: sqlx::Error,
    },
    #[error("failed to apply migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Connected, migrated SQLite store. Cloning is cheap (pool is `Arc`).
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
    path: PathBuf,
}

impl Store {
    /// Open `<state_dir>/state.db`, creating the file if missing, and
    /// apply every migration shipped under `migrations/`.
    pub async fn open(state_dir: &Path) -> Result<Self, StoreError> {
        let path = state_dir.join(DB_FILE_NAME);
        Self::open_at(&path).await
    }

    /// Open an arbitrary SQLite file. Used by tests against a tempdir.
    pub async fn open_at(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| StoreError::Open {
                path: path.to_path_buf(),
                source: sqlx::Error::Io(source),
            })?;
        }

        let url = format!("sqlite://{}", path.display());
        let opts = SqliteConnectOptions::from_str(&url)
            .map_err(|source| StoreError::Open { path: path.to_path_buf(), source })?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .pragma("cache_size", "-8000")
            .pragma("temp_store", "MEMORY")
            .disable_statement_logging();

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .min_connections(1)
            .connect_with(opts)
            .await
            .map_err(|source| StoreError::Open { path: path.to_path_buf(), source })?;

        MIGRATOR.run(&pool).await?;
        Self::populate_meta(&pool).await?;
        Self::ensure_default_project(&pool).await?;
        Self::warn_if_finding_id_collision_pressure(&pool).await?;

        Ok(Self { pool, path: path.to_path_buf() })
    }

    /// `finding_id_hash` truncates BLAKE3 to 64 bits so finding ids fit
    /// neatly in UI rows. Birthday-collision pressure is negligible for
    /// any plausible single-deployment row count, but a deployment that
    /// crosses ~2^28 rows is close enough to the 2^32 expected-collision
    /// bound that the operator deserves a warning while there is still
    /// time to plan a schema migration (a `hash_version` column on
    /// `findings`, or a widened id). Uses `MAX(rowid)` instead of
    /// `COUNT(*)` so the check is O(log n) and adds no measurable
    /// open-time latency on small databases.
    async fn warn_if_finding_id_collision_pressure(pool: &SqlitePool) -> Result<(), sqlx::Error> {
        const WARN_THRESHOLD: i64 = 1 << 28;
        let (max_rowid,): (Option<i64>,) =
            sqlx::query_as("SELECT MAX(rowid) FROM findings").fetch_one(pool).await?;
        if max_rowid.unwrap_or(0) >= WARN_THRESHOLD {
            tracing::warn!(
                target: "nyctos_core::store",
                approx_findings_rowid = max_rowid,
                threshold = WARN_THRESHOLD,
                "findings table crossed 2^28 rows; finding_id_hash truncates BLAKE3 to 64 bits so birthday collisions become statistically meaningful near 2^32 rows. Plan a schema migration that widens finding ids or adds a hash_version column before that boundary."
            );
        }
        Ok(())
    }

    /// Stamp the singleton `meta` row with the running binary's version,
    /// the applied schema version (mirrored from `_sqlx_migrations`), and
    /// a real `created_at` on first run. Subsequent opens leave
    /// `created_at` untouched so it remains the install timestamp.
    async fn populate_meta(pool: &SqlitePool) -> Result<(), sqlx::Error> {
        let now_ms = crate::time::now_epoch_ms();
        let agent_version = env!("CARGO_PKG_VERSION");
        let max_migration: (Option<i64>,) =
            sqlx::query_as("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await?;
        let schema_v = max_migration.0.unwrap_or(0);
        sqlx::query(
            "UPDATE meta SET \
                 schema_version = ?1, \
                 created_at = CASE WHEN created_at = 0 THEN ?2 ELSE created_at END, \
                 agent_version = ?3 \
             WHERE id = 1",
        )
        .bind(schema_v)
        .bind(now_ms)
        .bind(agent_version)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Transitional bootstrap: seed the `DEFAULT_PROJECT_ID` row so
    /// legacy callers without an explicit project context can still
    /// attach repos via the FK.
    async fn ensure_default_project(pool: &SqlitePool) -> Result<(), StoreError> {
        let now_ms = crate::time::now_epoch_ms();
        ProjectStore::new(pool).ensure_default(now_ms).await?;
        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn close(self) {
        self.pool.close().await;
    }

    /// Current applied schema version. Reads `meta.schema_version`, which
    /// is kept in sync with `MAX(_sqlx_migrations.version)` on every
    /// `open` via [`populate_meta`]. In debug builds the two are
    /// cross-checked; in release the `meta` row is authoritative.
    pub async fn schema_version(&self) -> Result<i64, StoreError> {
        let (meta_v,): (i64,) = sqlx::query_as("SELECT schema_version FROM meta WHERE id = 1")
            .fetch_one(&self.pool)
            .await?;
        debug_assert_eq!(
            meta_v,
            schema_version(&self.pool).await?,
            "meta.schema_version drift from _sqlx_migrations"
        );
        Ok(meta_v)
    }

    pub fn projects(&self) -> ProjectStore<'_> {
        ProjectStore::new(&self.pool)
    }
    pub fn repos(&self) -> RepoStore<'_> {
        RepoStore::new(&self.pool)
    }
    pub fn runs(&self) -> RunStore<'_> {
        RunStore::new(&self.pool)
    }
    pub fn run_repo_outcomes(&self) -> RunRepoOutcomeStore<'_> {
        RunRepoOutcomeStore::new(&self.pool)
    }
    pub fn findings(&self) -> FindingStore<'_> {
        FindingStore::new(&self.pool)
    }
    pub fn chains(&self) -> ChainStore<'_> {
        ChainStore::new(&self.pool)
    }
    pub fn payloads(&self) -> PayloadStore<'_> {
        PayloadStore::new(&self.pool)
    }
    pub fn candidate_findings(&self) -> CandidateFindingStore<'_> {
        CandidateFindingStore::new(&self.pool)
    }
    pub fn agent_traces(&self) -> AgentTraceStore<'_> {
        AgentTraceStore::new(&self.pool)
    }
    pub fn budgets(&self) -> BudgetStore<'_> {
        BudgetStore::new(&self.pool)
    }
    pub fn repro_bundles(&self) -> ReproBundleStore<'_> {
        ReproBundleStore::new(&self.pool)
    }
    pub fn schedules(&self) -> ScheduleStore<'_> {
        ScheduleStore::new(&self.pool)
    }
    pub fn webhooks(&self) -> WebhookStore<'_> {
        WebhookStore::new(&self.pool)
    }
    pub fn feedback(&self) -> FeedbackStore<'_> {
        FeedbackStore::new(&self.pool)
    }
    pub fn harness_specs(&self) -> HarnessSpecStore<'_> {
        HarnessSpecStore::new(&self.pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open_tmp() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Store::open(tmp.path()).await.expect("open");
        (tmp, store)
    }

    #[tokio::test]
    async fn open_creates_db_and_runs_migrations() {
        let (tmp, store) = open_tmp().await;
        let db_path = tmp.path().join("state.db");
        assert!(db_path.exists(), "state.db should be created");
        let v = store.schema_version().await.expect("schema_version");
        assert_eq!(v, CURRENT_SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn meta_row_populated_with_real_values() {
        let (_tmp, store) = open_tmp().await;
        let (schema_v, created_at, agent_version): (i64, i64, String) = sqlx::query_as(
            "SELECT schema_version, created_at, agent_version FROM meta WHERE id = 1",
        )
        .fetch_one(store.pool())
        .await
        .expect("meta row");
        assert_eq!(schema_v, CURRENT_SCHEMA_VERSION);
        assert!(created_at > 0, "created_at must be real epoch ms, got {created_at}");
        assert_eq!(agent_version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn meta_created_at_stable_across_reopens() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Store::open(tmp.path()).await.expect("open");
        let (first,): (i64,) = sqlx::query_as("SELECT created_at FROM meta WHERE id = 1")
            .fetch_one(store.pool())
            .await
            .expect("created_at");
        store.close().await;
        assert!(first > 0);
        // Sleep briefly so that any naive "always overwrite" would shift.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let store = Store::open(tmp.path()).await.expect("reopen");
        let (second,): (i64,) = sqlx::query_as("SELECT created_at FROM meta WHERE id = 1")
            .fetch_one(store.pool())
            .await
            .expect("created_at");
        assert_eq!(first, second, "created_at must be preserved across reopens");
    }

    #[tokio::test]
    async fn migrations_idempotent_across_reopens() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for _ in 0..3 {
            let store = Store::open(tmp.path()).await.expect("open");
            assert_eq!(
                store.schema_version().await.expect("schema_version"),
                CURRENT_SCHEMA_VERSION
            );
            store.close().await;
        }
    }

    #[tokio::test]
    async fn cross_table_finding_payload_chain_trace_roundtrip() {
        // Acceptance test: insert a finding, payload, chain, and agent trace,
        // query them back, then verify FK cascades.
        let (_tmp, s) = open_tmp().await;
        let testutil = &super::testutil::sample_repo;
        s.repos().upsert(&testutil("repo")).await.expect("repo");
        s.runs().insert(&super::testutil::sample_run("run-1")).await.expect("run");
        let f = super::testutil::sample_finding("run-1", "repo", "src/a.rs", "rule-1");
        let fid = f.id.clone();
        s.findings().upsert(&f).await.expect("finding");
        let p = super::testutil::sample_payload("payload-1", &fid);
        s.payloads().insert(&p).await.expect("payload");
        let c = super::testutil::sample_chain("chain-1", "run-1", &[&fid]);
        s.chains().insert(&c).await.expect("chain");
        s.findings().set_chain(&fid, "chain-1").await.expect("link");
        let t = super::trace::AgentTraceRecord {
            id: "trace-1".to_string(),
            finding_id: Some(fid.clone()),
            task_kind: "PayloadSynthesis".to_string(),
            runtime_name: "anthropic".to_string(),
            model: "claude-opus-4-7".to_string(),
            prompt_version: Some("payload/v1".to_string()),
            conversation_jsonl_path: None,
            tokens_in: 10,
            tokens_out: 20,
            cost_usd_micros: 100,
            cache_hits: 0,
            cache_misses: 0,
            duration_ms: Some(5_000),
            started_at: 5_000,
            finished_at: Some(10_000),
            verifier_blob: None,
        };
        s.agent_traces().insert(&t).await.expect("trace");

        // Read everything back.
        assert_eq!(s.findings().get(&fid).await.expect("f").expect("row").id, fid);
        assert_eq!(s.payloads().get("payload-1").await.expect("p").expect("row").finding_id, fid);
        assert_eq!(s.chains().get("chain-1").await.expect("c").expect("row").run_id, "run-1");
        assert_eq!(
            s.agent_traces().get("trace-1").await.expect("t").expect("row").finding_id.as_deref(),
            Some(fid.as_str())
        );

        // Deleting the run cascades to findings, payloads, chains, and
        // SET-NULLs the trace's finding_id.
        s.runs().delete("run-1").await.expect("del run");
        assert!(s.findings().get(&fid).await.expect("f").is_none());
        assert!(s.payloads().get("payload-1").await.expect("p").is_none());
        assert!(s.chains().get("chain-1").await.expect("c").is_none());
        let trace = s.agent_traces().get("trace-1").await.expect("t").expect("row");
        assert!(
            trace.finding_id.is_none(),
            "trace.finding_id must be SET NULL after finding cascade-deleted"
        );
    }

    #[tokio::test]
    async fn pragmas_are_set() {
        let (_tmp, store) = open_tmp().await;
        let (jmode,): (String,) = sqlx::query_as("PRAGMA journal_mode")
            .fetch_one(store.pool())
            .await
            .expect("journal_mode");
        assert_eq!(jmode.to_lowercase(), "wal");

        let (sync,): (i64,) = sqlx::query_as("PRAGMA synchronous")
            .fetch_one(store.pool())
            .await
            .expect("synchronous");
        // NORMAL = 1
        assert_eq!(sync, 1);

        let (fk,): (i64,) = sqlx::query_as("PRAGMA foreign_keys")
            .fetch_one(store.pool())
            .await
            .expect("foreign_keys");
        assert_eq!(fk, 1, "foreign keys must be enabled");
    }
}
