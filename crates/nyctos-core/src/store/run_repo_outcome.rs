//! `run_repo_outcomes` table - per-run, per-repo outcome history.
//!
//! The dispatcher emits a `RepoOutcome` (`Success` / `Inconclusive` /
//! `Failed`) per repo per run. This store mirrors that observation
//! onto SQLite so a historical run rendering can recover which repos
//! timed out or failed without replaying the WebSocket event stream.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::store::StoreError;

/// Canonical outcome label persisted in `run_repo_outcomes.outcome`.
/// Mirrors `RepoOutcomeTag` from `nyctos_types::event` but lives in
/// the store layer so writers do not import the event crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepoOutcomeLabel {
    Success,
    Inconclusive,
    Failed,
}

impl RepoOutcomeLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            RepoOutcomeLabel::Success => "Success",
            RepoOutcomeLabel::Inconclusive => "Inconclusive",
            RepoOutcomeLabel::Failed => "Failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRepoOutcomeRecord {
    pub run_id: String,
    pub repo: String,
    pub outcome: String,
    pub reason: Option<String>,
    pub elapsed_ms: i64,
}

pub struct RunRepoOutcomeStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> RunRepoOutcomeStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert or replace the outcome row for `(run_id, repo)`. Idempotent
    /// under repeated dispatcher writes within the same run.
    pub async fn upsert(&self, rec: &RunRepoOutcomeRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO run_repo_outcomes (run_id, repo, outcome, reason, elapsed_ms) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(run_id, repo) DO UPDATE SET \
                 outcome    = excluded.outcome, \
                 reason     = excluded.reason, \
                 elapsed_ms = excluded.elapsed_ms",
        )
        .bind(&rec.run_id)
        .bind(&rec.repo)
        .bind(&rec.outcome)
        .bind(&rec.reason)
        .bind(rec.elapsed_ms)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Every outcome row recorded for `run_id`, ordered by `repo`.
    pub async fn list_for_run(
        &self,
        run_id: &str,
    ) -> Result<Vec<RunRepoOutcomeRecord>, StoreError> {
        let rows = sqlx::query_as::<_, (String, String, String, Option<String>, i64)>(
            "SELECT run_id, repo, outcome, reason, elapsed_ms \
             FROM run_repo_outcomes \
             WHERE run_id = ? \
             ORDER BY repo ASC",
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(run_id, repo, outcome, reason, elapsed_ms)| RunRepoOutcomeRecord {
                run_id,
                repo,
                outcome,
                reason,
                elapsed_ms,
            })
            .collect())
    }

    /// Single outcome row for `(run_id, repo)` if recorded.
    pub async fn get(
        &self,
        run_id: &str,
        repo: &str,
    ) -> Result<Option<RunRepoOutcomeRecord>, StoreError> {
        let row = sqlx::query_as::<_, (String, String, String, Option<String>, i64)>(
            "SELECT run_id, repo, outcome, reason, elapsed_ms \
             FROM run_repo_outcomes \
             WHERE run_id = ? AND repo = ?",
        )
        .bind(run_id)
        .bind(repo)
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|(run_id, repo, outcome, reason, elapsed_ms)| RunRepoOutcomeRecord {
            run_id,
            repo,
            outcome,
            reason,
            elapsed_ms,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{fresh_store, sample_run};

    fn sample_outcome(run_id: &str, repo: &str) -> RunRepoOutcomeRecord {
        RunRepoOutcomeRecord {
            run_id: run_id.to_string(),
            repo: repo.to_string(),
            outcome: RepoOutcomeLabel::Success.as_str().to_string(),
            reason: None,
            elapsed_ms: 1_234,
        }
    }

    #[tokio::test]
    async fn upsert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("run-a")).await.expect("run");
        let rec = sample_outcome("run-a", "repo-1");
        s.run_repo_outcomes().upsert(&rec).await.expect("upsert");
        let got = s
            .run_repo_outcomes()
            .get("run-a", "repo-1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(got, rec);
    }

    #[tokio::test]
    async fn upsert_overwrites_existing_row() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("run-a")).await.expect("run");
        let mut rec = sample_outcome("run-a", "repo-1");
        s.run_repo_outcomes().upsert(&rec).await.expect("first");
        rec.outcome = RepoOutcomeLabel::Failed.as_str().to_string();
        rec.reason = Some("scanner crashed".to_string());
        rec.elapsed_ms = 9_999;
        s.run_repo_outcomes().upsert(&rec).await.expect("second");
        let got = s
            .run_repo_outcomes()
            .get("run-a", "repo-1")
            .await
            .expect("get")
            .expect("row");
        assert_eq!(got, rec);
    }

    #[tokio::test]
    async fn list_for_run_returns_every_repo_ordered() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("run-a")).await.expect("run");
        let alpha = RunRepoOutcomeRecord {
            run_id: "run-a".to_string(),
            repo: "alpha".to_string(),
            outcome: RepoOutcomeLabel::Success.as_str().to_string(),
            reason: None,
            elapsed_ms: 100,
        };
        let bravo = RunRepoOutcomeRecord {
            run_id: "run-a".to_string(),
            repo: "bravo".to_string(),
            outcome: RepoOutcomeLabel::Inconclusive.as_str().to_string(),
            reason: Some("StaticPassTimeout".to_string()),
            elapsed_ms: 60_000,
        };
        s.run_repo_outcomes().upsert(&bravo).await.expect("bravo");
        s.run_repo_outcomes().upsert(&alpha).await.expect("alpha");
        let got = s.run_repo_outcomes().list_for_run("run-a").await.expect("list");
        assert_eq!(got, vec![alpha, bravo]);
    }

    #[tokio::test]
    async fn list_for_run_isolates_per_run() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("run-a")).await.expect("a");
        s.runs().insert(&sample_run("run-b")).await.expect("b");
        s.run_repo_outcomes().upsert(&sample_outcome("run-a", "repo-1")).await.expect("a1");
        s.run_repo_outcomes().upsert(&sample_outcome("run-b", "repo-1")).await.expect("b1");
        let a_rows = s.run_repo_outcomes().list_for_run("run-a").await.expect("la");
        let b_rows = s.run_repo_outcomes().list_for_run("run-b").await.expect("lb");
        assert_eq!(a_rows.len(), 1);
        assert_eq!(b_rows.len(), 1);
        assert_eq!(a_rows[0].run_id, "run-a");
        assert_eq!(b_rows[0].run_id, "run-b");
    }

    #[tokio::test]
    async fn delete_run_cascades_to_outcomes() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("doomed")).await.expect("run");
        s.run_repo_outcomes()
            .upsert(&sample_outcome("doomed", "repo-1"))
            .await
            .expect("upsert");
        s.runs().delete("doomed").await.expect("delete");
        let got = s.run_repo_outcomes().list_for_run("doomed").await.expect("list");
        assert!(got.is_empty(), "FK cascade should have removed the outcome row");
    }
}
