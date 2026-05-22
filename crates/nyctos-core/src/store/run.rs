//! `runs` table - one row per scan execution.

use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

pub use nyctos_types::run::RunRecord;

use crate::store::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Halted,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Pending => "Pending",
            RunStatus::Running => "Running",
            RunStatus::Succeeded => "Succeeded",
            RunStatus::Failed => "Failed",
            RunStatus::Halted => "Halted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriggeredBy {
    Manual,
    Cron,
    Webhook,
    Pr,
    Ui,
}

impl TriggeredBy {
    pub fn as_str(self) -> &'static str {
        match self {
            TriggeredBy::Manual => "Manual",
            TriggeredBy::Cron => "Cron",
            TriggeredBy::Webhook => "Webhook",
            TriggeredBy::Pr => "PR",
            TriggeredBy::Ui => "UI",
        }
    }
}

pub struct RunStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> RunStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, r: &RunRecord) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            INSERT INTO runs (
                id, project_id, kind, started_at, finished_at, status, triggered_by,
                git_ref, parent_run_id, wall_clock_ms, total_ai_spend_usd_micros
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&r.id)
        .bind(&r.project_id)
        .bind(if r.kind.is_empty() { "Scan" } else { r.kind.as_str() })
        .bind(r.started_at)
        .bind(r.finished_at)
        .bind(&r.status)
        .bind(&r.triggered_by)
        .bind(&r.git_ref)
        .bind(&r.parent_run_id)
        .bind(r.wall_clock_ms)
        .bind(r.total_ai_spend_usd_micros)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<RunRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, project_id, kind,
                   started_at,
                   finished_at, status,
                   triggered_by,
                   git_ref, parent_run_id, wall_clock_ms,
                   total_ai_spend_usd_micros
            FROM runs WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_run_record).transpose()
    }

    pub async fn list_by_status(&self, status: &str) -> Result<Vec<RunRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, project_id, kind,
                   started_at,
                   finished_at, status,
                   triggered_by,
                   git_ref, parent_run_id, wall_clock_ms,
                   total_ai_spend_usd_micros
            FROM runs WHERE status = ? ORDER BY started_at DESC
            "#,
        )
        .bind(status)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_run_record).collect()
    }

    pub async fn finish(
        &self,
        id: &str,
        finished_at: i64,
        status: &str,
        wall_clock_ms: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE runs
               SET finished_at   = ?,
                   status        = ?,
                   wall_clock_ms = ?
             WHERE id = ?
            "#,
        )
        .bind(finished_at)
        .bind(status)
        .bind(wall_clock_ms)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn add_spend(&self, id: &str, micros: i64) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE runs SET total_ai_spend_usd_micros = total_ai_spend_usd_micros + ? WHERE id = ?",
        )
        .bind(micros)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Most recent earlier run, ranked by `started_at`. Used by the
    /// findings diff endpoint to anchor "new vs prior" badge logic.
    pub async fn prior_run_id(
        &self,
        run_id: &str,
        started_at: i64,
    ) -> Result<Option<String>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id FROM runs
            WHERE started_at < ? AND id != ?
            ORDER BY started_at DESC LIMIT 1
            "#,
        )
        .bind(started_at)
        .bind(run_id)
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|r| r.get("id")))
    }

    pub async fn delete(&self, id: &str) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM runs WHERE id = ?").bind(id).execute(self.pool).await?;
        Ok(res.rows_affected())
    }
}

fn row_to_run_record(row: sqlx::sqlite::SqliteRow) -> Result<RunRecord, StoreError> {
    Ok(RunRecord {
        id: row.try_get("id")?,
        project_id: row.try_get("project_id")?,
        kind: row.try_get("kind")?,
        started_at: row.try_get::<i64, _>("started_at")?,
        finished_at: row.try_get("finished_at")?,
        status: row.try_get("status")?,
        triggered_by: row.try_get("triggered_by")?,
        git_ref: row.try_get("git_ref")?,
        parent_run_id: row.try_get("parent_run_id")?,
        wall_clock_ms: row.try_get("wall_clock_ms")?,
        total_ai_spend_usd_micros: row.try_get::<i64, _>("total_ai_spend_usd_micros")?,
    })
}

#[cfg(test)]
mod tests {
    use crate::store::testutil::{fresh_store, sample_finding, sample_run};

    #[tokio::test]
    async fn insert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        let r = sample_run("run-1");
        s.runs().insert(&r).await.expect("insert");
        let got = s.runs().get("run-1").await.expect("get").expect("row");
        assert_eq!(got, r);
    }

    #[tokio::test]
    async fn list_by_status_filters() {
        let (_tmp, s) = fresh_store().await;
        let mut a = sample_run("a");
        a.status = "Succeeded".to_string();
        let mut b = sample_run("b");
        b.status = "Running".to_string();
        s.runs().insert(&a).await.expect("a");
        s.runs().insert(&b).await.expect("b");
        let running = s.runs().list_by_status("Running").await.expect("list");
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].id, "b");
    }

    #[tokio::test]
    async fn finish_updates_fields() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("r")).await.expect("insert");
        s.runs().finish("r", 9_999, "Succeeded", 7_000).await.expect("finish");
        let got = s.runs().get("r").await.expect("get").expect("row");
        assert_eq!(got.finished_at, Some(9_999));
        assert_eq!(got.status, "Succeeded");
        assert_eq!(got.wall_clock_ms, Some(7_000));
    }

    #[tokio::test]
    async fn add_spend_accumulates() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("r")).await.expect("insert");
        s.runs().add_spend("r", 1_000).await.expect("spend1");
        s.runs().add_spend("r", 2_500).await.expect("spend2");
        let got = s.runs().get("r").await.expect("get").expect("row");
        assert_eq!(got.total_ai_spend_usd_micros, 3_500);
    }

    #[tokio::test]
    async fn delete_cascades_to_findings() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&crate::store::testutil::sample_repo("r")).await.expect("repo");
        s.runs().insert(&sample_run("doomed")).await.expect("run");
        let f = sample_finding("doomed", "r", "src/a.rs", "rule-1");
        let fid = f.id.clone();
        s.findings().upsert(&f).await.expect("finding");
        s.runs().delete("doomed").await.expect("delete");
        assert!(
            s.findings().get(&fid).await.expect("get").is_none(),
            "FK cascade should have removed the finding"
        );
    }

    #[tokio::test]
    async fn parent_run_id_set_null_on_parent_delete() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("parent")).await.expect("p");
        let mut child = sample_run("child");
        child.parent_run_id = Some("parent".to_string());
        s.runs().insert(&child).await.expect("c");
        s.runs().delete("parent").await.expect("del");
        let got = s.runs().get("child").await.expect("get").expect("row");
        assert!(got.parent_run_id.is_none(), "expected SET NULL on parent delete");
    }
}
