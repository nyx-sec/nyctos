//! `repos` table - one row per repository the agent is configured to scan.

use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

pub use nyx_agent_types::repo::RepoRecord;

use crate::store::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Local,
    Git,
    GitHub,
    GitLab,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Local => "local",
            SourceKind::Git => "git",
            SourceKind::GitHub => "github",
            SourceKind::GitLab => "gitlab",
        }
    }
}

/// Tri-state for `PATCH` semantics on a nullable field: leave existing
/// value untouched, or replace it with `Some(...)` / `None`.
#[derive(Debug, Clone, Copy, Default)]
pub enum PatchOption<T> {
    #[default]
    Unset,
    Set(T),
}

/// Partial-update descriptor consumed by [`RepoStore::update`]. Fields
/// left as `None` (or `Unset` for nullable columns) preserve the
/// existing row's value.
#[derive(Debug)]
pub struct RepoPatch<'a> {
    pub name: &'a str,
    pub source_kind: Option<&'a str>,
    pub source_url_or_path: Option<&'a str>,
    pub branch: PatchOption<Option<&'a str>>,
    pub auth_ref: PatchOption<Option<&'a str>>,
    pub i_own_this: Option<bool>,
    pub updated_at: i64,
}

pub struct RepoStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> RepoStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn upsert(&self, r: &RepoRecord) -> Result<(), StoreError> {
        let i_own = i64::from(r.i_own_this);
        sqlx::query(
            r#"
            INSERT INTO repos (
                id, name, project_id, source_kind, source_url_or_path, branch, auth_ref,
                i_own_this, last_scan_run_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, name) DO UPDATE SET
                source_kind        = excluded.source_kind,
                source_url_or_path = excluded.source_url_or_path,
                branch             = excluded.branch,
                auth_ref           = excluded.auth_ref,
                i_own_this         = excluded.i_own_this,
                last_scan_run_id   = excluded.last_scan_run_id,
                updated_at         = excluded.updated_at
            "#,
        )
        .bind(&r.id)
        .bind(&r.name)
        .bind(&r.project_id)
        .bind(&r.source_kind)
        .bind(&r.source_url_or_path)
        .bind(&r.branch)
        .bind(&r.auth_ref)
        .bind(i_own)
        .bind(&r.last_scan_run_id)
        .bind(r.created_at)
        .bind(r.updated_at)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Legacy name lookup. If duplicate display names exist across
    /// projects, this returns the oldest matching row. New code should
    /// prefer [`Self::get_by_project_and_name`] or [`Self::get_by_id`].
    pub async fn get(&self, name: &str) -> Result<Option<RepoRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT repos.id, repos.name, repos.project_id,
                   repos.source_kind,
                   repos.source_url_or_path,
                   repos.branch, repos.auth_ref,
                   repos.i_own_this,
                   repos.last_scan_run_id,
                   runs.finished_at AS last_scan_finished_at,
                   repos.created_at,
                   repos.updated_at
            FROM repos
            LEFT JOIN runs ON runs.id = repos.last_scan_run_id
            WHERE repos.name = ?
            ORDER BY repos.created_at
            LIMIT 1
            "#,
        )
        .bind(name)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_repo_record).transpose()
    }

    pub async fn get_by_id(&self, id: &str) -> Result<Option<RepoRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT repos.id, repos.name, repos.project_id,
                   repos.source_kind, repos.source_url_or_path,
                   repos.branch, repos.auth_ref, repos.i_own_this,
                   repos.last_scan_run_id, runs.finished_at AS last_scan_finished_at,
                   repos.created_at, repos.updated_at
            FROM repos
            LEFT JOIN runs ON runs.id = repos.last_scan_run_id
            WHERE repos.id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_repo_record).transpose()
    }

    pub async fn get_by_project_and_name(
        &self,
        project_id: &str,
        name: &str,
    ) -> Result<Option<RepoRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT repos.id, repos.name, repos.project_id,
                   repos.source_kind, repos.source_url_or_path,
                   repos.branch, repos.auth_ref, repos.i_own_this,
                   repos.last_scan_run_id, runs.finished_at AS last_scan_finished_at,
                   repos.created_at, repos.updated_at
            FROM repos
            LEFT JOIN runs ON runs.id = repos.last_scan_run_id
            WHERE repos.project_id = ? AND repos.name = ?
            "#,
        )
        .bind(project_id)
        .bind(name)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_repo_record).transpose()
    }

    pub async fn list(&self) -> Result<Vec<RepoRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT repos.id, repos.name, repos.project_id,
                   repos.source_kind,
                   repos.source_url_or_path,
                   repos.branch, repos.auth_ref,
                   repos.i_own_this,
                   repos.last_scan_run_id,
                   runs.finished_at AS last_scan_finished_at,
                   repos.created_at,
                   repos.updated_at
            FROM repos
            LEFT JOIN runs ON runs.id = repos.last_scan_run_id
            ORDER BY repos.name, repos.project_id
            "#,
        )
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_repo_record).collect()
    }

    /// Repos attached to a specific project, alphabetical by name.
    pub async fn list_by_project(&self, project_id: &str) -> Result<Vec<RepoRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT repos.id, repos.name, repos.project_id,
                   repos.source_kind,
                   repos.source_url_or_path,
                   repos.branch, repos.auth_ref,
                   repos.i_own_this,
                   repos.last_scan_run_id,
                   runs.finished_at AS last_scan_finished_at,
                   repos.created_at,
                   repos.updated_at
            FROM repos
            LEFT JOIN runs ON runs.id = repos.last_scan_run_id
            WHERE repos.project_id = ?
            ORDER BY repos.name
            "#,
        )
        .bind(project_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_repo_record).collect()
    }

    /// Partial update of mutable repo fields. Returns `Ok(false)` if no
    /// row with `name` exists. `last_scan_run_id` is left untouched;
    /// that pointer is owned by the dispatcher via [`Self::set_last_scan`].
    /// `created_at` is preserved.
    pub async fn update(&self, patch: &RepoPatch<'_>) -> Result<bool, StoreError> {
        let Some(existing) = self.get(patch.name).await? else {
            return Ok(false);
        };
        let merged = RepoRecord {
            id: existing.id,
            name: existing.name,
            project_id: existing.project_id,
            source_kind: patch.source_kind.map(str::to_string).unwrap_or(existing.source_kind),
            source_url_or_path: patch
                .source_url_or_path
                .map(str::to_string)
                .unwrap_or(existing.source_url_or_path),
            branch: match patch.branch {
                PatchOption::Unset => existing.branch,
                PatchOption::Set(v) => v.map(str::to_string),
            },
            auth_ref: match patch.auth_ref {
                PatchOption::Unset => existing.auth_ref,
                PatchOption::Set(v) => v.map(str::to_string),
            },
            i_own_this: patch.i_own_this.unwrap_or(existing.i_own_this),
            last_scan_run_id: existing.last_scan_run_id,
            last_scan_finished_at: existing.last_scan_finished_at,
            created_at: existing.created_at,
            updated_at: patch.updated_at,
        };
        self.upsert(&merged).await?;
        Ok(true)
    }

    pub async fn set_last_scan(
        &self,
        name: &str,
        run_id: &str,
        updated_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE repos SET last_scan_run_id = ?, updated_at = ? WHERE name = ?")
            .bind(run_id)
            .bind(updated_at)
            .bind(name)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_last_scan_for_project(
        &self,
        project_id: &str,
        name: &str,
        run_id: &str,
        updated_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE repos SET last_scan_run_id = ?, updated_at = ? WHERE project_id = ? AND name = ?",
        )
        .bind(run_id)
        .bind(updated_at)
        .bind(project_id)
        .bind(name)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, name: &str) -> Result<u64, StoreError> {
        let res =
            sqlx::query("DELETE FROM repos WHERE name = ?").bind(name).execute(self.pool).await?;
        self.delete_legacy_name_refs_if_orphaned(name).await?;
        Ok(res.rows_affected())
    }

    pub async fn delete_by_project_and_name(
        &self,
        project_id: &str,
        name: &str,
    ) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM repos WHERE project_id = ? AND name = ?")
            .bind(project_id)
            .bind(name)
            .execute(self.pool)
            .await?;
        self.delete_legacy_name_refs_if_orphaned(name).await?;
        Ok(res.rows_affected())
    }

    async fn delete_legacy_name_refs_if_orphaned(&self, name: &str) -> Result<(), StoreError> {
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repos WHERE name = ?")
            .bind(name)
            .fetch_one(self.pool)
            .await?;
        if remaining == 0 {
            sqlx::query("DELETE FROM schedules WHERE repo = ?")
                .bind(name)
                .execute(self.pool)
                .await?;
            sqlx::query("DELETE FROM webhooks WHERE repo = ?")
                .bind(name)
                .execute(self.pool)
                .await?;
        }
        Ok(())
    }
}

fn row_to_repo_record(row: sqlx::sqlite::SqliteRow) -> Result<RepoRecord, StoreError> {
    Ok(RepoRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        project_id: row.try_get("project_id")?,
        source_kind: row.try_get("source_kind")?,
        source_url_or_path: row.try_get("source_url_or_path")?,
        branch: row.try_get("branch")?,
        auth_ref: row.try_get("auth_ref")?,
        i_own_this: row.try_get::<i64, _>("i_own_this")? != 0,
        last_scan_run_id: row.try_get("last_scan_run_id")?,
        last_scan_finished_at: row.try_get("last_scan_finished_at")?,
        created_at: row.try_get::<i64, _>("created_at")?,
        updated_at: row.try_get::<i64, _>("updated_at")?,
    })
}

#[cfg(test)]
mod tests {
    use crate::store::testutil::{fresh_store, sample_repo};

    #[tokio::test]
    async fn upsert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        let r = sample_repo("acme-app");
        s.repos().upsert(&r).await.expect("insert");
        let got = s.repos().get("acme-app").await.expect("get").expect("row");
        assert_eq!(got, r);
    }

    #[tokio::test]
    async fn upsert_is_idempotent_on_conflict() {
        let (_tmp, s) = fresh_store().await;
        let mut r = sample_repo("acme-app");
        s.repos().upsert(&r).await.expect("first");
        r.branch = Some("dev".to_string());
        r.updated_at = 9_999;
        s.repos().upsert(&r).await.expect("second");
        let got = s.repos().get("acme-app").await.expect("get").expect("row");
        assert_eq!(got.branch.as_deref(), Some("dev"));
        assert_eq!(got.updated_at, 9_999);
    }

    #[tokio::test]
    async fn list_by_project_filters_by_project_id() {
        use crate::store::testutil::sample_repo_for_project;
        let (_tmp, s) = fresh_store().await;
        s.projects().create("p-a", "alpha", None, None, None, 1_000).await.expect("project alpha");
        s.projects().create("p-b", "beta", None, None, None, 1_000).await.expect("project beta");
        s.repos().upsert(&sample_repo_for_project("repo-a1", "p-a")).await.expect("a1");
        s.repos().upsert(&sample_repo_for_project("repo-a2", "p-a")).await.expect("a2");
        s.repos().upsert(&sample_repo_for_project("repo-b1", "p-b")).await.expect("b1");

        let a_names: Vec<_> = s
            .repos()
            .list_by_project("p-a")
            .await
            .expect("list a")
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(a_names, vec!["repo-a1", "repo-a2"]);

        let b_names: Vec<_> = s
            .repos()
            .list_by_project("p-b")
            .await
            .expect("list b")
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(b_names, vec!["repo-b1"]);
    }

    #[tokio::test]
    async fn upsert_rejects_unknown_project_id() {
        let (_tmp, s) = fresh_store().await;
        let mut r = sample_repo("orphan");
        r.project_id = "does-not-exist".to_string();
        let err = s.repos().upsert(&r).await.expect_err("must fail FK");
        let msg = format!("{err}");
        assert!(msg.to_lowercase().contains("foreign key"), "expected FK violation, got: {msg}");
    }

    #[tokio::test]
    async fn list_returns_alphabetical() {
        let (_tmp, s) = fresh_store().await;
        for n in ["zeta", "alpha", "kappa"] {
            s.repos().upsert(&sample_repo(n)).await.expect("insert");
        }
        let names: Vec<_> =
            s.repos().list().await.expect("list").into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["alpha", "kappa", "zeta"]);
    }

    #[tokio::test]
    async fn delete_removes_row() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("doomed")).await.expect("insert");
        let affected = s.repos().delete("doomed").await.expect("delete");
        assert_eq!(affected, 1);
        assert!(s.repos().get("doomed").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn update_patches_subset_and_preserves_pointers() {
        use super::{PatchOption, RepoPatch};
        let (_tmp, s) = fresh_store().await;
        let mut r = sample_repo("billing");
        r.branch = Some("main".to_string());
        s.repos().upsert(&r).await.expect("insert");
        s.repos().set_last_scan("billing", "run-prior", 5_000).await.expect("seed last_scan");

        let patch = RepoPatch {
            name: "billing",
            source_kind: Some("git"),
            source_url_or_path: Some("https://example.com/billing.git"),
            branch: PatchOption::Set(Some("dev")),
            auth_ref: PatchOption::Set(None),
            i_own_this: None,
            updated_at: 7_777,
        };
        let updated = s.repos().update(&patch).await.expect("update");
        assert!(updated, "patch must report applied when row exists");

        let got = s.repos().get("billing").await.expect("get").expect("row");
        assert_eq!(got.source_kind, "git");
        assert_eq!(got.source_url_or_path, "https://example.com/billing.git");
        assert_eq!(got.branch.as_deref(), Some("dev"));
        assert_eq!(got.auth_ref, None);
        // Untouched: pointer + creation time + attestation flag.
        assert_eq!(got.last_scan_run_id.as_deref(), Some("run-prior"));
        assert_eq!(got.created_at, 1_000);
        assert!(got.i_own_this);
        assert_eq!(got.updated_at, 7_777);
    }

    #[tokio::test]
    async fn update_returns_false_when_missing() {
        use super::{PatchOption, RepoPatch};
        let (_tmp, s) = fresh_store().await;
        let patch = RepoPatch {
            name: "ghost",
            source_kind: Some("git"),
            source_url_or_path: None,
            branch: PatchOption::Unset,
            auth_ref: PatchOption::Unset,
            i_own_this: None,
            updated_at: 1,
        };
        let updated = s.repos().update(&patch).await.expect("update");
        assert!(!updated);
    }

    #[tokio::test]
    async fn last_scan_finished_at_joins_runs_table() {
        use crate::store::testutil::sample_run;
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("acme-app")).await.expect("insert repo");

        // No scan yet: pointer null, joined timestamp null.
        let before = s.repos().get("acme-app").await.expect("get").expect("row");
        assert!(before.last_scan_run_id.is_none());
        assert!(before.last_scan_finished_at.is_none());

        // Run row exists but is still in flight (finished_at = NULL): the
        // pointer points at it, joined timestamp stays null.
        s.runs().insert(&sample_run("run-flight")).await.expect("insert run");
        s.repos().set_last_scan("acme-app", "run-flight", 4_000).await.expect("set last_scan");
        let in_flight = s.repos().get("acme-app").await.expect("get").expect("row");
        assert_eq!(in_flight.last_scan_run_id.as_deref(), Some("run-flight"));
        assert!(in_flight.last_scan_finished_at.is_none());

        // Run finishes: joined timestamp surfaces. updated_at is the
        // dispatcher's stamp from set_last_scan, distinct from the run's
        // finished_at.
        s.runs().finish("run-flight", 5_500, "Succeeded", 3_500).await.expect("finish run");
        let after = s.repos().get("acme-app").await.expect("get").expect("row");
        assert_eq!(after.last_scan_run_id.as_deref(), Some("run-flight"));
        assert_eq!(after.last_scan_finished_at, Some(5_500));
        assert_eq!(after.updated_at, 4_000);

        // Pointer at a run id that does not exist (e.g. retention swept
        // the run row out from under us): join falls back to null
        // without erroring.
        s.repos().set_last_scan("acme-app", "run-missing", 6_000).await.expect("dangling");
        let dangling = s.repos().get("acme-app").await.expect("get").expect("row");
        assert_eq!(dangling.last_scan_run_id.as_deref(), Some("run-missing"));
        assert!(dangling.last_scan_finished_at.is_none());
    }

    #[tokio::test]
    async fn set_last_scan_updates_pointer_and_timestamp() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("acme-app")).await.expect("insert");
        s.repos().set_last_scan("acme-app", "run-xyz", 9_999).await.expect("set");
        let got = s.repos().get("acme-app").await.expect("get").expect("row");
        assert_eq!(got.last_scan_run_id.as_deref(), Some("run-xyz"));
        assert_eq!(got.updated_at, 9_999);
    }
}
