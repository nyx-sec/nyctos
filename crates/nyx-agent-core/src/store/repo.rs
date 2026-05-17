//! `repos` table - one row per repository the agent is configured to scan.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRecord {
    pub name: String,
    pub source_kind: String,
    pub source_url_or_path: String,
    pub branch: Option<String>,
    pub auth_ref: Option<String>,
    pub i_own_this: bool,
    pub last_scan_run_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct RepoStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> RepoStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn upsert(&self, r: &RepoRecord) -> Result<(), sqlx::Error> {
        let i_own = i64::from(r.i_own_this);
        sqlx::query!(
            r#"
            INSERT INTO repos (
                name, source_kind, source_url_or_path, branch, auth_ref,
                i_own_this, last_scan_run_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                source_kind        = excluded.source_kind,
                source_url_or_path = excluded.source_url_or_path,
                branch             = excluded.branch,
                auth_ref           = excluded.auth_ref,
                i_own_this         = excluded.i_own_this,
                last_scan_run_id   = excluded.last_scan_run_id,
                updated_at         = excluded.updated_at
            "#,
            r.name,
            r.source_kind,
            r.source_url_or_path,
            r.branch,
            r.auth_ref,
            i_own,
            r.last_scan_run_id,
            r.created_at,
            r.updated_at,
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, name: &str) -> Result<Option<RepoRecord>, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT name AS "name!", source_kind AS "source_kind!",
                   source_url_or_path AS "source_url_or_path!",
                   branch, auth_ref,
                   i_own_this AS "i_own_this!: i64",
                   last_scan_run_id,
                   created_at AS "created_at!: i64",
                   updated_at AS "updated_at!: i64"
            FROM repos WHERE name = ?
            "#,
            name
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|r| RepoRecord {
            name: r.name,
            source_kind: r.source_kind,
            source_url_or_path: r.source_url_or_path,
            branch: r.branch,
            auth_ref: r.auth_ref,
            i_own_this: r.i_own_this != 0,
            last_scan_run_id: r.last_scan_run_id,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    pub async fn list(&self) -> Result<Vec<RepoRecord>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT name AS "name!", source_kind AS "source_kind!",
                   source_url_or_path AS "source_url_or_path!",
                   branch, auth_ref,
                   i_own_this AS "i_own_this!: i64",
                   last_scan_run_id,
                   created_at AS "created_at!: i64",
                   updated_at AS "updated_at!: i64"
            FROM repos ORDER BY name
            "#
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| RepoRecord {
                name: r.name,
                source_kind: r.source_kind,
                source_url_or_path: r.source_url_or_path,
                branch: r.branch,
                auth_ref: r.auth_ref,
                i_own_this: r.i_own_this != 0,
                last_scan_run_id: r.last_scan_run_id,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    pub async fn set_last_scan(
        &self,
        name: &str,
        run_id: &str,
        updated_at: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE repos SET last_scan_run_id = ?, updated_at = ? WHERE name = ?",
            run_id,
            updated_at,
            name
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, name: &str) -> Result<u64, sqlx::Error> {
        let res = sqlx::query!("DELETE FROM repos WHERE name = ?", name).execute(self.pool).await?;
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use crate::store::testutil::{fresh_store, sample_repo};

    #[tokio::test]
    async fn upsert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        let r = sample_repo("nyx-pro");
        s.repos().upsert(&r).await.expect("insert");
        let got = s.repos().get("nyx-pro").await.expect("get").expect("row");
        assert_eq!(got, r);
    }

    #[tokio::test]
    async fn upsert_is_idempotent_on_conflict() {
        let (_tmp, s) = fresh_store().await;
        let mut r = sample_repo("nyx-pro");
        s.repos().upsert(&r).await.expect("first");
        r.branch = Some("dev".to_string());
        r.updated_at = 9_999;
        s.repos().upsert(&r).await.expect("second");
        let got = s.repos().get("nyx-pro").await.expect("get").expect("row");
        assert_eq!(got.branch.as_deref(), Some("dev"));
        assert_eq!(got.updated_at, 9_999);
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
    async fn set_last_scan_updates_pointer_and_timestamp() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("nyx-pro")).await.expect("insert");
        s.repos().set_last_scan("nyx-pro", "run-xyz", 9_999).await.expect("set");
        let got = s.repos().get("nyx-pro").await.expect("get").expect("row");
        assert_eq!(got.last_scan_run_id.as_deref(), Some("run-xyz"));
        assert_eq!(got.updated_at, 9_999);
    }
}
