//! `repos` table - one row per repository the agent is configured to scan.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    pub async fn get(&self, name: &str) -> Result<Option<RepoRecord>, StoreError> {
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

    pub async fn list(&self) -> Result<Vec<RepoRecord>, StoreError> {
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

    /// Partial update of mutable repo fields. Returns `Ok(false)` if no
    /// row with `name` exists. `last_scan_run_id` is left untouched —
    /// that pointer is owned by the dispatcher via [`Self::set_last_scan`].
    /// `created_at` is preserved.
    pub async fn update(&self, patch: &RepoPatch<'_>) -> Result<bool, StoreError> {
        let Some(existing) = self.get(patch.name).await? else {
            return Ok(false);
        };
        let merged = RepoRecord {
            name: existing.name,
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

    pub async fn delete(&self, name: &str) -> Result<u64, StoreError> {
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
    async fn update_patches_subset_and_preserves_pointers() {
        use super::{PatchOption, RepoPatch};
        let (_tmp, s) = fresh_store().await;
        let mut r = sample_repo("billing");
        r.branch = Some("main".to_string());
        s.repos().upsert(&r).await.expect("insert");
        s.repos()
            .set_last_scan("billing", "run-prior", 5_000)
            .await
            .expect("seed last_scan");

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
        assert_eq!(got.i_own_this, true);
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
    async fn set_last_scan_updates_pointer_and_timestamp() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("nyx-pro")).await.expect("insert");
        s.repos().set_last_scan("nyx-pro", "run-xyz", 9_999).await.expect("set");
        let got = s.repos().get("nyx-pro").await.expect("get").expect("row");
        assert_eq!(got.last_scan_run_id.as_deref(), Some("run-xyz"));
        assert_eq!(got.updated_at, 9_999);
    }
}
