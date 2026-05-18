//! `projects` table - one row per logical product. A project groups
//! related repos (backend, frontend, infra) that compose into a single
//! deployable app. Scans, env-builder merges, and chain validation all
//! hang off the project.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::store::StoreError;

/// Stable, well-known id for the transitional "default" project that
/// legacy callers without an explicit project context attach repos
/// to. Retained so older config files and older API consumers keep
/// working through the nested-project rollout.
pub const DEFAULT_PROJECT_ID: &str = "default-project";
pub const DEFAULT_PROJECT_NAME: &str = "default";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub target_base_url: Option<String>,
    pub env_config_json: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Tri-state for `PATCH` semantics on a nullable project field.
#[derive(Debug, Clone, Default)]
pub enum ProjectPatchOption<T> {
    #[default]
    Unset,
    Set(T),
}

#[derive(Debug, Default)]
pub struct ProjectPatch<'a> {
    pub description: ProjectPatchOption<Option<&'a str>>,
    pub target_base_url: ProjectPatchOption<Option<&'a str>>,
    pub env_config_json: ProjectPatchOption<Option<&'a str>>,
    pub updated_at: i64,
}

pub struct ProjectStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ProjectStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a new project. `id` is the stable row id; `name` is unique
    /// and surfaced to operators in UI / CLI listings. `now_ms` populates
    /// both `created_at` and `updated_at`.
    pub async fn create(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
        target_base_url: Option<&str>,
        env_config_json: Option<&str>,
        now_ms: i64,
    ) -> Result<ProjectRecord, StoreError> {
        sqlx::query!(
            r#"
            INSERT INTO projects (
                id, name, description, target_base_url, env_config_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
            id,
            name,
            description,
            target_base_url,
            env_config_json,
            now_ms,
            now_ms,
        )
        .execute(self.pool)
        .await?;
        Ok(ProjectRecord {
            id: id.to_string(),
            name: name.to_string(),
            description: description.map(str::to_string),
            target_base_url: target_base_url.map(str::to_string),
            env_config_json: env_config_json.map(str::to_string),
            created_at: now_ms,
            updated_at: now_ms,
        })
    }

    /// Idempotent: insert the default project row if it does not
    /// exist. Used as a transitional bootstrap so legacy callers
    /// without an explicit project context can still upsert repos
    /// against the FK.
    pub async fn ensure_default(&self, now_ms: i64) -> Result<ProjectRecord, StoreError> {
        if let Some(existing) = self.get(DEFAULT_PROJECT_ID).await? {
            return Ok(existing);
        }
        match self.create(DEFAULT_PROJECT_ID, DEFAULT_PROJECT_NAME, None, None, None, now_ms).await
        {
            Ok(rec) => Ok(rec),
            // Race: another connection inserted it first. Re-fetch.
            Err(StoreError::Sqlx(sqlx::Error::Database(db_err)))
                if db_err.code().as_deref() == Some("2067")
                    || db_err.code().as_deref() == Some("1555") =>
            {
                self.get(DEFAULT_PROJECT_ID)
                    .await?
                    .ok_or(StoreError::Sqlx(sqlx::Error::RowNotFound))
            }
            Err(other) => Err(other),
        }
    }

    pub async fn get(&self, id: &str) -> Result<Option<ProjectRecord>, StoreError> {
        let row = sqlx::query!(
            r#"
            SELECT id AS "id!", name AS "name!",
                   description, target_base_url, env_config_json,
                   created_at AS "created_at!: i64",
                   updated_at AS "updated_at!: i64"
            FROM projects WHERE id = ?
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|r| ProjectRecord {
            id: r.id,
            name: r.name,
            description: r.description,
            target_base_url: r.target_base_url,
            env_config_json: r.env_config_json,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    pub async fn get_by_name(&self, name: &str) -> Result<Option<ProjectRecord>, StoreError> {
        let row = sqlx::query!(
            r#"
            SELECT id AS "id!", name AS "name!",
                   description, target_base_url, env_config_json,
                   created_at AS "created_at!: i64",
                   updated_at AS "updated_at!: i64"
            FROM projects WHERE name = ?
            "#,
            name
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|r| ProjectRecord {
            id: r.id,
            name: r.name,
            description: r.description,
            target_base_url: r.target_base_url,
            env_config_json: r.env_config_json,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    pub async fn list(&self) -> Result<Vec<ProjectRecord>, StoreError> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!", name AS "name!",
                   description, target_base_url, env_config_json,
                   created_at AS "created_at!: i64",
                   updated_at AS "updated_at!: i64"
            FROM projects ORDER BY name
            "#
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ProjectRecord {
                id: r.id,
                name: r.name,
                description: r.description,
                target_base_url: r.target_base_url,
                env_config_json: r.env_config_json,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    /// Partial update. Returns `Ok(false)` if no row with `id` exists.
    pub async fn update(&self, id: &str, patch: &ProjectPatch<'_>) -> Result<bool, StoreError> {
        let Some(existing) = self.get(id).await? else {
            return Ok(false);
        };
        let description = match patch.description {
            ProjectPatchOption::Unset => existing.description,
            ProjectPatchOption::Set(v) => v.map(str::to_string),
        };
        let target_base_url = match patch.target_base_url {
            ProjectPatchOption::Unset => existing.target_base_url,
            ProjectPatchOption::Set(v) => v.map(str::to_string),
        };
        let env_config_json = match patch.env_config_json {
            ProjectPatchOption::Unset => existing.env_config_json,
            ProjectPatchOption::Set(v) => v.map(str::to_string),
        };
        sqlx::query!(
            r#"
            UPDATE projects SET
                description = ?,
                target_base_url = ?,
                env_config_json = ?,
                updated_at = ?
            WHERE id = ?
            "#,
            description,
            target_base_url,
            env_config_json,
            patch.updated_at,
            id,
        )
        .execute(self.pool)
        .await?;
        Ok(true)
    }

    pub async fn delete(&self, id: &str) -> Result<u64, StoreError> {
        let res = sqlx::query!("DELETE FROM projects WHERE id = ?", id).execute(self.pool).await?;
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::fresh_store;

    #[tokio::test]
    async fn create_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        let rec = s
            .projects()
            .create("p-1", "acme", Some("desc"), Some("http://x"), None, 1_000)
            .await
            .expect("create");
        let got = s.projects().get("p-1").await.expect("get").expect("row");
        assert_eq!(got, rec);
    }

    #[tokio::test]
    async fn get_by_name_resolves_id() {
        let (_tmp, s) = fresh_store().await;
        s.projects().create("p-1", "acme", None, None, None, 1_000).await.expect("create");
        let got = s.projects().get_by_name("acme").await.expect("name").expect("row");
        assert_eq!(got.id, "p-1");
    }

    #[tokio::test]
    async fn list_returns_alphabetical_by_name() {
        let (_tmp, s) = fresh_store().await;
        // fresh_store seeds DEFAULT_PROJECT_NAME = "default"; insert two more.
        s.projects().create("z", "zeta", None, None, None, 1_000).await.expect("z");
        s.projects().create("a", "alpha", None, None, None, 1_000).await.expect("a");
        let names: Vec<_> =
            s.projects().list().await.expect("list").into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["alpha", "default", "zeta"]);
    }

    #[tokio::test]
    async fn ensure_default_is_idempotent() {
        let (_tmp, s) = fresh_store().await;
        let first = s.projects().get(DEFAULT_PROJECT_ID).await.expect("get").expect("row");
        let again = s.projects().ensure_default(9_999).await.expect("ensure");
        assert_eq!(first.id, again.id);
        assert_eq!(first.created_at, again.created_at, "must not reset created_at");
    }

    #[tokio::test]
    async fn update_patches_subset() {
        let (_tmp, s) = fresh_store().await;
        s.projects().create("p-1", "acme", None, None, None, 1_000).await.expect("create");
        let patch = ProjectPatch {
            description: ProjectPatchOption::Set(Some("now described")),
            target_base_url: ProjectPatchOption::Set(Some("http://acme")),
            env_config_json: ProjectPatchOption::Unset,
            updated_at: 5_000,
        };
        assert!(s.projects().update("p-1", &patch).await.expect("update"));
        let got = s.projects().get("p-1").await.expect("get").expect("row");
        assert_eq!(got.description.as_deref(), Some("now described"));
        assert_eq!(got.target_base_url.as_deref(), Some("http://acme"));
        assert_eq!(got.env_config_json, None);
        assert_eq!(got.updated_at, 5_000);
    }

    #[tokio::test]
    async fn update_returns_false_when_missing() {
        let (_tmp, s) = fresh_store().await;
        let patch = ProjectPatch { updated_at: 1, ..Default::default() };
        assert!(!s.projects().update("ghost", &patch).await.expect("update"));
    }

    #[tokio::test]
    async fn delete_cascades_to_repos() {
        use crate::store::testutil::sample_repo_for_project;
        let (_tmp, s) = fresh_store().await;
        let p = s
            .projects()
            .create("p-doomed", "doomed", None, None, None, 1_000)
            .await
            .expect("create");
        let r = sample_repo_for_project("attached", &p.id);
        s.repos().upsert(&r).await.expect("upsert");
        let affected = s.projects().delete("p-doomed").await.expect("delete");
        assert_eq!(affected, 1);
        assert!(
            s.repos().get("attached").await.expect("get").is_none(),
            "FK cascade must drop repo"
        );
    }
}
