//! `projects` table - one row per logical product. A project groups
//! related repos (backend, frontend, infra) that compose into a single
//! deployable app. Scans, env-builder merges, and chain validation all
//! hang off the project.

#![allow(clippy::too_many_arguments)]

use sqlx::{Row, SqlitePool};

pub use nyctos_types::project::{ProjectRecord, ProjectRuntimeProfile};

use crate::store::StoreError;

/// Stable, well-known id for the transitional "default" project that
/// legacy callers without an explicit project context attach repos
/// to. Retained so older config files and older API consumers keep
/// working through the nested-project rollout.
pub const DEFAULT_PROJECT_ID: &str = "default-project";
pub const DEFAULT_PROJECT_NAME: &str = "default";

/// Tri-state for `PATCH` semantics on a nullable project field.
#[derive(Debug, Clone, Default)]
pub enum ProjectPatchOption<T> {
    #[default]
    Unset,
    Set(T),
}

#[derive(Debug, Default)]
pub struct ProjectPatch {
    pub description: ProjectPatchOption<Option<String>>,
    pub target_base_url: ProjectPatchOption<Option<String>>,
    pub env_config_json: ProjectPatchOption<Option<String>>,
    pub runtime_profile_json: ProjectPatchOption<Option<String>>,
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
        self.create_with_runtime_profile(
            id,
            name,
            description,
            target_base_url,
            env_config_json,
            None,
            now_ms,
        )
        .await
    }

    /// Insert a new project with an optional serialized runtime profile.
    pub async fn create_with_runtime_profile(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
        target_base_url: Option<&str>,
        env_config_json: Option<&str>,
        runtime_profile_json: Option<&str>,
        now_ms: i64,
    ) -> Result<ProjectRecord, StoreError> {
        sqlx::query(
            r#"
            INSERT INTO projects (
                id, name, description, target_base_url, env_config_json, runtime_profile_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(description)
        .bind(target_base_url)
        .bind(env_config_json)
        .bind(runtime_profile_json)
        .bind(now_ms)
        .bind(now_ms)
        .execute(self.pool)
        .await?;
        Ok(ProjectRecord {
            id: id.to_string(),
            name: name.to_string(),
            description: description.map(str::to_string),
            target_base_url: target_base_url.map(str::to_string),
            env_config_json: env_config_json.map(str::to_string),
            runtime_profile: parse_runtime_profile_json(runtime_profile_json.map(str::to_string))?,
            default_launch_profile: None,
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
        let row = sqlx::query(
            r#"
            SELECT projects.id, projects.name, projects.description, projects.target_base_url,
                   projects.env_config_json, projects.runtime_profile_json,
                   projects.created_at, projects.updated_at,
                   lp.id AS lp_id, lp.project_id AS lp_project_id, lp.name AS lp_name,
                   lp.mode AS lp_mode, lp.build_steps_json AS lp_build_steps_json,
                   lp.start_steps_json AS lp_start_steps_json,
                   lp.seed_steps_json AS lp_seed_steps_json,
                   lp.reset_steps_json AS lp_reset_steps_json,
                   lp.login_steps_json AS lp_login_steps_json,
                   lp.stop_steps_json AS lp_stop_steps_json,
                   lp.health_checks_json AS lp_health_checks_json,
                   lp.target_urls_json AS lp_target_urls_json,
                   lp.env_refs_json AS lp_env_refs_json,
                   lp.working_dirs_json AS lp_working_dirs_json,
                   lp.readiness AS lp_readiness, lp.created_at AS lp_created_at,
                   lp.updated_at AS lp_updated_at, lp.is_default AS lp_is_default
            FROM projects
            LEFT JOIN project_launch_profiles lp
              ON lp.project_id = projects.id AND lp.is_default = 1
            WHERE projects.id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_project_record).transpose()
    }

    pub async fn get_by_name(&self, name: &str) -> Result<Option<ProjectRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT projects.id, projects.name, projects.description, projects.target_base_url,
                   projects.env_config_json, projects.runtime_profile_json,
                   projects.created_at, projects.updated_at,
                   lp.id AS lp_id, lp.project_id AS lp_project_id, lp.name AS lp_name,
                   lp.mode AS lp_mode, lp.build_steps_json AS lp_build_steps_json,
                   lp.start_steps_json AS lp_start_steps_json,
                   lp.seed_steps_json AS lp_seed_steps_json,
                   lp.reset_steps_json AS lp_reset_steps_json,
                   lp.login_steps_json AS lp_login_steps_json,
                   lp.stop_steps_json AS lp_stop_steps_json,
                   lp.health_checks_json AS lp_health_checks_json,
                   lp.target_urls_json AS lp_target_urls_json,
                   lp.env_refs_json AS lp_env_refs_json,
                   lp.working_dirs_json AS lp_working_dirs_json,
                   lp.readiness AS lp_readiness, lp.created_at AS lp_created_at,
                   lp.updated_at AS lp_updated_at, lp.is_default AS lp_is_default
            FROM projects
            LEFT JOIN project_launch_profiles lp
              ON lp.project_id = projects.id AND lp.is_default = 1
            WHERE projects.name = ?
            "#,
        )
        .bind(name)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_project_record).transpose()
    }

    pub async fn list(&self) -> Result<Vec<ProjectRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT projects.id, projects.name, projects.description, projects.target_base_url,
                   projects.env_config_json, projects.runtime_profile_json,
                   projects.created_at, projects.updated_at,
                   lp.id AS lp_id, lp.project_id AS lp_project_id, lp.name AS lp_name,
                   lp.mode AS lp_mode, lp.build_steps_json AS lp_build_steps_json,
                   lp.start_steps_json AS lp_start_steps_json,
                   lp.seed_steps_json AS lp_seed_steps_json,
                   lp.reset_steps_json AS lp_reset_steps_json,
                   lp.login_steps_json AS lp_login_steps_json,
                   lp.stop_steps_json AS lp_stop_steps_json,
                   lp.health_checks_json AS lp_health_checks_json,
                   lp.target_urls_json AS lp_target_urls_json,
                   lp.env_refs_json AS lp_env_refs_json,
                   lp.working_dirs_json AS lp_working_dirs_json,
                   lp.readiness AS lp_readiness, lp.created_at AS lp_created_at,
                   lp.updated_at AS lp_updated_at, lp.is_default AS lp_is_default
            FROM projects
            LEFT JOIN project_launch_profiles lp
              ON lp.project_id = projects.id AND lp.is_default = 1
            ORDER BY projects.name
            "#,
        )
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_project_record).collect()
    }

    /// Partial update. Returns `Ok(false)` if no row with `id` exists.
    pub async fn update(&self, id: &str, patch: &ProjectPatch) -> Result<bool, StoreError> {
        let Some(existing) = self.get(id).await? else {
            return Ok(false);
        };
        let description = match &patch.description {
            ProjectPatchOption::Unset => existing.description,
            ProjectPatchOption::Set(v) => v.clone(),
        };
        let target_base_url = match &patch.target_base_url {
            ProjectPatchOption::Unset => existing.target_base_url,
            ProjectPatchOption::Set(v) => v.clone(),
        };
        let env_config_json = match &patch.env_config_json {
            ProjectPatchOption::Unset => existing.env_config_json,
            ProjectPatchOption::Set(v) => v.clone(),
        };
        let runtime_profile_json = match &patch.runtime_profile_json {
            ProjectPatchOption::Unset => {
                existing.runtime_profile.as_ref().map(serde_json::to_string).transpose()?
            }
            ProjectPatchOption::Set(v) => v.clone(),
        };
        sqlx::query(
            r#"
            UPDATE projects SET
                description = ?,
                target_base_url = ?,
                env_config_json = ?,
                runtime_profile_json = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(description)
        .bind(target_base_url)
        .bind(env_config_json)
        .bind(runtime_profile_json)
        .bind(patch.updated_at)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(true)
    }

    pub async fn delete(&self, id: &str) -> Result<u64, StoreError> {
        let res = sqlx::query!("DELETE FROM projects WHERE id = ?", id).execute(self.pool).await?;
        Ok(res.rows_affected())
    }
}

fn row_to_project_record(row: sqlx::sqlite::SqliteRow) -> Result<ProjectRecord, StoreError> {
    Ok(ProjectRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        target_base_url: row.try_get("target_base_url")?,
        env_config_json: row.try_get("env_config_json")?,
        runtime_profile: parse_runtime_profile_json(row.try_get("runtime_profile_json")?)?,
        default_launch_profile: row_to_default_launch_profile(&row)?,
        created_at: row.try_get::<i64, _>("created_at")?,
        updated_at: row.try_get::<i64, _>("updated_at")?,
    })
}

fn row_to_default_launch_profile(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Option<nyctos_types::product::ProjectLaunchProfile>, StoreError> {
    let id: Option<String> = row.try_get("lp_id")?;
    let Some(id) = id else {
        return Ok(None);
    };
    Ok(Some(nyctos_types::product::ProjectLaunchProfile {
        id,
        project_id: row.try_get("lp_project_id")?,
        name: row.try_get("lp_name")?,
        mode: row.try_get("lp_mode")?,
        build_steps: serde_json::from_str(&row.try_get::<String, _>("lp_build_steps_json")?)?,
        start_steps: serde_json::from_str(&row.try_get::<String, _>("lp_start_steps_json")?)?,
        seed_steps: serde_json::from_str(&row.try_get::<String, _>("lp_seed_steps_json")?)?,
        reset_steps: serde_json::from_str(&row.try_get::<String, _>("lp_reset_steps_json")?)?,
        login_steps: serde_json::from_str(&row.try_get::<String, _>("lp_login_steps_json")?)?,
        stop_steps: serde_json::from_str(&row.try_get::<String, _>("lp_stop_steps_json")?)?,
        health_checks: serde_json::from_str(&row.try_get::<String, _>("lp_health_checks_json")?)?,
        target_urls: serde_json::from_str(&row.try_get::<String, _>("lp_target_urls_json")?)?,
        env_refs: serde_json::from_str(&row.try_get::<String, _>("lp_env_refs_json")?)?,
        working_dirs: serde_json::from_str(&row.try_get::<String, _>("lp_working_dirs_json")?)?,
        readiness: row.try_get("lp_readiness")?,
        created_at: row.try_get::<i64, _>("lp_created_at")?,
        updated_at: row.try_get::<i64, _>("lp_updated_at")?,
        is_default: row.try_get::<i64, _>("lp_is_default")? != 0,
    }))
}

fn parse_runtime_profile_json(
    runtime_profile_json: Option<String>,
) -> Result<Option<ProjectRuntimeProfile>, StoreError> {
    runtime_profile_json
        .map(|json| serde_json::from_str(&json))
        .transpose()
        .map_err(StoreError::ProjectRuntimeProfileJson)
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
            description: ProjectPatchOption::Set(Some("now described".to_string())),
            target_base_url: ProjectPatchOption::Set(Some("http://acme".to_string())),
            env_config_json: ProjectPatchOption::Unset,
            runtime_profile_json: ProjectPatchOption::Unset,
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
    async fn runtime_profile_json_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        let profile_json = r#"{
            "build_commands":[{"command":"npm ci","repo_name":"web","timeout_seconds":120}],
            "start_commands":[{"command":"npm run dev","working_directory":"frontend"}],
            "health_check_url":"http://localhost:3000/health",
            "target_base_url":"http://localhost:3000",
            "allowed_hosts":["localhost","127.0.0.1"],
            "env_vars":[{"name":"NODE_ENV","value":"test","secret":false}],
            "env_file":".env.test",
            "timeout_seconds":300
        }"#;
        s.projects()
            .create_with_runtime_profile(
                "p-1",
                "acme",
                None,
                Some("http://localhost:3000"),
                None,
                Some(profile_json),
                1_000,
            )
            .await
            .expect("create");

        let got = s.projects().get("p-1").await.expect("get").expect("row");
        let profile = got.runtime_profile.expect("profile");
        assert_eq!(profile.build_commands[0].command, "npm ci");
        assert_eq!(profile.build_commands[0].repo_name.as_deref(), Some("web"));
        assert_eq!(profile.start_commands[0].working_directory.as_deref(), Some("frontend"));
        assert_eq!(profile.allowed_hosts, vec!["localhost", "127.0.0.1"]);
        assert_eq!(profile.env_vars[0].name, "NODE_ENV");
        assert_eq!(profile.env_file.as_deref(), Some(".env.test"));
        assert_eq!(profile.timeout_seconds, Some(300));
    }

    #[tokio::test]
    async fn update_can_set_and_clear_runtime_profile() {
        let (_tmp, s) = fresh_store().await;
        s.projects().create("p-1", "acme", None, None, None, 1_000).await.expect("create");

        let profile_json = r#"{"start_commands":[{"command":"cargo run"}]}"#;
        let patch = ProjectPatch {
            runtime_profile_json: ProjectPatchOption::Set(Some(profile_json.to_string())),
            updated_at: 2_000,
            ..Default::default()
        };
        assert!(s.projects().update("p-1", &patch).await.expect("set"));
        let got = s.projects().get("p-1").await.expect("get").expect("row");
        assert_eq!(got.runtime_profile.expect("profile").start_commands[0].command, "cargo run");

        let clear = ProjectPatch {
            runtime_profile_json: ProjectPatchOption::Set(None),
            updated_at: 3_000,
            ..Default::default()
        };
        assert!(s.projects().update("p-1", &clear).await.expect("clear"));
        let got = s.projects().get("p-1").await.expect("get").expect("row");
        assert!(got.runtime_profile.is_none());
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
