//! `project_integrations` table - outbound delivery settings scoped to
//! one project.

use sqlx::{Row, SqlitePool};

pub use nyctos_types::integration::{
    CreateProjectIntegrationRequest, PatchProjectIntegrationRequest, ProjectIntegrationEvent,
    ProjectIntegrationKind, ProjectIntegrationRecord,
};

use crate::store::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectIntegrationStoredRecord {
    pub public: ProjectIntegrationRecord,
    pub config_json: String,
}

#[derive(Debug, Clone)]
pub struct ProjectIntegrationInsert {
    pub id: String,
    pub project_id: String,
    pub kind: ProjectIntegrationKind,
    pub name: String,
    pub enabled: bool,
    pub events: Vec<ProjectIntegrationEvent>,
    pub min_severity: Option<String>,
    pub config_json: String,
    pub target: String,
    pub now_ms: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ProjectIntegrationPatch {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub events: Option<Vec<ProjectIntegrationEvent>>,
    pub min_severity: Option<Option<String>>,
    pub config_json: Option<String>,
    pub target: Option<String>,
    pub updated_at: i64,
}

pub struct ProjectIntegrationStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ProjectIntegrationStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        rec: ProjectIntegrationInsert,
    ) -> Result<ProjectIntegrationRecord, StoreError> {
        sqlx::query(
            r#"
            INSERT INTO project_integrations (
                id, project_id, kind, name, enabled, events_json, min_severity,
                config_json, target, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&rec.id)
        .bind(&rec.project_id)
        .bind(rec.kind.as_str())
        .bind(&rec.name)
        .bind(i64::from(rec.enabled))
        .bind(serde_json::to_string(&rec.events).map_err(StoreError::IntegrationJson)?)
        .bind(&rec.min_severity)
        .bind(&rec.config_json)
        .bind(&rec.target)
        .bind(rec.now_ms)
        .bind(rec.now_ms)
        .execute(self.pool)
        .await?;
        self.get(&rec.id).await?.ok_or(StoreError::Sqlx(sqlx::Error::RowNotFound))
    }

    pub async fn get(&self, id: &str) -> Result<Option<ProjectIntegrationRecord>, StoreError> {
        Ok(self.get_stored(id).await?.map(|r| r.public))
    }

    pub async fn get_stored(
        &self,
        id: &str,
    ) -> Result<Option<ProjectIntegrationStoredRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, project_id, kind, name, enabled, events_json, min_severity,
                   config_json, target, created_at, updated_at, last_delivery_at,
                   last_delivery_status, last_delivery_error
            FROM project_integrations
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_integration).transpose()
    }

    pub async fn list_by_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<ProjectIntegrationRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, project_id, kind, name, enabled, events_json, min_severity,
                   config_json, target, created_at, updated_at, last_delivery_at,
                   last_delivery_status, last_delivery_error
            FROM project_integrations
            WHERE project_id = ?
            ORDER BY created_at DESC, name
            "#,
        )
        .bind(project_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_integration_public).collect()
    }

    pub async fn list_enabled_by_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<ProjectIntegrationStoredRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, project_id, kind, name, enabled, events_json, min_severity,
                   config_json, target, created_at, updated_at, last_delivery_at,
                   last_delivery_status, last_delivery_error
            FROM project_integrations
            WHERE project_id = ? AND enabled = 1
            ORDER BY created_at ASC
            "#,
        )
        .bind(project_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_integration).collect()
    }

    pub async fn update(
        &self,
        id: &str,
        patch: ProjectIntegrationPatch,
    ) -> Result<Option<ProjectIntegrationRecord>, StoreError> {
        let Some(existing) = self.get_stored(id).await? else {
            return Ok(None);
        };
        let public = existing.public;
        let name = patch.name.unwrap_or(public.name);
        let enabled = patch.enabled.unwrap_or(public.enabled);
        let events = patch.events.unwrap_or(public.events);
        let min_severity = patch.min_severity.unwrap_or(public.min_severity);
        let config_json = patch.config_json.unwrap_or(existing.config_json);
        let target = patch.target.unwrap_or(public.target);
        sqlx::query(
            r#"
            UPDATE project_integrations SET
                name = ?,
                enabled = ?,
                events_json = ?,
                min_severity = ?,
                config_json = ?,
                target = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(name)
        .bind(i64::from(enabled))
        .bind(serde_json::to_string(&events).map_err(StoreError::IntegrationJson)?)
        .bind(min_severity)
        .bind(config_json)
        .bind(target)
        .bind(patch.updated_at)
        .bind(id)
        .execute(self.pool)
        .await?;
        self.get(id).await
    }

    pub async fn delete(&self, id: &str) -> Result<u64, StoreError> {
        let res = sqlx::query("DELETE FROM project_integrations WHERE id = ?")
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    pub async fn record_delivery(
        &self,
        id: &str,
        at_ms: i64,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            r#"
            UPDATE project_integrations SET
                last_delivery_at = ?,
                last_delivery_status = ?,
                last_delivery_error = ?
            WHERE id = ?
            "#,
        )
        .bind(at_ms)
        .bind(status)
        .bind(error)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }
}

fn row_to_integration_public(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ProjectIntegrationRecord, StoreError> {
    row_to_integration(row).map(|r| r.public)
}

fn row_to_integration(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ProjectIntegrationStoredRecord, StoreError> {
    let kind_raw: String = row.try_get("kind")?;
    let kind = ProjectIntegrationKind::from_str(&kind_raw)
        .ok_or_else(|| StoreError::InvalidIntegrationKind(kind_raw.clone()))?;
    let events_json: String = row.try_get("events_json")?;
    let events = serde_json::from_str(&events_json).map_err(StoreError::IntegrationJson)?;
    Ok(ProjectIntegrationStoredRecord {
        public: ProjectIntegrationRecord {
            id: row.try_get("id")?,
            project_id: row.try_get("project_id")?,
            kind,
            name: row.try_get("name")?,
            enabled: row.try_get::<i64, _>("enabled")? != 0,
            events,
            min_severity: row.try_get("min_severity")?,
            target: row.try_get("target")?,
            created_at: row.try_get::<i64, _>("created_at")?,
            updated_at: row.try_get::<i64, _>("updated_at")?,
            last_delivery_at: row.try_get("last_delivery_at")?,
            last_delivery_status: row.try_get("last_delivery_status")?,
            last_delivery_error: row.try_get("last_delivery_error")?,
        },
        config_json: row.try_get("config_json")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::fresh_store;

    fn insert(project_id: &str, id: &str, enabled: bool) -> ProjectIntegrationInsert {
        ProjectIntegrationInsert {
            id: id.to_string(),
            project_id: project_id.to_string(),
            kind: ProjectIntegrationKind::Webhook,
            name: id.to_string(),
            enabled,
            events: vec![ProjectIntegrationEvent::RunFinished],
            min_severity: Some("High".to_string()),
            config_json: r#"{"kind":"webhook","url":"https://example.invalid"}"#.to_string(),
            target: "example.invalid".to_string(),
            now_ms: 1_000,
        }
    }

    #[tokio::test]
    async fn create_then_list_by_project_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        s.integrations()
            .create(insert(crate::store::DEFAULT_PROJECT_ID, "int-1", true))
            .await
            .expect("create");
        let rows =
            s.integrations().list_by_project(crate::store::DEFAULT_PROJECT_ID).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target, "example.invalid");
        assert_eq!(rows[0].events, vec![ProjectIntegrationEvent::RunFinished]);
    }

    #[tokio::test]
    async fn enabled_list_excludes_disabled() {
        let (_tmp, s) = fresh_store().await;
        s.integrations()
            .create(insert(crate::store::DEFAULT_PROJECT_ID, "on", true))
            .await
            .expect("on");
        s.integrations()
            .create(insert(crate::store::DEFAULT_PROJECT_ID, "off", false))
            .await
            .expect("off");
        let rows = s
            .integrations()
            .list_enabled_by_project(crate::store::DEFAULT_PROJECT_ID)
            .await
            .unwrap();
        assert_eq!(rows.iter().map(|r| r.public.id.as_str()).collect::<Vec<_>>(), vec!["on"]);
    }

    #[tokio::test]
    async fn project_delete_cascades() {
        let (_tmp, s) = fresh_store().await;
        s.integrations()
            .create(insert(crate::store::DEFAULT_PROJECT_ID, "int-1", true))
            .await
            .expect("create");
        s.projects().delete(crate::store::DEFAULT_PROJECT_ID).await.expect("delete");
        assert!(s.integrations().get("int-1").await.expect("get").is_none());
    }
}
