//! `schedules` table - cron-style triggers; nullable `repo` means all-repos.

use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleRecord {
    pub id: String,
    pub repo: Option<String>,
    pub cron_expr: String,
    pub enabled: bool,
    pub last_fired_at: Option<i64>,
}

pub struct ScheduleStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ScheduleStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, s: &ScheduleRecord) -> Result<(), sqlx::Error> {
        let enabled = i64::from(s.enabled);
        sqlx::query!(
            r#"
            INSERT INTO schedules (id, repo, cron_expr, enabled, last_fired_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
            s.id,
            s.repo,
            s.cron_expr,
            enabled,
            s.last_fired_at,
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<ScheduleRecord>, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT id AS "id!", repo, cron_expr AS "cron_expr!",
                   enabled AS "enabled!: i64", last_fired_at
            FROM schedules WHERE id = ?
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|r| ScheduleRecord {
            id: r.id,
            repo: r.repo,
            cron_expr: r.cron_expr,
            enabled: r.enabled != 0,
            last_fired_at: r.last_fired_at,
        }))
    }

    pub async fn list_enabled(&self) -> Result<Vec<ScheduleRecord>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!", repo, cron_expr AS "cron_expr!",
                   enabled AS "enabled!: i64", last_fired_at
            FROM schedules WHERE enabled = 1
            "#
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ScheduleRecord {
                id: r.id,
                repo: r.repo,
                cron_expr: r.cron_expr,
                enabled: r.enabled != 0,
                last_fired_at: r.last_fired_at,
            })
            .collect())
    }

    pub async fn record_fired(&self, id: &str, fired_at: i64) -> Result<(), sqlx::Error> {
        sqlx::query!("UPDATE schedules SET last_fired_at = ? WHERE id = ?", fired_at, id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), sqlx::Error> {
        let e = i64::from(enabled);
        sqlx::query!("UPDATE schedules SET enabled = ? WHERE id = ?", e, id)
            .execute(self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{fresh_store, sample_repo};

    fn s_record(id: &str, repo: Option<&str>, enabled: bool) -> ScheduleRecord {
        ScheduleRecord {
            id: id.to_string(),
            repo: repo.map(str::to_string),
            cron_expr: "0 * * * *".to_string(),
            enabled,
            last_fired_at: None,
        }
    }

    #[tokio::test]
    async fn insert_then_get_with_repo() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("r")).await.expect("repo");
        let r = s_record("sch-1", Some("r"), true);
        s.schedules().insert(&r).await.expect("insert");
        let got = s.schedules().get("sch-1").await.expect("get").expect("row");
        assert_eq!(got, r);
    }

    #[tokio::test]
    async fn insert_with_null_repo_means_all_repos() {
        let (_tmp, s) = fresh_store().await;
        let r = s_record("sch-all", None, true);
        s.schedules().insert(&r).await.expect("insert");
        let got = s.schedules().get("sch-all").await.expect("get").expect("row");
        assert!(got.repo.is_none());
    }

    #[tokio::test]
    async fn list_enabled_excludes_disabled() {
        let (_tmp, s) = fresh_store().await;
        s.schedules().insert(&s_record("on", None, true)).await.expect("on");
        s.schedules().insert(&s_record("off", None, false)).await.expect("off");
        let got: Vec<_> =
            s.schedules().list_enabled().await.expect("list").into_iter().map(|r| r.id).collect();
        assert_eq!(got, vec!["on".to_string()]);
    }

    #[tokio::test]
    async fn record_fired_persists() {
        let (_tmp, s) = fresh_store().await;
        s.schedules().insert(&s_record("sch", None, true)).await.expect("insert");
        s.schedules().record_fired("sch", 11_111).await.expect("fire");
        let got = s.schedules().get("sch").await.expect("get").expect("row");
        assert_eq!(got.last_fired_at, Some(11_111));
    }

    #[tokio::test]
    async fn set_enabled_toggles() {
        let (_tmp, s) = fresh_store().await;
        s.schedules().insert(&s_record("sch", None, true)).await.expect("insert");
        s.schedules().set_enabled("sch", false).await.expect("disable");
        let got = s.schedules().get("sch").await.expect("get").expect("row");
        assert!(!got.enabled);
    }

    #[tokio::test]
    async fn cascade_from_repo_delete() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("doomed")).await.expect("repo");
        s.schedules().insert(&s_record("sch", Some("doomed"), true)).await.expect("insert");
        s.repos().delete("doomed").await.expect("del");
        assert!(
            s.schedules().get("sch").await.expect("get").is_none(),
            "schedule should cascade-delete with parent repo"
        );
    }
}
