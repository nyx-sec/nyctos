//! `webhooks` table - incoming hook config per repo.

use sqlx::SqlitePool;

use crate::store::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRecord {
    pub id: String,
    pub repo: String,
    pub hmac_secret_ref: String,
    pub branch_filter: Option<String>,
    pub enabled: bool,
}

pub struct WebhookStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> WebhookStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, w: &WebhookRecord) -> Result<(), StoreError> {
        let enabled = i64::from(w.enabled);
        sqlx::query!(
            r#"
            INSERT INTO webhooks (id, repo, hmac_secret_ref, branch_filter, enabled)
            VALUES (?, ?, ?, ?, ?)
            "#,
            w.id,
            w.repo,
            w.hmac_secret_ref,
            w.branch_filter,
            enabled,
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<WebhookRecord>, StoreError> {
        let row = sqlx::query!(
            r#"
            SELECT id AS "id!", repo AS "repo!",
                   hmac_secret_ref AS "hmac_secret_ref!",
                   branch_filter,
                   enabled AS "enabled!: i64"
            FROM webhooks WHERE id = ?
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|r| WebhookRecord {
            id: r.id,
            repo: r.repo,
            hmac_secret_ref: r.hmac_secret_ref,
            branch_filter: r.branch_filter,
            enabled: r.enabled != 0,
        }))
    }

    pub async fn list_enabled_for_repo(
        &self,
        repo: &str,
    ) -> Result<Vec<WebhookRecord>, StoreError> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!", repo AS "repo!",
                   hmac_secret_ref AS "hmac_secret_ref!",
                   branch_filter,
                   enabled AS "enabled!: i64"
            FROM webhooks WHERE repo = ? AND enabled = 1
            "#,
            repo
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| WebhookRecord {
                id: r.id,
                repo: r.repo,
                hmac_secret_ref: r.hmac_secret_ref,
                branch_filter: r.branch_filter,
                enabled: r.enabled != 0,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{fresh_store, sample_repo};

    fn hook(id: &str, repo: &str, enabled: bool) -> WebhookRecord {
        WebhookRecord {
            id: id.to_string(),
            repo: repo.to_string(),
            hmac_secret_ref: "secret/manager/key#1".to_string(),
            branch_filter: Some("main".to_string()),
            enabled,
        }
    }

    #[tokio::test]
    async fn insert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("r")).await.expect("repo");
        let h = hook("h-1", "r", true);
        s.webhooks().insert(&h).await.expect("insert");
        let got = s.webhooks().get("h-1").await.expect("get").expect("row");
        assert_eq!(got, h);
    }

    #[tokio::test]
    async fn list_enabled_excludes_disabled_and_other_repos() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("r1")).await.expect("r1");
        s.repos().upsert(&sample_repo("r2")).await.expect("r2");
        s.webhooks().insert(&hook("a", "r1", true)).await.expect("a");
        s.webhooks().insert(&hook("b", "r1", false)).await.expect("b");
        s.webhooks().insert(&hook("c", "r2", true)).await.expect("c");
        let got: Vec<_> = s
            .webhooks()
            .list_enabled_for_repo("r1")
            .await
            .expect("list")
            .into_iter()
            .map(|h| h.id)
            .collect();
        assert_eq!(got, vec!["a".to_string()]);
    }

    #[tokio::test]
    async fn cascade_from_repo_delete() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("doomed")).await.expect("repo");
        s.webhooks().insert(&hook("h", "doomed", true)).await.expect("insert");
        s.repos().delete("doomed").await.expect("del");
        assert!(
            s.webhooks().get("h").await.expect("get").is_none(),
            "webhook should cascade-delete with parent repo"
        );
    }
}
