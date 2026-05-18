//! `repro_bundles` table - tarballs of verifiable repro setups per finding.

use sqlx::SqlitePool;

use crate::store::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReproBundleRecord {
    pub id: String,
    pub finding_id: String,
    pub path: String,
    pub sha256: String,
    pub created_at: i64,
    pub last_replay_at: Option<i64>,
    pub last_replay_status: Option<String>,
}

pub struct ReproBundleStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ReproBundleStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, b: &ReproBundleRecord) -> Result<(), StoreError> {
        sqlx::query!(
            r#"
            INSERT INTO repro_bundles (
                id, finding_id, path, sha256, created_at,
                last_replay_at, last_replay_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
            b.id,
            b.finding_id,
            b.path,
            b.sha256,
            b.created_at,
            b.last_replay_at,
            b.last_replay_status,
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<ReproBundleRecord>, StoreError> {
        let row = sqlx::query_as!(
            ReproBundleRecord,
            r#"
            SELECT id AS "id!", finding_id AS "finding_id!",
                   path AS "path!", sha256 AS "sha256!",
                   created_at AS "created_at!: i64",
                   last_replay_at, last_replay_status
            FROM repro_bundles WHERE id = ?
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row)
    }

    pub async fn list_for_finding(
        &self,
        finding_id: &str,
    ) -> Result<Vec<ReproBundleRecord>, StoreError> {
        let rows = sqlx::query_as!(
            ReproBundleRecord,
            r#"
            SELECT id AS "id!", finding_id AS "finding_id!",
                   path AS "path!", sha256 AS "sha256!",
                   created_at AS "created_at!: i64",
                   last_replay_at, last_replay_status
            FROM repro_bundles WHERE finding_id = ? ORDER BY created_at
            "#,
            finding_id
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn record_replay(
        &self,
        id: &str,
        replay_at: i64,
        status: &str,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            r#"
            UPDATE repro_bundles
               SET last_replay_at = ?, last_replay_status = ?
             WHERE id = ?
            "#,
            replay_at,
            status,
            id
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{fresh_store, sample_finding, sample_repo, sample_run};

    fn bundle(id: &str, finding_id: &str) -> ReproBundleRecord {
        ReproBundleRecord {
            id: id.to_string(),
            finding_id: finding_id.to_string(),
            path: format!("/var/state/repos/{id}.tar.zst"),
            sha256: "deadbeef".to_string(),
            created_at: 6_000,
            last_replay_at: None,
            last_replay_status: None,
        }
    }

    async fn seed(s: &crate::store::Store) -> String {
        s.repos().upsert(&sample_repo("repo")).await.expect("repo");
        s.runs().insert(&sample_run("run")).await.expect("run");
        let f = sample_finding("run", "repo", "src/a.rs", "rule");
        let fid = f.id.clone();
        s.findings().upsert(&f).await.expect("finding");
        fid
    }

    #[tokio::test]
    async fn insert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        let b = bundle("b-1", &fid);
        s.repro_bundles().insert(&b).await.expect("insert");
        let got = s.repro_bundles().get("b-1").await.expect("get").expect("row");
        assert_eq!(got, b);
    }

    #[tokio::test]
    async fn record_replay_persists() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        s.repro_bundles().insert(&bundle("b", &fid)).await.expect("insert");
        s.repro_bundles().record_replay("b", 8_000, "Pass").await.expect("replay");
        let got = s.repro_bundles().get("b").await.expect("get").expect("row");
        assert_eq!(got.last_replay_at, Some(8_000));
        assert_eq!(got.last_replay_status.as_deref(), Some("Pass"));
    }

    #[tokio::test]
    async fn cascade_from_finding_delete() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        s.repro_bundles().insert(&bundle("b", &fid)).await.expect("insert");
        s.findings().delete(&fid).await.expect("del");
        assert!(s.repro_bundles().get("b").await.expect("get").is_none());
    }
}
