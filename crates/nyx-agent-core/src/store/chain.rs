//! `chains` table - cross-finding rationales produced by chain reasoner.

use sqlx::SqlitePool;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRecord {
    pub id: String,
    pub run_id: String,
    pub cross_repo: bool,
    pub member_ids: String,
    pub rationale_blob: Option<String>,
    pub attack_provenance: Option<String>,
    pub prompt_version: Option<String>,
}

pub struct ChainStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ChainStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, c: &ChainRecord) -> Result<(), sqlx::Error> {
        let cross_repo = i64::from(c.cross_repo);
        sqlx::query!(
            r#"
            INSERT INTO chains (
                id, run_id, cross_repo, member_ids, rationale_blob,
                attack_provenance, prompt_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
            c.id,
            c.run_id,
            cross_repo,
            c.member_ids,
            c.rationale_blob,
            c.attack_provenance,
            c.prompt_version,
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<ChainRecord>, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT id AS "id!", run_id AS "run_id!",
                   cross_repo AS "cross_repo!: i64",
                   member_ids AS "member_ids!",
                   rationale_blob, attack_provenance, prompt_version
            FROM chains WHERE id = ?
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(|r| ChainRecord {
            id: r.id,
            run_id: r.run_id,
            cross_repo: r.cross_repo != 0,
            member_ids: r.member_ids,
            rationale_blob: r.rationale_blob,
            attack_provenance: r.attack_provenance,
            prompt_version: r.prompt_version,
        }))
    }

    pub async fn delete(&self, id: &str) -> Result<u64, sqlx::Error> {
        let res = sqlx::query!("DELETE FROM chains WHERE id = ?", id).execute(self.pool).await?;
        Ok(res.rows_affected())
    }

    pub async fn list_by_run(&self, run_id: &str) -> Result<Vec<ChainRecord>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!", run_id AS "run_id!",
                   cross_repo AS "cross_repo!: i64",
                   member_ids AS "member_ids!",
                   rationale_blob, attack_provenance, prompt_version
            FROM chains WHERE run_id = ?
            "#,
            run_id
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ChainRecord {
                id: r.id,
                run_id: r.run_id,
                cross_repo: r.cross_repo != 0,
                member_ids: r.member_ids,
                rationale_blob: r.rationale_blob,
                attack_provenance: r.attack_provenance,
                prompt_version: r.prompt_version,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::store::testutil::{fresh_store, sample_chain, sample_run};

    #[tokio::test]
    async fn insert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("r")).await.expect("run");
        let c = sample_chain("c-1", "r", &["f-a", "f-b"]);
        s.chains().insert(&c).await.expect("insert");
        let got = s.chains().get("c-1").await.expect("get").expect("row");
        assert_eq!(got, c);
        assert!(!got.cross_repo);
    }

    #[tokio::test]
    async fn list_by_run_returns_matching_only() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("r1")).await.expect("r1");
        s.runs().insert(&sample_run("r2")).await.expect("r2");
        s.chains().insert(&sample_chain("c1", "r1", &["x"])).await.expect("c1");
        s.chains().insert(&sample_chain("c2", "r2", &["y"])).await.expect("c2");
        let got = s.chains().list_by_run("r1").await.expect("list");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "c1");
    }

    #[tokio::test]
    async fn cascade_from_run_delete() {
        let (_tmp, s) = fresh_store().await;
        s.runs().insert(&sample_run("doomed")).await.expect("run");
        s.chains().insert(&sample_chain("c", "doomed", &["a"])).await.expect("chain");
        s.runs().delete("doomed").await.expect("del");
        assert!(
            s.chains().get("c").await.expect("get").is_none(),
            "FK cascade should have removed the chain"
        );
    }
}
