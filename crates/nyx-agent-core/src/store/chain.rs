//! `chains` table - cross-finding rationales produced by chain reasoner.

use sqlx::{Row, SqlitePool};

pub use nyx_agent_types::chain::ChainRecord;

use super::attack_graph::AttackGraphStore;
use crate::store::StoreError;

pub struct ChainStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> ChainStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, c: &ChainRecord) -> Result<(), StoreError> {
        let cross_repo = if c.cross_repo { 1_i64 } else { 0_i64 };
        sqlx::query(
            r#"
            INSERT INTO chains (
                id, run_id, cross_repo, member_ids, rationale_blob,
                attack_provenance, prompt_version, status, verification_attempt_id,
                evidence_blob, severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&c.id)
        .bind(&c.run_id)
        .bind(cross_repo)
        .bind(&c.member_ids)
        .bind(&c.rationale_blob)
        .bind(&c.attack_provenance)
        .bind(&c.prompt_version)
        .bind(&c.status)
        .bind(&c.verification_attempt_id)
        .bind(&c.evidence_blob)
        .bind(&c.severity)
        .execute(self.pool)
        .await?;
        AttackGraphStore::new(self.pool).record_chain(c).await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<ChainRecord>, StoreError> {
        let row = sqlx::query(
            r#"
            SELECT id, run_id, cross_repo, member_ids,
                   rationale_blob, attack_provenance, prompt_version,
                   status, verification_attempt_id, evidence_blob, severity
            FROM chains WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        row.map(row_to_chain_record).transpose()
    }

    pub async fn delete(&self, id: &str) -> Result<u64, StoreError> {
        let res =
            sqlx::query("DELETE FROM chains WHERE id = ?").bind(id).execute(self.pool).await?;
        Ok(res.rows_affected())
    }

    pub async fn list_by_run(&self, run_id: &str) -> Result<Vec<ChainRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, cross_repo, member_ids,
                   rationale_blob, attack_provenance, prompt_version,
                   status, verification_attempt_id, evidence_blob, severity
            FROM chains WHERE run_id = ?
            "#,
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_chain_record).collect()
    }

    pub async fn list_by_run_and_status(
        &self,
        run_id: &str,
        status: &str,
    ) -> Result<Vec<ChainRecord>, StoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_id, cross_repo, member_ids,
                   rationale_blob, attack_provenance, prompt_version,
                   status, verification_attempt_id, evidence_blob, severity
            FROM chains WHERE run_id = ? AND status = ?
            ORDER BY id
            "#,
        )
        .bind(run_id)
        .bind(status)
        .fetch_all(self.pool)
        .await?;
        rows.into_iter().map(row_to_chain_record).collect()
    }

    pub async fn update_verification_state(
        &self,
        id: &str,
        status: &str,
        verification_attempt_id: Option<&str>,
        evidence_blob: Option<&str>,
        severity: Option<&str>,
    ) -> Result<Option<ChainRecord>, StoreError> {
        sqlx::query(
            r#"
            UPDATE chains SET
                status = ?,
                verification_attempt_id = COALESCE(?, verification_attempt_id),
                evidence_blob = COALESCE(?, evidence_blob),
                severity = COALESCE(?, severity)
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(verification_attempt_id)
        .bind(evidence_blob)
        .bind(severity)
        .bind(id)
        .execute(self.pool)
        .await?;
        self.get(id).await
    }
}

fn row_to_chain_record(row: sqlx::sqlite::SqliteRow) -> Result<ChainRecord, StoreError> {
    Ok(ChainRecord {
        id: row.try_get("id")?,
        run_id: row.try_get("run_id")?,
        cross_repo: row.try_get::<i64, _>("cross_repo")? != 0,
        member_ids: row.try_get("member_ids")?,
        rationale_blob: row.try_get("rationale_blob")?,
        attack_provenance: row.try_get("attack_provenance")?,
        prompt_version: row.try_get("prompt_version")?,
        status: row.try_get("status")?,
        verification_attempt_id: row.try_get("verification_attempt_id")?,
        evidence_blob: row.try_get("evidence_blob")?,
        severity: row.try_get("severity")?,
    })
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
