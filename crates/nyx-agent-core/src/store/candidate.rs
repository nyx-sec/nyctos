//! `candidate_findings` table - AI-proposed findings awaiting promotion.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateStatus {
    Pending,
    Promoted,
    Dismissed,
}

impl CandidateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CandidateStatus::Pending => "Pending",
            CandidateStatus::Promoted => "Promoted",
            CandidateStatus::Dismissed => "Dismissed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateFindingRecord {
    pub id: String,
    pub run_id: String,
    pub repo: String,
    pub path: String,
    pub line: Option<i64>,
    pub cap: String,
    pub rule_hint: Option<String>,
    pub rationale: Option<String>,
    pub suggested_payload_hint: Option<String>,
    pub status: String,
    pub prompt_version: Option<String>,
}

pub struct CandidateFindingStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> CandidateFindingStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, c: &CandidateFindingRecord) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO candidate_findings (
                id, run_id, repo, path, line, cap, rule_hint, rationale,
                suggested_payload_hint, status, prompt_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            c.id,
            c.run_id,
            c.repo,
            c.path,
            c.line,
            c.cap,
            c.rule_hint,
            c.rationale,
            c.suggested_payload_hint,
            c.status,
            c.prompt_version,
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<CandidateFindingRecord>, sqlx::Error> {
        let row = sqlx::query_as!(
            CandidateFindingRecord,
            r#"
            SELECT id AS "id!", run_id AS "run_id!", repo AS "repo!",
                   path AS "path!", line,
                   cap AS "cap!", rule_hint, rationale, suggested_payload_hint,
                   status AS "status!", prompt_version
            FROM candidate_findings WHERE id = ?
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row)
    }

    pub async fn list_pending(&self) -> Result<Vec<CandidateFindingRecord>, sqlx::Error> {
        let rows = sqlx::query_as!(
            CandidateFindingRecord,
            r#"
            SELECT id AS "id!", run_id AS "run_id!", repo AS "repo!",
                   path AS "path!", line,
                   cap AS "cap!", rule_hint, rationale, suggested_payload_hint,
                   status AS "status!", prompt_version
            FROM candidate_findings WHERE status = 'Pending'
            "#
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn set_status(&self, id: &str, status: &str) -> Result<(), sqlx::Error> {
        sqlx::query!("UPDATE candidate_findings SET status = ? WHERE id = ?", status, id)
            .execute(self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::store::testutil::{fresh_store, sample_candidate, sample_repo, sample_run};

    async fn seed(s: &crate::store::Store) {
        s.repos().upsert(&sample_repo("repo")).await.expect("repo");
        s.runs().insert(&sample_run("run")).await.expect("run");
    }

    #[tokio::test]
    async fn insert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let c = sample_candidate("c-1", "run", "repo");
        s.candidate_findings().insert(&c).await.expect("insert");
        let got = s.candidate_findings().get("c-1").await.expect("get").expect("row");
        assert_eq!(got, c);
    }

    #[tokio::test]
    async fn list_pending_excludes_other_states() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        s.candidate_findings()
            .insert(&sample_candidate("pending", "run", "repo"))
            .await
            .expect("p");
        let mut dismissed = sample_candidate("dismissed", "run", "repo");
        dismissed.status = "Dismissed".to_string();
        s.candidate_findings().insert(&dismissed).await.expect("d");
        let pending = s.candidate_findings().list_pending().await.expect("list");
        let ids: Vec<_> = pending.into_iter().map(|c| c.id).collect();
        assert_eq!(ids, vec!["pending".to_string()]);
    }

    #[tokio::test]
    async fn set_status_persists() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let c = sample_candidate("c", "run", "repo");
        s.candidate_findings().insert(&c).await.expect("insert");
        s.candidate_findings().set_status("c", "Promoted").await.expect("set");
        let got = s.candidate_findings().get("c").await.expect("get").expect("row");
        assert_eq!(got.status, "Promoted");
    }

    #[tokio::test]
    async fn cascade_from_run_delete() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        s.candidate_findings().insert(&sample_candidate("c", "run", "repo")).await.expect("insert");
        s.runs().delete("run").await.expect("del");
        assert!(
            s.candidate_findings().get("c").await.expect("get").is_none(),
            "candidate finding should cascade-delete with parent run"
        );
    }
}
