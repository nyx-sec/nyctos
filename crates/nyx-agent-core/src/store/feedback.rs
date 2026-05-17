//! `feedback` table - operator verdicts attached to findings.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorVerdict {
    Confirmed,
    FalsePositive,
    NeedsTriage,
}

impl OperatorVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            OperatorVerdict::Confirmed => "Confirmed",
            OperatorVerdict::FalsePositive => "FalsePositive",
            OperatorVerdict::NeedsTriage => "NeedsTriage",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackRecord {
    pub id: Option<i64>,
    pub finding_id: String,
    pub operator_verdict: String,
    pub notes: Option<String>,
    pub created_at: i64,
}

pub struct FeedbackStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> FeedbackStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, f: &FeedbackRecord) -> Result<i64, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            INSERT INTO feedback (finding_id, operator_verdict, notes, created_at)
            VALUES (?, ?, ?, ?)
            RETURNING id AS "id!: i64"
            "#,
            f.finding_id,
            f.operator_verdict,
            f.notes,
            f.created_at,
        )
        .fetch_one(self.pool)
        .await?;
        Ok(row.id)
    }

    pub async fn list_for_finding(
        &self,
        finding_id: &str,
    ) -> Result<Vec<FeedbackRecord>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT id AS "id!: i64", finding_id AS "finding_id!",
                   operator_verdict AS "operator_verdict!",
                   notes,
                   created_at AS "created_at!: i64"
            FROM feedback WHERE finding_id = ? ORDER BY created_at
            "#,
            finding_id
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| FeedbackRecord {
                id: Some(r.id),
                finding_id: r.finding_id,
                operator_verdict: r.operator_verdict,
                notes: r.notes,
                created_at: r.created_at,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{fresh_store, sample_finding, sample_repo, sample_run};

    async fn seed(s: &crate::store::Store) -> String {
        s.repos().upsert(&sample_repo("repo")).await.expect("repo");
        s.runs().insert(&sample_run("run")).await.expect("run");
        let f = sample_finding("run", "repo", "src/a.rs", "rule");
        let fid = f.id.clone();
        s.findings().upsert(&f).await.expect("finding");
        fid
    }

    fn fb(fid: &str, verdict: &str) -> FeedbackRecord {
        FeedbackRecord {
            id: None,
            finding_id: fid.to_string(),
            operator_verdict: verdict.to_string(),
            notes: Some("looked manually".to_string()),
            created_at: 7_000,
        }
    }

    #[tokio::test]
    async fn insert_returns_autoincrement_id_and_lists() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        let id1 = s.feedback().insert(&fb(&fid, "Confirmed")).await.expect("a");
        let id2 = s.feedback().insert(&fb(&fid, "FalsePositive")).await.expect("b");
        assert!(id1 < id2, "autoincrement should be monotonic");
        let got = s.feedback().list_for_finding(&fid).await.expect("list");
        assert_eq!(got.len(), 2);
    }

    #[tokio::test]
    async fn cascade_from_finding_delete() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        s.feedback().insert(&fb(&fid, "Confirmed")).await.expect("insert");
        s.findings().delete(&fid).await.expect("del");
        let got = s.feedback().list_for_finding(&fid).await.expect("list");
        assert!(got.is_empty(), "feedback should cascade-delete with parent finding");
    }
}
