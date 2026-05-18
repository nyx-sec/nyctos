//! `harness_specs` table - AI-derived per-sink harness specifications.
//!
//! Phase 15 adds this table alongside a `findings.spec_id` back-link so
//! the verifier can join a finding to the harness it should execute.
//! Runtime-checked SQL is used throughout to keep the `.sqlx/` cache
//! lean - the table only has insert / get / list-by-cap consumers and
//! nothing in this module needs the macro's compile-time describe.

use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

use crate::store::StoreError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessSpecRecord {
    pub id: String,
    pub cap: String,
    pub lang: String,
    pub spec_blob: String,
    pub attack_provenance: Option<String>,
    pub prompt_version: Option<String>,
    pub created_at: i64,
}

pub struct HarnessSpecStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> HarnessSpecStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, s: &HarnessSpecRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO harness_specs \
             (id, cap, lang, spec_blob, attack_provenance, prompt_version, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&s.id)
        .bind(&s.cap)
        .bind(&s.lang)
        .bind(&s.spec_blob)
        .bind(s.attack_provenance.as_deref())
        .bind(s.prompt_version.as_deref())
        .bind(s.created_at)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<HarnessSpecRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT id, cap, lang, spec_blob, attack_provenance, prompt_version, created_at \
             FROM harness_specs WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool)
        .await?;
        Ok(row.map(row_to_spec))
    }

    pub async fn list_by_cap(&self, cap: &str) -> Result<Vec<HarnessSpecRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, cap, lang, spec_blob, attack_provenance, prompt_version, created_at \
             FROM harness_specs WHERE cap = ? ORDER BY created_at",
        )
        .bind(cap)
        .fetch_all(self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_spec).collect())
    }
}

fn row_to_spec(row: sqlx::sqlite::SqliteRow) -> HarnessSpecRecord {
    HarnessSpecRecord {
        id: row.get("id"),
        cap: row.get("cap"),
        lang: row.get("lang"),
        spec_blob: row.get("spec_blob"),
        attack_provenance: row.get("attack_provenance"),
        prompt_version: row.get("prompt_version"),
        created_at: row.get("created_at"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::fresh_store;

    fn sample_spec(id: &str) -> HarnessSpecRecord {
        HarnessSpecRecord {
            id: id.to_string(),
            cap: "SQL_QUERY".to_string(),
            lang: "python".to_string(),
            spec_blob: r#"{"schema_version":1,"cap":"SQL_QUERY"}"#.to_string(),
            attack_provenance: Some("LlmSynthesised".to_string()),
            prompt_version: Some("phase15.spec_derivation.v1".to_string()),
            created_at: 4_000,
        }
    }

    #[tokio::test]
    async fn insert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        let rec = sample_spec("s-1");
        s.harness_specs().insert(&rec).await.expect("insert");
        let got = s.harness_specs().get("s-1").await.expect("get").expect("row");
        assert_eq!(got, rec);
    }

    #[tokio::test]
    async fn list_by_cap_filters() {
        let (_tmp, s) = fresh_store().await;
        let mut a = sample_spec("s-a");
        a.cap = "OS_COMMAND".to_string();
        s.harness_specs().insert(&a).await.expect("a");
        s.harness_specs().insert(&sample_spec("s-b")).await.expect("b");
        s.harness_specs().insert(&sample_spec("s-c")).await.expect("c");
        let sql = s.harness_specs().list_by_cap("SQL_QUERY").await.expect("list");
        assert_eq!(sql.len(), 2);
        let osc = s.harness_specs().list_by_cap("OS_COMMAND").await.expect("list");
        assert_eq!(osc.len(), 1);
    }
}
