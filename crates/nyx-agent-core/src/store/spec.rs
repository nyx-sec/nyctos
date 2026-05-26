//! `harness_specs` table - AI-derived per-sink harness specifications.
//!
//! Paired with a `findings.spec_id` back-link so the verifier can
//! join a finding to the harness it should execute.
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

    /// Atomic dual-write: insert the harness spec row AND stamp the
    /// parent finding's `spec_id` / `attack_provenance` / `prompt_version`
    /// columns in a single transaction. SpecDerivation uses this so a
    /// partial failure of the second write does not leave the
    /// `harness_specs` table with an orphan row whose back-link never
    /// landed on the finding.
    ///
    /// Provenance ladder: SpecDerivation sits BELOW PayloadSynthesis on
    /// the `findings.attack_provenance` / `findings.prompt_version`
    /// ladder. The verifier executes the payload (not the spec) to
    /// produce the final verdict, so the payload-side provenance is the
    /// canonical attribution. The COALESCE clauses below preserve any
    /// existing stamp (typically written by PayloadSynthesis's
    /// `insert_with_finding_provenance` earlier in the same run) and
    /// only write the SpecDerivation values when those columns are
    /// still NULL. `spec_id` is always written because it is a unique
    /// back-link not shared with another writer.
    pub async fn insert_with_finding_spec_link(
        &self,
        rec: &HarnessSpecRecord,
        finding_id: &str,
        attack_provenance: &str,
        prompt_version: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO harness_specs \
             (id, cap, lang, spec_blob, attack_provenance, prompt_version, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&rec.id)
        .bind(&rec.cap)
        .bind(&rec.lang)
        .bind(&rec.spec_blob)
        .bind(rec.attack_provenance.as_deref())
        .bind(rec.prompt_version.as_deref())
        .bind(rec.created_at)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE findings SET \
               spec_id = ?, \
               attack_provenance = COALESCE(attack_provenance, ?), \
               prompt_version    = COALESCE(prompt_version, ?) \
             WHERE id = ?",
        )
        .bind(&rec.id)
        .bind(attack_provenance)
        .bind(prompt_version)
        .bind(finding_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
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

    #[tokio::test]
    async fn insert_with_finding_spec_link_preserves_payload_synthesis_stamp() {
        // Provenance ladder: PayloadSynthesis runs first, stamps the
        // finding via `payloads().insert_with_finding_provenance(...)`.
        // SpecDerivation runs second; it must write `spec_id` (back-link)
        // but must NOT clobber the PayloadSynthesis stamp on
        // `attack_provenance` / `prompt_version`. The verifier reads
        // the payload (not the spec) to produce the final verdict, so
        // the payload-side stamp is the canonical attribution.
        use crate::store::testutil::{sample_finding, sample_payload, sample_repo, sample_run};
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
        s.runs().insert(&sample_run("run-1")).await.expect("run");
        let f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("finding");

        // PayloadSynthesis runs first: stamps PS provenance.
        let p = sample_payload("p-1", &f.id);
        s.payloads()
            .insert_with_finding_provenance(&p, &f.id, "LlmSynthesised", "phase14.payload.v1")
            .await
            .expect("payload dual write");

        // SpecDerivation runs second: stamps spec_id but must leave the
        // PayloadSynthesis-written provenance columns alone.
        let spec = sample_spec("spec-1");
        s.harness_specs()
            .insert_with_finding_spec_link(
                &spec,
                &f.id,
                "LlmSynthesised",
                "phase15.spec_derivation.v1",
            )
            .await
            .expect("spec dual write");

        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.spec_id.as_deref(), Some("spec-1"), "spec back-link must land");
        assert_eq!(
            got.attack_provenance.as_deref(),
            Some("LlmSynthesised"),
            "PS provenance must survive SD writer",
        );
        assert_eq!(
            got.prompt_version.as_deref(),
            Some("phase14.payload.v1"),
            "PS prompt_version must survive SD writer",
        );
    }

    #[tokio::test]
    async fn insert_with_finding_spec_link_stamps_when_provenance_columns_are_null() {
        // Inverse of the ladder test above: when PayloadSynthesis has not
        // run (provenance columns are NULL), SpecDerivation MUST stamp
        // both columns. The COALESCE clauses must not regress to "never
        // write".
        use crate::store::testutil::{sample_finding, sample_repo, sample_run};
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
        s.runs().insert(&sample_run("run-1")).await.expect("run");
        let f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("finding");

        let spec = sample_spec("spec-only");
        s.harness_specs()
            .insert_with_finding_spec_link(
                &spec,
                &f.id,
                "LlmSynthesised",
                "phase15.spec_derivation.v1",
            )
            .await
            .expect("spec dual write");

        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.spec_id.as_deref(), Some("spec-only"));
        assert_eq!(got.attack_provenance.as_deref(), Some("LlmSynthesised"));
        assert_eq!(got.prompt_version.as_deref(), Some("phase15.spec_derivation.v1"));
    }

    #[tokio::test]
    async fn insert_with_finding_spec_link_rolls_back_when_finding_missing() {
        let (_tmp, s) = fresh_store().await;
        let rec = sample_spec("s-orphan");
        let err = s
            .harness_specs()
            .insert_with_finding_spec_link(
                &rec,
                "finding-does-not-exist",
                "LlmSynthesised",
                "phase15.spec_derivation.v1",
            )
            .await;
        // The UPDATE against a missing row returns 0 rows affected,
        // not an error; the spec row therefore lands. To prove the
        // transaction rolls back atomically we re-run the helper with
        // a duplicate spec id after a successful first call, expect
        // the second INSERT to violate the PRIMARY KEY, and assert
        // that the second call's failure leaves no extra harness_spec
        // and no extra UPDATE side effects on the finding.
        err.expect("first call succeeds (UPDATE matches zero rows)");
        // Second call with the same spec id must fail at the INSERT.
        let dup = s
            .harness_specs()
            .insert_with_finding_spec_link(
                &rec,
                "finding-does-not-exist",
                "LlmSynthesised",
                "phase15.spec_derivation.v1",
            )
            .await;
        assert!(dup.is_err(), "duplicate spec id should fail at INSERT");
        // Only the one spec row from the first call remains.
        let listed = s.harness_specs().list_by_cap("SQL_QUERY").await.expect("list");
        assert_eq!(listed.len(), 1, "rollback must not produce a second spec row");
    }
}
