//! `payloads` table - AI-synthesised vuln/benign exploit pairs.

use sqlx::SqlitePool;

use crate::store::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadRecord {
    pub id: String,
    pub finding_id: String,
    pub cap: String,
    pub lang: String,
    pub vuln_bytes: Vec<u8>,
    pub benign_bytes: Option<Vec<u8>>,
    pub oracle_blob: Option<String>,
    pub attack_provenance: Option<String>,
    pub prompt_version: Option<String>,
    pub created_at: i64,
}

pub struct PayloadStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> PayloadStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert(&self, p: &PayloadRecord) -> Result<(), StoreError> {
        sqlx::query!(
            r#"
            INSERT INTO payloads (
                id, finding_id, cap, lang, vuln_bytes, benign_bytes,
                oracle_blob, attack_provenance, prompt_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            p.id,
            p.finding_id,
            p.cap,
            p.lang,
            p.vuln_bytes,
            p.benign_bytes,
            p.oracle_blob,
            p.attack_provenance,
            p.prompt_version,
            p.created_at,
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Atomic dual-write: insert the payload row AND stamp the parent
    /// finding's `attack_provenance` / `prompt_version` columns in a
    /// single transaction. PayloadSynthesis uses this so a partial
    /// failure of the second write does not leave an orphaned payload
    /// behind without the matching badge on the finding.
    pub async fn insert_with_finding_provenance(
        &self,
        p: &PayloadRecord,
        finding_id: &str,
        attack_provenance: &str,
        prompt_version: &str,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO payloads \
             (id, finding_id, cap, lang, vuln_bytes, benign_bytes, \
              oracle_blob, attack_provenance, prompt_version, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&p.id)
        .bind(&p.finding_id)
        .bind(&p.cap)
        .bind(&p.lang)
        .bind(&p.vuln_bytes)
        .bind(p.benign_bytes.as_deref())
        .bind(p.oracle_blob.as_deref())
        .bind(p.attack_provenance.as_deref())
        .bind(p.prompt_version.as_deref())
        .bind(p.created_at)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE findings SET attack_provenance = ?, prompt_version = ? WHERE id = ?")
            .bind(attack_provenance)
            .bind(prompt_version)
            .bind(finding_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<PayloadRecord>, StoreError> {
        let row = sqlx::query_as!(
            PayloadRecord,
            r#"
            SELECT id AS "id!", finding_id AS "finding_id!",
                   cap AS "cap!", lang AS "lang!",
                   vuln_bytes AS "vuln_bytes!: Vec<u8>",
                   benign_bytes AS "benign_bytes: Vec<u8>",
                   oracle_blob, attack_provenance, prompt_version,
                   created_at AS "created_at!: i64"
            FROM payloads WHERE id = ?
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
    ) -> Result<Vec<PayloadRecord>, StoreError> {
        let rows = sqlx::query_as!(
            PayloadRecord,
            r#"
            SELECT id AS "id!", finding_id AS "finding_id!",
                   cap AS "cap!", lang AS "lang!",
                   vuln_bytes AS "vuln_bytes!: Vec<u8>",
                   benign_bytes AS "benign_bytes: Vec<u8>",
                   oracle_blob, attack_provenance, prompt_version,
                   created_at AS "created_at!: i64"
            FROM payloads WHERE finding_id = ? ORDER BY created_at
            "#,
            finding_id
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use crate::store::testutil::{
        fresh_store, sample_finding, sample_payload, sample_repo, sample_run,
    };

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
        let p = sample_payload("p-1", &fid);
        s.payloads().insert(&p).await.expect("insert");
        let got = s.payloads().get("p-1").await.expect("get").expect("row");
        assert_eq!(got, p);
        assert_eq!(got.vuln_bytes, b"vuln-bytes".to_vec());
    }

    #[tokio::test]
    async fn list_for_finding_returns_only_matching() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        s.payloads().insert(&sample_payload("p-1", &fid)).await.expect("p1");
        s.payloads().insert(&sample_payload("p-2", &fid)).await.expect("p2");
        let got = s.payloads().list_for_finding(&fid).await.expect("list");
        assert_eq!(got.len(), 2);
    }

    #[tokio::test]
    async fn cascade_from_finding_delete() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        s.payloads().insert(&sample_payload("p-1", &fid)).await.expect("p");
        s.findings().delete(&fid).await.expect("del");
        assert!(
            s.payloads().get("p-1").await.expect("get").is_none(),
            "payload should cascade-delete with parent finding"
        );
    }

    #[tokio::test]
    async fn prompt_version_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        let mut p = sample_payload("p-1", &fid);
        p.prompt_version = Some("payload/v9".to_string());
        s.payloads().insert(&p).await.expect("insert");
        let got = s.payloads().get("p-1").await.expect("get").expect("row");
        assert_eq!(got.prompt_version.as_deref(), Some("payload/v9"));
    }

    #[tokio::test]
    async fn insert_with_finding_provenance_writes_both_sides() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        let p = sample_payload("p-tx", &fid);
        s.payloads()
            .insert_with_finding_provenance(
                &p,
                &fid,
                "LlmSynthesised",
                "phase14.payload_synthesis.v1",
            )
            .await
            .expect("dual write");
        let pay = s.payloads().get("p-tx").await.expect("get").expect("payload");
        assert_eq!(pay.id, "p-tx");
        let f = s.findings().get(&fid).await.expect("get").expect("finding");
        assert_eq!(f.attack_provenance.as_deref(), Some("LlmSynthesised"));
        assert_eq!(f.prompt_version.as_deref(), Some("phase14.payload_synthesis.v1"));
    }

    #[tokio::test]
    async fn insert_with_finding_provenance_rolls_back_on_duplicate_id() {
        let (_tmp, s) = fresh_store().await;
        let fid = seed(&s).await;
        let p = sample_payload("p-dup", &fid);
        s.payloads()
            .insert_with_finding_provenance(&p, &fid, "LlmSynthesised", "v1")
            .await
            .expect("first");
        // Mutate the would-be-stamped fields so a partial second write
        // would be visible.
        let second =
            s.payloads().insert_with_finding_provenance(&p, &fid, "ManualPromote", "v9").await;
        assert!(second.is_err(), "duplicate payload id must fail at INSERT");
        // Finding stamp must reflect ONLY the first call.
        let f = s.findings().get(&fid).await.expect("get").expect("finding");
        assert_eq!(
            f.attack_provenance.as_deref(),
            Some("LlmSynthesised"),
            "rollback must not leak the second call's provenance"
        );
        assert_eq!(
            f.prompt_version.as_deref(),
            Some("v1"),
            "rollback must not leak the second call's prompt_version"
        );
    }
}
