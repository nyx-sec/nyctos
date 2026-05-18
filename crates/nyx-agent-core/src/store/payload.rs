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
}
