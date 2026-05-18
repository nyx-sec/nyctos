//! `findings` table - the main aggregated finding store with stable hash
//! IDs so re-running a scan over the same code converges on the same row.

use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Row, SqlitePool};

use crate::store::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    Open,
    Verified,
    Quarantine,
    Closed,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Open => "Open",
            FindingStatus::Verified => "Verified",
            FindingStatus::Quarantine => "Quarantine",
            FindingStatus::Closed => "Closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingOrigin {
    Static,
    Ai,
    /// AI-discovered candidate finding that the Phase 19 verifier
    /// promoted from `candidate_findings.Pending` to a real `findings`
    /// row. Distinct from the bare `Ai` variant because the originating
    /// signal is the agent's source-code exploration, not a static-pass
    /// diag the agent later annotated.
    AiExploration,
    Manual,
}

impl FindingOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingOrigin::Static => "Static",
            FindingOrigin::Ai => "AI",
            FindingOrigin::AiExploration => "AiExploration",
            FindingOrigin::Manual => "Manual",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriageState {
    Open,
    Wontfix,
    Dupe,
    Accepted,
}

impl TriageState {
    pub fn as_str(self) -> &'static str {
        match self {
            TriageState::Open => "Open",
            TriageState::Wontfix => "Wontfix",
            TriageState::Dupe => "Dupe",
            TriageState::Accepted => "Accepted",
        }
    }
}

/// Stable hash for a finding row. Repeating a scan over the same
/// `(repo, path, line, cap, rule)` tuple converges on the same id.
///
/// BLAKE3 over a NUL-delimited tuple, truncated to the first 16 hex
/// characters (64 bits of state). The truncation is deliberate: UI rows
/// quote the id and 64 hex characters wrap badly. 16 hex chars gives
/// 2^32 expected pairs before a collision becomes more likely than not,
/// which is well above the row counts a single deployment scans.
pub fn finding_id_hash(repo: &str, path: &str, line: Option<i64>, cap: &str, rule: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(repo.as_bytes());
    h.update(b"\0");
    h.update(path.as_bytes());
    h.update(b"\0");
    h.update(&line.unwrap_or(-1).to_le_bytes());
    h.update(b"\0");
    h.update(cap.as_bytes());
    h.update(b"\0");
    h.update(rule.as_bytes());
    let digest = h.finalize();
    let bytes = digest.as_bytes();
    let mut out = String::with_capacity(16);
    for b in &bytes[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Filter accepted by [`FindingStore::list_filtered`]. Borrows from the
/// caller so the API can hand its query parameters straight through
/// without cloning.
#[derive(Debug, Default, Clone, Copy)]
pub struct FindingFilter<'a> {
    pub repo: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub cap: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub status: Option<&'a str>,
    pub severity: Option<&'a str>,
    pub triage_state: Option<&'a str>,
    pub chain_id: Option<&'a str>,
    /// When `false` (default) rows with `status = 'Quarantine'` are
    /// excluded. The Phase 11 list view leaves this off; the Quarantine
    /// page passes `true`.
    pub include_quarantine: bool,
    /// Optional row cap. `None` means "no LIMIT" - the UI is expected to
    /// stay below ~10k rows per page so a cap is informative, not a
    /// safety net.
    pub limit: Option<i64>,
}

fn row_to_finding(row: sqlx::sqlite::SqliteRow) -> FindingRecord {
    FindingRecord {
        id: row.get("id"),
        run_id: row.get("run_id"),
        repo: row.get("repo"),
        path: row.get("path"),
        line: row.get("line"),
        cap: row.get("cap"),
        rule: row.get("rule"),
        severity: row.get("severity"),
        status: row.get("status"),
        finding_origin: row.get("finding_origin"),
        first_seen: row.get("first_seen"),
        last_seen: row.get("last_seen"),
        superseded_by: row.get("superseded_by"),
        triage_state: row.get("triage_state"),
        triage_assigned_to: row.get("triage_assigned_to"),
        verdict_blob: row.get("verdict_blob"),
        repro_path: row.get("repro_path"),
        attack_provenance: row.get("attack_provenance"),
        prompt_version: row.get("prompt_version"),
        chain_id: row.get("chain_id"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: String,
    pub run_id: String,
    pub repo: String,
    pub path: String,
    pub line: Option<i64>,
    pub cap: String,
    pub rule: String,
    pub severity: String,
    pub status: String,
    pub finding_origin: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub superseded_by: Option<String>,
    pub triage_state: String,
    pub triage_assigned_to: Option<String>,
    pub verdict_blob: Option<String>,
    pub repro_path: Option<String>,
    pub attack_provenance: Option<String>,
    pub prompt_version: Option<String>,
    pub chain_id: Option<String>,
}

pub struct FindingStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> FindingStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn upsert(&self, f: &FindingRecord) -> Result<(), StoreError> {
        sqlx::query!(
            r#"
            INSERT INTO findings (
                id, run_id, repo, path, line, cap, rule, severity, status,
                finding_origin, first_seen, last_seen, superseded_by,
                triage_state, triage_assigned_to, verdict_blob, repro_path,
                attack_provenance, prompt_version, chain_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                run_id             = excluded.run_id,
                severity           = excluded.severity,
                status             = excluded.status,
                finding_origin     = excluded.finding_origin,
                last_seen          = excluded.last_seen,
                superseded_by      = excluded.superseded_by,
                triage_state       = excluded.triage_state,
                triage_assigned_to = excluded.triage_assigned_to,
                verdict_blob       = excluded.verdict_blob,
                repro_path         = excluded.repro_path,
                attack_provenance  = excluded.attack_provenance,
                prompt_version     = excluded.prompt_version,
                chain_id           = excluded.chain_id
            "#,
            f.id,
            f.run_id,
            f.repo,
            f.path,
            f.line,
            f.cap,
            f.rule,
            f.severity,
            f.status,
            f.finding_origin,
            f.first_seen,
            f.last_seen,
            f.superseded_by,
            f.triage_state,
            f.triage_assigned_to,
            f.verdict_blob,
            f.repro_path,
            f.attack_provenance,
            f.prompt_version,
            f.chain_id,
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get(&self, id: &str) -> Result<Option<FindingRecord>, StoreError> {
        let row = sqlx::query_as!(
            FindingRecord,
            r#"
            SELECT id AS "id!", run_id AS "run_id!", repo AS "repo!",
                   path AS "path!", line,
                   cap AS "cap!", rule AS "rule!", severity AS "severity!",
                   status AS "status!", finding_origin AS "finding_origin!",
                   first_seen AS "first_seen!: i64",
                   last_seen  AS "last_seen!: i64",
                   superseded_by, triage_state AS "triage_state!",
                   triage_assigned_to, verdict_blob, repro_path,
                   attack_provenance, prompt_version, chain_id
            FROM findings WHERE id = ?
            "#,
            id
        )
        .fetch_optional(self.pool)
        .await?;
        Ok(row)
    }

    /// List findings for `repo` filtered by the UI's standard
    /// `(cap, status, origin)` triple. Quarantine rows are excluded.
    pub async fn list_active_for_repo(&self, repo: &str) -> Result<Vec<FindingRecord>, StoreError> {
        let rows = sqlx::query_as!(
            FindingRecord,
            r#"
            SELECT id AS "id!", run_id AS "run_id!", repo AS "repo!",
                   path AS "path!", line,
                   cap AS "cap!", rule AS "rule!", severity AS "severity!",
                   status AS "status!", finding_origin AS "finding_origin!",
                   first_seen AS "first_seen!: i64",
                   last_seen  AS "last_seen!: i64",
                   superseded_by, triage_state AS "triage_state!",
                   triage_assigned_to, verdict_blob, repro_path,
                   attack_provenance, prompt_version, chain_id
            FROM findings
            WHERE repo = ? AND status != 'Quarantine'
            ORDER BY last_seen DESC
            "#,
            repo
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }

    /// Composite filter used by the Phase 11 findings browser. Every
    /// field is optional; combining them ANDs in SQLite, and an empty
    /// filter returns every active row (i.e. status != Quarantine
    /// unless [`FindingFilter::include_quarantine`] is set). Ordering
    /// matches [`list_active_for_repo`] / [`list_by_run`]: most-recent
    /// `last_seen` first.
    pub async fn list_filtered(
        &self,
        filter: &FindingFilter<'_>,
    ) -> Result<Vec<FindingRecord>, StoreError> {
        let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new(
            "SELECT id, run_id, repo, path, line, cap, rule, severity, status, \
             finding_origin, first_seen, last_seen, superseded_by, triage_state, \
             triage_assigned_to, verdict_blob, repro_path, attack_provenance, \
             prompt_version, chain_id FROM findings",
        );
        let mut needs_where = true;
        let mut push_clause = |qb: &mut QueryBuilder<sqlx::Sqlite>| {
            if needs_where {
                qb.push(" WHERE ");
                needs_where = false;
            } else {
                qb.push(" AND ");
            }
        };
        if !filter.include_quarantine {
            push_clause(&mut qb);
            qb.push("status != 'Quarantine'");
        }
        if let Some(repo) = filter.repo {
            push_clause(&mut qb);
            qb.push("repo = ").push_bind(repo.to_string());
        }
        if let Some(run_id) = filter.run_id {
            push_clause(&mut qb);
            qb.push("run_id = ").push_bind(run_id.to_string());
        }
        if let Some(cap) = filter.cap {
            push_clause(&mut qb);
            qb.push("cap = ").push_bind(cap.to_string());
        }
        if let Some(origin) = filter.origin {
            push_clause(&mut qb);
            qb.push("finding_origin = ").push_bind(origin.to_string());
        }
        if let Some(status) = filter.status {
            push_clause(&mut qb);
            qb.push("status = ").push_bind(status.to_string());
        }
        if let Some(severity) = filter.severity {
            push_clause(&mut qb);
            qb.push("severity = ").push_bind(severity.to_string());
        }
        if let Some(triage) = filter.triage_state {
            push_clause(&mut qb);
            qb.push("triage_state = ").push_bind(triage.to_string());
        }
        if let Some(chain_id) = filter.chain_id {
            push_clause(&mut qb);
            qb.push("chain_id = ").push_bind(chain_id.to_string());
        }
        qb.push(" ORDER BY last_seen DESC");
        if let Some(limit) = filter.limit {
            qb.push(" LIMIT ").push_bind(limit);
        }
        let rows = qb.build().fetch_all(self.pool).await?;
        let out = rows.into_iter().map(row_to_finding).collect();
        Ok(out)
    }

    pub async fn list_by_run(&self, run_id: &str) -> Result<Vec<FindingRecord>, StoreError> {
        let rows = sqlx::query_as!(
            FindingRecord,
            r#"
            SELECT id AS "id!", run_id AS "run_id!", repo AS "repo!",
                   path AS "path!", line,
                   cap AS "cap!", rule AS "rule!", severity AS "severity!",
                   status AS "status!", finding_origin AS "finding_origin!",
                   first_seen AS "first_seen!: i64",
                   last_seen  AS "last_seen!: i64",
                   superseded_by, triage_state AS "triage_state!",
                   triage_assigned_to, verdict_blob, repro_path,
                   attack_provenance, prompt_version, chain_id
            FROM findings WHERE run_id = ? ORDER BY last_seen DESC
            "#,
            run_id
        )
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn set_triage(
        &self,
        id: &str,
        state: &str,
        assignee: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "UPDATE findings SET triage_state = ?, triage_assigned_to = ? WHERE id = ?",
            state,
            assignee,
            id
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_chain(&self, id: &str, chain_id: &str) -> Result<(), StoreError> {
        sqlx::query!("UPDATE findings SET chain_id = ? WHERE id = ?", chain_id, id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Stamp `id` with the SpecDerivation result. Sets the `spec_id`
    /// back-link plus the `attack_provenance` / `prompt_version`
    /// columns so the findings detail view can render "AI synthesised
    /// the harness spec for this row" without an extra join. Runtime-
    /// checked SQL to keep the `.sqlx/` cache from growing for a
    /// helper that only runs once per finding per scan.
    pub async fn set_spec(
        &self,
        id: &str,
        spec_id: &str,
        attack_provenance: &str,
        prompt_version: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE findings SET spec_id = ?, attack_provenance = ?, prompt_version = ? \
             WHERE id = ?",
        )
        .bind(spec_id)
        .bind(attack_provenance)
        .bind(prompt_version)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Stamp `id` with the supplied `attack_provenance` + `prompt_version`
    /// pair without touching status / verdict_blob. Used after
    /// PayloadSynthesis insert so the finding's detail view can render
    /// "AI synthesised the payload for this row" without joining
    /// through the `payloads` table. Runtime-checked SQL to keep the
    /// `.sqlx/` cache from growing for a helper called once per
    /// finding per scan.
    pub async fn set_attack_provenance(
        &self,
        id: &str,
        attack_provenance: &str,
        prompt_version: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE findings SET attack_provenance = ?, prompt_version = ? WHERE id = ?")
            .bind(attack_provenance)
            .bind(prompt_version)
            .bind(id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    /// Stamp the Phase 19 verifier outcome on `id`: flips `status`
    /// (Verified for Confirmed, Closed for NotConfirmed, untouched for
    /// Errored — the caller passes the row's existing status in that
    /// case) and overwrites `verdict_blob` + `attack_provenance`.
    pub async fn set_verify_result(
        &self,
        id: &str,
        status: &str,
        verdict_blob: &str,
        attack_provenance: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE findings SET status = ?, verdict_blob = ?, attack_provenance = ? \
             WHERE id = ?",
        )
        .bind(status)
        .bind(verdict_blob)
        .bind(attack_provenance)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn supersede(&self, id: &str, by_id: &str) -> Result<(), StoreError> {
        sqlx::query!("UPDATE findings SET superseded_by = ? WHERE id = ?", by_id, id)
            .execute(self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<u64, StoreError> {
        let res = sqlx::query!("DELETE FROM findings WHERE id = ?", id).execute(self.pool).await?;
        Ok(res.rows_affected())
    }

    /// Flip `id` to `status = 'Quarantine'`, stamping `verdict_blob`
    /// with the supplied JSON reason. Phase 14's PayloadSynthesis
    /// fallback calls this when both synthesis attempts fail to parse;
    /// later phases (SpecDerivation, NovelFindingsDiscovery) reuse the
    /// same shape so the quarantine page can surface a uniform reason
    /// field. Runtime-checked SQL to avoid bloating the `.sqlx/` cache
    /// with a one-off operator-facing helper; the parameter is bound,
    /// so injection is not a concern.
    pub async fn quarantine(&self, id: &str, reason_json: &str) -> Result<u64, StoreError> {
        let res =
            sqlx::query("UPDATE findings SET status = 'Quarantine', verdict_blob = ? WHERE id = ?")
                .bind(reason_json)
                .bind(id)
                .execute(self.pool)
                .await?;
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{
        fresh_store, sample_chain, sample_finding, sample_repo, sample_run,
    };

    async fn seed(s: &crate::store::Store) {
        s.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
        s.runs().insert(&sample_run("run-1")).await.expect("run");
    }

    #[tokio::test]
    async fn stable_hash_converges_on_same_inputs() {
        let a = finding_id_hash("r", "p/x.rs", Some(10), "sqli", "rule-1");
        let b = finding_id_hash("r", "p/x.rs", Some(10), "sqli", "rule-1");
        assert_eq!(a, b);
        let c = finding_id_hash("r", "p/x.rs", Some(11), "sqli", "rule-1");
        assert_ne!(a, c);
    }

    #[test]
    fn stable_hash_is_16_hex_chars() {
        let h = finding_id_hash("r", "p", Some(1), "c", "rule");
        assert_eq!(h.len(), 16, "phase 06: hash truncated to 16 hex chars");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "must be lowercase hex: {h}"
        );
    }

    #[test]
    fn stable_hash_distinguishes_each_field() {
        let base = finding_id_hash("repo", "path", Some(7), "cap", "rule");
        assert_ne!(base, finding_id_hash("REPO", "path", Some(7), "cap", "rule"));
        assert_ne!(base, finding_id_hash("repo", "PATH", Some(7), "cap", "rule"));
        assert_ne!(base, finding_id_hash("repo", "path", Some(8), "cap", "rule"));
        assert_ne!(base, finding_id_hash("repo", "path", None, "cap", "rule"));
        assert_ne!(base, finding_id_hash("repo", "path", Some(7), "CAP", "rule"));
        assert_ne!(base, finding_id_hash("repo", "path", Some(7), "cap", "RULE"));
    }

    #[tokio::test]
    async fn upsert_then_get_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("insert");
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got, f);
    }

    #[tokio::test]
    async fn upsert_updates_existing_row() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let mut f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("first");
        f.severity = "Critical".to_string();
        f.last_seen = 9_000;
        s.findings().upsert(&f).await.expect("second");
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.severity, "Critical");
        assert_eq!(got.last_seen, 9_000);
        // first_seen is NOT overwritten on conflict.
        assert_eq!(got.first_seen, 3_000);
    }

    #[tokio::test]
    async fn list_active_excludes_quarantine() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let mut quarantined = sample_finding("run-1", "repo-1", "src/q.rs", "rule-q");
        quarantined.status = "Quarantine".to_string();
        let open = sample_finding("run-1", "repo-1", "src/o.rs", "rule-o");
        s.findings().upsert(&quarantined).await.expect("q");
        s.findings().upsert(&open).await.expect("o");
        let active = s.findings().list_active_for_repo("repo-1").await.expect("list");
        let ids: Vec<_> = active.into_iter().map(|f| f.id).collect();
        assert!(ids.contains(&open.id));
        assert!(!ids.contains(&quarantined.id), "Quarantine rows must not appear in active list");
    }

    #[tokio::test]
    async fn list_by_run_returns_only_matching_run() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        s.runs().insert(&sample_run("run-2")).await.expect("run-2");
        let a = sample_finding("run-1", "repo-1", "src/a.rs", "ra");
        let b = sample_finding("run-2", "repo-1", "src/b.rs", "rb");
        s.findings().upsert(&a).await.expect("a");
        s.findings().upsert(&b).await.expect("b");
        let r1 = s.findings().list_by_run("run-1").await.expect("list");
        assert_eq!(r1.len(), 1);
        assert_eq!(r1[0].id, a.id);
    }

    #[tokio::test]
    async fn set_triage_persists() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("insert");
        s.findings().set_triage(&f.id, "Wontfix", Some("alice")).await.expect("triage");
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.triage_state, "Wontfix");
        assert_eq!(got.triage_assigned_to.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn supersede_sets_pointer_and_clears_on_delete() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let old = sample_finding("run-1", "repo-1", "src/o.rs", "rule-o");
        let new = sample_finding("run-1", "repo-1", "src/n.rs", "rule-n");
        s.findings().upsert(&old).await.expect("old");
        s.findings().upsert(&new).await.expect("new");
        s.findings().supersede(&old.id, &new.id).await.expect("supersede");
        let got = s.findings().get(&old.id).await.expect("get").expect("row");
        assert_eq!(got.superseded_by.as_deref(), Some(new.id.as_str()));

        s.findings().delete(&new.id).await.expect("del new");
        let got = s.findings().get(&old.id).await.expect("get").expect("row");
        assert!(
            got.superseded_by.is_none(),
            "FK SET NULL should clear superseded_by when target deleted"
        );
    }

    #[tokio::test]
    async fn set_chain_links_finding_and_set_null_on_chain_delete() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("finding");
        let chain = sample_chain("chain-1", "run-1", &[&f.id]);
        s.chains().insert(&chain).await.expect("chain");
        s.findings().set_chain(&f.id, "chain-1").await.expect("link");
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.chain_id.as_deref(), Some("chain-1"));

        sqlx::query!("DELETE FROM chains WHERE id = ?", "chain-1")
            .execute(s.pool())
            .await
            .expect("del chain");
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert!(got.chain_id.is_none(), "expected SET NULL on chain delete");
    }

    #[tokio::test]
    async fn prompt_version_roundtrips() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let mut f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        f.prompt_version = Some("prompts/finding/v17".to_string());
        s.findings().upsert(&f).await.expect("insert");
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.prompt_version.as_deref(), Some("prompts/finding/v17"));
    }

    #[tokio::test]
    async fn list_filtered_combines_predicates() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        s.repos().upsert(&sample_repo("repo-2")).await.expect("repo-2");
        s.runs().insert(&sample_run("run-2")).await.expect("run-2");
        let mut a = sample_finding("run-1", "repo-1", "src/a.rs", "rule-a");
        a.severity = "High".to_string();
        a.finding_origin = "Static".to_string();
        let mut b = sample_finding("run-1", "repo-1", "src/b.rs", "rule-b");
        b.severity = "Low".to_string();
        b.finding_origin = "AI".to_string();
        let mut c = sample_finding("run-2", "repo-2", "src/c.rs", "rule-c");
        c.severity = "High".to_string();
        c.cap = "cmdi".to_string();
        s.findings().upsert(&a).await.expect("a");
        s.findings().upsert(&b).await.expect("b");
        s.findings().upsert(&c).await.expect("c");

        let all = s.findings().list_filtered(&FindingFilter::default()).await.expect("all");
        assert_eq!(all.len(), 3);

        let high = s
            .findings()
            .list_filtered(&FindingFilter { severity: Some("High"), ..Default::default() })
            .await
            .expect("sev");
        let ids: Vec<_> = high.into_iter().map(|f| f.id).collect();
        assert!(ids.contains(&a.id));
        assert!(ids.contains(&c.id));
        assert!(!ids.contains(&b.id));

        let by_cap_and_run = s
            .findings()
            .list_filtered(&FindingFilter {
                run_id: Some("run-2"),
                cap: Some("cmdi"),
                ..Default::default()
            })
            .await
            .expect("cap+run");
        assert_eq!(by_cap_and_run.len(), 1);
        assert_eq!(by_cap_and_run[0].id, c.id);

        let by_origin = s
            .findings()
            .list_filtered(&FindingFilter { origin: Some("AI"), ..Default::default() })
            .await
            .expect("origin");
        assert_eq!(by_origin.len(), 1);
        assert_eq!(by_origin[0].id, b.id);
    }

    #[tokio::test]
    async fn list_filtered_excludes_quarantine_unless_opted_in() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let open = sample_finding("run-1", "repo-1", "src/o.rs", "rule-o");
        let mut quarantined = sample_finding("run-1", "repo-1", "src/q.rs", "rule-q");
        quarantined.status = "Quarantine".to_string();
        s.findings().upsert(&open).await.expect("o");
        s.findings().upsert(&quarantined).await.expect("q");

        let active = s.findings().list_filtered(&FindingFilter::default()).await.expect("active");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, open.id);

        let everything = s
            .findings()
            .list_filtered(&FindingFilter { include_quarantine: true, ..Default::default() })
            .await
            .expect("everything");
        assert_eq!(everything.len(), 2);
    }

    #[tokio::test]
    async fn quarantine_flips_status_and_records_reason() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("insert");
        let n = s
            .findings()
            .quarantine(&f.id, "{\"reason\":\"payload synthesis failed twice\"}")
            .await
            .expect("quarantine");
        assert_eq!(n, 1);
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.status, "Quarantine");
        assert!(got
            .verdict_blob
            .as_deref()
            .unwrap_or_default()
            .contains("payload synthesis failed twice"));
    }

    #[tokio::test]
    async fn fk_required_run_id_rejects_unknown() {
        let (_tmp, s) = fresh_store().await;
        // intentionally do NOT insert run "ghost"
        s.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
        let f = sample_finding("ghost", "repo-1", "src/a.rs", "rule-1");
        let err = s.findings().upsert(&f).await.expect_err("must fail");
        let msg = format!("{err}");
        assert!(msg.to_lowercase().contains("foreign key"), "got: {msg}");
    }
}
