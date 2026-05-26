//! `findings` table - the main aggregated finding store with stable hash
//! IDs so re-running a scan over the same code converges on the same row.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Row, SqlitePool};

use crate::store::StoreError;

pub use nyctos_types::finding::FindingRecord;

/// Smoothing prior baked into [`FindingStore::per_path_promotion_rate`].
/// A path with only one observation must not get the full rate boost a
/// path with 50 observations does; this denominator floor dampens
/// low-cardinality rows. Picked at 5 because nyx-side AI passes
/// typically observe a path 1-3 times in one run.
pub const PROMOTION_RATE_LAPLACE_PRIOR: f64 = 5.0;

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
    /// AI-discovered candidate finding that the verifier promoted
    /// from `candidate_findings.Pending` to a real `findings` row.
    /// Distinct from the bare `Ai` variant because the originating
    /// signal is the agent's source-code exploration, not a
    /// static-pass diag the agent later annotated.
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
    pub project_id: Option<&'a str>,
    pub repo: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub cap: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub status: Option<&'a str>,
    pub severity: Option<&'a str>,
    pub triage_state: Option<&'a str>,
    pub chain_id: Option<&'a str>,
    /// When `false` (default) rows with `status = 'Quarantine'` are
    /// excluded. The default findings list view leaves this off;
    /// the Quarantine page passes `true`.
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
        spec_id: row.get("spec_id"),
    }
}

pub struct FindingStore<'a> {
    pool: &'a SqlitePool,
}

impl<'a> FindingStore<'a> {
    pub fn new(pool: &'a SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn upsert(&self, f: &FindingRecord) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
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
        .execute(&mut *tx)
        .await?;
        // Mirror the observation onto `run_findings` so the
        // FindingDiffStatus classifier can compare current-run
        // membership against prior runs. Runtime-checked SQL so the
        // `.sqlx/` cache does not grow for a one-line dual-write.
        sqlx::query(
            "INSERT INTO run_findings (run_id, finding_id, status) \
             VALUES (?, ?, ?) \
             ON CONFLICT(run_id, finding_id) DO UPDATE SET status = excluded.status",
        )
        .bind(&f.run_id)
        .bind(&f.id)
        .bind(&f.status)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// All `(finding_id, status)` pairs observed during `run_id`.
    /// Backs the `FindingDiffStatus` classifier in the API layer.
    /// Returns an empty vec when the run never observed any finding.
    pub async fn list_run_membership(
        &self,
        run_id: &str,
    ) -> Result<Vec<(String, String)>, StoreError> {
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT finding_id, status FROM run_findings WHERE run_id = ?",
        )
        .bind(run_id)
        .fetch_all(self.pool)
        .await?;
        Ok(rows)
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
                   attack_provenance, prompt_version, chain_id, spec_id
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
                   attack_provenance, prompt_version, chain_id, spec_id
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

    /// Composite filter used by the findings browser. Every
    /// field is optional; combining them ANDs in SQLite, and an empty
    /// filter returns every active row (i.e. status != Quarantine
    /// unless [`FindingFilter::include_quarantine`] is set). Ordering
    /// matches [`FindingStore::list_active_for_repo`] / [`FindingStore::list_by_run`]: most-recent
    /// `last_seen` first.
    pub async fn list_filtered(
        &self,
        filter: &FindingFilter<'_>,
    ) -> Result<Vec<FindingRecord>, StoreError> {
        let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new(
            "SELECT id, run_id, repo, path, line, cap, rule, severity, status, \
             finding_origin, first_seen, last_seen, superseded_by, triage_state, \
             triage_assigned_to, verdict_blob, repro_path, attack_provenance, \
             prompt_version, chain_id, spec_id FROM findings",
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
        if let Some(project_id) = filter.project_id {
            push_clause(&mut qb);
            qb.push("run_id IN (SELECT id FROM runs WHERE project_id = ")
                .push_bind(project_id.to_string())
                .push(")");
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
                   attack_provenance, prompt_version, chain_id, spec_id
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

    /// Per-path AI-finding promotion rate for `repo`, in [0.0, 1.0].
    /// Numerator: AI-originated findings on the path whose final
    /// status is `Open` (verifier-confirmed) or `Verified` (operator-
    /// promoted). Denominator: total AI-originated findings on the
    /// path, plus a Laplace prior so a path with one observation does
    /// not score the same as a path with fifty. Backs the file
    /// priority heuristic in the Novel discovery walker: paths that
    /// historically converted are more worth burning AI budget on.
    pub async fn per_path_promotion_rate(
        &self,
        repo: &str,
    ) -> Result<HashMap<String, f64>, StoreError> {
        let rows = sqlx::query(
            "SELECT path, \
                    SUM(CASE WHEN status IN ('Open','Verified') THEN 1 ELSE 0 END) AS promotions, \
                    COUNT(*) AS total \
             FROM findings \
             WHERE repo = ? AND attack_provenance IN ('AiExploration','LlmSynthesised') \
             GROUP BY path",
        )
        .bind(repo)
        .fetch_all(self.pool)
        .await?;
        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let path: String = row.get("path");
            let promotions: i64 = row.get("promotions");
            let total: i64 = row.get("total");
            let rate = (promotions as f64) / (total as f64 + PROMOTION_RATE_LAPLACE_PRIOR);
            out.insert(path, rate.clamp(0.0, 1.0));
        }
        Ok(out)
    }

    /// Stamp the verifier outcome on `id`: flips `status` (Verified
    /// for Confirmed, Closed for NotConfirmed, untouched for Errored,
    /// where the caller passes the row's existing status) and
    /// overwrites `verdict_blob` + `attack_provenance`.
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

    /// Operator-driven promote: flip `id` to `new_status`, write the
    /// supplied JSON `verdict_blob`, and stamp
    /// `attack_provenance = 'ManualPromote'` so the audit trail
    /// distinguishes operator overrides from verifier-confirmed rows.
    /// Mirror image of the candidate-side `promote_candidate_to_finding`
    /// path: both writers now produce a typed `ManualPromote` blob
    /// instead of reusing `set_verify_result`.
    pub async fn manual_promote(
        &self,
        id: &str,
        new_status: &str,
        verdict_blob: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE findings SET status = ?, verdict_blob = ?, attack_provenance = 'ManualPromote' \
             WHERE id = ?",
        )
        .bind(new_status)
        .bind(verdict_blob)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Operator-driven dismissal: flip `id` to `'Closed'`, write the
    /// supplied JSON `verdict_blob`, and stamp
    /// `attack_provenance = 'ManualDismiss'`. Used for the quarantine
    /// dismiss flow, where reusing `set_verify_result` would silently
    /// inherit the prior verifier's provenance and obscure the
    /// operator's intent.
    pub async fn manual_dismiss(&self, id: &str, verdict_blob: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE findings SET status = 'Closed', verdict_blob = ?, \
             attack_provenance = 'ManualDismiss' WHERE id = ?",
        )
        .bind(verdict_blob)
        .bind(id)
        .execute(self.pool)
        .await?;
        Ok(())
    }

    /// Flip `id` to `status = 'Quarantine'`, stamping `verdict_blob`
    /// with the supplied JSON reason. PayloadSynthesis falls back
    /// here when both synthesis attempts fail to parse;
    /// SpecDerivation and NovelFindingsDiscovery reuse the same
    /// shape so the quarantine page can surface a uniform reason
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
        fresh_store, sample_chain, sample_finding, sample_repo, sample_repo_for_project, sample_run,
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
        assert_eq!(h.len(), 16, "finding id hash truncated to 16 hex chars");
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
    async fn spec_id_surfaces_on_every_read_path() {
        // SpecDerivation writes `findings.spec_id` via
        // `HarnessSpecStore::insert_with_finding_spec_link`. The reads
        // exposed by `FindingStore::get` / `list_active_for_repo` /
        // `list_by_run` / `list_filtered` must all project the column
        // so a UI back-link can render without joining `harness_specs`.
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("finding");
        let spec = crate::store::HarnessSpecRecord {
            id: "spec-1".to_string(),
            cap: "SQL_QUERY".to_string(),
            lang: "python".to_string(),
            spec_blob: r#"{"schema_version":1,"cap":"SQL_QUERY"}"#.to_string(),
            attack_provenance: Some("LlmSynthesised".to_string()),
            prompt_version: Some("phase15.spec_derivation.v1".to_string()),
            created_at: 4_000,
        };
        s.harness_specs()
            .insert_with_finding_spec_link(
                &spec,
                &f.id,
                "LlmSynthesised",
                "phase15.spec_derivation.v1",
            )
            .await
            .expect("dual write");

        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.spec_id.as_deref(), Some("spec-1"));

        let active = s.findings().list_active_for_repo("repo-1").await.expect("active");
        assert_eq!(
            active.iter().find(|r| r.id == f.id).and_then(|r| r.spec_id.as_deref()),
            Some("spec-1")
        );

        let by_run = s.findings().list_by_run("run-1").await.expect("by run");
        assert_eq!(
            by_run.iter().find(|r| r.id == f.id).and_then(|r| r.spec_id.as_deref()),
            Some("spec-1")
        );

        let filtered = s
            .findings()
            .list_filtered(&FindingFilter { repo: Some("repo-1"), ..Default::default() })
            .await
            .expect("filtered");
        assert_eq!(
            filtered.iter().find(|r| r.id == f.id).and_then(|r| r.spec_id.as_deref()),
            Some("spec-1")
        );
    }

    #[tokio::test]
    async fn upsert_does_not_clobber_existing_spec_id() {
        // A re-scan upserts a FindingRecord constructed by the static
        // pass with `spec_id: None`. The existing AI-side back-link on
        // the row must survive the conflict-update so the UI does not
        // lose the SpecDerivation pointer between scans.
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let mut f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("first insert");
        let spec = crate::store::HarnessSpecRecord {
            id: "spec-keep".to_string(),
            cap: "SQL_QUERY".to_string(),
            lang: "python".to_string(),
            spec_blob: "{}".to_string(),
            attack_provenance: None,
            prompt_version: None,
            created_at: 4_000,
        };
        s.harness_specs()
            .insert_with_finding_spec_link(&spec, &f.id, "LlmSynthesised", "v1")
            .await
            .expect("dual write");
        f.severity = "Critical".to_string();
        f.last_seen = 9_000;
        s.findings().upsert(&f).await.expect("re-upsert");
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.spec_id.as_deref(), Some("spec-keep"));
        assert_eq!(got.severity, "Critical");
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
    async fn list_filtered_scopes_by_project() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("repo-1")).await.expect("repo-1");
        s.projects()
            .create("project-2", "project-2", None, None, None, 1_000)
            .await
            .expect("project-2");
        s.repos().upsert(&sample_repo_for_project("repo-2", "project-2")).await.expect("repo-2");

        let mut run_1 = sample_run("run-1");
        run_1.project_id = Some(crate::store::project::DEFAULT_PROJECT_ID.to_string());
        s.runs().insert(&run_1).await.expect("run-1");
        let mut run_2 = sample_run("run-2");
        run_2.project_id = Some("project-2".to_string());
        s.runs().insert(&run_2).await.expect("run-2");

        let a = sample_finding("run-1", "repo-1", "src/a.rs", "rule-a");
        let b = sample_finding("run-2", "repo-2", "src/b.rs", "rule-b");
        s.findings().upsert(&a).await.expect("a");
        s.findings().upsert(&b).await.expect("b");

        let got = s
            .findings()
            .list_filtered(&FindingFilter {
                project_id: Some(crate::store::project::DEFAULT_PROJECT_ID),
                ..Default::default()
            })
            .await
            .expect("project filter");
        assert_eq!(got.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), vec![a.id.as_str()]);
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

    #[tokio::test]
    async fn manual_promote_stamps_provenance_and_status() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let mut f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        f.status = "Quarantine".to_string();
        f.attack_provenance = Some("PayloadSynthesis".to_string());
        f.verdict_blob = Some(r#"{"kind":"PayloadSynthFailed"}"#.to_string());
        s.findings().upsert(&f).await.expect("insert");

        s.findings()
            .manual_promote(&f.id, "Open", r#"{"kind":"ManualPromote","from":"quarantine"}"#)
            .await
            .expect("promote");
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.status, "Open");
        assert_eq!(got.attack_provenance.as_deref(), Some("ManualPromote"));
        assert_eq!(
            got.verdict_blob.as_deref(),
            Some(r#"{"kind":"ManualPromote","from":"quarantine"}"#),
        );
    }

    #[tokio::test]
    async fn upsert_dual_writes_run_findings_row() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("insert");
        let mem = s.findings().list_run_membership("run-1").await.expect("membership");
        assert_eq!(mem.len(), 1);
        assert_eq!(mem[0].0, f.id);
        assert_eq!(mem[0].1, "Open");
    }

    #[tokio::test]
    async fn upsert_updates_run_findings_status_on_status_change() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let mut f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("insert");
        f.status = "Verified".to_string();
        s.findings().upsert(&f).await.expect("re-upsert");
        let mem = s.findings().list_run_membership("run-1").await.expect("membership");
        assert_eq!(mem.len(), 1);
        assert_eq!(mem[0].1, "Verified");
    }

    #[tokio::test]
    async fn list_run_membership_scopes_to_run_id() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        s.runs().insert(&sample_run("run-2")).await.expect("run-2");
        let f1 = sample_finding("run-1", "repo-1", "src/a.rs", "rule-a");
        let f2 = sample_finding("run-2", "repo-1", "src/b.rs", "rule-b");
        s.findings().upsert(&f1).await.expect("f1");
        s.findings().upsert(&f2).await.expect("f2");

        let mem1 = s.findings().list_run_membership("run-1").await.expect("mem1");
        let ids1: Vec<&str> = mem1.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids1.len(), 1);
        assert!(ids1.contains(&f1.id.as_str()));

        let mem2 = s.findings().list_run_membership("run-2").await.expect("mem2");
        let ids2: Vec<&str> = mem2.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids2.len(), 1);
        assert!(ids2.contains(&f2.id.as_str()));
    }

    #[tokio::test]
    async fn run_findings_cascade_clears_on_run_delete() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        s.findings().upsert(&f).await.expect("insert");
        s.runs().delete("run-1").await.expect("delete run");
        let mem = s.findings().list_run_membership("run-1").await.expect("membership");
        assert!(mem.is_empty(), "FK cascade should empty run_findings on run delete");
    }

    #[tokio::test]
    async fn per_path_promotion_rate_groups_ai_rows_by_path_and_applies_prior() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        // Path A: 1 AI-promoted (Open) row. With Laplace prior 5 the
        // rate floats around 1/(1+5)=0.167: non-zero, but well below
        // the full-confidence ceiling.
        let mut a = sample_finding("run-1", "repo-1", "hot.py", "rule-a");
        a.attack_provenance = Some("LlmSynthesised".to_string());
        a.status = "Open".to_string();
        s.findings().upsert(&a).await.expect("a");

        // Path B: 5 AI-promoted rows. Rate -> 5/(5+5) = 0.5.
        for i in 0..5 {
            let mut b = sample_finding("run-1", "repo-1", "warm.py", &format!("rule-b{i}"));
            b.attack_provenance = Some("AiExploration".to_string());
            b.status = "Verified".to_string();
            s.findings().upsert(&b).await.expect("b");
        }

        // Path C: 2 AI-rejected (Quarantine) rows. Rate -> 0/(2+5) = 0.
        for i in 0..2 {
            let mut c = sample_finding("run-1", "repo-1", "cold.py", &format!("rule-c{i}"));
            c.attack_provenance = Some("LlmSynthesised".to_string());
            c.status = "Quarantine".to_string();
            s.findings().upsert(&c).await.expect("c");
        }

        // Static-pass row on path D must NOT count (no attack_provenance).
        let d = sample_finding("run-1", "repo-1", "static.py", "rule-d");
        s.findings().upsert(&d).await.expect("d");

        let rates = s.findings().per_path_promotion_rate("repo-1").await.expect("rates");
        let a_rate = rates.get("hot.py").copied().unwrap_or(0.0);
        let b_rate = rates.get("warm.py").copied().unwrap_or(0.0);
        let c_rate = rates.get("cold.py").copied().unwrap_or(0.0);
        assert!((a_rate - 1.0 / 6.0).abs() < 1e-9, "hot.py rate: {a_rate}");
        assert!((b_rate - 0.5).abs() < 1e-9, "warm.py rate: {b_rate}");
        assert!(c_rate.abs() < 1e-9, "cold.py rate: {c_rate}");
        assert!(!rates.contains_key("static.py"), "static-pass rows must be excluded");
        assert!(b_rate > a_rate && a_rate > c_rate, "ordering must reflect promotion signal");
    }

    #[tokio::test]
    async fn per_path_promotion_rate_scopes_to_repo() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        s.repos().upsert(&sample_repo("repo-2")).await.expect("repo-2");
        let mut a = sample_finding("run-1", "repo-1", "shared.py", "rule-a");
        a.attack_provenance = Some("LlmSynthesised".to_string());
        a.status = "Open".to_string();
        s.findings().upsert(&a).await.expect("a");
        let mut b = sample_finding("run-1", "repo-2", "shared.py", "rule-b");
        b.attack_provenance = Some("LlmSynthesised".to_string());
        b.status = "Quarantine".to_string();
        s.findings().upsert(&b).await.expect("b");
        let r1 = s.findings().per_path_promotion_rate("repo-1").await.expect("r1");
        let r2 = s.findings().per_path_promotion_rate("repo-2").await.expect("r2");
        assert!(r1.get("shared.py").copied().unwrap_or(0.0) > 0.0);
        assert_eq!(r2.get("shared.py").copied().unwrap_or(0.0), 0.0);
    }

    #[tokio::test]
    async fn manual_dismiss_stamps_provenance_and_closes_row() {
        let (_tmp, s) = fresh_store().await;
        seed(&s).await;
        let mut f = sample_finding("run-1", "repo-1", "src/a.rs", "rule-1");
        f.status = "Quarantine".to_string();
        f.attack_provenance = Some("SpecDerivation".to_string());
        s.findings().upsert(&f).await.expect("insert");

        s.findings().manual_dismiss(&f.id, r#"{"kind":"ManualDismiss"}"#).await.expect("dismiss");
        let got = s.findings().get(&f.id).await.expect("get").expect("row");
        assert_eq!(got.status, "Closed");
        assert_eq!(got.attack_provenance.as_deref(), Some("ManualDismiss"));
        assert_eq!(got.verdict_blob.as_deref(), Some(r#"{"kind":"ManualDismiss"}"#));
    }
}
