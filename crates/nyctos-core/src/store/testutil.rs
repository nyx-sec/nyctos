//! Test helpers shared across store-module unit tests.

use tempfile::TempDir;

use super::{
    candidate::CandidateFindingRecord,
    chain::ChainRecord,
    finding::{finding_id_hash, FindingRecord},
    payload::PayloadRecord,
    project::DEFAULT_PROJECT_ID,
    repo::RepoRecord,
    run::RunRecord,
    Store,
};

pub async fn fresh_store() -> (TempDir, Store) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    (tmp, store)
}

pub fn sample_repo(name: &str) -> RepoRecord {
    sample_repo_for_project(name, DEFAULT_PROJECT_ID)
}

pub fn sample_repo_for_project(name: &str, project_id: &str) -> RepoRecord {
    RepoRecord {
        name: name.to_string(),
        project_id: project_id.to_string(),
        source_kind: "local".to_string(),
        source_url_or_path: format!("/tmp/{name}"),
        branch: Some("main".to_string()),
        auth_ref: None,
        i_own_this: true,
        last_scan_run_id: None,
        last_scan_finished_at: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

pub fn sample_run(id: &str) -> RunRecord {
    RunRecord {
        id: id.to_string(),
        started_at: 2_000,
        finished_at: None,
        status: "Running".to_string(),
        triggered_by: "Manual".to_string(),
        git_ref: Some("refs/heads/main".to_string()),
        parent_run_id: None,
        wall_clock_ms: None,
        total_ai_spend_usd_micros: 0,
    }
}

pub fn sample_finding(run_id: &str, repo: &str, path: &str, rule: &str) -> FindingRecord {
    let id = finding_id_hash(repo, path, Some(10), "sqli", rule);
    FindingRecord {
        id,
        run_id: run_id.to_string(),
        repo: repo.to_string(),
        path: path.to_string(),
        line: Some(10),
        cap: "sqli".to_string(),
        rule: rule.to_string(),
        severity: "High".to_string(),
        status: "Open".to_string(),
        finding_origin: "Static".to_string(),
        first_seen: 3_000,
        last_seen: 3_000,
        superseded_by: None,
        triage_state: "Open".to_string(),
        triage_assigned_to: None,
        verdict_blob: None,
        repro_path: None,
        attack_provenance: None,
        prompt_version: None,
        chain_id: None,
    }
}

pub fn sample_payload(id: &str, finding_id: &str) -> PayloadRecord {
    PayloadRecord {
        id: id.to_string(),
        finding_id: finding_id.to_string(),
        cap: "sqli".to_string(),
        lang: "rust".to_string(),
        vuln_bytes: b"vuln-bytes".to_vec(),
        benign_bytes: Some(b"benign-bytes".to_vec()),
        oracle_blob: Some("{\"oracle\":\"diff\"}".to_string()),
        attack_provenance: None,
        prompt_version: Some("p:0001".to_string()),
        created_at: 4_000,
    }
}

pub fn sample_chain(id: &str, run_id: &str, members: &[&str]) -> ChainRecord {
    ChainRecord {
        id: id.to_string(),
        run_id: run_id.to_string(),
        cross_repo: false,
        member_ids: serde_json::to_string(members).expect("serialise member_ids"),
        rationale_blob: Some("{\"because\":\"chain\"}".to_string()),
        attack_provenance: None,
        prompt_version: Some("p:0002".to_string()),
    }
}

pub fn sample_candidate(id: &str, run_id: &str, repo: &str) -> CandidateFindingRecord {
    CandidateFindingRecord {
        id: id.to_string(),
        run_id: run_id.to_string(),
        repo: repo.to_string(),
        path: "src/lib.rs".to_string(),
        line: Some(42),
        cap: "sqli".to_string(),
        rule_hint: Some("interpolated-query".to_string()),
        rationale: Some("ai noticed string concatenation".to_string()),
        suggested_payload_hint: None,
        status: "Pending".to_string(),
        prompt_version: Some("p:0003".to_string()),
    }
}
