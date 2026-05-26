//! `report.json` written by `scan --output` and consumed by
//! `pr-comment --report`.
//!
//! The shape captures the per-run finding + chain inventory plus
//! optional metadata about the `--since-ref` filter that produced it.
//! Everything pr-comment needs to render a grouped comment is here -
//! no live store lookup is required at comment time, so CI can run
//! `pr-comment` on a runner that never touched SQLite.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use nyctos_core::store::{
    ChainRecord, FindingRecord, NyxSignalRecord, PentestCandidateRecord, Store, StoreError,
    VerifiedVulnerabilityRecord,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub run_id: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub status: String,
    pub triggered_by: String,
    /// Repositories included in this report. Sorted for stable diffs.
    pub repos: Vec<String>,
    /// Echoed back from `--since-ref` so the comment surface can show
    /// the operator which base the diff was computed against. `None`
    /// when scan ran without the flag.
    pub since_ref: Option<String>,
    #[serde(default)]
    pub verified_vulnerabilities: Vec<ReportVulnerability>,
    #[serde(default)]
    pub verified_chains: Vec<ReportVerifiedChain>,
    #[serde(default)]
    pub signal_counts: ReportSignalCounts,
    #[serde(default)]
    pub pentest_candidates: Vec<ReportCandidate>,
    #[serde(default)]
    pub findings: Vec<ReportFinding>,
    #[serde(default)]
    pub chains: Vec<ReportChain>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportVulnerability {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub confidence: f64,
    pub vuln_class: String,
    pub status: String,
    pub affected_components: Vec<serde_json::Value>,
    pub source_candidate_ids: Vec<String>,
    pub source_signal_ids: Vec<String>,
    pub verification_attempt_ids: Vec<String>,
    #[serde(default)]
    pub verification_artifacts: Vec<String>,
    pub chain_id: Option<String>,
    pub evidence_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportVerifiedChain {
    pub id: String,
    pub member_ids: Vec<String>,
    pub status: String,
    pub verification_attempt_id: Option<String>,
    pub severity: Option<String>,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSignalCounts {
    pub total: u32,
    pub meaningful: u32,
    pub suppressed: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportCandidate {
    pub id: String,
    pub source: String,
    pub source_ids: Vec<String>,
    pub title: String,
    pub vuln_class: String,
    pub severity_guess: String,
    pub status: String,
    pub confidence: f64,
    pub affected_components: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportFinding {
    pub id: String,
    pub repo: String,
    pub path: String,
    pub line: Option<i64>,
    pub cap: String,
    pub rule: String,
    pub severity: String,
    pub status: String,
    pub finding_origin: String,
    pub chain_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportChain {
    pub id: String,
    pub cross_repo: bool,
    pub member_ids: Vec<String>,
    pub rationale: Option<String>,
}

pub const REPORT_SCHEMA_VERSION: u32 = 4;

/// Schema versions this binary knows how to read. A future minor /
/// compatible bump can append here so older readers refuse loudly
/// rather than silently dropping fields they cannot parse.
pub const SUPPORTED_REPORT_SCHEMA_VERSIONS: &[u32] = &[1, 2, 3, 4];

#[derive(Debug, thiserror::Error)]
pub enum ScanReportError {
    #[error("io error writing report to {path}: {source}")]
    Write { path: String, source: std::io::Error },
    #[error("io error reading report from {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error(
        "report schema_version {found} not supported by this binary (supported: {supported:?}); \
         upgrade `nyctos` to read this report"
    )]
    UnsupportedSchemaVersion { found: u32, supported: Vec<u32> },
}

impl ScanReport {
    /// Read a report from disk. Used by `pr-comment`.
    pub fn load(path: &Path) -> Result<Self, ScanReportError> {
        let bytes = std::fs::read(path)
            .map_err(|source| ScanReportError::Read { path: path.display().to_string(), source })?;
        let report: Self = serde_json::from_slice(&bytes)?;
        if !SUPPORTED_REPORT_SCHEMA_VERSIONS.contains(&report.schema_version) {
            return Err(ScanReportError::UnsupportedSchemaVersion {
                found: report.schema_version,
                supported: SUPPORTED_REPORT_SCHEMA_VERSIONS.to_vec(),
            });
        }
        Ok(report)
    }

    /// Drop every row the PR-comment surface would not render. Mirrors
    /// [`crate::cmd::pr_comment::filter_for_pr`]: keeps only verified
    /// vulnerabilities and live-verified chains. Used by `scan
    /// --output --output-only-pr-worthy` so the on-disk report stays
    /// small on runs whose static-pass output dwarfs the verified set.
    pub fn retain_pr_worthy(&mut self) {
        self.findings.clear();
        self.chains.clear();
        self.pentest_candidates.clear();
        self.verified_vulnerabilities
            .retain(|v| matches!(v.status.as_str(), "Open" | "Verified" | "Confirmed"));
        self.verified_chains
            .retain(|c| c.status == "Verified" || c.verification_attempt_id.is_some());

        let mut repos: Vec<String> =
            self.verified_vulnerabilities.iter().flat_map(vulnerability_repos).collect();
        repos.sort();
        repos.dedup();
        self.repos = repos;
    }

    /// Serialise the report to `path` with stable, pretty-printed JSON.
    pub fn write(&self, path: &Path) -> Result<(), ScanReportError> {
        let json = serde_json::to_vec_pretty(self)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|source| ScanReportError::Write {
                    path: path.display().to_string(),
                    source,
                })?;
            }
        }
        std::fs::write(path, json).map_err(|source| ScanReportError::Write {
            path: path.display().to_string(),
            source,
        })?;
        Ok(())
    }
}

/// Read every persisted finding + chain for `run_id` and assemble a
/// [`ScanReport`]. When `changed_files` is `Some`, findings whose
/// `(repo, path)` is not in the set are dropped before serialisation.
pub async fn build_report(
    store: &Store,
    run_id: &str,
    run_meta: RunMeta<'_>,
    since_ref: Option<&str>,
    changed_files: Option<&HashMap<String, HashSet<String>>>,
) -> Result<ScanReport, ScanReportError> {
    let raw_findings = store.findings().list_by_run(run_id).await?;
    let raw_chains = store.chains().list_by_run(run_id).await?;
    let raw_vulnerabilities = store.verified_vulnerabilities().list_by_run(run_id).await?;
    let raw_signals = store.nyx_signals().list_by_run(run_id, false).await?;
    let raw_attempts = store.verification_attempts().list_by_run(run_id).await?;
    let raw_candidates = store.pentest_candidates().list_by_run(run_id).await?;

    let findings: Vec<ReportFinding> = raw_findings
        .into_iter()
        .filter(|f| keep_finding(f, changed_files))
        .map(map_finding)
        .collect();
    let attempt_artifacts: HashMap<String, Vec<String>> =
        raw_attempts.into_iter().map(|attempt| (attempt.id, attempt.artifact_paths)).collect();
    let verified_vulnerabilities: Vec<ReportVulnerability> =
        raw_vulnerabilities.into_iter().map(|v| map_vulnerability(v, &attempt_artifacts)).collect();
    let verified_chains: Vec<ReportVerifiedChain> = raw_chains
        .iter()
        .filter(|c| c.status == "Verified" || c.verification_attempt_id.is_some())
        .cloned()
        .map(map_verified_chain)
        .collect();
    let signal_counts = signal_counts(&raw_signals);

    let mut repos: Vec<String> = verified_vulnerabilities
        .iter()
        .flat_map(vulnerability_repos)
        .chain(findings.iter().map(|f| f.repo.clone()))
        .collect();
    repos.sort();
    repos.dedup();

    Ok(ScanReport {
        schema_version: REPORT_SCHEMA_VERSION,
        run_id: run_id.to_string(),
        started_at: run_meta.started_at,
        finished_at: run_meta.finished_at,
        status: run_meta.status.to_string(),
        triggered_by: run_meta.triggered_by.to_string(),
        repos,
        since_ref: since_ref.map(|s| s.to_string()),
        verified_vulnerabilities,
        verified_chains,
        signal_counts,
        pentest_candidates: raw_candidates.into_iter().map(map_candidate).collect(),
        findings,
        chains: raw_chains.into_iter().map(map_chain).collect(),
    })
}

#[derive(Debug, Clone, Copy)]
pub struct RunMeta<'a> {
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub status: &'a str,
    pub triggered_by: &'a str,
}

fn keep_finding(
    f: &FindingRecord,
    changed_files: Option<&HashMap<String, HashSet<String>>>,
) -> bool {
    match changed_files {
        None => true,
        Some(map) => map.get(&f.repo).map(|paths| paths.contains(&f.path)).unwrap_or(false),
    }
}

fn map_finding(f: FindingRecord) -> ReportFinding {
    ReportFinding {
        id: f.id,
        repo: f.repo,
        path: f.path,
        line: f.line,
        cap: f.cap,
        rule: f.rule,
        severity: f.severity,
        status: f.status,
        finding_origin: f.finding_origin,
        chain_id: f.chain_id,
    }
}

fn map_vulnerability(
    v: VerifiedVulnerabilityRecord,
    attempt_artifacts: &HashMap<String, Vec<String>>,
) -> ReportVulnerability {
    let mut verification_artifacts = v
        .verification_attempt_ids
        .iter()
        .filter_map(|id| attempt_artifacts.get(id))
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    verification_artifacts.sort();
    verification_artifacts.dedup();
    ReportVulnerability {
        id: v.id,
        title: v.title,
        severity: v.severity,
        confidence: v.confidence,
        vuln_class: v.vuln_class,
        status: v.status,
        affected_components: v.affected_components,
        source_candidate_ids: v.source_candidate_ids,
        source_signal_ids: v.source_signal_ids,
        verification_attempt_ids: v.verification_attempt_ids,
        verification_artifacts,
        chain_id: v.chain_id,
        evidence_summary: v.evidence_summary,
    }
}

fn map_chain(c: ChainRecord) -> ReportChain {
    // `chains.member_ids` is persisted as a JSON-serialised
    // `Vec<String>` by the chain reasoner; the testutil sometimes
    // round-trips through the same shape and sometimes hands us a
    // comma-separated list, so try JSON first and fall back to CSV.
    let member_ids: Vec<String> = serde_json::from_str(&c.member_ids).unwrap_or_else(|_| {
        c.member_ids.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    });
    let rationale = c.rationale_blob.and_then(extract_rationale);
    ReportChain { id: c.id, cross_repo: c.cross_repo, member_ids, rationale }
}

fn map_verified_chain(c: ChainRecord) -> ReportVerifiedChain {
    let member_ids: Vec<String> = serde_json::from_str(&c.member_ids).unwrap_or_else(|_| {
        c.member_ids.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    });
    let rationale = c.rationale_blob.and_then(extract_rationale);
    ReportVerifiedChain {
        id: c.id,
        member_ids,
        status: c.status,
        verification_attempt_id: c.verification_attempt_id,
        severity: c.severity,
        rationale,
    }
}

fn signal_counts(signals: &[NyxSignalRecord]) -> ReportSignalCounts {
    let total = signals.len() as u32;
    let meaningful = signals.iter().filter(|s| s.meaningful).count() as u32;
    ReportSignalCounts { total, meaningful, suppressed: total.saturating_sub(meaningful) }
}

fn map_candidate(c: PentestCandidateRecord) -> ReportCandidate {
    ReportCandidate {
        id: c.id,
        source: c.source,
        source_ids: c.source_ids,
        title: c.title,
        vuln_class: c.vuln_class,
        severity_guess: c.severity_guess,
        status: c.status,
        confidence: c.confidence,
        affected_components: c.affected_components,
    }
}

pub fn vulnerability_repos(v: &ReportVulnerability) -> Vec<String> {
    let mut repos = Vec::new();
    for component in &v.affected_components {
        if let Some(repo) = component.get("repo").and_then(|v| v.as_str()) {
            repos.push(repo.to_string());
        }
    }
    if repos.is_empty() {
        repos.push("<project>".to_string());
    }
    repos
}

pub fn vulnerability_primary_location(v: &ReportVulnerability) -> (String, String, Option<i64>) {
    if let Some(component) = v.affected_components.first() {
        let repo =
            component.get("repo").and_then(|v| v.as_str()).unwrap_or("<project>").to_string();
        let path = component
            .get("path")
            .or_else(|| component.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or(&v.title)
            .to_string();
        let line = component.get("line").and_then(|v| v.as_i64());
        return (repo, path, line);
    }
    ("<project>".to_string(), v.title.clone(), None)
}

/// Pull the human-facing string out of the rationale blob the chain
/// reasoner persists (`{"rationale": "..."}`); pass through whatever
/// is there when the blob is not the expected shape so future schema
/// changes do not silently swallow the value.
fn extract_rationale(blob: String) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&blob) {
        if let Some(text) = v.get("rationale").and_then(|r| r.as_str()) {
            return Some(text.to_string());
        }
    }
    Some(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_finding(id: &str, repo: &str, path: &str) -> ReportFinding {
        ReportFinding {
            id: id.to_string(),
            repo: repo.to_string(),
            path: path.to_string(),
            line: Some(42),
            cap: "sqli".to_string(),
            rule: "py.sqli".to_string(),
            severity: "High".to_string(),
            status: "Verified".to_string(),
            finding_origin: "Static".to_string(),
            chain_id: None,
        }
    }

    fn sample_vulnerability(id: &str, repo: &str, path: &str) -> ReportVulnerability {
        ReportVulnerability {
            id: id.to_string(),
            title: format!("Verified issue {id}"),
            severity: "High".to_string(),
            confidence: 0.95,
            vuln_class: "SQLi".to_string(),
            status: "Open".to_string(),
            affected_components: vec![
                serde_json::json!({ "repo": repo, "path": path, "line": 42 }),
            ],
            source_candidate_ids: vec![format!("pc-{id}")],
            source_signal_ids: vec![format!("sig-{id}")],
            verification_attempt_ids: vec![format!("va-{id}")],
            verification_artifacts: Vec::new(),
            chain_id: None,
            evidence_summary: "confirmed by live verification".to_string(),
        }
    }

    #[test]
    fn round_trip_through_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("report.json");
        let report = ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            run_id: "run-1".into(),
            started_at: 100,
            finished_at: Some(200),
            status: "Succeeded".into(),
            triggered_by: "ci".into(),
            repos: vec!["alpha".into(), "beta".into()],
            since_ref: Some("origin/main".into()),
            verified_vulnerabilities: vec![ReportVulnerability {
                verification_artifacts: vec![
                    "/state/traces/run-1/browser_verification/va-v-a/browser-final.png".into(),
                    "/state/traces/run-1/browser_verification/va-v-a/browser-replay.json".into(),
                ],
                ..sample_vulnerability("v-a", "alpha", "src/a.py")
            }],
            verified_chains: vec![ReportVerifiedChain {
                id: "vc1".into(),
                member_ids: vec!["v-a".into(), "v-b".into()],
                status: "Verified".into(),
                verification_attempt_id: Some("va-chain".into()),
                severity: Some("High".into()),
                rationale: Some("live chain verified".into()),
            }],
            signal_counts: ReportSignalCounts { total: 4, meaningful: 2, suppressed: 2 },
            pentest_candidates: vec![ReportCandidate {
                id: "pc-route".into(),
                source: "RouteDiscovery+JavaScriptBundle".into(),
                source_ids: vec!["route:admin".into(), "bundle:admin".into()],
                title: "Administrative surface discovered".into(),
                vuln_class: "ADMIN_SURFACE".into(),
                severity_guess: "Medium".into(),
                status: "NeedsLiveTest".into(),
                confidence: 0.6,
                affected_components: vec![serde_json::json!({"url_path":"/api/admin"})],
            }],
            findings: vec![sample_finding("f-a", "alpha", "src/a.py")],
            chains: vec![ReportChain {
                id: "c1".into(),
                cross_repo: true,
                member_ids: vec!["f-a".into(), "f-b".into()],
                rationale: Some("controller reaches sink".into()),
            }],
        };
        report.write(&path).unwrap();
        let loaded = ScanReport::load(&path).unwrap();
        assert_eq!(loaded, report);
    }

    #[test]
    fn keep_finding_with_changed_files_filter() {
        let mut map: HashMap<String, HashSet<String>> = HashMap::new();
        map.entry("alpha".into()).or_default().insert("src/a.py".into());
        let kept = FindingRecord {
            id: "x".into(),
            run_id: "r".into(),
            repo: "alpha".into(),
            path: "src/a.py".into(),
            line: None,
            cap: "sqli".into(),
            rule: "r".into(),
            severity: "High".into(),
            status: "Open".into(),
            finding_origin: "Static".into(),
            first_seen: 0,
            last_seen: 0,
            superseded_by: None,
            triage_state: "Open".into(),
            triage_assigned_to: None,
            verdict_blob: None,
            repro_path: None,
            attack_provenance: None,
            prompt_version: None,
            chain_id: None,
            spec_id: None,
        };
        let dropped = FindingRecord { path: "src/b.py".into(), ..kept.clone() };
        let other_repo = FindingRecord { repo: "beta".into(), ..kept.clone() };
        assert!(keep_finding(&kept, Some(&map)));
        assert!(!keep_finding(&dropped, Some(&map)));
        assert!(!keep_finding(&other_repo, Some(&map)));
        assert!(keep_finding(&dropped, None));
    }

    #[test]
    fn map_chain_parses_json_member_ids() {
        let raw = ChainRecord {
            id: "c1".into(),
            run_id: "r".into(),
            cross_repo: true,
            member_ids: r#"["a","b","c"]"#.into(),
            rationale_blob: Some(r#"{"rationale":"controller reaches sink"}"#.into()),
            attack_provenance: None,
            prompt_version: None,
            status: "Proposed".into(),
            verification_attempt_id: None,
            evidence_blob: None,
            severity: None,
        };
        let mapped = map_chain(raw);
        assert_eq!(mapped.member_ids, vec!["a", "b", "c"]);
        assert_eq!(mapped.rationale.as_deref(), Some("controller reaches sink"));
    }

    #[test]
    fn map_vulnerability_attaches_attempt_artifacts() {
        let raw = VerifiedVulnerabilityRecord {
            id: "vuln-a".into(),
            run_id: "run-1".into(),
            project_id: "proj-1".into(),
            title: "Browser XSS".into(),
            severity: "High".into(),
            confidence: 0.95,
            risk_score: 8.4,
            risk_rating: "High".into(),
            risk_score_source: "nyctos-agent".into(),
            risk_score_rationale: "Browser oracle confirmed script execution.".into(),
            vuln_class: "XSS".into(),
            affected_components: vec![serde_json::json!({"repo":"web","path":"src/app.tsx"})],
            business_impact: "Script execution".into(),
            evidence_summary: "Browser oracle confirmed execution".into(),
            repro_steps: "Open replay".into(),
            remediation: "Escape HTML".into(),
            source_candidate_ids: vec!["pc-1".into()],
            source_signal_ids: vec!["sig-1".into()],
            verification_attempt_ids: vec!["va-1".into()],
            chain_id: None,
            status: "Open".into(),
            first_seen: 1,
            last_seen: 2,
        };
        let artifacts = HashMap::from([(
            "va-1".to_string(),
            vec![
                "/state/traces/run-1/browser_verification/va-1/browser-final.png".to_string(),
                "/state/traces/run-1/browser_verification/va-1/browser-replay.json".to_string(),
            ],
        )]);

        let mapped = map_vulnerability(raw, &artifacts);

        assert_eq!(mapped.verification_artifacts.len(), 2);
        assert!(mapped
            .verification_artifacts
            .iter()
            .any(|path| path.ends_with("browser-final.png")));
        assert!(mapped
            .verification_artifacts
            .iter()
            .any(|path| path.ends_with("browser-replay.json")));
    }

    #[test]
    fn retain_pr_worthy_keeps_verified_vulnerabilities_and_verified_chains() {
        let mut report = ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            run_id: "run-1".into(),
            started_at: 0,
            finished_at: None,
            status: "Succeeded".into(),
            triggered_by: "ci".into(),
            repos: vec!["alpha".into(), "beta".into(), "gamma".into()],
            since_ref: None,
            verified_vulnerabilities: vec![
                sample_vulnerability("v-confirmed", "alpha", "src/a.py"),
                ReportVulnerability {
                    status: "NeedsReview".into(),
                    ..sample_vulnerability("v-review", "beta", "src/review.py")
                },
                ReportVulnerability {
                    status: "FalsePositive".into(),
                    ..sample_vulnerability("v-fp", "gamma", "src/b.py")
                },
            ],
            verified_chains: vec![
                ReportVerifiedChain {
                    id: "c-verified".into(),
                    member_ids: vec!["v-confirmed".into()],
                    status: "Verified".into(),
                    verification_attempt_id: Some("va-chain".into()),
                    severity: Some("High".into()),
                    rationale: None,
                },
                ReportVerifiedChain {
                    id: "c-proposed".into(),
                    member_ids: vec!["f-chain".into()],
                    status: "Proposed".into(),
                    verification_attempt_id: None,
                    severity: None,
                    rationale: None,
                },
            ],
            signal_counts: ReportSignalCounts::default(),
            pentest_candidates: vec![ReportCandidate {
                id: "pc-open".into(),
                source: "RouteDiscovery".into(),
                source_ids: vec!["route:/api/admin".into()],
                title: "Admin route".into(),
                vuln_class: "ADMIN_SURFACE".into(),
                severity_guess: "Medium".into(),
                status: "NeedsLiveTest".into(),
                confidence: 0.5,
                affected_components: Vec::new(),
            }],
            findings: vec![
                ReportFinding {
                    status: "Verified".into(),
                    ..sample_finding("f-confirmed", "alpha", "src/a.py")
                },
                ReportFinding {
                    status: "Open".into(),
                    ..sample_finding("f-open", "alpha", "src/b.py")
                },
                ReportFinding {
                    status: "Open".into(),
                    chain_id: Some("c-cross".into()),
                    ..sample_finding("f-chain", "beta", "src/c.py")
                },
                ReportFinding {
                    status: "Open".into(),
                    ..sample_finding("f-orphan", "gamma", "src/d.py")
                },
            ],
            chains: vec![
                ReportChain {
                    id: "c-cross".into(),
                    cross_repo: true,
                    member_ids: vec!["f-chain".into()],
                    rationale: None,
                },
                ReportChain {
                    id: "c-local".into(),
                    cross_repo: false,
                    member_ids: vec!["f-orphan".into()],
                    rationale: None,
                },
            ],
        };
        report.retain_pr_worthy();
        let ids: Vec<&str> =
            report.verified_vulnerabilities.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["v-confirmed"]);
        assert!(report.findings.is_empty());
        assert!(report.chains.is_empty());
        assert!(report.pentest_candidates.is_empty());
        assert_eq!(report.verified_chains.len(), 1);
        assert_eq!(report.verified_chains[0].id, "c-verified");
        assert_eq!(report.repos, vec!["alpha"]);
    }

    #[test]
    fn load_refuses_unsupported_schema_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("report.json");
        let report = ScanReport {
            schema_version: 9999,
            run_id: "run-1".into(),
            started_at: 0,
            finished_at: None,
            status: "Succeeded".into(),
            triggered_by: "ci".into(),
            repos: vec![],
            since_ref: None,
            verified_vulnerabilities: vec![],
            verified_chains: vec![],
            signal_counts: ReportSignalCounts::default(),
            pentest_candidates: vec![],
            findings: vec![],
            chains: vec![],
        };
        std::fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
        match ScanReport::load(&path) {
            Err(ScanReportError::UnsupportedSchemaVersion { found, supported }) => {
                assert_eq!(found, 9999);
                assert_eq!(supported, SUPPORTED_REPORT_SCHEMA_VERSIONS.to_vec());
            }
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
    }

    #[test]
    fn supported_schema_versions_includes_current_constant() {
        assert!(SUPPORTED_REPORT_SCHEMA_VERSIONS.contains(&REPORT_SCHEMA_VERSION));
    }

    #[test]
    fn map_chain_falls_back_to_csv_when_not_json() {
        let raw = ChainRecord {
            id: "c2".into(),
            run_id: "r".into(),
            cross_repo: false,
            member_ids: "a, b ,c".into(),
            rationale_blob: Some("opaque blob".into()),
            attack_provenance: None,
            prompt_version: None,
            status: "Proposed".into(),
            verification_attempt_id: None,
            evidence_blob: None,
            severity: None,
        };
        let mapped = map_chain(raw);
        assert_eq!(mapped.member_ids, vec!["a", "b", "c"]);
        assert_eq!(mapped.rationale.as_deref(), Some("opaque blob"));
    }
}
