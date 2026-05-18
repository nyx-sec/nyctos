//! Deduplicated PR-comment writer for the GitHub Actions integration.
//!
//! Reads a [`crate::cmd::scan_report::ScanReport`], filters to findings
//! that an operator should see on the PR (`Verified` status, or members
//! of a cross-repo chain), groups them by file and severity, and posts
//! or updates a single Markdown comment on the target PR.
//!
//! Dedup is achieved by embedding a hidden HTML marker at the top of
//! the body; subsequent runs list the PR's comments, find the one
//! carrying the marker, and PATCH it in place rather than appending a
//! new comment per scan.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::scan_report::{ReportChain, ReportFinding, ScanReport};

/// Hidden HTML marker placed at the top of the comment body. The
/// version suffix lets future schema bumps reuse the same approach
/// without colliding with an in-flight comment from an older binary.
pub const COMMENT_MARKER: &str = "<!-- nyx-agent:pr-comment v1 -->";

/// Default GitHub REST base. Override via `--gh-api` for GHE.
pub const DEFAULT_GH_API_BASE: &str = "https://api.github.com";

/// User agent reported to the GH API. GitHub rejects requests with a
/// missing UA, so always send one.
pub const USER_AGENT: &str = "nyx-agent-pr-comment";

#[derive(Debug, thiserror::Error)]
pub enum PrCommentError {
    #[error("repo descriptor `{0}` is not `owner/repo`")]
    BadRepo(String),
    #[error("github api error: {0}")]
    GitHub(String),
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error(transparent)]
    Report(#[from] super::scan_report::ScanReportError),
    #[error("token is required (set --token-env or GITHUB_TOKEN)")]
    MissingToken,
}

/// Configuration for [`run`]. Built from CLI args + env.
#[derive(Debug, Clone)]
pub struct PrCommentConfig {
    pub repo: String,
    pub pr: u32,
    pub token: String,
    pub ui_url: Option<String>,
    pub gh_api: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrCommentOutcome {
    pub posted_findings: usize,
    pub posted_chains: usize,
    pub updated_existing: bool,
    /// True when no rows passed the Confirmed/cross-repo filter, in
    /// which case the comment surface is left untouched.
    pub skipped_empty: bool,
}

/// Top-level entry point. Loads the report, builds the body, then
/// either creates or updates the marker-tagged comment on the PR.
pub async fn run(
    report_path: &Path,
    cfg: PrCommentConfig,
) -> Result<PrCommentOutcome, PrCommentError> {
    let report = ScanReport::load(report_path)?;
    let (owner, repo_name) = split_repo(&cfg.repo)?;

    let filtered = filter_for_pr(&report);
    if filtered.findings.is_empty() {
        return Ok(PrCommentOutcome {
            posted_findings: 0,
            posted_chains: 0,
            updated_existing: false,
            skipped_empty: true,
        });
    }

    let body = build_comment_body(&filtered, &report, cfg.ui_url.as_deref());

    let client = build_client(&cfg.token)?;
    let existing = find_existing_comment(&client, &cfg.gh_api, owner, repo_name, cfg.pr).await?;
    let updated = if let Some(id) = existing {
        update_comment(&client, &cfg.gh_api, owner, repo_name, id, &body).await?;
        true
    } else {
        create_comment(&client, &cfg.gh_api, owner, repo_name, cfg.pr, &body).await?;
        false
    };

    Ok(PrCommentOutcome {
        posted_findings: filtered.findings.len(),
        posted_chains: filtered.chains.len(),
        updated_existing: updated,
        skipped_empty: false,
    })
}

/// Pure-function view of the rows that should land on the PR. Split
/// out so unit tests can assert filtering + grouping without a live
/// HTTP client.
#[derive(Debug, Clone, Default)]
pub struct FilteredFindings<'a> {
    pub findings: Vec<&'a ReportFinding>,
    pub chains: Vec<&'a ReportChain>,
}

/// Keep findings that are either:
///   * `status = Verified` (Confirmed by the dynamic verifier), or
///   * members of a chain with `cross_repo = true`.
///
/// Everything else stays in the operator's local UI so the PR comment
/// does not spam noise.
pub fn filter_for_pr(report: &ScanReport) -> FilteredFindings<'_> {
    let cross_repo_chains: std::collections::HashSet<&str> = report
        .chains
        .iter()
        .filter(|c| c.cross_repo)
        .map(|c| c.id.as_str())
        .collect();
    let cross_repo_members: std::collections::HashSet<&str> = report
        .chains
        .iter()
        .filter(|c| c.cross_repo)
        .flat_map(|c| c.member_ids.iter().map(|s| s.as_str()))
        .collect();
    let findings: Vec<&ReportFinding> = report
        .findings
        .iter()
        .filter(|f| {
            let confirmed = f.status == "Verified";
            let in_cross_repo_chain = f
                .chain_id
                .as_deref()
                .map(|cid| cross_repo_chains.contains(cid))
                .unwrap_or(false)
                || cross_repo_members.contains(f.id.as_str());
            confirmed || in_cross_repo_chain
        })
        .collect();
    let visible_chains: Vec<&ReportChain> = report
        .chains
        .iter()
        .filter(|c| c.cross_repo)
        .collect();
    FilteredFindings { findings, chains: visible_chains }
}

/// Render the grouped PR comment body. Groups by `(repo, path)` first
/// for visual locality, then sorts each group's rows by severity rank
/// (Critical/High/Medium/Low/Info) descending so the worst row in each
/// file lands at the top.
pub fn build_comment_body(
    filtered: &FilteredFindings<'_>,
    report: &ScanReport,
    ui_url: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str(COMMENT_MARKER);
    out.push('\n');
    out.push_str("## nyx-agent: confirmed findings on this PR\n\n");

    let confirmed_count = filtered
        .findings
        .iter()
        .filter(|f| f.status == "Verified")
        .count();
    let chain_count = filtered.chains.len();
    let total_count = filtered.findings.len();
    out.push_str(&format!(
        "**{total_count}** finding{} ({confirmed_count} Confirmed, {chain_count} cross-repo chain{}).\n\n",
        if total_count == 1 { "" } else { "s" },
        if chain_count == 1 { "" } else { "s" },
    ));
    if let Some(since) = &report.since_ref {
        out.push_str(&format!("Diff base: `{}`.\n\n", since));
    }
    out.push_str(&format!(
        "Run ID `{}`. Full details (trace viewer, verifier output, repro bundles) stay in the operator's local UI{}.\n\n",
        report.run_id,
        match ui_url {
            Some(url) => format!(" - [open run]({}/runs/{})", trim_url(url), report.run_id),
            None => String::new(),
        }
    ));

    out.push_str("### By file\n\n");
    let groups = group_by_file(&filtered.findings);
    for ((repo, path), rows) in groups {
        out.push_str(&format!("- **`{repo}` / `{path}`**\n"));
        for row in rows {
            let line = row.line.map(|l| format!(":{l}")).unwrap_or_default();
            let severity_badge = severity_badge(&row.severity);
            let origin_badge = origin_badge(&row.finding_origin);
            let id = short_id(&row.id);
            let chain = match &row.chain_id {
                Some(cid) => format!(" (chain `{}`)", short_id(cid)),
                None => String::new(),
            };
            out.push_str(&format!(
                "  - {severity_badge} {origin_badge} `{rule}`{line}{chain} - id `{id}`\n",
                rule = row.rule
            ));
        }
    }

    if !filtered.chains.is_empty() {
        out.push_str("\n### Cross-repo chains\n\n");
        for chain in &filtered.chains {
            let members = chain
                .member_ids
                .iter()
                .map(|m| format!("`{}`", short_id(m)))
                .collect::<Vec<_>>()
                .join(" - ");
            out.push_str(&format!(
                "- `{}` ({} members): {}\n",
                short_id(&chain.id),
                chain.member_ids.len(),
                members
            ));
        }
    }

    out.push_str(
        "\n<sub>Only Confirmed findings + cross-repo chains are posted here. Everything else (Open, Quarantine, Inconclusive) stays in the operator's UI.</sub>\n",
    );
    out
}

fn group_by_file<'a>(
    findings: &'a [&ReportFinding],
) -> BTreeMap<(String, String), Vec<&'a ReportFinding>> {
    let mut map: BTreeMap<(String, String), Vec<&ReportFinding>> = BTreeMap::new();
    for f in findings {
        map.entry((f.repo.clone(), f.path.clone()))
            .or_default()
            .push(*f);
    }
    for rows in map.values_mut() {
        rows.sort_by(|a, b| {
            severity_rank(&b.severity)
                .cmp(&severity_rank(&a.severity))
                .then_with(|| a.id.cmp(&b.id))
        });
    }
    map
}

fn severity_rank(sev: &str) -> u8 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" | "med" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_badge(sev: &str) -> String {
    let rank = severity_rank(sev);
    let label = match rank {
        4 => "CRIT",
        3 => "HIGH",
        2 => "MED",
        1 => "LOW",
        _ => "INFO",
    };
    format!("**{label}**")
}

fn origin_badge(origin: &str) -> &'static str {
    match origin {
        "Static" => "[static]",
        "AI" => "[ai]",
        "AiExploration" => "[ai-exploration]",
        "Manual" => "[manual]",
        _ => "[?]",
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

fn trim_url(url: &str) -> &str {
    url.trim_end_matches('/')
}

fn split_repo(repo: &str) -> Result<(&str, &str), PrCommentError> {
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| PrCommentError::BadRepo(repo.to_string()))?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return Err(PrCommentError::BadRepo(repo.to_string()));
    }
    let safe = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    if !safe(owner) || !safe(name) {
        return Err(PrCommentError::BadRepo(repo.to_string()));
    }
    Ok((owner, name))
}

fn build_client(token: &str) -> Result<reqwest::Client, PrCommentError> {
    use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT as UA};
    if token.is_empty() {
        return Err(PrCommentError::MissingToken);
    }
    let mut headers = HeaderMap::new();
    let mut auth_val = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|e| PrCommentError::GitHub(format!("invalid token: {e}")))?;
    auth_val.set_sensitive(true);
    headers.insert(AUTHORIZATION, auth_val);
    headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
    headers.insert("X-GitHub-Api-Version", HeaderValue::from_static("2022-11-28"));
    headers.insert(UA, HeaderValue::from_static(USER_AGENT));
    Ok(reqwest::Client::builder().default_headers(headers).build()?)
}

#[derive(Debug, Deserialize)]
struct CommentEnvelope {
    id: u64,
    body: Option<String>,
}

#[derive(Debug, Serialize)]
struct CommentBody<'a> {
    body: &'a str,
}

async fn find_existing_comment(
    client: &reqwest::Client,
    api_base: &str,
    owner: &str,
    repo: &str,
    pr: u32,
) -> Result<Option<u64>, PrCommentError> {
    let mut page: u32 = 1;
    loop {
        let url = format!(
            "{}/repos/{}/{}/issues/{}/comments?per_page=100&page={}",
            trim_url(api_base),
            owner,
            repo,
            pr,
            page
        );
        let res = client.get(&url).send().await?;
        if !res.status().is_success() {
            return Err(PrCommentError::GitHub(format!(
                "list comments returned {}",
                res.status()
            )));
        }
        let comments: Vec<CommentEnvelope> = res.json().await?;
        if comments.is_empty() {
            return Ok(None);
        }
        for c in &comments {
            if c.body.as_deref().map(|b| b.contains(COMMENT_MARKER)).unwrap_or(false) {
                return Ok(Some(c.id));
            }
        }
        if comments.len() < 100 {
            return Ok(None);
        }
        page += 1;
        if page > 100 {
            return Ok(None);
        }
    }
}

async fn create_comment(
    client: &reqwest::Client,
    api_base: &str,
    owner: &str,
    repo: &str,
    pr: u32,
    body: &str,
) -> Result<(), PrCommentError> {
    let url = format!(
        "{}/repos/{}/{}/issues/{}/comments",
        trim_url(api_base),
        owner,
        repo,
        pr
    );
    let res = client.post(&url).json(&CommentBody { body }).send().await?;
    if !res.status().is_success() {
        return Err(PrCommentError::GitHub(format!(
            "create comment returned {}",
            res.status()
        )));
    }
    Ok(())
}

async fn update_comment(
    client: &reqwest::Client,
    api_base: &str,
    owner: &str,
    repo: &str,
    comment_id: u64,
    body: &str,
) -> Result<(), PrCommentError> {
    let url = format!(
        "{}/repos/{}/{}/issues/comments/{}",
        trim_url(api_base),
        owner,
        repo,
        comment_id
    );
    let res = client.patch(&url).json(&CommentBody { body }).send().await?;
    if !res.status().is_success() {
        return Err(PrCommentError::GitHub(format!(
            "update comment returned {}",
            res.status()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::scan_report::{ReportChain, ReportFinding, ScanReport, REPORT_SCHEMA_VERSION};

    fn finding(
        id: &str,
        repo: &str,
        path: &str,
        sev: &str,
        status: &str,
        chain: Option<&str>,
    ) -> ReportFinding {
        ReportFinding {
            id: id.into(),
            repo: repo.into(),
            path: path.into(),
            line: Some(10),
            cap: "sqli".into(),
            rule: "py.sqli".into(),
            severity: sev.into(),
            status: status.into(),
            finding_origin: "Static".into(),
            chain_id: chain.map(|s| s.into()),
        }
    }

    fn empty_report() -> ScanReport {
        ScanReport {
            schema_version: REPORT_SCHEMA_VERSION,
            run_id: "r1".into(),
            started_at: 0,
            finished_at: None,
            status: "Succeeded".into(),
            triggered_by: "ci".into(),
            repos: Vec::new(),
            since_ref: Some("origin/main".into()),
            findings: Vec::new(),
            chains: Vec::new(),
        }
    }

    #[test]
    fn filter_keeps_confirmed_and_cross_repo_chain_members_only() {
        let mut report = empty_report();
        report.findings = vec![
            finding("a", "alpha", "src/a.py", "High", "Verified", None),
            finding("b", "alpha", "src/b.py", "Low", "Open", None),
            finding("c", "alpha", "src/c.py", "High", "Open", Some("chain-cross")),
            finding("d", "alpha", "src/d.py", "Medium", "Open", Some("chain-local")),
            finding("e", "beta", "src/e.py", "High", "Quarantine", None),
        ];
        report.chains = vec![
            ReportChain {
                id: "chain-cross".into(),
                cross_repo: true,
                member_ids: vec!["c".into(), "z".into()],
                rationale: None,
            },
            ReportChain {
                id: "chain-local".into(),
                cross_repo: false,
                member_ids: vec!["d".into()],
                rationale: None,
            },
        ];
        let filtered = filter_for_pr(&report);
        let ids: Vec<&str> = filtered.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"a"), "Confirmed should land: {ids:?}");
        assert!(ids.contains(&"c"), "cross-repo member should land: {ids:?}");
        assert!(!ids.contains(&"b"), "Open w/o chain should drop: {ids:?}");
        assert!(!ids.contains(&"d"), "intra-repo chain should drop: {ids:?}");
        assert!(!ids.contains(&"e"), "Quarantine should drop: {ids:?}");
        assert_eq!(filtered.chains.len(), 1);
        assert_eq!(filtered.chains[0].id, "chain-cross");
    }

    #[test]
    fn comment_body_carries_marker_and_groups() {
        let mut report = empty_report();
        report.findings = vec![
            finding("aaaaaaaaaaaa1", "alpha", "src/a.py", "High", "Verified", None),
            finding("aaaaaaaaaaaa2", "alpha", "src/a.py", "Critical", "Verified", None),
            finding("bbbbbbbbbbbb1", "alpha", "src/b.py", "Medium", "Verified", None),
        ];
        let filtered = filter_for_pr(&report);
        let body = build_comment_body(&filtered, &report, Some("https://ops.example.com/"));
        assert!(body.starts_with(COMMENT_MARKER), "marker missing: {body}");
        assert!(body.contains("**3** finding"));
        // src/a.py before src/b.py and Critical row sorts above High
        let a_idx = body.find("`alpha` / `src/a.py`").expect("a.py group");
        let b_idx = body.find("`alpha` / `src/b.py`").expect("b.py group");
        assert!(a_idx < b_idx);
        let crit_idx = body.find("**CRIT**").expect("crit badge");
        let high_idx = body.find("**HIGH**").expect("high badge");
        assert!(crit_idx < high_idx, "crit should sort above high in same file");
        assert!(body.contains("https://ops.example.com/runs/r1"));
        assert!(body.contains("Diff base: `origin/main`"));
    }

    #[test]
    fn comment_body_omits_run_link_when_ui_url_missing() {
        let mut report = empty_report();
        report.findings = vec![finding("a", "alpha", "src/a.py", "High", "Verified", None)];
        let filtered = filter_for_pr(&report);
        let body = build_comment_body(&filtered, &report, None);
        assert!(!body.contains("open run"));
    }

    #[test]
    fn split_repo_rejects_bad_input() {
        assert!(split_repo("noslash").is_err());
        assert!(split_repo("a/b/c").is_err());
        assert!(split_repo("/b").is_err());
        assert!(split_repo("a/").is_err());
        assert_eq!(split_repo("octocat/hello").unwrap(), ("octocat", "hello"));
    }

    #[test]
    fn severity_badge_maps_known_levels() {
        assert!(severity_badge("Critical").contains("CRIT"));
        assert!(severity_badge("HIGH").contains("HIGH"));
        assert!(severity_badge("medium").contains("MED"));
        assert!(severity_badge("Low").contains("LOW"));
        assert!(severity_badge("Info").contains("INFO"));
        assert!(severity_badge("unknown").contains("INFO"));
    }
}
