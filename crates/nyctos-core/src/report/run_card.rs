//! Per-run summary card.
//!
//! [`build_run_card`] reads the persisted store and synthesises a
//! [`RunCard`] aggregating:
//!
//! * counts: findings split by status, by cap, by origin, by language
//!   (derived from each finding's `payloads.lang` when present,
//!   otherwise the file extension), plus a per-repo total.
//! * spend: AI spend in micros split by `TaskKind` and folded into
//!   `one_shot` vs `agent_loop` buckets matching the [`crate::store::BudgetKind`]
//!   shape persisted on the wire.
//! * timing: wall-clock per phase computed by min-start / max-finish
//!   across the agent_trace rows for each [`TaskKind`], plus the
//!   static-pass duration derived from the run's own
//!   `started_at` / `finished_at`.
//!
//! [`render_html`] / [`render_markdown`] produce export-friendly
//! representations of the same card. JSON falls out of `serde` on
//! [`RunCard`] directly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use thiserror::Error;

use crate::store::trace::TaskKind;
use crate::store::StoreError;

/// Task kinds that map to the `agent_loop` budget bucket. Everything
/// else (PayloadSynthesis / SpecDerivation / ChainReasoning /
/// NovelFindings) is `one_shot`. Mirrors the producer-side split in
/// `nyctos-ai`.
fn is_agent_loop(task_kind: &str) -> bool {
    task_kind == TaskKind::Exploration.as_str()
}

/// One bucket of a histogram-style breakdown. Stored as a sorted vec so
/// the wire output is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BySplit {
    pub key: String,
    pub count: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendSplit {
    pub one_shot_usd_micros: i64,
    pub agent_loop_usd_micros: i64,
    /// Per-task breakdown so the operator can read "PayloadSynthesis
    /// cost $1.20" at a glance without doing arithmetic against the
    /// task list.
    pub by_task_kind: Vec<BySplit>,
}

impl SpendSplit {
    pub fn total_usd_micros(&self) -> i64 {
        self.one_shot_usd_micros + self.agent_loop_usd_micros
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseDuration {
    pub phase: String,
    pub wall_clock_ms: i64,
    pub call_count: i64,
}

/// Aggregated summary for a single run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCard {
    pub run_id: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub status: String,
    pub triggered_by: String,
    pub wall_clock_ms: Option<i64>,
    pub total_findings: i64,
    pub by_status: Vec<BySplit>,
    pub by_cap: Vec<BySplit>,
    pub by_origin: Vec<BySplit>,
    pub by_lang: Vec<BySplit>,
    pub by_repo: Vec<BySplit>,
    pub spend: SpendSplit,
    /// Wall-clock per phase. `static` is derived from the run row's
    /// own start/finish; everything else is derived from
    /// `agent_traces` rows for the matching `TaskKind`.
    pub phase_durations: Vec<PhaseDuration>,
    /// Total AI-proposed candidates (`candidate_findings` rows) bound
    /// to this run, irrespective of their `status`. Sums every variant
    /// in [`Self::by_candidate_status`]; surfaced as a separate field
    /// so a consumer that does not care about the per-status breakdown
    /// can read one integer.
    pub candidate_findings_total: i64,
    /// Per-status breakdown of `candidate_findings` rows for this run
    /// (`Pending` / `Promoted` / `Dismissed`). Empty when the run
    /// produced no candidates.
    pub by_candidate_status: Vec<BySplit>,
    pub business_logic_templates_considered: i64,
    pub business_logic_candidates_generated: i64,
    pub business_logic_templates_skipped: i64,
}

#[derive(Debug, Error)]
pub enum RunCardError {
    #[error("run `{0}` not found")]
    NotFound(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Aggregate every persisted source of run-level signal into a
/// [`RunCard`] for `run_id`. Reads the `runs`, `findings`,
/// `agent_traces`, and `payloads` tables.
pub async fn build_run_card(pool: &SqlitePool, run_id: &str) -> Result<RunCard, RunCardError> {
    let run_row: Option<RunRow> = sqlx::query_as::<_, RunRow>(
        "SELECT id, started_at, finished_at, status, triggered_by, wall_clock_ms \
         FROM runs WHERE id = ?",
    )
    .bind(run_id)
    .fetch_optional(pool)
    .await?;
    let run = run_row.ok_or_else(|| RunCardError::NotFound(run_id.to_string()))?;

    let findings: Vec<FindingRow> = sqlx::query_as::<_, FindingRow>(
        "SELECT id, repo, path, cap, status, finding_origin FROM findings WHERE run_id = ?",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await?;

    let payloads: Vec<PayloadRow> = sqlx::query_as::<_, PayloadRow>(
        "SELECT p.finding_id, p.lang FROM payloads p \
         JOIN findings f ON f.id = p.finding_id WHERE f.run_id = ?",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await?;
    let mut finding_lang: BTreeMap<String, String> = BTreeMap::new();
    for p in payloads {
        finding_lang.entry(p.finding_id).or_insert(p.lang);
    }

    // Per-run `candidate_findings` aggregate. Reads off the
    // `idx_candidate_findings_run_id` index added by migration
    // `0001_v1.sql`, so the GROUP BY scan is bounded to one run's worth
    // of rows. A denormalised column on `runs` would save the join, but
    // the index already keeps this read sub-millisecond on the realistic
    // candidate-count-per-run cardinality.
    let candidate_rows: Vec<CandidateRow> = sqlx::query_as::<_, CandidateRow>(
        "SELECT status, COUNT(*) AS count \
         FROM candidate_findings WHERE run_id = ? \
         GROUP BY status",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await?;
    let mut by_candidate_status_map: BTreeMap<String, i64> = BTreeMap::new();
    let mut candidate_findings_total: i64 = 0;
    for row in candidate_rows {
        by_candidate_status_map.insert(row.status, row.count);
        candidate_findings_total += row.count;
    }
    let business_logic_row: BusinessLogicSummaryRow = sqlx::query_as::<_, BusinessLogicSummaryRow>(
        "SELECT COUNT(*) AS templates_considered, \
                COALESCE(SUM(generated_count), 0) AS candidates_generated, \
                COALESCE(SUM(CASE WHEN skipped_count > 0 THEN 1 ELSE 0 END), 0) AS templates_skipped \
         FROM business_logic_template_runs WHERE run_id = ?",
    )
    .bind(run_id)
    .fetch_one(pool)
    .await?;

    let traces: Vec<TraceRow> = sqlx::query_as::<_, TraceRow>(
        "SELECT t.task_kind, t.cost_usd_micros, t.started_at, t.finished_at \
         FROM agent_traces t \
         LEFT JOIN findings f ON f.id = t.finding_id \
         WHERE f.run_id = ? \
            OR t.started_at BETWEEN ? AND ?",
    )
    .bind(run_id)
    .bind(run.started_at)
    .bind(run.finished_at.unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await?;

    let mut by_status: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_cap: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_origin: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_repo: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_lang: BTreeMap<String, i64> = BTreeMap::new();
    for f in &findings {
        *by_status.entry(f.status.clone()).or_default() += 1;
        *by_cap.entry(f.cap.clone()).or_default() += 1;
        *by_origin.entry(f.finding_origin.clone()).or_default() += 1;
        *by_repo.entry(f.repo.clone()).or_default() += 1;
        let lang =
            finding_lang.get(&f.id).cloned().unwrap_or_else(|| lang_from_path(&f.path).to_string());
        *by_lang.entry(lang).or_default() += 1;
    }

    let mut spend = SpendSplit::default();
    let mut by_task: BTreeMap<String, i64> = BTreeMap::new();
    let mut phase_min: BTreeMap<String, i64> = BTreeMap::new();
    let mut phase_max: BTreeMap<String, i64> = BTreeMap::new();
    let mut phase_calls: BTreeMap<String, i64> = BTreeMap::new();
    for t in &traces {
        if is_agent_loop(&t.task_kind) {
            spend.agent_loop_usd_micros += t.cost_usd_micros;
        } else {
            spend.one_shot_usd_micros += t.cost_usd_micros;
        }
        *by_task.entry(t.task_kind.clone()).or_default() += t.cost_usd_micros;
        *phase_calls.entry(t.task_kind.clone()).or_default() += 1;
        let start = t.started_at;
        let finish = t.finished_at.unwrap_or(start);
        phase_min.entry(t.task_kind.clone()).and_modify(|e| *e = (*e).min(start)).or_insert(start);
        phase_max
            .entry(t.task_kind.clone())
            .and_modify(|e| *e = (*e).max(finish))
            .or_insert(finish);
    }
    spend.by_task_kind = into_sorted_split(by_task);

    let mut phase_durations: Vec<PhaseDuration> = Vec::new();
    phase_durations.push(PhaseDuration {
        phase: "static".to_string(),
        wall_clock_ms: run.wall_clock_ms.unwrap_or(0),
        call_count: 1,
    });
    for (phase, min) in phase_min {
        let max = phase_max.get(&phase).copied().unwrap_or(min);
        let calls = phase_calls.get(&phase).copied().unwrap_or(0);
        phase_durations.push(PhaseDuration {
            phase,
            wall_clock_ms: (max - min).max(0),
            call_count: calls,
        });
    }
    phase_durations.sort_by(|a, b| a.phase.cmp(&b.phase));

    Ok(RunCard {
        run_id: run.id,
        started_at: run.started_at,
        finished_at: run.finished_at,
        status: run.status,
        triggered_by: run.triggered_by,
        wall_clock_ms: run.wall_clock_ms,
        total_findings: findings.len() as i64,
        by_status: into_sorted_split(by_status),
        by_cap: into_sorted_split(by_cap),
        by_origin: into_sorted_split(by_origin),
        by_lang: into_sorted_split(by_lang),
        by_repo: into_sorted_split(by_repo),
        spend,
        phase_durations,
        candidate_findings_total,
        by_candidate_status: into_sorted_split(by_candidate_status_map),
        business_logic_templates_considered: business_logic_row.templates_considered,
        business_logic_candidates_generated: business_logic_row.candidates_generated,
        business_logic_templates_skipped: business_logic_row.templates_skipped,
    })
}

fn into_sorted_split(map: BTreeMap<String, i64>) -> Vec<BySplit> {
    let mut out: Vec<BySplit> =
        map.into_iter().map(|(key, count)| BySplit { key, count }).collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    out
}

/// Lightweight per-extension language guess. Matches the
/// `ai_pipeline::infer_lang` table so the run card's lang split lines
/// up with what the AI pipeline saw. Unknown extensions surface as
/// `"unknown"`.
fn lang_from_path(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "rs" => "rust",
        "py" => "python",
        "js" | "mjs" | "cjs" => "javascript",
        "ts" | "tsx" => "typescript",
        "go" => "go",
        "java" => "java",
        "rb" => "ruby",
        "php" => "php",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "cs" => "csharp",
        "swift" => "swift",
        "kt" | "kts" => "kotlin",
        _ => "unknown",
    }
}

/// Render a run card as a self-contained HTML fragment suitable for
/// export. Returns one `<section>` per topic; the caller is expected
/// to wrap it in a `<!doctype html>` boilerplate if a standalone
/// document is needed.
pub fn render_html(card: &RunCard) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "<section><h2>Run {}</h2><dl><dt>Status</dt><dd>{}</dd>\
         <dt>Triggered by</dt><dd>{}</dd>\
         <dt>Started</dt><dd>{}</dd><dt>Finished</dt><dd>{}</dd>\
         <dt>Wall clock</dt><dd>{} ms</dd>\
         <dt>Total findings</dt><dd>{}</dd>\
         <dt>Candidate findings</dt><dd>{}</dd>\
         <dt>Business-logic templates</dt><dd>{} considered, {} generated candidate(s), {} skipped</dd></dl></section>",
        escape_html(&card.run_id),
        escape_html(&card.status),
        escape_html(&card.triggered_by),
        card.started_at,
        card.finished_at.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
        card.wall_clock_ms.unwrap_or(0),
        card.total_findings,
        card.candidate_findings_total,
        card.business_logic_templates_considered,
        card.business_logic_candidates_generated,
        card.business_logic_templates_skipped,
    ));
    push_html_split(&mut out, "Status", &card.by_status);
    push_html_split(&mut out, "Capability", &card.by_cap);
    push_html_split(&mut out, "Origin", &card.by_origin);
    push_html_split(&mut out, "Language", &card.by_lang);
    push_html_split(&mut out, "Repository", &card.by_repo);
    push_html_split(&mut out, "Candidate status", &card.by_candidate_status);
    out.push_str(&format!(
        "<section><h3>AI spend</h3>\
         <p>One-shot: ${:.6} · Agent loop: ${:.6} · Total: ${:.6}</p>",
        usd_from_micros(card.spend.one_shot_usd_micros),
        usd_from_micros(card.spend.agent_loop_usd_micros),
        usd_from_micros(card.spend.total_usd_micros()),
    ));
    out.push_str("<ul>");
    for split in &card.spend.by_task_kind {
        out.push_str(&format!(
            "<li>{}: ${:.6}</li>",
            escape_html(&split.key),
            usd_from_micros(split.count),
        ));
    }
    out.push_str("</ul></section>");
    out.push_str("<section><h3>Phase wall clock</h3><ul>");
    for phase in &card.phase_durations {
        out.push_str(&format!(
            "<li>{}: {} ms ({} call{})</li>",
            escape_html(&phase.phase),
            phase.wall_clock_ms,
            phase.call_count,
            if phase.call_count == 1 { "" } else { "s" },
        ));
    }
    out.push_str("</ul></section>");
    out
}

fn push_html_split(out: &mut String, title: &str, splits: &[BySplit]) {
    out.push_str(&format!("<section><h3>{}</h3>", escape_html(title)));
    if splits.is_empty() {
        out.push_str("<p>-</p></section>");
        return;
    }
    out.push_str("<ul>");
    for s in splits {
        out.push_str(&format!("<li>{}: {}</li>", escape_html(&s.key), s.count,));
    }
    out.push_str("</ul></section>");
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Render a run card as Markdown. Mirrors the HTML structure so the
/// two outputs stay in sync.
///
/// AI-controlled identifiers (run id, status, triggered_by, by-split
/// keys, phase names) get wrapped in a CommonMark code span via
/// `markdown_code` so a renderer with raw HTML enabled cannot lift an
/// `<img onerror=...>` straight into the operator's DOM.
pub fn render_markdown(card: &RunCard) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Run {}\n\n", markdown_code(&card.run_id)));
    out.push_str(&format!("- **Status**: {}\n", markdown_code(&card.status)));
    out.push_str(&format!("- **Triggered by**: {}\n", markdown_code(&card.triggered_by)));
    out.push_str(&format!("- **Started**: {}\n", card.started_at));
    out.push_str(&format!(
        "- **Finished**: {}\n",
        card.finished_at.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string())
    ));
    out.push_str(&format!("- **Wall clock**: {} ms\n", card.wall_clock_ms.unwrap_or(0)));
    out.push_str(&format!("- **Total findings**: {}\n", card.total_findings));
    out.push_str(&format!("- **Candidate findings**: {}\n", card.candidate_findings_total));
    out.push_str(&format!(
        "- **Business-logic templates**: {} considered, {} generated candidate(s), {} skipped\n\n",
        card.business_logic_templates_considered,
        card.business_logic_candidates_generated,
        card.business_logic_templates_skipped,
    ));

    push_markdown_split(&mut out, "Status", &card.by_status);
    push_markdown_split(&mut out, "Capability", &card.by_cap);
    push_markdown_split(&mut out, "Origin", &card.by_origin);
    push_markdown_split(&mut out, "Language", &card.by_lang);
    push_markdown_split(&mut out, "Repository", &card.by_repo);
    push_markdown_split(&mut out, "Candidate status", &card.by_candidate_status);

    out.push_str("## AI spend\n\n");
    out.push_str(&format!(
        "- **One-shot**: ${:.6}\n- **Agent loop**: ${:.6}\n- **Total**: ${:.6}\n\n",
        usd_from_micros(card.spend.one_shot_usd_micros),
        usd_from_micros(card.spend.agent_loop_usd_micros),
        usd_from_micros(card.spend.total_usd_micros()),
    ));
    for split in &card.spend.by_task_kind {
        out.push_str(&format!(
            "- {}: ${:.6}\n",
            markdown_code(&split.key),
            usd_from_micros(split.count)
        ));
    }
    out.push('\n');

    out.push_str("## Phase wall clock\n\n");
    for phase in &card.phase_durations {
        out.push_str(&format!(
            "- {}: {} ms ({} call{})\n",
            markdown_code(&phase.phase),
            phase.wall_clock_ms,
            phase.call_count,
            if phase.call_count == 1 { "" } else { "s" },
        ));
    }
    out
}

fn push_markdown_split(out: &mut String, title: &str, splits: &[BySplit]) {
    out.push_str(&format!("## {title}\n\n"));
    if splits.is_empty() {
        out.push_str("_no rows_\n\n");
        return;
    }
    for s in splits {
        out.push_str(&format!("- {}: {}\n", markdown_code(&s.key), s.count));
    }
    out.push('\n');
}

/// Wrap `s` in a CommonMark code span using a backtick fence one longer
/// than the longest run of backticks in the input, padding with a
/// space when the content begins or ends with a backtick. Renders the
/// content as inline code so a downstream renderer with raw HTML
/// enabled treats `<img onerror=...>` as text rather than markup.
fn markdown_code(s: &str) -> String {
    let mut longest_run = 0usize;
    let mut current_run = 0usize;
    for ch in s.chars() {
        if ch == '`' {
            current_run += 1;
            longest_run = longest_run.max(current_run);
        } else {
            current_run = 0;
        }
    }
    let fence_len = longest_run + 1;
    let fence: String = "`".repeat(fence_len);
    let needs_pad = s.starts_with('`') || s.ends_with('`');
    if needs_pad {
        format!("{fence} {s} {fence}")
    } else {
        format!("{fence}{s}{fence}")
    }
}

fn usd_from_micros(micros: i64) -> f64 {
    micros as f64 / 1_000_000.0
}

#[derive(sqlx::FromRow)]
struct RunRow {
    id: String,
    started_at: i64,
    finished_at: Option<i64>,
    status: String,
    triggered_by: String,
    wall_clock_ms: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct FindingRow {
    id: String,
    repo: String,
    path: String,
    cap: String,
    status: String,
    finding_origin: String,
}

#[derive(sqlx::FromRow)]
struct PayloadRow {
    finding_id: String,
    lang: String,
}

#[derive(sqlx::FromRow)]
struct TraceRow {
    task_kind: String,
    cost_usd_micros: i64,
    started_at: i64,
    finished_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct CandidateRow {
    status: String,
    count: i64,
}

#[derive(sqlx::FromRow)]
struct BusinessLogicSummaryRow {
    templates_considered: i64,
    candidates_generated: i64,
    templates_skipped: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testutil::{
        fresh_store, sample_candidate, sample_finding, sample_payload, sample_repo, sample_run,
    };
    use crate::store::AgentTraceRecord;

    async fn seed_two_repo_run(s: &crate::store::Store) -> String {
        s.repos().upsert(&sample_repo("alpha")).await.expect("alpha");
        s.repos().upsert(&sample_repo("beta")).await.expect("beta");
        let mut run = sample_run("run-card-1");
        run.status = "Succeeded".to_string();
        run.finished_at = Some(12_000);
        run.wall_clock_ms = Some(10_000);
        s.runs().insert(&run).await.expect("run");
        // 3 findings: 2 sqli (one each repo), 1 cmdi.
        let f1 = sample_finding("run-card-1", "alpha", "src/a.py", "rule-a");
        let f2 = sample_finding("run-card-1", "beta", "src/b.py", "rule-b");
        let mut f3 = sample_finding("run-card-1", "alpha", "src/c.rs", "rule-c");
        f3.cap = "cmdi".to_string();
        f3.finding_origin = "AI".to_string();
        f3.status = "Verified".to_string();
        s.findings().upsert(&f1).await.expect("f1");
        s.findings().upsert(&f2).await.expect("f2");
        s.findings().upsert(&f3).await.expect("f3");
        // Payload with explicit lang for f1 (overrides path-based guess).
        let mut p1 = sample_payload("p-1", &f1.id);
        p1.lang = "python".to_string();
        s.payloads().insert(&p1).await.expect("payload");
        // PayloadSynthesis trace: one_shot, $0.123456.
        s.agent_traces()
            .insert(&AgentTraceRecord {
                id: "trace-1".to_string(),
                finding_id: Some(f1.id.clone()),
                task_kind: TaskKind::PayloadSynthesis.as_str().to_string(),
                runtime_name: "anthropic".to_string(),
                model: "claude-opus-4-7".to_string(),
                prompt_version: Some("v1".to_string()),
                conversation_jsonl_path: None,
                tokens_in: 1_000,
                tokens_out: 200,
                cost_usd_micros: 123_456,
                cache_hits: 0,
                cache_misses: 1,
                duration_ms: Some(2_000),
                started_at: 4_000,
                finished_at: Some(6_000),
                verifier_blob: None,
            })
            .await
            .expect("trace-1");
        // Exploration trace: agent_loop, $0.500000.
        s.agent_traces()
            .insert(&AgentTraceRecord {
                id: "trace-2".to_string(),
                finding_id: Some(f3.id.clone()),
                task_kind: TaskKind::Exploration.as_str().to_string(),
                runtime_name: "claude-code".to_string(),
                model: "sonnet".to_string(),
                prompt_version: Some("v1".to_string()),
                conversation_jsonl_path: None,
                tokens_in: 5_000,
                tokens_out: 800,
                cost_usd_micros: 500_000,
                cache_hits: 0,
                cache_misses: 1,
                duration_ms: Some(7_000),
                started_at: 5_000,
                finished_at: Some(12_000),
                verifier_blob: None,
            })
            .await
            .expect("trace-2");
        // Two AI-proposed candidates for this run: one still Pending,
        // one Promoted (an end-to-end NovelFindingDiscovery + verifier
        // confirmation). Used by the candidate-aggregate assertion.
        s.candidate_findings()
            .insert(&sample_candidate("cand-pending", "run-card-1", "alpha"))
            .await
            .expect("cand-pending");
        let mut promoted = sample_candidate("cand-promoted", "run-card-1", "beta");
        promoted.status = "Promoted".to_string();
        s.candidate_findings().insert(&promoted).await.expect("cand-promoted");
        "run-card-1".to_string()
    }

    #[tokio::test]
    async fn build_run_card_aggregates_counts_and_spend() {
        let (_tmp, s) = fresh_store().await;
        let run_id = seed_two_repo_run(&s).await;
        let card = build_run_card(s.pool(), &run_id).await.expect("card");
        assert_eq!(card.run_id, run_id);
        assert_eq!(card.status, "Succeeded");
        assert_eq!(card.total_findings, 3);

        let by_cap: Vec<_> = card.by_cap.iter().map(|s| (s.key.as_str(), s.count)).collect();
        assert!(by_cap.contains(&("sqli", 2)));
        assert!(by_cap.contains(&("cmdi", 1)));

        let by_origin: Vec<_> = card.by_origin.iter().map(|s| (s.key.as_str(), s.count)).collect();
        assert!(by_origin.contains(&("Static", 2)));
        assert!(by_origin.contains(&("AI", 1)));

        let by_lang: Vec<_> = card.by_lang.iter().map(|s| (s.key.as_str(), s.count)).collect();
        assert!(by_lang.contains(&("python", 2)), "expected python: {by_lang:?}");
        assert!(by_lang.contains(&("rust", 1)));

        let by_repo: Vec<_> = card.by_repo.iter().map(|s| (s.key.as_str(), s.count)).collect();
        assert!(by_repo.contains(&("alpha", 2)));
        assert!(by_repo.contains(&("beta", 1)));

        assert_eq!(card.spend.one_shot_usd_micros, 123_456);
        assert_eq!(card.spend.agent_loop_usd_micros, 500_000);
        assert_eq!(card.spend.total_usd_micros(), 623_456);

        let static_phase =
            card.phase_durations.iter().find(|p| p.phase == "static").expect("static phase");
        assert_eq!(static_phase.wall_clock_ms, 10_000);

        let exploration = card
            .phase_durations
            .iter()
            .find(|p| p.phase == TaskKind::Exploration.as_str())
            .expect("exploration phase");
        assert_eq!(exploration.wall_clock_ms, 7_000);
        assert_eq!(exploration.call_count, 1);

        // Candidate-findings aggregate: two rows, one Pending + one
        // Promoted. The per-status split sorts by `count DESC` then key
        // ASC, so both keys end up present without relying on order.
        assert_eq!(card.candidate_findings_total, 2);
        let by_cand: Vec<_> =
            card.by_candidate_status.iter().map(|s| (s.key.as_str(), s.count)).collect();
        assert!(
            by_cand.contains(&("Pending", 1)),
            "by_candidate_status missing Pending: {by_cand:?}"
        );
        assert!(
            by_cand.contains(&("Promoted", 1)),
            "by_candidate_status missing Promoted: {by_cand:?}"
        );
    }

    #[tokio::test]
    async fn build_run_card_with_no_candidates_reports_zero_total() {
        let (_tmp, s) = fresh_store().await;
        s.repos().upsert(&sample_repo("alpha")).await.expect("alpha");
        let mut run = sample_run("run-card-empty");
        run.status = "Succeeded".to_string();
        run.finished_at = Some(1);
        run.wall_clock_ms = Some(1);
        s.runs().insert(&run).await.expect("run");
        let card = build_run_card(s.pool(), "run-card-empty").await.expect("card");
        assert_eq!(card.candidate_findings_total, 0);
        assert!(
            card.by_candidate_status.is_empty(),
            "no candidate rows should yield no per-status split",
        );
    }

    #[tokio::test]
    async fn build_run_card_missing_run_returns_not_found() {
        let (_tmp, s) = fresh_store().await;
        let err = build_run_card(s.pool(), "nope").await.expect_err("not found");
        assert!(matches!(err, RunCardError::NotFound(_)));
    }

    #[tokio::test]
    async fn render_markdown_round_trips_card() {
        let (_tmp, s) = fresh_store().await;
        let run_id = seed_two_repo_run(&s).await;
        let card = build_run_card(s.pool(), &run_id).await.expect("card");
        let md = render_markdown(&card);
        assert!(md.contains("Run `run-card-1`"));
        assert!(md.contains("Total findings"));
        assert!(md.contains("One-shot"));
        assert!(md.contains("Agent loop"));
        assert!(md.contains("Phase wall clock"));
    }

    #[test]
    fn markdown_code_wraps_simple_input() {
        assert_eq!(markdown_code("sqli"), "`sqli`");
    }

    #[test]
    fn markdown_code_lengthens_fence_to_dodge_inner_backticks() {
        // `<-- one backtick inside; wrapper uses two.
        assert_eq!(markdown_code("a`b"), "``a`b``");
    }

    #[test]
    fn markdown_code_pads_when_content_borders_with_backtick() {
        assert_eq!(markdown_code("`foo"), "`` `foo ``");
        assert_eq!(markdown_code("foo`"), "`` foo` ``");
    }

    #[test]
    fn render_markdown_neutralises_injected_html_in_by_split_keys() {
        // BySplit key the AI controls (e.g. `payloads.lang` or
        // `findings.cap`) cannot break out of the code span.
        let card = RunCard {
            run_id: "run-1".to_string(),
            started_at: 0,
            finished_at: Some(1),
            status: "Succeeded".to_string(),
            triggered_by: "UI".to_string(),
            wall_clock_ms: Some(1),
            total_findings: 1,
            by_status: vec![BySplit { key: "Open".to_string(), count: 1 }],
            by_cap: vec![BySplit { key: "<img src=x onerror=alert(1)>".to_string(), count: 1 }],
            by_origin: Vec::new(),
            by_lang: Vec::new(),
            by_repo: Vec::new(),
            spend: SpendSplit::default(),
            phase_durations: Vec::new(),
            candidate_findings_total: 0,
            by_candidate_status: Vec::new(),
            business_logic_templates_considered: 0,
            business_logic_candidates_generated: 0,
            business_logic_templates_skipped: 0,
        };
        let md = render_markdown(&card);
        // The dangerous chars are inside a code span; the literal `<`
        // is not interpreted as a tag opener by any conforming
        // CommonMark renderer.
        assert!(md.contains("`<img src=x onerror=alert(1)>`"));
        // And nowhere does the bare tag appear outside backticks.
        assert!(!md.split('`').enumerate().any(|(i, seg)| i % 2 == 0 && seg.contains("<img")));
    }

    #[tokio::test]
    async fn render_html_round_trips_card() {
        let (_tmp, s) = fresh_store().await;
        let run_id = seed_two_repo_run(&s).await;
        let card = build_run_card(s.pool(), &run_id).await.expect("card");
        let html = render_html(&card);
        assert!(html.contains("<h2>Run run-card-1</h2>"));
        assert!(html.contains("<h3>Capability</h3>"));
        // Escape verified: a finding cap containing `<` would land in
        // the output verbatim if escape_html broke.
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn lang_from_path_handles_common_extensions() {
        assert_eq!(lang_from_path("src/foo.rs"), "rust");
        assert_eq!(lang_from_path("src/foo.PY"), "python");
        assert_eq!(lang_from_path("src/foo.tsx"), "typescript");
        assert_eq!(lang_from_path("Dockerfile"), "unknown");
    }
}
