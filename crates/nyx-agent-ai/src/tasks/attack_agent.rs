//! Unsafe local attack-agent task.
//!
//! This is a pre-MVP "let it try to break the dev app" agent loop. It
//! deliberately does not route live actions through Nyx Agent's guarded
//! verifier policy. The binary decides when to invoke this task; once
//! invoked, the task gives the CLI-backed agent repository context,
//! target URLs, prior candidates, and an artifact directory, then lifts
//! `record_attack_vulnerability` tool outputs into typed rows the
//! product pipeline can persist.

use nyx_agent_types::agent::{
    AgentResult, AgentTask, AgentTraceMetrics, AiError, Budget, BudgetKind, ExtractedAgentResult,
};
use nyx_agent_types::event::EventSink;
use serde::Serialize;

use crate::runtime::AiRuntime;

pub const ATTACK_AGENT_PROMPT_VERSION: &str = "phase-pre-mvp.unsafe-attack-agent.v2";
pub const DEFAULT_ATTACK_AGENT_MAX_TURNS: u32 = 80;

pub const DEFAULT_ATTACK_AGENT_TOOL_NAMES: &[&str] =
    &["Bash", "Read", "Grep", "Write", "Edit", "record_attack_vulnerability"];

#[derive(Debug, Clone)]
pub struct AttackAgentScope {
    pub run_id: String,
    pub project_id: String,
    pub task_id: String,
    pub target_urls: Vec<String>,
    pub workspaces: Vec<AttackWorkspace>,
    pub known_leads: Vec<AttackAgentKnownLead>,
    pub existing_vulnerabilities: Vec<ExistingVulnerabilitySummary>,
    pub artifact_dir: String,
    pub max_turns: u32,
    pub run_cap_usd_micros: i64,
    pub profile: AttackAgentProfile,
}

impl AttackAgentScope {
    pub fn new(run_id: impl Into<String>, project_id: impl Into<String>) -> Self {
        let run_id = run_id.into();
        Self {
            task_id: format!("attack-agent-{run_id}"),
            run_id,
            project_id: project_id.into(),
            target_urls: Vec::new(),
            workspaces: Vec::new(),
            known_leads: Vec::new(),
            existing_vulnerabilities: Vec::new(),
            artifact_dir: String::new(),
            max_turns: DEFAULT_ATTACK_AGENT_MAX_TURNS,
            run_cap_usd_micros: i64::MAX,
            profile: AttackAgentProfile::Generalist,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackAgentProfile {
    Generalist,
    BusinessLogic,
    PaymentsBilling,
    UserDataPrivacy,
    AuthSession,
    ApiInput,
    InfraDevProd,
    AbuseAutomation,
    CriticalChainHunter,
    Triage,
}

impl AttackAgentProfile {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Generalist => "generalist",
            Self::BusinessLogic => "business_logic",
            Self::PaymentsBilling => "payments_billing",
            Self::UserDataPrivacy => "user_data_privacy",
            Self::AuthSession => "auth_session",
            Self::ApiInput => "api_input",
            Self::InfraDevProd => "infra_dev_prod",
            Self::AbuseAutomation => "abuse_automation",
            Self::CriticalChainHunter => "critical_chain_hunter",
            Self::Triage => "triage",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Generalist => "Generalist live attack agent",
            Self::BusinessLogic => "Business logic specialist",
            Self::PaymentsBilling => "Payments and billing specialist",
            Self::UserDataPrivacy => "User data and privacy specialist",
            Self::AuthSession => "Authentication and session specialist",
            Self::ApiInput => "API and input-handling specialist",
            Self::InfraDevProd => "Infrastructure and dev/prod drift specialist",
            Self::AbuseAutomation => "Abuse and automation specialist",
            Self::CriticalChainHunter => "Critical cross-domain chain hunter",
            Self::Triage => "Attack finding triage agent",
        }
    }

    fn instructions(self) -> &'static str {
        match self {
            Self::Generalist => {
                "Operate broadly across the live app. Use prior candidates to pick the most promising routes, then pursue live proof."
            }
            Self::BusinessLogic => {
                "Focus on workflow and state-machine abuse: role transitions, ownership changes, invite flows, approval gates, quotas, plan enforcement, object lifecycle edges, concurrency, replay, and order-of-operation mistakes. Try to break the product's assumptions, not just its input validation."
            }
            Self::PaymentsBilling => {
                "Focus on payments, billing, subscriptions, invoices, coupons, trials, plan changes, payment status, refunds, webhooks, idempotency, and entitlement enforcement. Look for ways to obtain paid capabilities, alter billing state, or forge provider-originated events. Treat mock providers as dev-only unless production wiring shares the same trust boundary."
            }
            Self::UserDataPrivacy => {
                "Focus on user data exposure: IDORs, cross-tenant reads/writes, exports, imports, search, files, logs, analytics payloads, deleted-user data, admin views, and overbroad API responses. Prioritize live proof that one user or tenant can access another user's data."
            }
            Self::AuthSession => {
                "Focus on authentication, authorization, sessions, cookies, password reset, magic links, OAuth, MFA, CSRF, role checks, token lifetime, invite acceptance, account linking, and privilege escalation. Build multiple user roles where needed and prove boundary breaks live."
            }
            Self::ApiInput => {
                "Focus on API and parser abuse: mass assignment, validation gaps, hidden fields, schema mismatches, file uploads, SSRF-like fetches, command/path injection, unsafe deserialization, template injection, cache poisoning, and content-type confusion. Prefer targeted probes derived from source over broad scanning."
            }
            Self::InfraDevProd => {
                "Focus on deployment assumptions, secrets, environment config, debug endpoints, local services, dev mailers, seed credentials, logs, queues, storage buckets, admin tooling, CORS, and network trust. Classify dev-only behavior separately and record only production-relevant or locally dangerous impact as vulnerabilities."
            }
            Self::AbuseAutomation => {
                "Focus on abuse at scale: rate limits, brute force, enumeration, scraping, invite or email spam, SMS/email cost abuse, queue flooding, resource exhaustion, free-tier bypass, replay, and automation-resistant workflows. Use small safe volumes and reason from source for scale impact."
            }
            Self::CriticalChainHunter => {
                "Read the prior candidates, signals, and existing vulnerabilities as ingredients. Your job is to find new catastrophic chains that span multiple domains and were easy for specialists to miss: auth plus billing, IDOR plus export, dev drift plus secret access, webhook trust plus entitlement, or low-severity primitives chained into account takeover, cross-tenant compromise, payment bypass, persistent admin access, or secret exfiltration. Do not merely summarize previous findings; attempt live chain proof and record only new or materially upgraded impact."
            }
            Self::Triage => {
                "Act as the final attack triage pass. Review existing vulnerabilities, prior candidates, and any live evidence available in the artifact directory. Deduplicate mentally, resolve dev-only noise, and attempt focused live checks only where they can confirm, upgrade, or reject a high-impact issue. Record a vulnerability only when you have stronger live proof or a materially different impact chain."
            }
        }
    }

    fn render_for_prompt(self) -> String {
        format!("{} ({})\n{}", self.title(), self.slug(), self.instructions())
    }
}

pub const SPECIALIST_ATTACK_AGENT_PROFILES: &[AttackAgentProfile] = &[
    AttackAgentProfile::BusinessLogic,
    AttackAgentProfile::PaymentsBilling,
    AttackAgentProfile::UserDataPrivacy,
    AttackAgentProfile::AuthSession,
    AttackAgentProfile::ApiInput,
    AttackAgentProfile::InfraDevProd,
    AttackAgentProfile::AbuseAutomation,
];

pub const DEFAULT_ATTACK_AGENT_PROFILES: &[AttackAgentProfile] = &[
    AttackAgentProfile::BusinessLogic,
    AttackAgentProfile::PaymentsBilling,
    AttackAgentProfile::UserDataPrivacy,
    AttackAgentProfile::AuthSession,
    AttackAgentProfile::ApiInput,
    AttackAgentProfile::InfraDevProd,
    AttackAgentProfile::AbuseAutomation,
    AttackAgentProfile::CriticalChainHunter,
    AttackAgentProfile::Triage,
];

#[derive(Debug, Clone)]
pub struct AttackWorkspace {
    pub repo: String,
    pub root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackAgentKnownLead {
    pub id: String,
    pub source: String,
    pub title: String,
    pub vuln_class: String,
    pub severity: String,
    pub status: String,
    pub location: Option<String>,
    pub hypothesis: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingVulnerabilitySummary {
    pub id: String,
    pub title: String,
    pub vuln_class: String,
    pub severity: String,
    pub confidence_percent: u8,
    pub status: String,
    pub evidence_summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AttackAgentVulnerability {
    pub title: String,
    pub vuln_class: String,
    pub severity: String,
    pub confidence: u8,
    pub affected_components: Vec<serde_json::Value>,
    pub business_impact: String,
    pub evidence_summary: String,
    pub repro_steps: String,
    pub remediation: String,
    pub source_candidate_ids: Vec<String>,
    pub source_signal_ids: Vec<String>,
    pub proof_artifact_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttackAgentAuditEntry {
    pub action: String,
    pub summary: String,
}

#[derive(Debug)]
pub enum AttackAgentOutcome {
    Completed {
        vulnerabilities: Vec<AttackAgentVulnerability>,
        audit: Vec<AttackAgentAuditEntry>,
        final_message: String,
        turns: u32,
        spent_usd_micros: i64,
        prompt_version: String,
        metrics: AgentTraceMetrics,
    },
}

pub async fn run<R: AiRuntime + ?Sized>(
    runtime: &R,
    scope: &AttackAgentScope,
    sink: EventSink,
) -> Result<AttackAgentOutcome, AiError> {
    let task = build_agent_task(scope);
    let budget = Budget {
        run_id: scope.run_id.clone(),
        kind: BudgetKind::AgentLoop,
        cap_usd_micros: scope.run_cap_usd_micros,
    };
    let result = runtime.agent_loop(task, budget, sink).await?;
    let (vulnerabilities, audit) = lift_extracted(&result);
    let metrics = AgentTraceMetrics::from_agent_result(&result);
    Ok(AttackAgentOutcome::Completed {
        vulnerabilities,
        audit,
        final_message: result.final_message,
        turns: result.turns,
        spent_usd_micros: result.cost_usd_micros,
        prompt_version: result.prompt_version,
        metrics,
    })
}

fn build_agent_task(scope: &AttackAgentScope) -> AgentTask {
    let system = include_str!("../prompts/attack_agent.v1.system.md").to_string();
    let mut objective = include_str!("../prompts/attack_agent.v1.objective.md").to_string();
    objective = objective.replace("@@TARGETS@@", &render_targets(&scope.target_urls));
    objective = objective.replace("@@WORKSPACES@@", &render_workspaces(&scope.workspaces));
    objective = objective.replace("@@KNOWN_LEADS@@", &render_known_leads(&scope.known_leads));
    objective = objective.replace(
        "@@EXISTING_VULNERABILITIES@@",
        &render_existing_vulnerabilities(&scope.existing_vulnerabilities),
    );
    objective = objective.replace("@@ARTIFACT_DIR@@", &scope.artifact_dir);
    objective = objective.replace("@@MAX_TURNS@@", &scope.max_turns.to_string());
    objective = objective.replace("@@RUN_ID@@", &scope.run_id);
    objective = objective.replace("@@PROJECT_ID@@", &scope.project_id);
    objective = objective.replace("@@AGENT_PROFILE@@", &scope.profile.render_for_prompt());

    AgentTask {
        prompt_version: format!("{}.{}", ATTACK_AGENT_PROMPT_VERSION, scope.profile.slug()),
        task_id: scope.task_id.clone(),
        system,
        objective,
        tools: DEFAULT_ATTACK_AGENT_TOOL_NAMES.iter().map(|s| s.to_string()).collect(),
        working_directory: scope.workspaces.first().map(|w| w.root.clone()),
        max_turns: scope.max_turns,
    }
}

fn render_targets(targets: &[String]) -> String {
    if targets.is_empty() {
        return "(none configured; inspect the workspace and stop without live probes)".to_string();
    }
    targets.iter().map(|target| format!("- {target}")).collect::<Vec<_>>().join("\n")
}

fn render_workspaces(workspaces: &[AttackWorkspace]) -> String {
    if workspaces.is_empty() {
        return "(no workspace roots supplied)".to_string();
    }
    workspaces
        .iter()
        .map(|workspace| format!("- {}: {}", workspace.repo, workspace.root))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_known_leads(leads: &[AttackAgentKnownLead]) -> String {
    if leads.is_empty() {
        return "(none)".to_string();
    }
    leads
        .iter()
        .take(40)
        .map(|lead| {
            serde_json::json!({
                "id": lead.id,
                "source": lead.source,
                "title": compact(&lead.title, 160),
                "class": lead.vuln_class,
                "severity": lead.severity,
                "status": lead.status,
                "location": lead.location,
                "hypothesis": compact(&lead.hypothesis, 260),
            })
            .to_string()
        })
        .map(|line| format!("- {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_existing_vulnerabilities(vulns: &[ExistingVulnerabilitySummary]) -> String {
    if vulns.is_empty() {
        return "(none)".to_string();
    }
    vulns
        .iter()
        .take(30)
        .map(|vuln| {
            serde_json::json!({
                "id": vuln.id,
                "title": compact(&vuln.title, 160),
                "class": vuln.vuln_class,
                "severity": vuln.severity,
                "confidence": vuln.confidence_percent,
                "status": vuln.status,
                "evidence": compact(&vuln.evidence_summary, 240),
            })
            .to_string()
        })
        .map(|line| format!("- {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn compact(raw: &str, max_chars: usize) -> String {
    let compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = String::new();
    for (idx, ch) in compact.chars().enumerate() {
        if idx >= max_chars {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

fn lift_extracted(
    result: &AgentResult,
) -> (Vec<AttackAgentVulnerability>, Vec<AttackAgentAuditEntry>) {
    let mut vulnerabilities = Vec::new();
    let mut audit = Vec::with_capacity(result.extracted.len());
    for ex in &result.extracted {
        match ex {
            ExtractedAgentResult::AttackVulnerability {
                title,
                vuln_class,
                severity,
                confidence,
                affected_components,
                business_impact,
                evidence_summary,
                repro_steps,
                remediation,
                source_candidate_ids,
                source_signal_ids,
                proof_artifact_paths,
            } => {
                vulnerabilities.push(AttackAgentVulnerability {
                    title: title.clone(),
                    vuln_class: vuln_class.clone(),
                    severity: severity.clone(),
                    confidence: *confidence,
                    affected_components: affected_components.clone(),
                    business_impact: business_impact.clone(),
                    evidence_summary: evidence_summary.clone(),
                    repro_steps: repro_steps.clone(),
                    remediation: remediation.clone(),
                    source_candidate_ids: source_candidate_ids.clone(),
                    source_signal_ids: source_signal_ids.clone(),
                    proof_artifact_paths: proof_artifact_paths.clone(),
                });
                audit.push(AttackAgentAuditEntry {
                    action: "record_attack_vulnerability".to_string(),
                    summary: format!("{title} class={vuln_class} confidence={confidence}%"),
                });
            }
            ExtractedAgentResult::ExplorationEvent { message } => {
                audit.push(AttackAgentAuditEntry {
                    action: "<other>".to_string(),
                    summary: compact(message, 160),
                });
            }
            other => {
                audit.push(AttackAgentAuditEntry {
                    action: "<other>".to_string(),
                    summary: format!("{other:?}"),
                });
            }
        }
    }
    (vulnerabilities, audit)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use nyx_agent_types::agent::{
        AgentResult, AgentTask, Budget, CacheStats, CostEstimate, Prompt, Response, TokenUsage,
    };
    use nyx_agent_types::event::AgentEvent;
    use tokio::sync::broadcast;

    use super::*;

    struct FakeRuntime {
        task: Mutex<Option<AgentTask>>,
        result: AgentResult,
    }

    #[async_trait]
    impl AiRuntime for FakeRuntime {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn default_model(&self) -> &str {
            "fake-model"
        }

        fn supports_agent_loop(&self) -> bool {
            true
        }

        fn supports_prompt_cache(&self) -> bool {
            false
        }

        fn supports_deterministic_sampling(&self) -> bool {
            false
        }

        async fn one_shot(
            &self,
            _prompt: Prompt,
            _budget: Budget,
            _sink: EventSink,
        ) -> Result<Response, AiError> {
            Err(AiError::UnsupportedMode("one_shot"))
        }

        async fn agent_loop(
            &self,
            task: AgentTask,
            _budget: Budget,
            _sink: EventSink,
        ) -> Result<AgentResult, AiError> {
            *self.task.lock().expect("task mutex") = Some(task);
            Ok(self.result.clone())
        }

        fn cost_estimate(&self, _prompt: &Prompt) -> Option<CostEstimate> {
            None
        }
    }

    #[tokio::test]
    async fn lifts_attack_vulnerability_and_passes_context() {
        let result = AgentResult {
            prompt_version: ATTACK_AGENT_PROMPT_VERSION.to_string(),
            task_id: "attack-agent-run-1".to_string(),
            model: "fake-model".to_string(),
            final_message: "done".to_string(),
            turns: 3,
            usage: TokenUsage { input_tokens: 10, output_tokens: 20 },
            cache: Some(CacheStats::default()),
            cost_usd_micros: 123,
            extracted: vec![ExtractedAgentResult::AttackVulnerability {
                title: "Admin export without auth".to_string(),
                vuln_class: "AUTH_BYPASS".to_string(),
                severity: "Critical".to_string(),
                confidence: 97,
                affected_components: vec![serde_json::json!({"endpoint":"GET /admin/export"})],
                business_impact: "Exported tenant data".to_string(),
                evidence_summary: "curl returned CSV".to_string(),
                repro_steps: "curl /admin/export".to_string(),
                remediation: "Require admin auth".to_string(),
                source_candidate_ids: vec!["pc-1".to_string()],
                source_signal_ids: vec![],
                proof_artifact_paths: vec!["/tmp/proof.png".to_string()],
            }],
        };
        let runtime = Arc::new(FakeRuntime { task: Mutex::new(None), result });
        let mut scope = AttackAgentScope::new("run-1", "project-1");
        scope.target_urls = vec!["http://127.0.0.1:3000".to_string()];
        scope.workspaces =
            vec![AttackWorkspace { repo: "app".to_string(), root: "/tmp/app".to_string() }];
        scope.artifact_dir = "/tmp/artifacts".to_string();
        let (tx, _) = broadcast::channel::<AgentEvent>(4);

        let outcome = run(runtime.as_ref(), &scope, tx).await.expect("run");
        let vulnerabilities = match outcome {
            AttackAgentOutcome::Completed { vulnerabilities, .. } => vulnerabilities,
        };
        assert_eq!(vulnerabilities[0].title, "Admin export without auth");
        let task = runtime.task.lock().expect("task").clone().expect("task captured");
        assert!(task.objective.contains("http://127.0.0.1:3000"));
        assert!(task.objective.contains("Generalist live attack agent"));
        assert_eq!(task.prompt_version, format!("{}.generalist", ATTACK_AGENT_PROMPT_VERSION));
        assert_eq!(task.working_directory.as_deref(), Some("/tmp/app"));
    }
}
