use std::collections::{BTreeMap, BTreeSet};

use nyctos_core::store::{finding_id_hash, NyxSignalRecord, PentestCandidateRecord, Store};
use nyctos_core::RunConfig;
use nyctos_types::product::{ApiClientCallModel, FormModel, RouteModel, RouteModelEndpoint};

use crate::pentest_tools;

const SOURCE_LINE_WINDOW: i64 = 80;
const RESEARCH_SOURCE: &str = "ResearchMode";
const RESEARCH_MODE_VERSION: &str = "research-mode.product-invariants.v1";
const MAX_RESEARCH_ROUTE_HYPOTHESES_PER_CATEGORY: usize = 4;
const MAX_RESEARCH_MEMORY_HYPOTHESES: usize = 6;

pub async fn synthesize_weak_signal_candidates(
    store: &Store,
    run_id: &str,
    project_id: &str,
    route_model: &RouteModel,
    run_config: &RunConfig,
) -> anyhow::Result<u32> {
    let signals = store.nyx_signals().list_by_run(run_id, true).await?;
    let mut drafts = CandidateDrafts::default();

    for route in &route_model.backend_routes {
        add_route_candidates(&mut drafts, route, &signals);
    }
    for call in &route_model.api_client_calls {
        add_api_client_candidates(&mut drafts, call);
    }
    for form in &route_model.forms {
        add_form_candidates(&mut drafts, form, &signals);
    }
    if run_config.research_mode_enabled {
        let memory = match store.pentest_candidates().list_by_run(run_id).await {
            Ok(rows) => rows,
            Err(err) => {
                tracing::warn!(
                    run_id = %run_id,
                    error = %err,
                    "research mode candidate synthesis: failed to load exploration memory; continuing with route model only"
                );
                Vec::new()
            }
        };
        add_research_mode_candidates(&mut drafts, route_model, &memory);
    }

    let candidates = drafts.into_records(run_id, project_id);
    pentest_tools::persist_pentest_candidates_deduped(store, candidates).await
}

fn add_route_candidates(
    drafts: &mut CandidateDrafts,
    route: &RouteModelEndpoint,
    signals: &[NyxSignalRecord],
) {
    let route_source =
        if route.middleware.iter().any(|m| m == "openapi") { "OpenAPI" } else { "RouteDiscovery" };
    for lead in route_leads(
        &route.method,
        &route.path,
        route.state_changing,
        &route.auth_checks,
        &route.body_fields,
        &route.params,
    ) {
        let component = serde_json::json!({
            "kind": "route",
            "repo": route.repo,
            "method": route.method,
            "url_path": route.path,
            "path": route.handler_file,
            "line": route.line,
            "params": route.params,
            "body_fields": route.body_fields,
            "route_source": route_source,
        });
        let mut source_ids = vec![route_source_id(
            route_source,
            route.repo.as_deref(),
            &route.method,
            &route.path,
            route.handler_file.as_deref(),
            route.line,
        )];
        source_ids.extend(matching_signal_ids(
            route.repo.as_deref(),
            route.handler_file.as_deref(),
            route.line,
            signals,
        ));
        drafts.add(CandidateLead {
            class: lead.class,
            title: lead.title,
            severity: lead.severity,
            source: route_source.to_string(),
            source_ids,
            component,
            hypothesis: format!(
                "{} observed {} {}; live verification must prove exploit-specific behavior before this is reported.",
                route_source, route.method, route.path
            ),
            test_plan: None,
            confidence: lead.confidence + route.confidence.min(1.0) * 0.08,
        });
    }
}

fn add_api_client_candidates(drafts: &mut CandidateDrafts, call: &ApiClientCallModel) {
    for lead in surface_leads(&call.method, &call.path, false) {
        let source = if call.file.as_deref().map(looks_like_bundle_path).unwrap_or(false) {
            "JavaScriptBundle"
        } else {
            "ApiClientDiscovery"
        };
        drafts.add(CandidateLead {
            class: lead.class,
            title: lead.title,
            severity: lead.severity,
            source: source.to_string(),
            source_ids: vec![route_source_id(
                source,
                call.repo.as_deref(),
                &call.method,
                &call.path,
                call.file.as_deref(),
                call.line,
            )],
            component: serde_json::json!({
                "kind": "api_client",
                "repo": call.repo,
                "method": call.method,
                "url_path": call.path,
                "path": call.file,
                "line": call.line,
                "route_source": source,
            }),
            hypothesis: format!(
                "{} observed a client-side call to {} {}; live verification must prove the surface is vulnerable.",
                source, call.method, call.path
            ),
            test_plan: None,
            confidence: lead.confidence + call.confidence.min(1.0) * 0.06,
        });
    }
}

fn add_form_candidates(
    drafts: &mut CandidateDrafts,
    form: &FormModel,
    signals: &[NyxSignalRecord],
) {
    if form.state_changing && form.csrf_markers.is_empty() {
        let mut source_ids = vec![route_source_id(
            "FormDiscovery",
            form.repo.as_deref(),
            &form.method,
            &form.action,
            form.file.as_deref(),
            form.line,
        )];
        source_ids.extend(matching_signal_ids(
            form.repo.as_deref(),
            form.file.as_deref(),
            form.line,
            signals,
        ));
        drafts.add(CandidateLead {
            class: "CSRF_CANDIDATE".to_string(),
            title: format!("State-changing form without an obvious CSRF marker: {}", form.action),
            severity: "Medium".to_string(),
            source: "FormDiscovery".to_string(),
            source_ids,
            component: serde_json::json!({
                "kind": "form",
                "repo": form.repo,
                "method": form.method,
                "action": form.action,
                "path": form.file,
                "line": form.line,
                "fields": form.fields,
                "csrf_markers": form.csrf_markers,
                "route_source": "FormDiscovery",
            }),
            hypothesis: format!(
                "A {} form posts to {} with no static CSRF marker. Live verification must prove a cross-site request can cause an unauthorized state change.",
                form.method, form.action
            ),
            test_plan: None,
            confidence: 0.48 + form.confidence.min(1.0) * 0.08,
        });
    }
}

#[derive(Debug, Clone, Copy)]
struct ResearchRouteCategory {
    id: &'static str,
    vuln_class: &'static str,
    severity: &'static str,
    title: &'static str,
    invariant: &'static str,
    route_terms: &'static [&'static str],
    field_terms: &'static [&'static str],
    require_state_changing: bool,
    confidence: f64,
}

const RESEARCH_ROUTE_CATEGORIES: &[ResearchRouteCategory] = &[
    ResearchRouteCategory {
        id: "lifecycle_transition",
        vuln_class: "LIFECYCLE_INVARIANT_BYPASS",
        severity: "High",
        title: "Lifecycle transition invariant",
        invariant: "state transitions should enforce ownership, role, current state, and one-way transition rules",
        route_terms: &[
            "activate", "deactivate", "suspend", "unsuspend", "archive", "restore", "cancel",
            "close", "reopen", "approve", "reject", "publish", "unpublish", "complete", "void",
        ],
        field_terms: &["status", "state", "transition", "workflow", "approved", "cancelled"],
        require_state_changing: true,
        confidence: 0.68,
    },
    ResearchRouteCategory {
        id: "stale_access",
        vuln_class: "STALE_ACCESS",
        severity: "High",
        title: "Stale access after access change",
        invariant: "authorization decisions should be revalidated after membership, sharing, revocation, ownership, or deletion changes",
        route_terms: &[
            "share", "unshare", "revoke", "grant", "permission", "permissions", "member",
            "members", "collaborator", "transfer", "delete", "remove",
        ],
        field_terms: &["role", "permission", "access", "owner", "member", "collaborator"],
        require_state_changing: true,
        confidence: 0.70,
    },
    ResearchRouteCategory {
        id: "replay",
        vuln_class: "REPLAY_OR_TOKEN_REUSE",
        severity: "High",
        title: "Replay or token reuse invariant",
        invariant: "single-use tokens, invites, callbacks, OTPs, and webhooks should reject reuse, stale state, and reordered delivery",
        route_terms: &[
            "token", "reset", "invite", "invitation", "otp", "mfa", "magic", "callback",
            "webhook", "redeem", "accept", "verify",
        ],
        field_terms: &["token", "code", "otp", "nonce", "signature", "event_id"],
        require_state_changing: true,
        confidence: 0.67,
    },
    ResearchRouteCategory {
        id: "entitlement_mismatch",
        vuln_class: "ENTITLEMENT_MISMATCH",
        severity: "High",
        title: "Downgrade or entitlement mismatch",
        invariant: "billing, plan, quota, and role changes should stay consistent with server-side entitlements on every dependent action",
        route_terms: &[
            "billing", "subscription", "subscriptions", "plan", "plans", "entitlement",
            "quota", "seat", "seats", "tier", "upgrade", "downgrade", "checkout",
        ],
        field_terms: &["plan", "tier", "role", "quota", "seat", "price", "amount", "entitlement"],
        require_state_changing: false,
        confidence: 0.69,
    },
    ResearchRouteCategory {
        id: "invite_team_org_transition",
        vuln_class: "INVITE_OR_MEMBERSHIP_TRANSITION",
        severity: "High",
        title: "Invite, team, or org transition invariant",
        invariant: "invite, team, org, and role transitions should bind actor, target org, role, expiration, and current membership state",
        route_terms: &[
            "invite", "invitation", "team", "teams", "org", "organization", "workspace",
            "member", "members", "role", "roles",
        ],
        field_terms: &["email", "role", "org_id", "team_id", "workspace_id", "expires"],
        require_state_changing: true,
        confidence: 0.71,
    },
    ResearchRouteCategory {
        id: "webhook_event_consistency",
        vuln_class: "WEBHOOK_EVENT_CONSISTENCY",
        severity: "High",
        title: "Webhook or event consistency invariant",
        invariant: "event receivers and callbacks should authenticate origin, deduplicate delivery, and keep side effects consistent under retries",
        route_terms: &[
            "webhook", "callback", "event", "events", "receiver", "notification", "notify",
            "integration",
        ],
        field_terms: &["event", "event_id", "signature", "hmac", "payload", "topic", "type"],
        require_state_changing: true,
        confidence: 0.66,
    },
    ResearchRouteCategory {
        id: "ai_agent_indirect_action",
        vuln_class: "AI_AGENT_INDIRECT_ACTION",
        severity: "High",
        title: "AI agent indirect action invariant",
        invariant: "AI and agent endpoints should not let untrusted content trigger privileged tool calls, data access, or workflow side effects",
        route_terms: &[
            "ai", "assistant", "agent", "agents", "chat", "copilot", "llm", "tool", "tools",
            "action", "actions",
        ],
        field_terms: &["prompt", "message", "instruction", "tool", "action", "query", "input"],
        require_state_changing: false,
        confidence: 0.66,
    },
    ResearchRouteCategory {
        id: "background_job_side_effect",
        vuln_class: "BACKGROUND_JOB_SIDE_EFFECT",
        severity: "Medium",
        title: "Background job side-effect invariant",
        invariant: "queued, async, import/export, sync, and reporting actions should enforce auth, idempotency, tenant scope, and cleanup after completion",
        route_terms: &[
            "job", "jobs", "task", "tasks", "queue", "export", "import", "sync", "report",
            "reports", "email", "worker", "batch",
        ],
        field_terms: &["job_id", "task_id", "format", "email", "callback", "file", "report_id"],
        require_state_changing: true,
        confidence: 0.61,
    },
];

fn add_research_mode_candidates(
    drafts: &mut CandidateDrafts,
    route_model: &RouteModel,
    memory: &[PentestCandidateRecord],
) {
    for category in RESEARCH_ROUTE_CATEGORIES {
        let mut generated = 0_usize;
        for route in route_model
            .backend_routes
            .iter()
            .filter(|route| research_category_matches_route(category, route))
        {
            let memory_refs = memory_refs_for_route(route, memory);
            drafts.add(research_route_lead(category, route, memory_refs));
            generated += 1;
            if generated >= MAX_RESEARCH_ROUTE_HYPOTHESES_PER_CATEGORY {
                break;
            }
        }
    }
    add_research_memory_pivots(drafts, memory);
}

fn research_route_lead(
    category: &ResearchRouteCategory,
    route: &RouteModelEndpoint,
    memory_refs: Vec<String>,
) -> CandidateLead {
    let method = route.method.to_ascii_uppercase();
    let mut source_ids = vec![research_route_source_id(category.id, route)];
    source_ids.extend(memory_refs.iter().map(|id| format!("research-memory:{id}")));
    let component = research_route_component(category, route, &memory_refs);
    CandidateLead {
        class: category.vuln_class.to_string(),
        title: format!("{}: {method} {}", category.title, route.path),
        severity: category.severity.to_string(),
        source: RESEARCH_SOURCE.to_string(),
        source_ids,
        component,
        hypothesis: format!(
            "Research mode selected {method} {path} because product invariant `{invariant}` may break across lifecycle, auth, replay, entitlement, team/org, event, AI-agent, or background-job boundaries. Confirmation requires concrete live evidence under the normal verifier safety policy.",
            path = route.path,
            invariant = category.invariant
        ),
        test_plan: Some(research_test_plan(category)),
        confidence: (category.confidence + route.confidence.min(1.0) * 0.05).min(0.82),
    }
}

fn add_research_memory_pivots(drafts: &mut CandidateDrafts, memory: &[PentestCandidateRecord]) {
    let mut generated = 0_usize;
    for candidate in memory.iter().filter(|c| c.source != RESEARCH_SOURCE) {
        let text = candidate_memory_text(candidate);
        let Some(category) = RESEARCH_ROUTE_CATEGORIES
            .iter()
            .find(|category| research_category_matches_text(category, &text))
        else {
            continue;
        };
        let (method, path) = candidate_primary_route(candidate)
            .unwrap_or_else(|| ("GET".to_string(), format!("<candidate:{}>", candidate.id)));
        let component = serde_json::json!({
            "kind": "research_mode_memory",
            "research_mode": true,
            "research_mode_provenance": {
                "mode": "research",
                "version": RESEARCH_MODE_VERSION,
                "source": "exploration_memory",
                "category": category.id,
                "invariant": category.invariant,
                "source_candidate_id": candidate.id,
                "source_candidate_source": candidate.source,
            },
            "category": category.id,
            "invariant": category.invariant,
            "source_candidate_id": candidate.id,
            "memory_source": candidate.source,
            "memory_title": candidate.title,
            "method": method,
            "url_path": path,
        });
        let mut source_ids =
            vec![format!("research-memory:{}", candidate.id), candidate.id.clone()];
        source_ids.extend(candidate.source_ids.iter().take(4).cloned());
        drafts.add(CandidateLead {
            class: category.vuln_class.to_string(),
            title: format!("Research follow-up on {}: {}", category.title, candidate.title),
            severity: category.severity.to_string(),
            source: RESEARCH_SOURCE.to_string(),
            source_ids,
            component,
            hypothesis: format!(
                "Research mode used prior candidate `{}` as exploration memory and pivoted it into the `{}` invariant. The verifier must still collect fresh live evidence before reporting.",
                candidate.id, category.id
            ),
            test_plan: Some(research_test_plan(category)),
            confidence: (candidate.confidence + 0.05).clamp(0.55, 0.80),
        });
        generated += 1;
        if generated >= MAX_RESEARCH_MEMORY_HYPOTHESES {
            break;
        }
    }
}

fn research_route_component(
    category: &ResearchRouteCategory,
    route: &RouteModelEndpoint,
    memory_refs: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "kind": "research_mode_hypothesis",
        "research_mode": true,
        "research_mode_provenance": {
            "mode": "research",
            "version": RESEARCH_MODE_VERSION,
            "source": "semantic_route_model",
            "category": category.id,
            "invariant": category.invariant,
            "memory_candidate_ids": memory_refs,
        },
        "category": category.id,
        "invariant": category.invariant,
        "repo": route.repo,
        "method": route.method,
        "url_path": route.path,
        "path": route.handler_file,
        "line": route.line,
        "params": route.params,
        "body_fields": route.body_fields,
        "auth_checks": route.auth_checks,
        "role_checks": route.role_checks,
        "state_changing": route.state_changing,
    })
}

fn research_test_plan(category: &ResearchRouteCategory) -> String {
    format!(
        "Research mode invariant plan: map preconditions and forbidden transitions for `{}`; prefer read-only or dry-run evidence; if confirmation needs mutation, rely on the existing exploit-mode, state-changing, request-cap, rate-limit, target-scope, and reset gates. Record positive evidence only when the invariant is observably broken.",
        category.invariant
    )
}

fn research_category_matches_route(
    category: &ResearchRouteCategory,
    route: &RouteModelEndpoint,
) -> bool {
    if category.require_state_changing && !route.state_changing {
        return false;
    }
    let text = research_route_text(route);
    research_category_matches_text(category, &text)
}

fn research_category_matches_text(category: &ResearchRouteCategory, text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    category.route_terms.iter().chain(category.field_terms.iter()).any(|needle| {
        let needle = needle.to_ascii_lowercase();
        lower.contains(&needle)
    })
}

fn research_route_text(route: &RouteModelEndpoint) -> String {
    let mut parts = vec![route.method.as_str(), route.path.as_str()];
    parts.extend(route.params.iter().map(String::as_str));
    parts.extend(route.body_fields.iter().map(String::as_str));
    parts.extend(route.auth_checks.iter().map(String::as_str));
    parts.extend(route.role_checks.iter().map(String::as_str));
    parts.join(" ")
}

fn research_route_source_id(category_id: &str, route: &RouteModelEndpoint) -> String {
    format!(
        "research-mode:{category_id}:{}:{}:{}:{}",
        route.repo.as_deref().unwrap_or("*"),
        route.method.to_ascii_uppercase(),
        normalise_path(&route.path),
        route.handler_file.as_deref().unwrap_or("*")
    )
}

fn memory_refs_for_route(
    route: &RouteModelEndpoint,
    memory: &[PentestCandidateRecord],
) -> Vec<String> {
    let target = normalise_path(&route.path);
    memory
        .iter()
        .filter(|candidate| candidate_mentions_route(candidate, &target))
        .map(|candidate| candidate.id.clone())
        .take(6)
        .collect()
}

fn candidate_mentions_route(candidate: &PentestCandidateRecord, route_path: &str) -> bool {
    let text_hit = candidate_memory_text(candidate).contains(route_path);
    text_hit
        || candidate.affected_components.iter().any(|component| {
            component
                .as_object()
                .and_then(|obj| {
                    obj.get("url_path")
                        .or_else(|| obj.get("action"))
                        .or_else(|| obj.get("matched_at"))
                        .or_else(|| obj.get("target"))
                        .or_else(|| obj.get("url"))
                        .and_then(|value| value.as_str())
                })
                .map(|path| normalise_path(path) == route_path)
                .unwrap_or(false)
        })
}

fn candidate_memory_text(candidate: &PentestCandidateRecord) -> String {
    let mut parts = vec![
        candidate.source.as_str(),
        candidate.title.as_str(),
        candidate.vuln_class.as_str(),
        candidate.hypothesis.as_str(),
    ];
    for component in &candidate.affected_components {
        if let Some(obj) = component.as_object() {
            for key in ["url_path", "action", "matched_at", "target", "url", "path", "kind"] {
                if let Some(value) = obj.get(key).and_then(|value| value.as_str()) {
                    parts.push(value);
                }
            }
        }
    }
    parts.join(" ").to_ascii_lowercase()
}

fn candidate_primary_route(candidate: &PentestCandidateRecord) -> Option<(String, String)> {
    for component in &candidate.affected_components {
        let Some(obj) = component.as_object() else {
            continue;
        };
        let path = obj
            .get("url_path")
            .or_else(|| obj.get("action"))
            .or_else(|| obj.get("matched_at"))
            .or_else(|| obj.get("target"))
            .or_else(|| obj.get("url"))
            .and_then(|value| value.as_str())?;
        let method = obj
            .get("method")
            .and_then(|value| value.as_str())
            .unwrap_or("GET")
            .to_ascii_uppercase();
        return Some((method, normalise_path(path)));
    }
    None
}

#[derive(Debug, Clone)]
struct SurfaceLead {
    class: String,
    title: String,
    severity: String,
    confidence: f64,
}

fn route_leads(
    method: &str,
    path: &str,
    state_changing: bool,
    auth_checks: &[String],
    body_fields: &[String],
    params: &[String],
) -> Vec<SurfaceLead> {
    let mut leads = surface_leads(method, path, state_changing);
    let has_auth = !auth_checks.is_empty();
    if state_changing && !has_auth {
        leads.push(SurfaceLead {
            class: "UNAUTHENTICATED_STATE_CHANGE".to_string(),
            title: format!("State-changing route without obvious auth: {method} {path}"),
            severity: "Medium".to_string(),
            confidence: 0.46,
        });
    }
    let id_like = params.iter().chain(body_fields.iter()).any(|name| {
        let lower = name.to_ascii_lowercase();
        lower == "id"
            || lower.ends_with("_id")
            || lower.contains("account")
            || lower.contains("user")
    });
    if id_like && !has_auth {
        leads.push(SurfaceLead {
            class: "IDOR_CANDIDATE".to_string(),
            title: format!("Object identifier route without obvious auth: {method} {path}"),
            severity: "Medium".to_string(),
            confidence: 0.44,
        });
    }
    leads
}

fn surface_leads(method: &str, path: &str, _state_changing: bool) -> Vec<SurfaceLead> {
    let lower = path.to_ascii_lowercase();
    let checks = [
        ("graphql", "GraphQL endpoint discovered", "GRAPHQL_EXPOSURE", "Medium", 0.48),
        ("swagger", "Swagger/OpenAPI surface discovered", "API_DOCS_EXPOSURE", "Medium", 0.50),
        ("openapi", "Swagger/OpenAPI surface discovered", "API_DOCS_EXPOSURE", "Medium", 0.50),
        ("admin", "Administrative surface discovered", "ADMIN_SURFACE", "Medium", 0.52),
        ("debug", "Debug route discovered", "DIAGNOSTIC_EXPOSURE", "Medium", 0.50),
        ("actuator", "Spring actuator route discovered", "DIAGNOSTIC_EXPOSURE", "Medium", 0.50),
        ("metrics", "Metrics route discovered", "DIAGNOSTIC_EXPOSURE", "Low", 0.42),
        ("internal", "Internal route discovered", "INTERNAL_SURFACE", "Medium", 0.48),
        ("config", "Configuration route discovered", "CONFIG_EXPOSURE", "Medium", 0.50),
    ];
    checks
        .iter()
        .filter(|(needle, _, _, _, _)| lower.contains(needle))
        .map(|(_, title, class, severity, confidence)| SurfaceLead {
            class: (*class).to_string(),
            title: format!("{title}: {method} {path}"),
            severity: (*severity).to_string(),
            confidence: *confidence,
        })
        .collect()
}

#[derive(Debug)]
struct CandidateLead {
    class: String,
    title: String,
    severity: String,
    source: String,
    source_ids: Vec<String>,
    component: serde_json::Value,
    hypothesis: String,
    test_plan: Option<String>,
    confidence: f64,
}

#[derive(Default)]
struct CandidateDrafts {
    by_key: BTreeMap<String, CandidateDraft>,
}

impl CandidateDrafts {
    fn add(&mut self, lead: CandidateLead) {
        let key = candidate_key(&lead.class, &lead.component);
        self.by_key.entry(key).or_insert_with(|| CandidateDraft::new(&lead)).merge(lead);
    }

    fn into_records(self, run_id: &str, project_id: &str) -> Vec<PentestCandidateRecord> {
        let now_ms = nyctos_core::now_epoch_ms();
        self.by_key
            .into_iter()
            .map(|(key, draft)| draft.into_record(run_id, project_id, &key, now_ms))
            .collect()
    }
}

struct CandidateDraft {
    title: String,
    class: String,
    severity: String,
    sources: BTreeSet<String>,
    source_ids: BTreeSet<String>,
    components: Vec<serde_json::Value>,
    component_keys: BTreeSet<String>,
    hypotheses: Vec<String>,
    test_plans: Vec<String>,
    confidence: f64,
}

impl CandidateDraft {
    fn new(lead: &CandidateLead) -> Self {
        Self {
            title: lead.title.clone(),
            class: lead.class.clone(),
            severity: lead.severity.clone(),
            sources: BTreeSet::new(),
            source_ids: BTreeSet::new(),
            components: Vec::new(),
            component_keys: BTreeSet::new(),
            hypotheses: Vec::new(),
            test_plans: Vec::new(),
            confidence: 0.0,
        }
    }

    fn merge(&mut self, lead: CandidateLead) {
        self.sources.insert(lead.source);
        self.source_ids.extend(lead.source_ids.into_iter().filter(|id| !id.trim().is_empty()));
        let component_key = serde_json::to_string(&lead.component).unwrap_or_default();
        if self.component_keys.insert(component_key) {
            self.components.push(lead.component);
        }
        if !self.hypotheses.iter().any(|h| h == &lead.hypothesis) {
            self.hypotheses.push(lead.hypothesis);
        }
        if let Some(test_plan) = lead.test_plan {
            if !self.test_plans.iter().any(|p| p == &test_plan) {
                self.test_plans.push(test_plan);
            }
        }
        if severity_rank(&lead.severity) > severity_rank(&self.severity) {
            self.severity = lead.severity;
            self.title = lead.title;
        }
        self.confidence = self.confidence.max(lead.confidence).min(0.78);
    }

    fn into_record(
        self,
        run_id: &str,
        project_id: &str,
        key: &str,
        now_ms: i64,
    ) -> PentestCandidateRecord {
        let source = self.sources.into_iter().collect::<Vec<_>>().join("+");
        let source_ids = self.source_ids.into_iter().collect::<Vec<_>>();
        let mut components = self.components;
        for component in &mut components {
            if let Some(obj) = component.as_object_mut() {
                obj.insert(
                    "source_ids".to_string(),
                    serde_json::Value::Array(
                        source_ids.iter().cloned().map(serde_json::Value::String).collect(),
                    ),
                );
            }
        }
        let test_plan = if self.test_plans.is_empty() {
            "Derive a safe live HTTP/browser confirmation from the combined weak signals; do not report as verified without live evidence.".to_string()
        } else {
            self.test_plans.join("\n")
        };
        PentestCandidateRecord {
            id: format!("pc-weak-{}", finding_id_hash(run_id, key, None, &self.class, &source)),
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            source,
            source_ids,
            title: self.title,
            vuln_class: self.class,
            severity_guess: self.severity,
            affected_components: components,
            hypothesis: self.hypotheses.join("\n"),
            test_plan,
            status: "NeedsLiveTest".to_string(),
            rejection_reason: None,
            confidence: self.confidence,
            trace_id: None,
            created_at: now_ms,
            updated_at: now_ms,
        }
    }
}

fn candidate_key(class: &str, component: &serde_json::Value) -> String {
    let target = component
        .get("url_path")
        .or_else(|| component.get("action"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| component.get("path").and_then(|v| v.as_str()).unwrap_or("<unknown>"));
    let method = component.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
    format!("{}:{}:{}", normalise_key(class), method.to_ascii_uppercase(), normalise_path(target))
}

fn route_source_id(
    source: &str,
    repo: Option<&str>,
    method: &str,
    path: &str,
    file: Option<&str>,
    line: Option<i64>,
) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}",
        source,
        repo.unwrap_or("*"),
        method.to_ascii_uppercase(),
        normalise_path(path),
        file.unwrap_or("*"),
        line.map(|l| l.to_string()).unwrap_or_else(|| "*".to_string())
    )
}

fn matching_signal_ids(
    repo: Option<&str>,
    path: Option<&str>,
    line: Option<i64>,
    signals: &[NyxSignalRecord],
) -> Vec<String> {
    let Some(path) = path else {
        return Vec::new();
    };
    signals
        .iter()
        .filter(|signal| repo.map(|repo| repo == signal.repo).unwrap_or(true))
        .filter(|signal| signal.path == path)
        .filter(|signal| match (line, signal.line) {
            (Some(a), Some(b)) => (a - b).abs() <= SOURCE_LINE_WINDOW,
            _ => true,
        })
        .map(|signal| signal.id.clone())
        .collect()
}

fn looks_like_bundle_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/dist/")
        || lower.contains("/build/")
        || lower.contains("/public/")
        || lower.contains("/assets/")
        || lower.contains("bundle")
        || lower.contains(".min.")
}

fn normalise_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        if let Ok(url) = reqwest::Url::parse(trimmed) {
            return url.path().trim_end_matches('/').to_ascii_lowercase();
        }
    }
    let path = trimmed.split('?').next().unwrap_or(trimmed).trim_end_matches('/');
    if path.is_empty() || path == "(current page)" || path.starts_with('/') {
        path.to_ascii_lowercase()
    } else {
        format!("/{}", path.to_ascii_lowercase())
    }
}

fn normalise_key(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace('\\', "/")
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" | "informational" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nyctos_core::store::RunRecord;

    #[tokio::test]
    async fn synthesizes_deduped_candidate_with_source_attribution() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        store.projects().create("project-1", "acme", None, None, None, 1).await.unwrap();
        store
            .runs()
            .insert(&RunRecord {
                id: "run-weak-1".to_string(),
                project_id: Some("project-1".to_string()),
                kind: "Scan".to_string(),
                started_at: 2_000,
                finished_at: None,
                status: "Running".to_string(),
                triggered_by: "Manual".to_string(),
                git_ref: None,
                parent_run_id: None,
                wall_clock_ms: None,
                total_ai_spend_usd_micros: 0,
            })
            .await
            .unwrap();

        let route_model = RouteModel {
            backend_routes: vec![RouteModelEndpoint {
                method: "GET".to_string(),
                path: "/api/admin/debug".to_string(),
                repo: Some("api".to_string()),
                handler_file: Some("src/routes.rs".to_string()),
                line: Some(42),
                params: Vec::new(),
                middleware: Vec::new(),
                auth_checks: Vec::new(),
                role_checks: Vec::new(),
                body_fields: Vec::new(),
                state_changing: false,
                confidence: 0.8,
                evidence: Vec::new(),
                ..RouteModelEndpoint::default()
            }],
            api_client_calls: vec![ApiClientCallModel {
                method: "GET".to_string(),
                path: "/api/admin/debug".to_string(),
                repo: Some("web".to_string()),
                file: Some("dist/app.min.js".to_string()),
                line: Some(1),
                confidence: 0.58,
                evidence: Vec::new(),
            }],
            ..RouteModel::default()
        };

        let persisted = synthesize_weak_signal_candidates(
            &store,
            "run-weak-1",
            "project-1",
            &route_model,
            &RunConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(persisted, 2);
        let candidates = store.pentest_candidates().list_by_run("run-weak-1").await.unwrap();
        assert_eq!(candidates.len(), 2);
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.vuln_class == "ADMIN_SURFACE")
            .expect("admin candidate");
        assert_eq!(candidate.vuln_class, "ADMIN_SURFACE");
        assert!(candidate.source.contains("RouteDiscovery"));
        assert!(candidate.source.contains("JavaScriptBundle"));
        assert_eq!(candidate.status, "NeedsLiveTest");
        assert!(candidate.source_ids.len() >= 2);
        assert!(candidate.hypothesis.contains("live verification"));
    }

    #[tokio::test]
    async fn research_mode_adds_product_invariant_hypotheses_normal_mode_does_not() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path()).await.unwrap();
        store.projects().create("project-1", "acme", None, None, None, 1).await.unwrap();
        store.runs().insert(&run_record("run-normal")).await.unwrap();
        store.runs().insert(&run_record("run-research")).await.unwrap();

        let route_model = RouteModel {
            backend_routes: vec![
                research_route(
                    "POST",
                    "/api/billing/subscriptions/{subscription_id}/downgrade",
                    true,
                    &["require_user"],
                    &["plan_id", "effective_at"],
                ),
                research_route(
                    "POST",
                    "/api/orgs/{org_id}/invites",
                    true,
                    &["require_user"],
                    &["email", "role", "expires_at"],
                ),
                research_route(
                    "POST",
                    "/api/jobs/export",
                    true,
                    &["require_user"],
                    &["format", "callback_url"],
                ),
            ],
            ..RouteModel::default()
        };

        let normal = synthesize_weak_signal_candidates(
            &store,
            "run-normal",
            "project-1",
            &route_model,
            &RunConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(normal, 0, "fixture routes should not produce normal weak-signal candidates");

        store
            .pentest_candidates()
            .insert(&PentestCandidateRecord {
                id: "pc-memory-invite".to_string(),
                run_id: "run-research".to_string(),
                project_id: "project-1".to_string(),
                source: "ZAPBaseline".to_string(),
                source_ids: vec!["zap:/api/orgs/{org_id}/invites".to_string()],
                title: "Invite endpoint observed during crawl".to_string(),
                vuln_class: "INTERNAL_SURFACE".to_string(),
                severity_guess: "Medium".to_string(),
                affected_components: vec![serde_json::json!({
                    "kind": "route",
                    "method": "POST",
                    "url_path": "/api/orgs/{org_id}/invites",
                    "repo": "api"
                })],
                hypothesis: "Crawler found an invite transition; check role and replay handling."
                    .to_string(),
                test_plan: "existing scanner lead".to_string(),
                status: "NeedsLiveTest".to_string(),
                rejection_reason: None,
                confidence: 0.58,
                trace_id: None,
                created_at: 10,
                updated_at: 10,
            })
            .await
            .unwrap();

        let research_config = RunConfig { research_mode_enabled: true, ..RunConfig::default() };
        let research = synthesize_weak_signal_candidates(
            &store,
            "run-research",
            "project-1",
            &route_model,
            &research_config,
        )
        .await
        .unwrap();
        assert!(research >= 3, "research mode should add invariant hypotheses");

        let rows = store.pentest_candidates().list_by_run("run-research").await.unwrap();
        let research_rows =
            rows.iter().filter(|row| row.source == RESEARCH_SOURCE).collect::<Vec<_>>();
        assert!(!research_rows.is_empty(), "expected ResearchMode candidates");
        assert!(research_rows.iter().any(|row| row.vuln_class == "ENTITLEMENT_MISMATCH"));
        assert!(research_rows
            .iter()
            .any(|row| row.vuln_class == "INVITE_OR_MEMBERSHIP_TRANSITION"));
        assert!(research_rows.iter().any(|row| row.vuln_class == "BACKGROUND_JOB_SIDE_EFFECT"));
        assert!(research_rows
            .iter()
            .any(|row| { row.source_ids.iter().any(|id| id.contains("pc-memory-invite")) }));
        assert!(research_rows.iter().any(|row| {
            row.affected_components.iter().any(|component| {
                component
                    .get("research_mode_provenance")
                    .and_then(|p| p.get("version"))
                    .and_then(|v| v.as_str())
                    == Some(RESEARCH_MODE_VERSION)
            })
        }));
    }

    fn run_record(id: &str) -> RunRecord {
        RunRecord {
            id: id.to_string(),
            project_id: Some("project-1".to_string()),
            kind: "Scan".to_string(),
            started_at: 2_000,
            finished_at: None,
            status: "Running".to_string(),
            triggered_by: "Manual".to_string(),
            git_ref: None,
            parent_run_id: None,
            wall_clock_ms: None,
            total_ai_spend_usd_micros: 0,
        }
    }

    fn research_route(
        method: &str,
        path: &str,
        state_changing: bool,
        auth_checks: &[&str],
        body_fields: &[&str],
    ) -> RouteModelEndpoint {
        RouteModelEndpoint {
            method: method.to_string(),
            path: path.to_string(),
            repo: Some("api".to_string()),
            handler_file: Some("src/routes.rs".to_string()),
            line: Some(42),
            params: Vec::new(),
            middleware: Vec::new(),
            auth_checks: auth_checks.iter().map(|s| (*s).to_string()).collect(),
            role_checks: Vec::new(),
            body_fields: body_fields.iter().map(|s| (*s).to_string()).collect(),
            state_changing,
            confidence: 0.82,
            evidence: Vec::new(),
            ..RouteModelEndpoint::default()
        }
    }
}
