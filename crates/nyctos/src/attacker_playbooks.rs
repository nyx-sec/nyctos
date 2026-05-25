use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use nyctos_core::store::{finding_id_hash, PentestCandidateRecord, Store};
use nyctos_types::product::{
    ApiClientCallModel, FormModel, FrontendRouteModel, RouteModel, RouteModelEndpoint,
};
use serde_json::{json, Value};

use crate::pentest_tools;

const PLAYBOOK_SOURCE: &str = "AttackerPlaybook";
const MAX_PLAYBOOK_CANDIDATES: usize = 120;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AttackerPlaybookReport {
    pub candidates_generated: u32,
    pub candidates_persisted: u32,
}

impl AttackerPlaybookReport {
    pub fn summary(&self) -> String {
        format!(
            "attacker playbooks generated {} lead(s), persisted or updated {}",
            self.candidates_generated, self.candidates_persisted
        )
    }
}

pub async fn synthesize_attacker_playbook_candidates(
    store: &Store,
    run_id: &str,
    project_id: &str,
    route_model: &RouteModel,
) -> anyhow::Result<AttackerPlaybookReport> {
    let candidates = generate_attacker_playbook_candidates(run_id, project_id, route_model);
    let candidates_generated = candidates.len() as u32;
    let candidates_persisted =
        pentest_tools::persist_pentest_candidates_deduped(store, candidates).await?;
    Ok(AttackerPlaybookReport { candidates_generated, candidates_persisted })
}

pub fn generate_attacker_playbook_candidates(
    run_id: &str,
    project_id: &str,
    route_model: &RouteModel,
) -> Vec<PentestCandidateRecord> {
    let mut drafts = PlaybookDrafts::default();

    for route in &route_model.backend_routes {
        add_surface_playbook_leads(&mut drafts, EndpointSurface::from_route(route));
    }
    for call in &route_model.api_client_calls {
        add_surface_playbook_leads(&mut drafts, EndpointSurface::from_api_client(call));
    }
    for form in &route_model.forms {
        add_surface_playbook_leads(&mut drafts, EndpointSurface::from_form(form));
    }
    for frontend in &route_model.frontend_routes {
        add_surface_playbook_leads(&mut drafts, EndpointSurface::from_frontend_route(frontend));
    }

    let mut candidates = drafts.into_records(run_id, project_id);
    candidates.sort_by(candidate_rank_order);
    candidates.truncate(MAX_PLAYBOOK_CANDIDATES);
    candidates
}

fn add_surface_playbook_leads(drafts: &mut PlaybookDrafts, surface: EndpointSurface) {
    add_admin_debug_lead(drafts, &surface);
    add_open_redirect_leads(drafts, &surface);
    add_ssrf_leads(drafts, &surface);
    add_file_flow_leads(drafts, &surface);
    add_webhook_lead(drafts, &surface);
    add_tenant_isolation_lead(drafts, &surface);
    add_cors_lead(drafts, &surface);
    add_client_injection_lead(drafts, &surface);
    add_business_logic_abuse_lead(drafts, &surface);
}

fn add_admin_debug_lead(drafts: &mut PlaybookDrafts, surface: &EndpointSurface) {
    let lower = surface.lower_path();
    let matched = [
        "admin", "debug", "dev", "internal", "config", "swagger", "openapi", "actuator", "metrics",
    ]
    .into_iter()
    .filter(|needle| lower.contains(needle))
    .map(str::to_string)
    .collect::<Vec<_>>();
    if matched.is_empty() {
        return;
    }

    let missing_auth = surface.auth_checks.is_empty() && surface.role_checks.is_empty();
    let severity = if missing_auth && contains_any(&lower, &["admin", "debug", "internal"]) {
        "High"
    } else if lower.contains("metrics") {
        "Low"
    } else {
        "Medium"
    };
    let confidence = bounded_confidence(
        0.48 + surface.confidence.min(1.0) * 0.2
            + (matched.len() as f64).min(3.0) * 0.03
            + if missing_auth { 0.05 } else { 0.0 },
    );
    let impact = if lower.contains("admin") {
        80
    } else if contains_any(&lower, &["debug", "internal", "config"]) {
        76
    } else {
        62
    };
    drafts.add(PlaybookLead {
        class: "ADMIN_DEBUG_EXPOSURE".to_string(),
        title: format!("Admin/debug exposure lead: {} {}", surface.method, surface.path),
        severity: severity.to_string(),
        impact,
        confidence,
        source_id_suffix: None,
        component: surface.component(
            "admin_debug_exposure",
            None,
            json!({
                "matched_markers": matched,
                "auth_evidence": auth_evidence(surface),
                "safe_probe_hint": if surface.is_read_only() {
                    "read-only baseline comparison"
                } else {
                    "state-changing route; planner should emit a no-plan reason"
                },
                "chain_hints": ["admin surface", "debug data", "auth bypass calibration"],
            }),
        ),
        hypothesis: format!(
            "{} {} has admin/debug/internal markers. This is an unverified exposure lead; live validation must prove reachable sensitive behavior before reporting it.",
            surface.method, surface.path
        ),
    });
}

fn add_open_redirect_leads(drafts: &mut PlaybookDrafts, surface: &EndpointSurface) {
    for param in surface.all_params().into_iter().filter(|param| param_looks_redirectish(param)) {
        let confidence = bounded_confidence(
            0.5 + surface.confidence.min(1.0) * 0.18
                + if surface.is_read_only() { 0.06 } else { 0.0 }
                + if surface.lower_path().contains("callback") { 0.04 } else { 0.0 },
        );
        drafts.add(PlaybookLead {
            class: "OPEN_REDIRECT".to_string(),
            title: format!(
                "Open redirect parameter lead: {} {} `{}`",
                surface.method, surface.path, param
            ),
            severity: "Medium".to_string(),
            impact: 68,
            confidence,
            source_id_suffix: Some(param.clone()),
            component: surface.component(
                "open_redirect",
                Some(&param),
                json!({
                    "param_role": "redirect_target",
                    "safe_probe_hint": "append an off-site URL and require a Location-header oracle",
                    "chain_hints": ["login callback", "token leakage", "phishing redirect"],
                }),
            ),
            hypothesis: format!(
                "{} {} accepts redirect-like parameter `{}`. This is an unverified lead until a same-origin request proves an attacker-controlled Location header.",
                surface.method, surface.path, param
            ),
        });
    }
}

fn add_ssrf_leads(drafts: &mut PlaybookDrafts, surface: &EndpointSurface) {
    let lower = surface.lower_path();
    let params = surface.all_params();
    let mut matched_params =
        params.into_iter().filter(|param| param_looks_url_fetchish(param)).collect::<Vec<_>>();
    if matched_params.is_empty() && path_looks_url_fetchish(&lower) {
        matched_params.push("url".to_string());
    }
    if matched_params.is_empty() || !path_looks_url_fetchish(&lower) {
        return;
    }
    matched_params.sort();
    matched_params.dedup();

    for param in matched_params {
        drafts.add(PlaybookLead {
            class: "SSRF".to_string(),
            title: format!(
                "SSRF-like fetch/proxy lead: {} {} `{}`",
                surface.method, surface.path, param
            ),
            severity: "High".to_string(),
            impact: 86,
            confidence: bounded_confidence(0.54 + surface.confidence.min(1.0) * 0.2),
            source_id_suffix: Some(param.clone()),
            component: surface.component(
                "ssrf_url_fetch",
                Some(&param),
                json!({
                    "param_role": "server_side_url_or_callback",
                    "safe_probe_hint": "no live probe without an in-scope callback or seeded local target",
                    "chain_hints": ["metadata access", "internal service reachability", "webhook callback trust"],
                }),
            ),
            hypothesis: format!(
                "{} {} combines fetch/proxy route shape with URL-like input `{}`. This remains an unverified SSRF-style lead until a scoped callback oracle exists.",
                surface.method, surface.path, param
            ),
        });
    }
}

fn add_file_flow_leads(drafts: &mut PlaybookDrafts, surface: &EndpointSurface) {
    let lower = surface.lower_path();
    let params = surface.all_params();
    let file_params =
        params.into_iter().filter(|param| param_looks_fileish(param)).collect::<Vec<_>>();
    let path_fileish = path_looks_fileish(&lower);
    if !path_fileish && file_params.is_empty() {
        return;
    }

    let upload_like = !surface.is_read_only()
        || contains_any(&lower, &["upload", "import", "avatar", "attachment", "media"]);
    let (class, title_kind, severity, impact, safe_probe_hint) = if upload_like {
        (
            "FILE_UPLOAD_FLOW",
            "File upload/import flow lead",
            "High",
            78,
            "state-changing upload/import; planner should emit a no-plan reason",
        )
    } else {
        (
            "FILE_DOWNLOAD_FLOW",
            "File download/export flow lead",
            "High",
            82,
            "read-only filename/path variation with a strong content oracle",
        )
    };
    let param = file_params.first().cloned();
    drafts.add(PlaybookLead {
        class: class.to_string(),
        title: format!("{title_kind}: {} {}", surface.method, surface.path),
        severity: severity.to_string(),
        impact,
        confidence: bounded_confidence(
            0.5
                + surface.confidence.min(1.0) * 0.2
                + if param.is_some() { 0.06 } else { 0.0 },
        ),
        source_id_suffix: param.clone(),
        component: surface.component(
            if upload_like { "file_upload_flow" } else { "file_download_flow" },
            param.as_deref(),
            json!({
                "file_params": file_params,
                "safe_probe_hint": safe_probe_hint,
                "chain_hints": ["file permission bypass", "path traversal", "stored content abuse"],
            }),
        ),
        hypothesis: format!(
            "{} {} has file upload/download route shape. This is an unverified lead; live validation must stay read-only unless an explicit seeded upload harness exists.",
            surface.method, surface.path
        ),
    });
}

fn add_webhook_lead(drafts: &mut PlaybookDrafts, surface: &EndpointSurface) {
    let lower = surface.lower_path();
    let indicators = surface
        .all_params()
        .into_iter()
        .filter(|param| param_looks_webhook_trustish(param))
        .collect::<Vec<_>>();
    let webhook_path = contains_any(&lower, &["webhook", "webhooks", "/hooks", "/events"]);
    let provider_callback = lower.contains("callback")
        && !contains_any(&lower, &["/auth/", "oauth", "login", "sso"])
        && (!indicators.is_empty()
            || contains_any(&lower, &["stripe", "github", "slack", "twilio", "shopify", "paypal"]));
    if !webhook_path && !provider_callback {
        return;
    }
    drafts.add(PlaybookLead {
        class: "WEBHOOK_TRUST".to_string(),
        title: format!("Webhook trust-boundary lead: {} {}", surface.method, surface.path),
        severity: "High".to_string(),
        impact: 88,
        confidence: bounded_confidence(
            0.5
                + surface.confidence.min(1.0) * 0.2
                + if indicators.is_empty() { 0.0 } else { 0.06 },
        ),
        source_id_suffix: None,
        component: surface.component(
            "webhook_trust",
            None,
            json!({
                "signature_or_trust_indicators": indicators,
                "safe_probe_hint": "no synthetic callback event unless a seeded harmless webhook fixture exists",
                "chain_hints": ["signature bypass", "event replay", "payment or account state mutation"],
            }),
        ),
        hypothesis: format!(
            "{} {} looks like a webhook/callback boundary. This is an unverified trust lead; validation must prove unsigned/replayed events are accepted before reporting.",
            surface.method, surface.path
        ),
    });
}

fn add_tenant_isolation_lead(drafts: &mut PlaybookDrafts, surface: &EndpointSurface) {
    let lower = surface.lower_path();
    let id_params = surface
        .all_params()
        .into_iter()
        .filter(|param| param_looks_tenant_or_owner_id(param))
        .collect::<Vec<_>>();
    let path_scoped = contains_any(
        &lower,
        &[
            "tenant",
            "account",
            "accounts",
            "user",
            "users",
            "org",
            "organization",
            "workspace",
            "team",
            "customer",
            "project",
        ],
    );
    if id_params.is_empty() && !path_scoped {
        return;
    }
    drafts.add(PlaybookLead {
        class: "TENANT_ISOLATION".to_string(),
        title: format!("Tenant/account isolation lead: {} {}", surface.method, surface.path),
        severity: "High".to_string(),
        impact: 90,
        confidence: bounded_confidence(
            0.5
                + surface.confidence.min(1.0) * 0.2
                + if id_params.is_empty() { 0.0 } else { 0.08 }
                + if surface.auth_checks.is_empty() { 0.03 } else { 0.0 },
        ),
        source_id_suffix: id_params.first().cloned(),
        component: surface.component(
            "tenant_account_isolation",
            id_params.first().map(String::as_str),
            json!({
                "tenant_or_owner_params": id_params,
                "auth_evidence": auth_evidence(surface),
                "safe_probe_hint": "read-only owner-versus-peer comparison using configured test objects",
                "chain_hints": ["IDOR", "tenant breakout", "role confusion"],
            }),
        ),
        hypothesis: format!(
            "{} {} appears scoped by tenant/account/user/org identifiers. This is an unverified isolation lead until role-separated live validation confirms cross-account access.",
            surface.method, surface.path
        ),
    });
}

fn add_cors_lead(drafts: &mut PlaybookDrafts, surface: &EndpointSurface) {
    if !surface.is_read_only() {
        return;
    }
    let lower = surface.lower_path();
    let cors_relevant = surface.method == "OPTIONS"
        || contains_any(
            &lower,
            &[
                "/api/", "auth", "account", "user", "tenant", "admin", "profile", "session",
                "settings",
            ],
        );
    if !cors_relevant {
        return;
    }
    drafts.add(PlaybookLead {
        class: "CORS_MISCONFIG".to_string(),
        title: format!("CORS policy lead: {} {}", surface.method, surface.path),
        severity: "Medium".to_string(),
        impact: 63,
        confidence: bounded_confidence(0.46 + surface.confidence.min(1.0) * 0.18),
        source_id_suffix: None,
        component: surface.component(
            "cors_policy",
            None,
            json!({
                "param_role": "origin_header",
                "safe_probe_hint": "send a read-only request with an untrusted Origin header",
                "chain_hints": ["session data exfiltration", "credentialed API read"],
            }),
        ),
        hypothesis: format!(
            "{} {} is a CORS-relevant endpoint. This is an unverified lead until headers show an untrusted origin is allowed.",
            surface.method, surface.path
        ),
    });
}

fn add_client_injection_lead(drafts: &mut PlaybookDrafts, surface: &EndpointSurface) {
    let lower = surface.lower_path();
    let params = surface
        .all_params()
        .into_iter()
        .filter(|param| param_looks_client_injectionish(param))
        .collect::<Vec<_>>();
    if params.is_empty() && !contains_any(&lower, &["search", "preview", "render"]) {
        return;
    }
    if !surface.is_browser_surface() {
        return;
    }
    drafts.add(PlaybookLead {
        class: "CLIENT_SIDE_INJECTION".to_string(),
        title: format!("Client-side injection lead: {} {}", surface.method, surface.path),
        severity: "Medium".to_string(),
        impact: 61,
        confidence: bounded_confidence(
            0.44
                + surface.confidence.min(1.0) * 0.16
                + if params.is_empty() { 0.0 } else { 0.06 },
        ),
        source_id_suffix: params.first().cloned(),
        component: surface.component(
            "client_side_injection",
            params.first().map(String::as_str),
            json!({
                "client_controlled_params": params,
                "safe_probe_hint": "browser-only inert marker injection with DOM oracle",
                "chain_hints": ["DOM XSS", "open redirect handoff", "token exfiltration"],
            }),
        ),
        hypothesis: format!(
            "{} {} has client-controlled search/render input. This is an unverified client-side injection lead until browser validation observes execution or DOM reflection.",
            surface.method, surface.path
        ),
    });
}

fn add_business_logic_abuse_lead(drafts: &mut PlaybookDrafts, surface: &EndpointSurface) {
    let lower = surface.lower_text();
    if !contains_any(
        &lower,
        &[
            "credit",
            "credits",
            "coupon",
            "discount",
            "price",
            "billing",
            "payment",
            "checkout",
            "subscription",
            "plan",
            "quantity",
            "refund",
            "invoice",
        ],
    ) {
        return;
    }
    drafts.add(PlaybookLead {
        class: "BUSINESS_LOGIC_ABUSE".to_string(),
        title: format!("Credits/payment logic lead: {} {}", surface.method, surface.path),
        severity: "High".to_string(),
        impact: 74,
        confidence: bounded_confidence(0.45 + surface.confidence.min(1.0) * 0.18),
        source_id_suffix: None,
        component: surface.component(
            "credits_payment_business_logic",
            None,
            json!({
                "safe_probe_hint": "no live payment/credit mutation without disposable seeded state",
                "chain_hints": ["coupon replay", "price tampering", "credit exhaustion bypass"],
            }),
        ),
        hypothesis: format!(
            "{} {} touches credits/payment/pricing semantics. This is an unverified business-logic lead; Nyctos must not mutate customer/payment state for validation.",
            surface.method, surface.path
        ),
    });
}

#[derive(Debug, Clone)]
struct EndpointSurface {
    source_kind: String,
    method: String,
    path: String,
    repo: Option<String>,
    file: Option<String>,
    line: Option<i64>,
    params: Vec<String>,
    query_params: Vec<String>,
    body_fields: Vec<String>,
    form_fields: Vec<String>,
    auth_checks: Vec<String>,
    role_checks: Vec<String>,
    state_changing: bool,
    confidence: f64,
    evidence_count: usize,
}

impl EndpointSurface {
    fn from_route(route: &RouteModelEndpoint) -> Self {
        let query_params = query_param_names(&route.path);
        Self {
            source_kind: "route".to_string(),
            method: route.method.to_ascii_uppercase(),
            path: path_without_query(&route.path),
            repo: route.repo.clone(),
            file: route.handler_file.clone(),
            line: route.line,
            params: route.params.clone(),
            query_params,
            body_fields: route.body_fields.clone(),
            form_fields: Vec::new(),
            auth_checks: route.auth_checks.clone(),
            role_checks: route.role_checks.clone(),
            state_changing: route.state_changing,
            confidence: route.confidence,
            evidence_count: route.evidence.len().max(1),
        }
    }

    fn from_api_client(call: &ApiClientCallModel) -> Self {
        let query_params = query_param_names(&call.path);
        let method = call.method.to_ascii_uppercase();
        Self {
            source_kind: "api_client".to_string(),
            method: method.clone(),
            path: path_without_query(&call.path),
            repo: call.repo.clone(),
            file: call.file.clone(),
            line: call.line,
            params: Vec::new(),
            query_params,
            body_fields: Vec::new(),
            form_fields: Vec::new(),
            auth_checks: Vec::new(),
            role_checks: Vec::new(),
            state_changing: !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS"),
            confidence: call.confidence,
            evidence_count: call.evidence.len().max(1),
        }
    }

    fn from_form(form: &FormModel) -> Self {
        let query_params = query_param_names(&form.action);
        Self {
            source_kind: "form".to_string(),
            method: form.method.to_ascii_uppercase(),
            path: path_without_query(&form.action),
            repo: form.repo.clone(),
            file: form.file.clone(),
            line: form.line,
            params: Vec::new(),
            query_params,
            body_fields: Vec::new(),
            form_fields: form.fields.clone(),
            auth_checks: form.csrf_markers.clone(),
            role_checks: Vec::new(),
            state_changing: form.state_changing,
            confidence: form.confidence,
            evidence_count: form.evidence.len().max(1),
        }
    }

    fn from_frontend_route(route: &FrontendRouteModel) -> Self {
        Self {
            source_kind: "frontend_route".to_string(),
            method: "GET".to_string(),
            path: route.path.clone(),
            repo: route.repo.clone(),
            file: route.file.clone(),
            line: route.line,
            params: route_params(&route.path),
            query_params: query_param_names(&route.path),
            body_fields: Vec::new(),
            form_fields: Vec::new(),
            auth_checks: Vec::new(),
            role_checks: Vec::new(),
            state_changing: false,
            confidence: route.confidence,
            evidence_count: route.evidence.len().max(1),
        }
    }

    fn is_read_only(&self) -> bool {
        !self.state_changing && matches!(self.method.as_str(), "GET" | "HEAD" | "OPTIONS")
    }

    fn is_browser_surface(&self) -> bool {
        matches!(self.source_kind.as_str(), "form" | "frontend_route") || self.method == "GET"
    }

    fn all_params(&self) -> Vec<String> {
        let mut params = Vec::new();
        params.extend(self.params.clone());
        params.extend(self.query_params.clone());
        params.extend(self.body_fields.clone());
        params.extend(self.form_fields.clone());
        params.sort_by_key(|param| param.to_ascii_lowercase());
        params.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        params
    }

    fn lower_path(&self) -> String {
        self.path.to_ascii_lowercase()
    }

    fn lower_text(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.path,
            self.params.join(" "),
            self.query_params.join(" "),
            self.body_fields.join(" "),
            self.form_fields.join(" ")
        )
        .to_ascii_lowercase()
    }

    fn component(&self, playbook: &str, param: Option<&str>, extra: Value) -> Value {
        let mut component = json!({
            "kind": self.source_kind.as_str(),
            "source": PLAYBOOK_SOURCE,
            "playbook": playbook,
            "lead_status": "unverified",
            "repo": self.repo,
            "method": self.method,
            "url_path": self.path,
            "path": self.file,
            "line": self.line,
            "params": self.params,
            "query_params": self.query_params,
            "body_fields": self.body_fields,
            "form_fields": self.form_fields,
            "auth_checks": self.auth_checks,
            "role_checks": self.role_checks,
            "state_changing": self.state_changing,
            "route_confidence": self.confidence,
            "route_evidence_count": self.evidence_count,
        });
        if let Some(param) = param {
            component["param"] = json!(param);
        }
        if let Some(obj) = component.as_object_mut() {
            if let Some(extra_obj) = extra.as_object() {
                for (key, value) in extra_obj {
                    obj.insert(key.clone(), value.clone());
                }
            }
        }
        component
    }

    fn source_id(&self, class: &str, suffix: Option<&str>) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            PLAYBOOK_SOURCE,
            class,
            self.source_kind,
            self.repo.as_deref().unwrap_or("*"),
            self.method,
            normalise_path(&self.path),
            suffix.unwrap_or("*")
        )
    }
}

#[derive(Debug, Clone)]
struct PlaybookLead {
    class: String,
    title: String,
    severity: String,
    impact: u16,
    confidence: f64,
    source_id_suffix: Option<String>,
    component: Value,
    hypothesis: String,
}

#[derive(Default)]
struct PlaybookDrafts {
    by_key: BTreeMap<String, PlaybookDraft>,
}

impl PlaybookDrafts {
    fn add(&mut self, lead: PlaybookLead) {
        let key = playbook_key(&lead.class, &lead.component);
        self.by_key.entry(key).or_insert_with(|| PlaybookDraft::new(&lead)).merge(lead);
    }

    fn into_records(self, run_id: &str, project_id: &str) -> Vec<PentestCandidateRecord> {
        let now_ms = nyctos_core::now_epoch_ms();
        self.by_key
            .into_iter()
            .map(|(key, draft)| draft.into_record(run_id, project_id, &key, now_ms))
            .collect()
    }
}

struct PlaybookDraft {
    title: String,
    class: String,
    severity: String,
    impact: u16,
    confidence: f64,
    rank_score: f64,
    source_ids: BTreeSet<String>,
    components: Vec<Value>,
    component_keys: BTreeSet<String>,
    hypotheses: Vec<String>,
}

impl PlaybookDraft {
    fn new(lead: &PlaybookLead) -> Self {
        Self {
            title: lead.title.clone(),
            class: lead.class.clone(),
            severity: lead.severity.clone(),
            impact: lead.impact,
            confidence: 0.0,
            rank_score: 0.0,
            source_ids: BTreeSet::new(),
            components: Vec::new(),
            component_keys: BTreeSet::new(),
            hypotheses: Vec::new(),
        }
    }

    fn merge(&mut self, lead: PlaybookLead) {
        let evidence_score = route_evidence_score(&lead.component);
        let rank_score = lead.impact as f64 + (lead.confidence * 20.0) + evidence_score;
        if rank_score > self.rank_score
            || (rank_score == self.rank_score
                && severity_rank(&lead.severity) > severity_rank(&self.severity))
        {
            self.title = lead.title.clone();
        }
        if severity_rank(&lead.severity) > severity_rank(&self.severity) {
            self.severity = lead.severity.clone();
        }
        self.impact = self.impact.max(lead.impact);
        self.confidence = self.confidence.max(lead.confidence).min(0.86);
        self.rank_score = self.rank_score.max(rank_score);

        if let Some(surface) = surface_from_component(&lead.component) {
            self.source_ids
                .insert(surface.source_id(&lead.class, lead.source_id_suffix.as_deref()));
        }
        let component_key = serde_json::to_string(&lead.component).unwrap_or_default();
        if self.component_keys.insert(component_key) {
            self.components.push(lead.component);
        }
        if !self.hypotheses.iter().any(|h| h == &lead.hypothesis) {
            self.hypotheses.push(lead.hypothesis);
        }
    }

    fn into_record(
        self,
        run_id: &str,
        project_id: &str,
        key: &str,
        now_ms: i64,
    ) -> PentestCandidateRecord {
        let source_ids = self.source_ids.into_iter().collect::<Vec<_>>();
        let mut components = self.components;
        for component in &mut components {
            if let Some(obj) = component.as_object_mut() {
                obj.insert("playbook_rank_score".to_string(), json!(round_score(self.rank_score)));
                obj.insert("impact_score".to_string(), json!(self.impact));
                obj.insert("source_ids".to_string(), json!(source_ids));
            }
        }
        PentestCandidateRecord {
            id: format!(
                "pc-playbook-{}",
                finding_id_hash(run_id, key, None, &self.class, PLAYBOOK_SOURCE)
            ),
            run_id: run_id.to_string(),
            project_id: project_id.to_string(),
            source: PLAYBOOK_SOURCE.to_string(),
            source_ids,
            title: self.title,
            vuln_class: self.class,
            severity_guess: self.severity,
            affected_components: components,
            hypothesis: self.hypotheses.join("\n"),
            test_plan: "Derive a safe route-scoped live plan from this deterministic attacker playbook lead; if no safe scoped probe exists, emit a structured no-plan reason. This remains an unverified lead until live validation confirms it.".to_string(),
            status: "NeedsLiveTest".to_string(),
            rejection_reason: None,
            confidence: self.confidence,
            trace_id: None,
            created_at: now_ms,
            updated_at: now_ms,
        }
    }
}

fn surface_from_component(component: &Value) -> Option<EndpointSurface> {
    let obj = component.as_object()?;
    let method = obj.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string();
    Some(EndpointSurface {
        source_kind: obj.get("kind").and_then(|v| v.as_str()).unwrap_or("component").to_string(),
        method,
        path: obj.get("url_path").and_then(|v| v.as_str()).unwrap_or("/").to_string(),
        repo: obj.get("repo").and_then(|v| v.as_str()).map(str::to_string),
        file: obj.get("path").and_then(|v| v.as_str()).map(str::to_string),
        line: obj.get("line").and_then(|v| v.as_i64()),
        params: string_array(component, "params"),
        query_params: string_array(component, "query_params"),
        body_fields: string_array(component, "body_fields"),
        form_fields: string_array(component, "form_fields"),
        auth_checks: string_array(component, "auth_checks"),
        role_checks: string_array(component, "role_checks"),
        state_changing: obj.get("state_changing").and_then(|v| v.as_bool()).unwrap_or(false),
        confidence: obj.get("route_confidence").and_then(|v| v.as_f64()).unwrap_or(0.5),
        evidence_count: obj.get("route_evidence_count").and_then(|v| v.as_u64()).unwrap_or(1)
            as usize,
    })
}

fn playbook_key(class: &str, component: &Value) -> String {
    let method = component.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
    let path = component
        .get("url_path")
        .or_else(|| component.get("action"))
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    let param = component.get("param").and_then(|v| v.as_str()).unwrap_or("*");
    format!(
        "{}:{}:{}:{}",
        class.to_ascii_lowercase(),
        method.to_ascii_uppercase(),
        normalise_path(path),
        param.to_ascii_lowercase()
    )
}

fn candidate_rank_order(a: &PentestCandidateRecord, b: &PentestCandidateRecord) -> Ordering {
    let a_rank = candidate_rank_score(a);
    let b_rank = candidate_rank_score(b);
    b_rank
        .partial_cmp(&a_rank)
        .unwrap_or(Ordering::Equal)
        .then_with(|| severity_rank(&b.severity_guess).cmp(&severity_rank(&a.severity_guess)))
        .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap_or(Ordering::Equal))
        .then_with(|| a.vuln_class.cmp(&b.vuln_class))
        .then_with(|| a.title.cmp(&b.title))
}

fn candidate_rank_score(candidate: &PentestCandidateRecord) -> f64 {
    candidate
        .affected_components
        .iter()
        .filter_map(|component| component.get("playbook_rank_score").and_then(|v| v.as_f64()))
        .fold(0.0, f64::max)
}

fn route_evidence_score(component: &Value) -> f64 {
    let source_kind = component.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let source_score = match source_kind {
        "route" => 8.0,
        "api_client" => 5.0,
        "form" => 4.0,
        "frontend_route" => 3.0,
        _ => 2.0,
    };
    let confidence = component.get("route_confidence").and_then(|v| v.as_f64()).unwrap_or(0.5);
    let evidence_count =
        component.get("route_evidence_count").and_then(|v| v.as_u64()).unwrap_or(1).min(3) as f64;
    source_score + (confidence.min(1.0) * 10.0) + evidence_count
}

fn auth_evidence(surface: &EndpointSurface) -> Value {
    json!({
        "auth_checks": surface.auth_checks,
        "role_checks": surface.role_checks,
        "has_obvious_auth_or_role_gate": !surface.auth_checks.is_empty() || !surface.role_checks.is_empty(),
    })
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::Array(values)) => {
            values.iter().filter_map(|value| value.as_str()).map(str::to_string).collect()
        }
        Some(Value::String(value)) => vec![value.to_string()],
        _ => Vec::new(),
    }
}

fn query_param_names(raw: &str) -> Vec<String> {
    let Some((_, query)) = raw.split_once('?') else {
        return Vec::new();
    };
    let mut params = query
        .split('&')
        .filter_map(|pair| pair.split('=').next())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    params.sort_by_key(|param| param.to_ascii_lowercase());
    params.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    params
}

fn path_without_query(raw: &str) -> String {
    let path = raw.split('?').next().unwrap_or(raw).trim();
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn route_params(path: &str) -> Vec<String> {
    path.split('/')
        .filter_map(|part| {
            part.strip_prefix(':')
                .or_else(|| part.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
                .or_else(|| part.strip_prefix('<').and_then(|s| s.strip_suffix('>')))
                .map(str::to_string)
        })
        .collect()
}

fn normalise_path(raw: &str) -> String {
    let path = raw.split('?').next().unwrap_or(raw).trim().trim_end_matches('/');
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_ascii_lowercase()
    } else {
        format!("/{}", path.to_ascii_lowercase())
    }
}

fn bounded_confidence(raw: f64) -> f64 {
    raw.clamp(0.1, 0.86)
}

fn round_score(raw: f64) -> f64 {
    (raw * 100.0).round() / 100.0
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

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn param_looks_redirectish(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "next",
            "redirect",
            "redirect_uri",
            "return",
            "return_url",
            "callback",
            "continue",
            "destination",
            "url",
        ],
    )
}

fn path_looks_url_fetchish(lower_path: &str) -> bool {
    contains_any(
        lower_path,
        &[
            "fetch",
            "proxy",
            "preview",
            "render",
            "screenshot",
            "oembed",
            "metadata",
            "import-url",
            "url/import",
        ],
    )
}

fn param_looks_url_fetchish(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    matches!(lower.as_str(), "url" | "uri" | "target" | "endpoint" | "src")
        || contains_any(&lower, &["callback", "webhook", "feed", "remote", "avatar_url"])
}

fn path_looks_fileish(lower_path: &str) -> bool {
    contains_any(
        lower_path,
        &[
            "file",
            "files",
            "download",
            "upload",
            "export",
            "import",
            "attachment",
            "avatar",
            "media",
        ],
    )
}

fn param_looks_fileish(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    matches!(lower.as_str(), "file" | "filename" | "path" | "key" | "name")
        || contains_any(&lower, &["file", "path", "download", "attachment"])
}

fn param_looks_webhook_trustish(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    contains_any(
        &lower,
        &["signature", "sig", "hmac", "secret", "token", "timestamp", "event", "payload"],
    )
}

fn param_looks_tenant_or_owner_id(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower == "id"
        || lower.ends_with("_id")
        || lower.ends_with("id")
        || contains_any(
            &lower,
            &[
                "tenant",
                "account",
                "user",
                "org",
                "organization",
                "workspace",
                "team",
                "customer",
                "project",
            ],
        )
}

fn param_looks_client_injectionish(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    matches!(lower.as_str(), "q" | "query" | "search" | "html" | "content")
        || contains_any(&lower, &["message", "comment", "preview", "return", "redirect"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_planning::{LiveTestPlanSynthesisContext, LiveTestPlanSynthesizer};
    use nyctos_types::live_plan::{LiveTestPlan, NoPlanReasonCode};
    use nyctos_types::product::RouteEvidence;

    fn route(
        method: &str,
        path: &str,
        params: &[&str],
        body_fields: &[&str],
    ) -> RouteModelEndpoint {
        RouteModelEndpoint {
            method: method.to_string(),
            path: path.to_string(),
            repo: Some("api".to_string()),
            handler_file: Some(format!(
                "src/routes/{}.rs",
                path.trim_matches('/')
                    .replace('/', "_")
                    .replace(':', "_")
                    .replace('{', "")
                    .replace('}', "")
            )),
            line: Some(10),
            params: params.iter().map(|s| s.to_string()).collect(),
            middleware: Vec::new(),
            auth_checks: Vec::new(),
            role_checks: Vec::new(),
            body_fields: body_fields.iter().map(|s| s.to_string()).collect(),
            state_changing: !matches!(method, "GET" | "HEAD" | "OPTIONS"),
            confidence: 0.82,
            evidence: vec![RouteEvidence {
                path: "src/routes.rs".to_string(),
                line: Some(10),
                snippet: format!("router.{}({path})", method.to_ascii_lowercase()),
            }],
            ..RouteModelEndpoint::default()
        }
    }

    fn api_call(method: &str, path: &str) -> ApiClientCallModel {
        ApiClientCallModel {
            method: method.to_string(),
            path: path.to_string(),
            repo: Some("web".to_string()),
            file: Some("src/api.ts".to_string()),
            line: Some(4),
            confidence: 0.76,
            evidence: Vec::new(),
        }
    }

    fn form(method: &str, action: &str, fields: &[&str]) -> FormModel {
        FormModel {
            method: method.to_string(),
            action: action.to_string(),
            repo: Some("web".to_string()),
            file: Some("src/page.html".to_string()),
            line: Some(3),
            fields: fields.iter().map(|s| s.to_string()).collect(),
            csrf_markers: Vec::new(),
            state_changing: !matches!(method, "GET" | "HEAD" | "OPTIONS"),
            confidence: 0.7,
            evidence: Vec::new(),
        }
    }

    fn synthetic_model() -> RouteModel {
        RouteModel {
            backend_routes: vec![
                route("GET", "/api/admin/debug", &[], &[]),
                route("GET", "/auth/callback?next=", &[], &[]),
                route("GET", "/api/proxy?url=", &[], &[]),
                route("GET", "/api/download", &["file"], &[]),
                route("POST", "/api/uploads", &[], &["file"]),
                route("POST", "/webhooks/stripe", &[], &["signature", "event_id"]),
                route(
                    "GET",
                    "/api/tenants/{tenant_id}/users/{user_id}",
                    &["tenant_id", "user_id"],
                    &[],
                ),
                route("OPTIONS", "/api/account", &[], &[]),
            ],
            api_client_calls: vec![api_call("GET", "/api/fetch?url=")],
            forms: vec![
                form("GET", "/search", &["q"]),
                form("POST", "/api/credits/apply", &["coupon", "amount"]),
            ],
            ..RouteModel::default()
        }
    }

    #[test]
    fn generates_target_playbook_classes_from_routes_clients_and_forms() {
        let candidates =
            generate_attacker_playbook_candidates("run-playbook", "project-1", &synthetic_model());
        let classes = candidates.iter().map(|c| c.vuln_class.as_str()).collect::<BTreeSet<_>>();
        for class in [
            "ADMIN_DEBUG_EXPOSURE",
            "OPEN_REDIRECT",
            "SSRF",
            "FILE_DOWNLOAD_FLOW",
            "FILE_UPLOAD_FLOW",
            "WEBHOOK_TRUST",
            "TENANT_ISOLATION",
            "CORS_MISCONFIG",
            "CLIENT_SIDE_INJECTION",
            "BUSINESS_LOGIC_ABUSE",
        ] {
            assert!(classes.contains(class), "missing {class}; got {classes:?}");
        }
        assert!(candidates.iter().any(|c| {
            c.vuln_class == "SSRF"
                && c.affected_components.iter().any(|component| {
                    component.get("kind").and_then(|v| v.as_str()) == Some("api_client")
                })
        }));
        assert!(candidates.iter().any(|c| {
            c.vuln_class == "BUSINESS_LOGIC_ABUSE"
                && c.affected_components
                    .iter()
                    .any(|component| component.get("kind").and_then(|v| v.as_str()) == Some("form"))
        }));
    }

    #[test]
    fn ranks_playbook_candidates_in_stable_descending_order() {
        let first =
            generate_attacker_playbook_candidates("run-rank", "project-1", &synthetic_model());
        let second =
            generate_attacker_playbook_candidates("run-rank", "project-1", &synthetic_model());
        assert_eq!(
            first.iter().map(|c| (&c.vuln_class, &c.title)).collect::<Vec<_>>(),
            second.iter().map(|c| (&c.vuln_class, &c.title)).collect::<Vec<_>>()
        );
        let scores = first.iter().map(candidate_rank_score).collect::<Vec<_>>();
        assert!(scores.windows(2).all(|pair| pair[0] >= pair[1]), "{scores:?}");
        assert_eq!(first[0].vuln_class, "TENANT_ISOLATION");
    }

    #[test]
    fn safe_playbook_candidates_receive_executable_live_plans() {
        let model = synthetic_model();
        let candidates = generate_attacker_playbook_candidates("run-plan", "project-1", &model);
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
        });

        let redirect = candidates.iter().find(|c| c.vuln_class == "OPEN_REDIRECT").unwrap();
        let cors = candidates.iter().find(|c| c.vuln_class == "CORS_MISCONFIG").unwrap();
        assert!(matches!(synth.synthesize(redirect), LiveTestPlan::SingleHttp(_)));
        match synth.synthesize(cors) {
            LiveTestPlan::SingleHttp(plan) => {
                assert_eq!(
                    plan.request.headers.get("Origin").map(String::as_str),
                    Some("https://nyctos.invalid")
                );
                assert_eq!(
                    plan.oracle
                        .header_contains
                        .get("access-control-allow-origin")
                        .map(String::as_str),
                    Some("nyctos.invalid")
                );
            }
            other => panic!("expected CORS single HTTP plan, got {other:?}"),
        }
    }

    #[test]
    fn unsafe_or_ambiguous_playbooks_receive_clear_no_plan_reasons() {
        let model = synthetic_model();
        let candidates = generate_attacker_playbook_candidates("run-no-plan", "project-1", &model);
        let targets = vec!["http://localhost:3000".to_string()];
        let auth = Vec::new();
        let synth = LiveTestPlanSynthesizer::new(LiveTestPlanSynthesisContext {
            route_model: Some(&model),
            target_urls: &targets,
            auth_profiles: &auth,
            browser_checks_enabled: false,
            allow_state_changing: false,
        });

        for (class, expected_code) in [
            ("SSRF", NoPlanReasonCode::UnsafeProbe),
            ("FILE_UPLOAD_FLOW", NoPlanReasonCode::StateChangingBlocked),
            ("WEBHOOK_TRUST", NoPlanReasonCode::UnsafeProbe),
            ("BUSINESS_LOGIC_ABUSE", NoPlanReasonCode::UnsafeProbe),
            ("TENANT_ISOLATION", NoPlanReasonCode::AuthMissing),
        ] {
            let candidate = candidates.iter().find(|c| c.vuln_class == class).unwrap();
            let plan = synth.synthesize(candidate);
            let reason = plan.no_plan_reason().unwrap_or_else(|| {
                panic!("expected no-plan for {class}, got {plan:?}");
            });
            assert_eq!(reason.code, expected_code, "{class}: {reason:?}");
            assert!(!reason.message.trim().is_empty());
        }
    }

    #[test]
    fn generated_playbook_candidates_remain_unverified_leads() {
        let candidates =
            generate_attacker_playbook_candidates("run-leads", "project-1", &synthetic_model());
        assert!(!candidates.is_empty());
        for candidate in candidates {
            assert_eq!(candidate.status, "NeedsLiveTest");
            assert_ne!(candidate.status, "Verified");
            assert!(candidate.hypothesis.contains("unverified"));
            assert!(candidate.affected_components.iter().all(|component| {
                component.get("lead_status").and_then(|v| v.as_str()) == Some("unverified")
            }));
        }
    }
}
