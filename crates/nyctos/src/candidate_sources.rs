use std::collections::{BTreeMap, BTreeSet};

use nyctos_core::store::{finding_id_hash, NyxSignalRecord, PentestCandidateRecord, Store};
use nyctos_types::product::{ApiClientCallModel, FormModel, RouteModel, RouteModelEndpoint};

use crate::pentest_tools;

const SOURCE_LINE_WINDOW: i64 = 80;

pub async fn synthesize_weak_signal_candidates(
    store: &Store,
    run_id: &str,
    project_id: &str,
    route_model: &RouteModel,
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
            confidence: 0.48 + form.confidence.min(1.0) * 0.08,
        });
    }
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
            test_plan: "Derive a safe live HTTP/browser confirmation from the combined weak signals; do not report as verified without live evidence.".to_string(),
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
    if path.is_empty() || path == "(current page)" {
        path.to_ascii_lowercase()
    } else if path.starts_with('/') {
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

        let persisted =
            synthesize_weak_signal_candidates(&store, "run-weak-1", "project-1", &route_model)
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
}
