//! End-to-end smoke tests for the loopback API.
//!
//! Each test boots the router on an ephemeral port (`127.0.0.1:0`), drives
//! it with a real `reqwest` client (HTTP) or `tokio-tungstenite` (WS),
//! then shuts down. The store and event sink are spawned per-test so
//! the suite parallelises cleanly.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::broadcast;

use nyx_agent_api::{
    build_router, AuthConfig, AuthSetupAgent, AuthSetupAgentFuture, AuthSetupAgentOutput,
    AuthSetupAgentRequest, ProjectSetupAgent, ProjectSetupAgentFuture, ProjectSetupAgentOutput,
    ProjectSetupAgentRequest, RemediationAgent, RemediationAgentFuture, RemediationAgentOutput,
    RemediationAgentRequest, RemediationChangedFile, ScanTrigger, ScanTriggerError,
    ScanTriggerSource, SeedSetupAgent, SeedSetupAgentFuture, SeedSetupAgentOutput,
    SeedSetupAgentRequest, ServerState, SetupContext,
};
use nyx_agent_core::store::{
    ChainRecord, EnvironmentRunRecord, FindingRecord, PentestCandidateRecord,
    ProjectLaunchProfileInput, RepoRecord, RunRecord, VerificationAttemptRecord,
    VerifiedVulnerabilityRecord, DEFAULT_PROJECT_ID,
};
use nyx_agent_core::{run_event_log_path, Config, SecretStore, Store};
use nyx_agent_types::event::{AgentEvent, EventSink, RepoOutcomeTag, ReproEvent, RunEvent};
use nyx_agent_types::product::{LaunchStep, ProjectSetupVerificationStatus, SeedSetupPlan};
use nyx_agent_types::project::{
    AuthSetupVerification, AuthSetupVerificationStatus, ProjectAuthMode, ProjectAuthOwnedObject,
    ProjectAuthProfile, ProjectRuntimeEnvVar,
};

struct StubScanTrigger {
    run_id: String,
}

impl ScanTrigger for StubScanTrigger {
    fn trigger<'a>(
        &'a self,
        _source: ScanTriggerSource,
        _project_id: Option<String>,
        _repo: Option<String>,
        _run_overrides: Option<nyx_agent_api::ScanRunOverrides>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
        let id = self.run_id.clone();
        Box::pin(async move { Ok(id) })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedScanCall {
    source: ScanTriggerSource,
    project_id: Option<String>,
    repo: Option<String>,
    run_overrides: Option<nyx_agent_api::ScanRunOverrides>,
}

#[derive(Default)]
struct RecordingOverridesTrigger {
    calls: tokio::sync::Mutex<Vec<RecordedScanCall>>,
}

impl ScanTrigger for RecordingOverridesTrigger {
    fn trigger<'a>(
        &'a self,
        source: ScanTriggerSource,
        project_id: Option<String>,
        repo: Option<String>,
        run_overrides: Option<nyx_agent_api::ScanRunOverrides>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
        Box::pin(async move {
            let mut calls = self.calls.lock().await;
            let id = format!("run-{}", calls.len());
            calls.push(RecordedScanCall { source, project_id, repo, run_overrides });
            Ok(id)
        })
    }
}

struct StubAuthSetupAgent;

impl AuthSetupAgent for StubAuthSetupAgent {
    fn explore<'a>(&'a self, req: AuthSetupAgentRequest) -> AuthSetupAgentFuture<'a> {
        Box::pin(async move {
            assert_eq!(req.static_login_paths, vec!["/api/auth/sign-in".to_string()]);
            assert!(req.files_inspected > 0);
            Ok(AuthSetupAgentOutput {
                profiles: vec![ProjectAuthProfile {
                    role: "manager".to_string(),
                    role_aliases: Vec::new(),
                    mode: ProjectAuthMode::AiAuto,
                    label: Some("Repo manager".to_string()),
                    tenant: None,
                    session_cache_ttl_seconds: None,
                    session_import_path: None,
                    login_url: Some("/api/auth/sign-in".to_string()),
                    username: None,
                    username_env: Some("NYX_AGENT_MANAGER_EMAIL".to_string()),
                    login_email_env: None,
                    password_env: Some("NYX_AGENT_MANAGER_PASSWORD".to_string()),
                    password_secret_ref: None,
                    cookie_env: None,
                    bearer_token_env: None,
                    headers: Vec::new(),
                    otp_source: None,
                    post_login_assertions: Vec::new(),
                    post_login_assertion: None,
                    custom_command: None,
                    owned_objects: Vec::new(),
                }],
                roles: vec!["manager".to_string()],
                login_paths: vec!["/api/auth/sign-in".to_string()],
                object_routes: vec!["/api/workspaces/{id}".to_string()],
                files_inspected: req.files_inspected,
                verification: AuthSetupVerification {
                    status: AuthSetupVerificationStatus::Verified,
                    checks: vec!["agent matched sign-in route".to_string()],
                    warnings: Vec::new(),
                },
                message: "Auth exploration agent saved 1 repo-specific role profile(s); verification passed.".to_string(),
            })
        })
    }
}

struct FailingAuthSetupAgent;

impl AuthSetupAgent for FailingAuthSetupAgent {
    fn explore<'a>(&'a self, _req: AuthSetupAgentRequest) -> AuthSetupAgentFuture<'a> {
        Box::pin(async move {
            Err(nyx_agent_api::AuthSetupAgentError::Failed(
                "transport error: DNS lookup failed".to_string(),
            ))
        })
    }
}

struct StubProjectSetupAgent;

impl ProjectSetupAgent for StubProjectSetupAgent {
    fn explore<'a>(&'a self, req: ProjectSetupAgentRequest) -> ProjectSetupAgentFuture<'a> {
        Box::pin(async move {
            assert!(!req.workspace_roots.is_empty());
            Ok(ProjectSetupAgentOutput {
                profile: ProjectLaunchProfileInput {
                    name: Some("AI local dev".to_string()),
                    mode: Some("custom-commands".to_string()),
                    build_steps: Vec::new(),
                    start_steps: vec![LaunchStep {
                        command: "npm run dev".to_string(),
                        repo_id: None,
                        repo_name: Some("web".to_string()),
                        working_directory: None,
                        timeout_seconds: Some(120),
                        stdin: None,
                    }],
                    seed_steps: Vec::new(),
                    reset_steps: vec![LaunchStep {
                        command: "npm run dev:reset".to_string(),
                        repo_id: None,
                        repo_name: Some("web".to_string()),
                        working_directory: None,
                        timeout_seconds: Some(120),
                        stdin: Some("y\n".to_string()),
                    }],
                    login_steps: Vec::new(),
                    stop_steps: Vec::new(),
                    health_checks: Vec::new(),
                    target_urls: vec!["http://127.0.0.1:8787".to_string()],
                    env_refs: Vec::new(),
                    working_dirs: Vec::new(),
                },
                summary: "detected npm dev workflow".to_string(),
                checks: vec!["package.json inspected".to_string()],
                warnings: Vec::new(),
                verification_status: ProjectSetupVerificationStatus::Verified,
                message: "Project setup agent prepared a launch profile.".to_string(),
            })
        })
    }
}

struct StubSeedSetupAgent;

impl SeedSetupAgent for StubSeedSetupAgent {
    fn explore<'a>(&'a self, req: SeedSetupAgentRequest) -> SeedSetupAgentFuture<'a> {
        Box::pin(async move {
            assert!(!req.workspace_roots.is_empty());
            assert!(req.launch_profile.is_some());
            Ok(SeedSetupAgentOutput {
                plan: SeedSetupPlan {
                    seed_steps: vec![LaunchStep {
                        command: "npm run nyx-agent:seed".to_string(),
                        repo_id: None,
                        repo_name: Some("web".to_string()),
                        working_directory: None,
                        timeout_seconds: Some(120),
                        stdin: None,
                    }],
                    reset_steps: vec![LaunchStep {
                        command: "npm run dev:reset".to_string(),
                        repo_id: None,
                        repo_name: Some("web".to_string()),
                        working_directory: None,
                        timeout_seconds: Some(120),
                        stdin: Some("y\n".to_string()),
                    }],
                    env_vars: vec![
                        ProjectRuntimeEnvVar {
                            name: "NYX_AGENT_USER_A_EMAIL".to_string(),
                            value: "user-a@example.test".to_string(),
                            secret: false,
                        },
                        ProjectRuntimeEnvVar {
                            name: "NYX_AGENT_USER_A_PASSWORD".to_string(),
                            value: "nyx-agent-user-a-pass".to_string(),
                            secret: true,
                        },
                    ],
                    roles: vec!["user_a".to_string(), "user_b".to_string(), "manager".to_string()],
                    seeded_objects: vec![ProjectAuthOwnedObject {
                        name: "workspace".to_string(),
                        id: "nyx-agent-workspace-a".to_string(),
                        route: Some("/api/workspaces/{id}".to_string()),
                        marker: Some("nyx-agent-owned-by-user-a".to_string()),
                    }],
                    summary: "prepared deterministic users and one owned workspace".to_string(),
                    checks: vec!["seed script found".to_string()],
                    warnings: Vec::new(),
                },
                message: "Seed setup agent prepared deterministic fixtures.".to_string(),
            })
        })
    }
}

struct StubRemediationAgent;

impl RemediationAgent for StubRemediationAgent {
    fn fix<'a>(&'a self, req: RemediationAgentRequest) -> RemediationAgentFuture<'a> {
        Box::pin(async move {
            assert_eq!(req.vulnerability.id, "vuln-1");
            assert!(!req.workspace_roots.is_empty());
            Ok(RemediationAgentOutput {
                changed_files: vec![RemediationChangedFile {
                    repo: "web".to_string(),
                    path: "src/reviews.ts".to_string(),
                    status: "modified".to_string(),
                    additions: Some(8),
                    deletions: Some(2),
                }],
                summary: "Escaped review output.".to_string(),
                final_message: "Summary:\nEscaped review output.".to_string(),
            })
        })
    }
}

struct TestServer {
    addr: std::net::SocketAddr,
    events: EventSink,
    store: Store,
    logs_dir: std::path::PathBuf,
    _tmp: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
    token: Option<String>,
}

impl TestServer {
    async fn start() -> Self {
        Self::start_with_trigger(Arc::new(StubScanTrigger { run_id: "run-fake".to_string() })).await
    }

    async fn start_with_trigger(trigger: Arc<dyn ScanTrigger>) -> Self {
        Self::start_with_options(trigger, false, true).await
    }

    /// `with_auth = true` mints a bearer token and turns on the auth
    /// middleware; tests that exercise unauthenticated handlers pass
    /// `false`. `setup_complete = false` puts the server in
    /// fresh-install mode so `/setup` is reachable.
    async fn start_with_options(
        trigger: Arc<dyn ScanTrigger>,
        with_auth: bool,
        setup_complete: bool,
    ) -> Self {
        Self::start_with_options_and_agent(trigger, with_auth, setup_complete, None).await
    }

    async fn start_with_auth_setup_agent(agent: Arc<dyn AuthSetupAgent>) -> Self {
        Self::start_with_options_and_agent(
            Arc::new(StubScanTrigger { run_id: "run-fake".to_string() }),
            false,
            true,
            Some(agent),
        )
        .await
    }

    async fn start_with_project_setup_agent(agent: Arc<dyn ProjectSetupAgent>) -> Self {
        Self::start_with_options_and_agents(
            Arc::new(StubScanTrigger { run_id: "run-fake".to_string() }),
            false,
            true,
            None,
            Some(agent),
            None,
            None,
        )
        .await
    }

    async fn start_with_setup_agents(
        project_agent: Arc<dyn ProjectSetupAgent>,
        seed_agent: Arc<dyn SeedSetupAgent>,
        auth_agent: Arc<dyn AuthSetupAgent>,
    ) -> Self {
        Self::start_with_options_and_agents(
            Arc::new(StubScanTrigger { run_id: "run-fake".to_string() }),
            false,
            true,
            Some(auth_agent),
            Some(project_agent),
            Some(seed_agent),
            None,
        )
        .await
    }

    async fn start_with_remediation_agent(agent: Arc<dyn RemediationAgent>) -> Self {
        Self::start_with_options_and_agents(
            Arc::new(StubScanTrigger { run_id: "run-fake".to_string() }),
            false,
            true,
            None,
            None,
            None,
            Some(agent),
        )
        .await
    }

    async fn start_with_options_and_agent(
        trigger: Arc<dyn ScanTrigger>,
        with_auth: bool,
        setup_complete: bool,
        auth_setup_agent: Option<Arc<dyn AuthSetupAgent>>,
    ) -> Self {
        Self::start_with_options_and_agents(
            trigger,
            with_auth,
            setup_complete,
            auth_setup_agent,
            None,
            None,
            None,
        )
        .await
    }

    async fn start_with_options_and_agents(
        trigger: Arc<dyn ScanTrigger>,
        with_auth: bool,
        setup_complete: bool,
        auth_setup_agent: Option<Arc<dyn AuthSetupAgent>>,
        project_setup_agent: Option<Arc<dyn ProjectSetupAgent>>,
        seed_setup_agent: Option<Arc<dyn SeedSetupAgent>>,
        remediation_agent: Option<Arc<dyn RemediationAgent>>,
    ) -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = Store::open(tmp.path()).await.expect("open store");
        let (events, _rx) = broadcast::channel::<AgentEvent>(64);
        let config_path = tmp.path().join("nyx-agent.toml");
        let setup = SetupContext::new(
            config_path,
            Config::default(),
            setup_complete,
            SecretStore::memory(),
        );
        let auth = if with_auth {
            AuthConfig::new(Some(nyx_agent_core::mint_token()))
        } else {
            AuthConfig::default()
        };
        let token = auth.token.clone();
        let logs_dir = tmp.path().join("logs");
        let mut state = ServerState::new(store.clone(), events.clone(), trigger, setup, auth)
            .with_state_logs_dir(logs_dir.clone());
        if let Some(agent) = auth_setup_agent {
            state = state.with_auth_setup_agent(agent);
        }
        if let Some(agent) = project_setup_agent {
            state = state.with_project_setup_agent(agent);
        }
        if let Some(agent) = seed_setup_agent {
            state = state.with_seed_setup_agent(agent);
        }
        if let Some(agent) = remediation_agent {
            state = state.with_remediation_agent(agent);
        }
        let app = build_router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        TestServer { addr, events, store, logs_dir, _tmp: tmp, handle, token }
    }

    fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn ws_base(&self) -> String {
        format!("ws://{}", self.addr)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn sample_repo(name: &str) -> RepoRecord {
    RepoRecord {
        id: format!("repo-default-{name}"),
        name: name.to_string(),
        project_id: DEFAULT_PROJECT_ID.to_string(),
        source_kind: "local-path".to_string(),
        source_url_or_path: format!("/tmp/{name}"),
        branch: None,
        auth_ref: None,
        i_own_this: true,
        last_scan_run_id: None,
        last_scan_finished_at: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn sample_run(id: &str) -> RunRecord {
    RunRecord {
        id: id.to_string(),
        project_id: None,
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

async fn make_default_project_ready(srv: &TestServer) {
    srv.store.repos().upsert(&sample_repo("web")).await.expect("repo");
    srv.store
        .launch_profiles()
        .upsert_default(
            DEFAULT_PROJECT_ID,
            &ProjectLaunchProfileInput {
                name: None,
                mode: None,
                build_steps: Vec::new(),
                start_steps: Vec::new(),
                seed_steps: Vec::new(),
                reset_steps: Vec::new(),
                login_steps: Vec::new(),
                stop_steps: Vec::new(),
                health_checks: Vec::new(),
                target_urls: vec!["http://localhost:3000".to_string()],
                env_refs: Vec::new(),
                working_dirs: Vec::new(),
            },
            2_000,
        )
        .await
        .expect("launch profile");
}

async fn wait_auth_setup_job(
    client: &reqwest::Client,
    base: &str,
    project_id: &str,
    job_id: &str,
) -> Value {
    for _ in 0..50 {
        let job: Value = client
            .get(format!("{base}/api/v1/projects/{project_id}/auth/auto-setup/{job_id}"))
            .send()
            .await
            .expect("get auth job")
            .json()
            .await
            .expect("auth job json");
        if matches!(job["status"].as_str(), Some("succeeded" | "failed")) {
            return job;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("auth setup job did not finish");
}

async fn wait_project_setup_job(
    client: &reqwest::Client,
    base: &str,
    project_id: &str,
    job_id: &str,
) -> Value {
    for _ in 0..50 {
        let job: Value = client
            .get(format!("{base}/api/v1/projects/{project_id}/setup/ai/{job_id}"))
            .send()
            .await
            .expect("get project setup job")
            .json()
            .await
            .expect("project setup job json");
        if matches!(job["status"].as_str(), Some("succeeded" | "failed")) {
            return job;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("project setup job did not finish");
}

async fn wait_vulnerability_fix_job(
    client: &reqwest::Client,
    base: &str,
    vulnerability_id: &str,
    job_id: &str,
) -> Value {
    for _ in 0..50 {
        let job: Value = client
            .get(format!("{base}/api/v1/vulnerabilities/{vulnerability_id}/fix/{job_id}"))
            .send()
            .await
            .expect("get vulnerability fix job")
            .json()
            .await
            .expect("vulnerability fix job json");
        if matches!(job["status"].as_str(), Some("succeeded" | "failed")) {
            return job;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("vulnerability fix job did not finish");
}

#[tokio::test]
async fn project_integrations_crud_roundtrips() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let create = serde_json::json!({
        "name": "Security alerts",
        "enabled": true,
        "events": ["run_finished", "finding_verified"],
        "min_severity": "High",
        "config": {
            "kind": "webhook",
            "url": "https://example.com/nyx-agent",
            "signing_secret": "secret"
        }
    });
    let created: Value = client
        .post(format!("{}/api/v1/projects/{}/integrations", srv.base(), DEFAULT_PROJECT_ID))
        .json(&create)
        .send()
        .await
        .expect("create")
        .error_for_status()
        .expect("create status")
        .json()
        .await
        .expect("create json");
    let id = created["id"].as_str().expect("id");
    assert_eq!(created["project_id"], DEFAULT_PROJECT_ID);
    assert_eq!(created["kind"], "webhook");
    assert_eq!(created["target"], "example.com");
    assert!(created.get("config").is_none(), "public row must not expose secret config");

    let listed: Value = client
        .get(format!("{}/api/v1/projects/{}/integrations", srv.base(), DEFAULT_PROJECT_ID))
        .send()
        .await
        .expect("list")
        .error_for_status()
        .expect("list status")
        .json()
        .await
        .expect("list json");
    assert_eq!(listed.as_array().expect("array").len(), 1);

    let patched: Value = client
        .patch(format!("{}/api/v1/projects/{}/integrations/{}", srv.base(), DEFAULT_PROJECT_ID, id))
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .expect("patch")
        .error_for_status()
        .expect("patch status")
        .json()
        .await
        .expect("patch json");
    assert_eq!(patched["enabled"], false);

    let deleted: Value = client
        .delete(format!(
            "{}/api/v1/projects/{}/integrations/{}",
            srv.base(),
            DEFAULT_PROJECT_ID,
            id
        ))
        .send()
        .await
        .expect("delete")
        .error_for_status()
        .expect("delete status")
        .json()
        .await
        .expect("delete json");
    assert_eq!(deleted["ok"], true);
}

fn sample_finding(run_id: &str, repo: &str, path: &str, rule: &str) -> FindingRecord {
    let id = nyx_agent_core::store::finding_id_hash(repo, path, Some(10), "sqli", rule);
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
        spec_id: None,
    }
}

fn sample_chain(id: &str, run_id: &str, members: &[&str]) -> ChainRecord {
    ChainRecord {
        id: id.to_string(),
        run_id: run_id.to_string(),
        cross_repo: false,
        member_ids: serde_json::to_string(members).unwrap(),
        rationale_blob: None,
        attack_provenance: None,
        prompt_version: None,
        status: "Proposed".to_string(),
        verification_attempt_id: None,
        evidence_blob: None,
        severity: None,
    }
}

fn sample_vulnerability(id: &str, run_id: &str, project_id: &str) -> VerifiedVulnerabilityRecord {
    VerifiedVulnerabilityRecord {
        id: id.to_string(),
        run_id: run_id.to_string(),
        project_id: project_id.to_string(),
        title: "Authentication bypass".to_string(),
        severity: "Critical".to_string(),
        confidence: 0.96,
        risk_score: 9.6,
        risk_rating: "Critical".to_string(),
        risk_score_source: "nyx-agent".to_string(),
        risk_score_rationale: "Live verification reached a protected endpoint without a session."
            .to_string(),
        vuln_class: "auth".to_string(),
        affected_components: vec![serde_json::json!({"repo":"web","path":"src/auth.ts"})],
        business_impact: "Attackers can enter another tenant's account.".to_string(),
        evidence_summary: "Live verification reached the protected endpoint without a session."
            .to_string(),
        repro_steps: "Replay the verified browser script.".to_string(),
        remediation: "Validate the session before issuing the callback token.".to_string(),
        source_candidate_ids: vec!["candidate-1".to_string()],
        source_signal_ids: vec!["signal-1".to_string()],
        verification_attempt_ids: vec!["attempt-1".to_string()],
        chain_id: None,
        status: "Open".to_string(),
        first_seen: 4_000,
        last_seen: 4_100,
    }
}

#[tokio::test]
async fn health_returns_ok() {
    let srv = TestServer::start().await;
    let resp = reqwest::get(format!("{}/api/v1/health", srv.base())).await.expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn vulnerability_status_endpoints_update_single_and_bulk_rows() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let mut run = sample_run("run-vuln-status");
    run.project_id = Some(DEFAULT_PROJECT_ID.to_string());
    srv.store.runs().insert(&run).await.expect("run");
    let vuln = sample_vulnerability("vuln-api", "run-vuln-status", DEFAULT_PROJECT_ID);
    srv.store.verified_vulnerabilities().upsert(&vuln).await.expect("vuln");

    let loaded: Value = client
        .get(format!("{}/api/v1/vulnerabilities/vuln-api", srv.base()))
        .send()
        .await
        .expect("get vulnerability")
        .error_for_status()
        .expect("get vulnerability status")
        .json()
        .await
        .expect("get vulnerability json");
    assert_eq!(loaded["id"], "vuln-api");
    assert_eq!(loaded["risk_score"], 9.6);

    let patched: Value = client
        .patch(format!("{}/api/v1/vulnerabilities/vuln-api/status", srv.base()))
        .json(&serde_json::json!({"status":"in progress"}))
        .send()
        .await
        .expect("patch")
        .error_for_status()
        .expect("patch status")
        .json()
        .await
        .expect("patch json");
    assert_eq!(patched["status"], "InProgress");

    let bulk: Value = client
        .patch(format!("{}/api/v1/vulnerabilities/status", srv.base()))
        .json(&serde_json::json!({"ids":["vuln-api"],"status":"false_positive"}))
        .send()
        .await
        .expect("bulk patch")
        .error_for_status()
        .expect("bulk status")
        .json()
        .await
        .expect("bulk json");
    assert_eq!(bulk[0]["status"], "FalsePositive");

    let listed: Value = client
        .get(format!("{}/api/v1/vulnerabilities", srv.base()))
        .send()
        .await
        .expect("list")
        .error_for_status()
        .expect("list status")
        .json()
        .await
        .expect("list json");
    assert_eq!(listed[0]["status"], "FalsePositive");
    assert_eq!(listed[0]["risk_score"], 9.6);
    assert_eq!(listed[0]["risk_rating"], "Critical");
    assert_eq!(listed[0]["risk_score_source"], "nyx-agent");
}

#[tokio::test]
async fn vulnerability_fix_endpoint_runs_remediation_agent_job() {
    let srv = TestServer::start_with_remediation_agent(Arc::new(StubRemediationAgent)).await;
    let client = reqwest::Client::new();
    let repo_dir = srv._tmp.path().join("web");
    std::fs::create_dir_all(repo_dir.join("src")).expect("repo dir");
    let now = nyx_agent_core::now_epoch_ms();
    srv.store
        .repos()
        .upsert(&RepoRecord {
            id: "repo-web".to_string(),
            name: "web".to_string(),
            project_id: DEFAULT_PROJECT_ID.to_string(),
            source_kind: "local".to_string(),
            source_url_or_path: repo_dir.display().to_string(),
            branch: None,
            auth_ref: None,
            i_own_this: true,
            last_scan_run_id: None,
            last_scan_finished_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("repo");
    let mut run = sample_run("run-1");
    run.project_id = Some(DEFAULT_PROJECT_ID.to_string());
    srv.store.runs().insert(&run).await.expect("run");
    let vuln = sample_vulnerability("vuln-1", "run-1", DEFAULT_PROJECT_ID);
    srv.store.verified_vulnerabilities().upsert(&vuln).await.expect("vuln");

    let started: Value = client
        .post(format!("{}/api/v1/vulnerabilities/vuln-1/fix", srv.base()))
        .send()
        .await
        .expect("post fix")
        .error_for_status()
        .expect("post fix status")
        .json()
        .await
        .expect("post fix json");
    let job_id = started["job"]["id"].as_str().expect("job id");
    let job = wait_vulnerability_fix_job(&client, &srv.base(), "vuln-1", job_id).await;

    assert_eq!(job["status"], "succeeded");
    assert_eq!(job["result"]["summary"], "Escaped review output.");
    assert_eq!(job["result"]["changed_files"][0]["path"], "src/reviews.ts");
}

#[tokio::test]
async fn repos_crud_roundtrip() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let repos_url = format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID);

    let resp = client
        .post(&repos_url)
        .json(&serde_json::json!({
            "name": "alpha",
            "source_kind": "local-path",
            "source_url_or_path": "/tmp/alpha",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let listed: Vec<RepoRecord> =
        client.get(&repos_url).send().await.expect("get").json().await.expect("json");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "alpha");

    let del = client.delete(format!("{repos_url}/alpha")).send().await.expect("delete");
    assert_eq!(del.status(), reqwest::StatusCode::OK);

    let del_again = client.delete(format!("{repos_url}/alpha")).send().await.expect("delete");
    assert_eq!(del_again.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn post_repos_refuses_without_ownership_attestation() {
    let srv = TestServer::start().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID))
        .json(&serde_json::json!({
            "name": "shady",
            "source_kind": "git",
            "source_url_or_path": "https://example.com/shady.git",
            "i_own_this": false,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn runs_endpoint_lists_and_gets_by_id() {
    let srv = TestServer::start().await;
    let mut default_project_run = sample_run("run-A");
    default_project_run.project_id = Some(DEFAULT_PROJECT_ID.to_string());
    srv.store.runs().insert(&default_project_run).await.expect("insert");
    srv.store
        .projects()
        .create("project-other", "project-other", None, None, None, 1_000)
        .await
        .expect("other project");
    let mut other_project_run = sample_run("run-B");
    other_project_run.project_id = Some("project-other".to_string());
    srv.store.runs().insert(&other_project_run).await.expect("insert other");

    let one: RunRecord = reqwest::get(format!("{}/api/v1/runs/run-A", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(one.id, "run-A");

    let listed: Vec<RunRecord> = reqwest::get(format!("{}/api/v1/runs?status=Running", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert!(listed.iter().any(|r| r.id == "run-A"));

    let filtered: Vec<RunRecord> = reqwest::get(format!(
        "{}/api/v1/runs?status=Running&project_id={}",
        srv.base(),
        DEFAULT_PROJECT_ID
    ))
    .await
    .expect("get")
    .json()
    .await
    .expect("json");
    assert_eq!(filtered.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), vec!["run-A"]);

    let missing =
        reqwest::get(format!("{}/api/v1/runs/does-not-exist", srv.base())).await.expect("get");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn business_logic_templates_endpoint_lists_registry() {
    let srv = TestServer::start().await;
    let templates: Vec<Value> =
        reqwest::get(format!("{}/api/v1/business-logic/templates", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");

    assert!(templates.iter().any(|template| {
        template["id"] == "tenant_object_isolation"
            && template["version"] == "1"
            && template["mutability"] == "state_changing"
    }));
    assert!(templates.iter().any(|template| {
        template["id"] == "password_reset_token_replay" && template["availability"] == "executable"
    }));
    assert!(templates.iter().any(|template| {
        template["id"] == "invite_accept_reuse" && template["availability"] == "executable"
    }));
}

#[tokio::test]
async fn run_business_logic_summary_roundtrips_counts() {
    let srv = TestServer::start().await;
    let mut run = sample_run("run-bl");
    run.project_id = Some(DEFAULT_PROJECT_ID.to_string());
    srv.store.runs().insert(&run).await.expect("run");
    srv.store
        .business_logic_template_runs()
        .upsert(&nyx_agent_types::business_logic::BusinessLogicTemplateRunRecord {
            run_id: "run-bl".to_string(),
            project_id: DEFAULT_PROJECT_ID.to_string(),
            template_id: "tenant_object_isolation".to_string(),
            template_version: "1".to_string(),
            generated_count: 2,
            skipped_count: 0,
            skip_reasons: Vec::new(),
            dry_run: true,
            created_at: 1,
            updated_at: 1,
        })
        .await
        .expect("summary");
    srv.store
        .business_logic_template_runs()
        .upsert(&nyx_agent_types::business_logic::BusinessLogicTemplateRunRecord {
            run_id: "run-bl".to_string(),
            project_id: DEFAULT_PROJECT_ID.to_string(),
            template_id: "password_reset_token_misuse".to_string(),
            template_version: "1".to_string(),
            generated_count: 0,
            skipped_count: 1,
            skip_reasons: vec!["metadata-only".to_string()],
            dry_run: true,
            created_at: 1,
            updated_at: 1,
        })
        .await
        .expect("summary");

    let body: Value = reqwest::get(format!("{}/api/v1/runs/run-bl/business-logic", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(body["templates_considered"], 2);
    assert_eq!(body["candidates_generated"], 2);
    assert_eq!(body["templates_skipped"], 1);
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["templates"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn candidates_endpoint_preserves_business_logic_template_provenance() {
    let srv = TestServer::start().await;
    let mut run = sample_run("run-bl-candidate");
    run.project_id = Some(DEFAULT_PROJECT_ID.to_string());
    srv.store.runs().insert(&run).await.expect("run");
    srv.store
        .pentest_candidates()
        .insert(&PentestCandidateRecord {
            id: "pc-bl-1".to_string(),
            run_id: "run-bl-candidate".to_string(),
            project_id: DEFAULT_PROJECT_ID.to_string(),
            source: "BusinessLogicTemplate".to_string(),
            source_ids: vec![
                "business-template:tenant_object_isolation:api:GET:/api/files:*".to_string()
            ],
            title: "Tenant object isolation".to_string(),
            vuln_class: "BUSINESS_LOGIC_OBJECT_ISOLATION".to_string(),
            severity_guess: "High".to_string(),
            affected_components: vec![serde_json::json!({
                "kind": "business_logic_template",
                "template_provenance": {
                    "template_id": "tenant_object_isolation",
                    "template_version": "1"
                },
                "route_path": "/api/files/:id",
                "roles": ["user_a", "user_b"]
            })],
            hypothesis: "Cross-role object read should fail".to_string(),
            test_plan: "{}".to_string(),
            status: "NeedsLiveTest".to_string(),
            rejection_reason: None,
            confidence: 0.7,
            trace_id: None,
            created_at: 20,
            updated_at: 20,
        })
        .await
        .expect("candidate");

    let body: Vec<Value> =
        reqwest::get(format!("{}/api/v1/runs/run-bl-candidate/candidates", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert_eq!(
        body[0]["affected_components"][0]["template_provenance"]["template_id"],
        "tenant_object_isolation"
    );
}

#[tokio::test]
async fn run_event_log_endpoint_streams_persisted_jsonl() {
    let srv = TestServer::start().await;
    srv.store.runs().insert(&sample_run("run-log")).await.expect("insert");
    let path = run_event_log_path(&srv.logs_dir, "run-log");
    tokio::fs::create_dir_all(path.parent().expect("parent")).await.expect("mkdir");
    tokio::fs::write(
        &path,
        br#"{"ts_ms":1,"event":{"kind":"Run","data":{"kind":"RunStarted","run_id":"run-log","project_id":"project","repos":[],"started_at_ms":1}}}
"#,
    )
    .await
    .expect("write log");

    let resp = reqwest::get(format!("{}/api/v1/runs/run-log/events.jsonl", srv.base()))
        .await
        .expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.headers().get(reqwest::header::CONTENT_TYPE).unwrap(), "application/x-ndjson");
    let body = resp.text().await.expect("body");
    assert!(body.contains("\"RunStarted\""));

    let missing = reqwest::get(format!("{}/api/v1/runs/run-A/events.jsonl", srv.base()))
        .await
        .expect("get missing run");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn verification_attempts_endpoint_returns_artifact_paths() {
    let srv = TestServer::start().await;
    let mut run = sample_run("run-A");
    run.project_id = Some(DEFAULT_PROJECT_ID.to_string());
    srv.store.runs().insert(&run).await.expect("run");
    let profile = srv
        .store
        .launch_profiles()
        .upsert_default(
            DEFAULT_PROJECT_ID,
            &ProjectLaunchProfileInput {
                name: None,
                mode: None,
                build_steps: Vec::new(),
                start_steps: Vec::new(),
                seed_steps: Vec::new(),
                reset_steps: Vec::new(),
                login_steps: Vec::new(),
                stop_steps: Vec::new(),
                health_checks: Vec::new(),
                target_urls: vec!["http://localhost:3000".to_string()],
                env_refs: Vec::new(),
                working_dirs: Vec::new(),
            },
            2_100,
        )
        .await
        .expect("profile");
    srv.store
        .environment_runs()
        .insert(&EnvironmentRunRecord {
            id: "env-1".to_string(),
            run_id: "run-A".to_string(),
            project_id: DEFAULT_PROJECT_ID.to_string(),
            profile_id: profile.id,
            status: "Ready".to_string(),
            started_at: Some(2_200),
            ready_at: Some(2_300),
            stopped_at: None,
            target_urls: vec!["http://localhost:3000".to_string()],
            health: None,
            logs_dir: None,
            teardown: None,
        })
        .await
        .expect("env");
    srv.store
        .verification_attempts()
        .insert(&VerificationAttemptRecord {
            id: "va-browser-1".to_string(),
            run_id: "run-A".to_string(),
            project_id: DEFAULT_PROJECT_ID.to_string(),
            environment_run_id: "env-1".to_string(),
            candidate_id: None,
            chain_id: None,
            method: "browser".to_string(),
            status: "Confirmed".to_string(),
            started_at: 2_400,
            finished_at: Some(2_700),
            duration_ms: Some(300),
            request: Some(serde_json::json!({"kind":"browser"})),
            response: Some(
                serde_json::json!({"browser":{"artifact_paths":["/state/browser-final.png"]}}),
            ),
            oracle: Some(serde_json::json!({"success":true})),
            artifact_paths: vec![
                "/state/browser-final.png".to_string(),
                "/state/browser-replay.json".to_string(),
            ],
            error: None,
            replay_stable: None,
        })
        .await
        .expect("attempt");

    let attempts: Vec<VerificationAttemptRecord> =
        reqwest::get(format!("{}/api/v1/runs/run-A/verification-attempts", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");

    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].id, "va-browser-1");
    assert!(attempts[0].artifact_paths.iter().any(|path| path.ends_with("browser-final.png")));
    assert!(attempts[0].artifact_paths.iter().any(|path| path.ends_with("browser-replay.json")));
}

#[tokio::test]
async fn findings_endpoints_filter_by_repo_and_run() {
    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
    srv.store.runs().insert(&sample_run("run-A")).await.expect("run");
    let finding = sample_finding("run-A", "repo-1", "src/a.rs", "rule-1");
    srv.store.findings().upsert(&finding).await.expect("finding");

    let by_repo: Vec<FindingRecord> =
        reqwest::get(format!("{}/api/v1/findings?repo=repo-1", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert_eq!(by_repo.len(), 1);

    let by_run: Vec<FindingRecord> =
        reqwest::get(format!("{}/api/v1/findings?run_id=run-A", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert_eq!(by_run.len(), 1);

    let got: FindingRecord = reqwest::get(format!("{}/api/v1/findings/{}", srv.base(), finding.id))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(got.id, finding.id);

    // Global view (no filter) returns every active finding.
    let global: Vec<FindingRecord> = reqwest::get(format!("{}/api/v1/findings", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(global.len(), 1);
}

#[tokio::test]
async fn findings_endpoint_filters_by_cap_and_severity() {
    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
    srv.store.runs().insert(&sample_run("run-A")).await.expect("run");

    let mut taint = sample_finding("run-A", "repo-1", "src/a.rs", "taint");
    taint.cap = "sqli".to_string();
    taint.severity = "High".to_string();
    let mut cmdi = sample_finding("run-A", "repo-1", "src/b.rs", "cmd");
    cmdi.cap = "cmdi".to_string();
    cmdi.severity = "Low".to_string();
    srv.store.findings().upsert(&taint).await.expect("taint");
    srv.store.findings().upsert(&cmdi).await.expect("cmdi");

    let high: Vec<FindingRecord> =
        reqwest::get(format!("{}/api/v1/findings?severity=High", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert_eq!(high.len(), 1);
    assert_eq!(high[0].id, taint.id);

    let cmdi_only: Vec<FindingRecord> =
        reqwest::get(format!("{}/api/v1/findings?cap=cmdi", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert_eq!(cmdi_only.len(), 1);
    assert_eq!(cmdi_only[0].id, cmdi.id);
}

#[tokio::test]
async fn runs_findings_endpoint_marks_diff_status() {
    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
    srv.store.runs().insert(&sample_run("run-A")).await.expect("run");
    // sample_run.started_at = 2_000; sample_finding.first_seen = 3_000.
    // 3_000 >= 2_000, so every row classifies as `new`.
    let finding = sample_finding("run-A", "repo-1", "src/a.rs", "rule-1");
    srv.store.findings().upsert(&finding).await.expect("finding");

    let body: serde_json::Value =
        reqwest::get(format!("{}/api/v1/runs/run-A/findings", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert_eq!(body["run_id"], "run-A");
    assert!(body["prior_run_id"].is_null());
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["diff_status"], "new");
    assert_eq!(items[0]["id"], finding.id);
}

#[tokio::test]
async fn runs_findings_endpoint_applies_facet_filters_server_side() {
    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
    srv.store.repos().upsert(&sample_repo("repo-2")).await.expect("repo-2");
    srv.store.runs().insert(&sample_run("run-A")).await.expect("run");

    let mut taint = sample_finding("run-A", "repo-1", "src/a.rs", "taint");
    taint.cap = "sqli".to_string();
    taint.severity = "High".to_string();
    taint.finding_origin = "Static".to_string();
    let mut cmdi = sample_finding("run-A", "repo-2", "src/b.rs", "cmd");
    cmdi.cap = "cmdi".to_string();
    cmdi.severity = "Low".to_string();
    cmdi.finding_origin = "AI".to_string();
    srv.store.findings().upsert(&taint).await.expect("taint");
    srv.store.findings().upsert(&cmdi).await.expect("cmdi");

    // No filters: both rows.
    let all: serde_json::Value = reqwest::get(format!("{}/api/v1/runs/run-A/findings", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(all["items"].as_array().expect("items").len(), 2);

    // Filter by cap.
    let by_cap: serde_json::Value =
        reqwest::get(format!("{}/api/v1/runs/run-A/findings?cap=sqli", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    let items = by_cap["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], taint.id);
    assert_eq!(items[0]["diff_status"], "new");

    // Filter by repo + origin combined.
    let by_repo_origin: serde_json::Value =
        reqwest::get(format!("{}/api/v1/runs/run-A/findings?repo=repo-2&origin=AI", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    let items = by_repo_origin["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], cmdi.id);

    // A filter that matches nothing returns an empty items array but
    // keeps the run_id / prior_run_id envelope.
    let empty: serde_json::Value =
        reqwest::get(format!("{}/api/v1/runs/run-A/findings?severity=Critical", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert_eq!(empty["run_id"], "run-A");
    assert_eq!(empty["items"].as_array().expect("items").len(), 0);
}

#[tokio::test]
async fn runs_findings_endpoint_marks_regressed_when_status_differs_from_prior() {
    // Prior run observed the finding with status=Closed; current run
    // observes the same finding with status=Open → regressed.
    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
    let mut prior = sample_run("run-prior");
    prior.started_at = 1_000;
    srv.store.runs().insert(&prior).await.expect("prior");
    let mut current = sample_run("run-current");
    current.started_at = 5_000;
    srv.store.runs().insert(&current).await.expect("current");

    let mut prior_obs = sample_finding("run-prior", "repo-1", "src/a.rs", "rule-1");
    prior_obs.status = "Closed".to_string();
    srv.store.findings().upsert(&prior_obs).await.expect("prior obs");

    let mut current_obs = sample_finding("run-current", "repo-1", "src/a.rs", "rule-1");
    current_obs.status = "Open".to_string();
    srv.store.findings().upsert(&current_obs).await.expect("current obs");

    let body: serde_json::Value =
        reqwest::get(format!("{}/api/v1/runs/run-current/findings", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert_eq!(body["run_id"], "run-current");
    assert_eq!(body["prior_run_id"], "run-prior");
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["diff_status"], "regressed");
    assert_eq!(items[0]["id"], current_obs.id);
}

#[tokio::test]
async fn runs_findings_endpoint_marks_unchanged_when_status_matches_prior() {
    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
    let mut prior = sample_run("run-prior");
    prior.started_at = 1_000;
    srv.store.runs().insert(&prior).await.expect("prior");
    let mut current = sample_run("run-current");
    current.started_at = 5_000;
    srv.store.runs().insert(&current).await.expect("current");

    let prior_obs = sample_finding("run-prior", "repo-1", "src/a.rs", "rule-1");
    srv.store.findings().upsert(&prior_obs).await.expect("prior obs");
    let current_obs = sample_finding("run-current", "repo-1", "src/a.rs", "rule-1");
    srv.store.findings().upsert(&current_obs).await.expect("current obs");

    let body: serde_json::Value =
        reqwest::get(format!("{}/api/v1/runs/run-current/findings", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["diff_status"], "unchanged");
}

#[tokio::test]
async fn runs_findings_endpoint_surfaces_closed_rows_absent_from_current_run() {
    // Prior run observed two findings with status=Open; current run
    // only observes one of them. The absent one surfaces under
    // diff_status="closed" with its latest-known row body (i.e. the
    // prior observation, since no current observation overrode it).
    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
    let mut prior = sample_run("run-prior");
    prior.started_at = 1_000;
    srv.store.runs().insert(&prior).await.expect("prior");
    let mut current = sample_run("run-current");
    current.started_at = 5_000;
    srv.store.runs().insert(&current).await.expect("current");

    let still_open = sample_finding("run-prior", "repo-1", "src/a.rs", "rule-a");
    let gone = sample_finding("run-prior", "repo-1", "src/b.rs", "rule-b");
    srv.store.findings().upsert(&still_open).await.expect("a prior");
    srv.store.findings().upsert(&gone).await.expect("b prior");

    let current_obs = sample_finding("run-current", "repo-1", "src/a.rs", "rule-a");
    srv.store.findings().upsert(&current_obs).await.expect("a current");

    let body: serde_json::Value =
        reqwest::get(format!("{}/api/v1/runs/run-current/findings", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
    let by_id: std::collections::HashMap<String, String> = items
        .iter()
        .map(|i| {
            (
                i["id"].as_str().unwrap_or_default().to_string(),
                i["diff_status"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    assert_eq!(by_id.get(&current_obs.id).map(String::as_str), Some("unchanged"));
    assert_eq!(by_id.get(&gone.id).map(String::as_str), Some("closed"));
}

#[tokio::test]
async fn runs_findings_endpoint_applies_facet_filter_to_closed_rows() {
    // Closed rows must respect the user-supplied repo facet so a
    // ?repo=X filter does not bleed Closed rows from other repos.
    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo-1");
    srv.store.repos().upsert(&sample_repo("repo-2")).await.expect("repo-2");
    let mut prior = sample_run("run-prior");
    prior.started_at = 1_000;
    srv.store.runs().insert(&prior).await.expect("prior");
    let mut current = sample_run("run-current");
    current.started_at = 5_000;
    srv.store.runs().insert(&current).await.expect("current");

    let other_repo = sample_finding("run-prior", "repo-2", "src/a.rs", "rule-a");
    srv.store.findings().upsert(&other_repo).await.expect("other repo");

    let body: serde_json::Value =
        reqwest::get(format!("{}/api/v1/runs/run-current/findings?repo=repo-1", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    let items = body["items"].as_array().expect("items array");
    assert!(items.is_empty(), "repo-2's closed finding must not leak under ?repo=repo-1");
}

#[tokio::test]
async fn traces_endpoint_resolves_candidate_id_via_back_link() {
    // `/findings/:id/traces` dispatches on the `cand-` id prefix: a
    // candidate-shaped id walks the `candidate_findings.trace_id`
    // back-link, while a finding id keeps the direct
    // `agent_traces.finding_id` index. Without the dispatch the
    // quarantine UI would always render "No AI calls recorded for this
    // finding yet" for a Pending candidate.
    use nyx_agent_core::store::{AgentTraceRecord, CandidateFindingRecord};

    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
    srv.store.runs().insert(&sample_run("run-N")).await.expect("run");

    let trace = AgentTraceRecord {
        id: "trace-novel-api".to_string(),
        finding_id: None,
        task_kind: "NovelFindings".to_string(),
        runtime_name: "anthropic".to_string(),
        model: "claude-opus-4-7".to_string(),
        prompt_version: Some("novel.v1".to_string()),
        conversation_jsonl_path: None,
        tokens_in: 800,
        tokens_out: 120,
        cost_usd_micros: 9_500,
        cache_hits: 0,
        cache_misses: 1,
        duration_ms: Some(400),
        started_at: 4_000,
        finished_at: Some(4_400),
        verifier_blob: None,
    };
    srv.store.agent_traces().insert(&trace).await.expect("trace");

    let cand = CandidateFindingRecord {
        id: "cand-api-1".to_string(),
        run_id: "run-N".to_string(),
        repo: "repo-1".to_string(),
        path: "app/handlers.py".to_string(),
        line: Some(6),
        cap: "SQL_QUERY".to_string(),
        rule_hint: Some("py.sql.exec".to_string()),
        rationale: Some("ai-noticed reuse of SQL-concat pattern".to_string()),
        suggested_payload_hint: None,
        status: "Pending".to_string(),
        prompt_version: Some("novel.v1".to_string()),
        trace_id: Some("trace-novel-api".to_string()),
    };
    srv.store.candidate_findings().insert(&cand).await.expect("cand");

    let rows: Vec<Value> =
        reqwest::get(format!("{}/api/v1/findings/cand-api-1/traces", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert_eq!(rows.len(), 1, "candidate trace lookup must return the back-linked row");
    assert_eq!(rows[0]["id"], "trace-novel-api");
    assert_eq!(rows[0]["task_kind"], "NovelFindings");
}

#[tokio::test]
async fn traces_endpoint_returns_empty_for_untraced_candidate() {
    // A candidate that was never linked to a trace (legacy / non-AI)
    // must still resolve its trace lookup as an empty list instead of
    // a 404.
    use nyx_agent_core::store::CandidateFindingRecord;

    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("repo-1")).await.expect("repo");
    srv.store.runs().insert(&sample_run("run-N")).await.expect("run");
    let cand = CandidateFindingRecord {
        id: "cand-untraced".to_string(),
        run_id: "run-N".to_string(),
        repo: "repo-1".to_string(),
        path: "src/a.py".to_string(),
        line: None,
        cap: "sqli".to_string(),
        rule_hint: None,
        rationale: None,
        suggested_payload_hint: None,
        status: "Pending".to_string(),
        prompt_version: None,
        trace_id: None,
    };
    srv.store.candidate_findings().insert(&cand).await.expect("cand");
    let rows: Vec<Value> =
        reqwest::get(format!("{}/api/v1/findings/cand-untraced/traces", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert!(rows.is_empty(), "untraced candidate must return [], not 404");
}

#[tokio::test]
async fn chains_endpoint_returns_row_or_404() {
    let srv = TestServer::start().await;
    srv.store.runs().insert(&sample_run("run-A")).await.expect("run");
    let chain = sample_chain("chain-1", "run-A", &["f-a", "f-b"]);
    srv.store.chains().insert(&chain).await.expect("chain");

    let got: ChainRecord = reqwest::get(format!("{}/api/v1/chains/chain-1", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(got.id, "chain-1");

    let missing = reqwest::get(format!("{}/api/v1/chains/missing", srv.base())).await.expect("get");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn chains_list_endpoint_filters_by_run_id() {
    let srv = TestServer::start().await;
    srv.store.runs().insert(&sample_run("run-A")).await.expect("run-A");
    srv.store.runs().insert(&sample_run("run-B")).await.expect("run-B");
    srv.store
        .chains()
        .insert(&sample_chain("chain-A-1", "run-A", &["f-a"]))
        .await
        .expect("chain-A-1");
    srv.store
        .chains()
        .insert(&sample_chain("chain-A-2", "run-A", &["f-b"]))
        .await
        .expect("chain-A-2");
    srv.store
        .chains()
        .insert(&sample_chain("chain-B-1", "run-B", &["f-c"]))
        .await
        .expect("chain-B-1");

    let got: Vec<ChainRecord> =
        reqwest::get(format!("{}/api/v1/chains?run_id=run-A&include_proposed=true", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    let mut ids: Vec<_> = got.iter().map(|c| c.id.clone()).collect();
    ids.sort();
    assert_eq!(ids, vec!["chain-A-1".to_string(), "chain-A-2".to_string()]);

    let empty: Vec<ChainRecord> =
        reqwest::get(format!("{}/api/v1/chains?run_id=run-missing", srv.base()))
            .await
            .expect("get")
            .json()
            .await
            .expect("json");
    assert!(empty.is_empty());

    let bad = reqwest::get(format!("{}/api/v1/chains", srv.base())).await.expect("get");
    assert_eq!(bad.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn scan_endpoint_calls_trigger() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "run-from-scan".to_string() });
    let srv = TestServer::start_with_trigger(trigger).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/projects/{}/scan?repo=foo", srv.base(), DEFAULT_PROJECT_ID))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["run_id"], "run-from-scan");
}

#[tokio::test]
async fn scan_endpoint_stamps_manual_source_for_runs_triggered_by() {
    let trigger = Arc::new(RecordingTrigger::default());
    let srv = TestServer::start_with_trigger(trigger.clone() as Arc<dyn ScanTrigger>).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/projects/{}/scan", srv.base(), DEFAULT_PROJECT_ID))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let calls = trigger.calls.lock().await.clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].0,
        ScanTriggerSource::Manual,
        "API-driven scan must stamp `Manual` so the daemon records `UI` in runs.triggered_by",
    );
}

#[tokio::test]
async fn start_pentest_rejects_state_changing_without_exploit_mode() {
    let trigger = Arc::new(RecordingOverridesTrigger::default());
    let srv = TestServer::start_with_trigger(trigger.clone() as Arc<dyn ScanTrigger>).await;
    make_default_project_ready(&srv).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/projects/{}/pentest", srv.base(), DEFAULT_PROJECT_ID))
        .json(&serde_json::json!({
            "exploit_mode_enabled": false,
            "allow_state_changing_live_probes": true,
        }))
        .send()
        .await
        .expect("post");

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.expect("json");
    assert!(body["error"]["message"].as_str().unwrap().contains("require exploit mode"));
    assert!(trigger.calls.lock().await.is_empty());
}

#[tokio::test]
async fn start_pentest_passes_exploit_overrides_to_trigger() {
    let trigger = Arc::new(RecordingOverridesTrigger::default());
    let srv = TestServer::start_with_trigger(trigger.clone() as Arc<dyn ScanTrigger>).await;
    make_default_project_ready(&srv).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/projects/{}/pentest", srv.base(), DEFAULT_PROJECT_ID))
        .json(&serde_json::json!({
            "exploit_mode_enabled": true,
            "allow_state_changing_live_probes": true,
            "exploit_dry_run": true,
            "browser_checks_enabled": true,
            "business_logic_templates_enabled": true,
            "research_mode_enabled": true,
            "unsafe_attack_agent_enabled": true,
            "business_logic_template_ids": ["tenant_object_isolation"],
        }))
        .send()
        .await
        .expect("post");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["run_id"], "run-0");

    let calls = trigger.calls.lock().await.clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].source, ScanTriggerSource::Manual);
    assert_eq!(calls[0].project_id.as_deref(), Some(DEFAULT_PROJECT_ID));
    assert_eq!(calls[0].repo, None);
    assert_eq!(
        calls[0].run_overrides,
        Some(nyx_agent_api::ScanRunOverrides {
            exploit_mode_enabled: true,
            allow_state_changing_live_probes: true,
            exploit_dry_run: Some(true),
            browser_checks_enabled: Some(true),
            business_logic_templates_enabled: Some(true),
            research_mode_enabled: Some(true),
            unsafe_attack_agent_enabled: Some(true),
            business_logic_template_ids: Some(vec!["tenant_object_isolation".to_string()]),
        }),
    );
}

#[tokio::test]
async fn websocket_receives_repo_started_and_finished() {
    let srv = TestServer::start().await;
    let url = format!("{}/api/v1/events?run_id=run-ws", srv.ws_base());

    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.expect("ws connect");
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Push frames after the client has connected.
    let events = srv.events.clone();
    let publisher = tokio::spawn(async move {
        // Tiny delay so the subscriber is attached before broadcast goes
        // out: broadcast only delivers to receivers that exist at send
        // time; the WS task subscribes on upgrade, which is in flight
        // when `connect_async` returns.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = events.send(AgentEvent::Run {
            data: RunEvent::RunStarted {
                run_id: "run-ws".to_string(),
                project_id: "test-project".to_string(),
                repos: vec!["alpha".to_string()],
                started_at_ms: 1,
            },
        });
        let _ = events.send(AgentEvent::Run {
            data: RunEvent::RepoStarted {
                run_id: "run-ws".to_string(),
                project_id: "test-project".to_string(),
                repo: "alpha".to_string(),
                started_at_ms: 2,
            },
        });
        // Send a frame for an unrelated run; the filter should drop it.
        let _ = events.send(AgentEvent::Run {
            data: RunEvent::RepoStarted {
                run_id: "other-run".to_string(),
                project_id: "test-project".to_string(),
                repo: "beta".to_string(),
                started_at_ms: 3,
            },
        });
        let _ = events.send(AgentEvent::Run {
            data: RunEvent::RepoFinished {
                run_id: "run-ws".to_string(),
                project_id: "test-project".to_string(),
                repo: "alpha".to_string(),
                outcome: RepoOutcomeTag::Success,
                elapsed_ms: 7,
            },
        });
    });

    let mut saw_started = false;
    let mut saw_finished = false;
    let mut saw_unrelated = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let next = tokio::time::timeout(Duration::from_millis(500), ws_rx.next()).await;
        let frame = match next {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(err))) => panic!("ws err: {err}"),
            Ok(None) => break,
            Err(_) => continue,
        };
        let text = match frame {
            tokio_tungstenite::tungstenite::Message::Text(t) => t,
            tokio_tungstenite::tungstenite::Message::Close(_) => break,
            _ => continue,
        };
        let v: Value = serde_json::from_str(&text).expect("json");
        if v["kind"] == "Run" {
            let kind = v["data"]["kind"].as_str().unwrap_or("");
            let id = v["data"]["run_id"].as_str().unwrap_or("");
            if id == "other-run" {
                saw_unrelated = true;
            }
            if id == "run-ws" {
                if kind == "RepoStarted" {
                    saw_started = true;
                }
                if kind == "RepoFinished" {
                    saw_finished = true;
                }
            }
        }
        if saw_started && saw_finished {
            break;
        }
    }

    let _ = ws_tx.send(tokio_tungstenite::tungstenite::Message::Close(None)).await;
    publisher.await.expect("publisher");

    assert!(saw_started, "WS must receive RepoStarted frame");
    assert!(saw_finished, "WS must receive RepoFinished frame");
    assert!(!saw_unrelated, "run_id filter must drop unrelated runs");
}

#[tokio::test]
async fn setup_status_reports_incomplete_for_fresh_install() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let body: Value = reqwest::get(format!("{}/api/v1/setup/status", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(body["complete"], false);
    assert_eq!(body["ai_runtime"], "none");
    assert_eq!(body["sandbox_backend"], "auto");
}

#[tokio::test]
async fn setup_submit_writes_toml_and_marks_complete() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/setup", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "none",
            "sandbox_backend": "process",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let after: Value = reqwest::get(format!("{}/api/v1/setup/status", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(after["complete"], true);
    assert_eq!(after["sandbox_backend"], "process");
}

#[tokio::test]
async fn setup_submit_persists_anthropic_api_key_through_memory_backend() {
    // CI does not have a keychain agent, so `SecretStore::default()` would
    // fail at `set_password` time. The memory backend exercises the
    // full submit_setup path including the `secrets.set(...)` call.
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/setup", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "anthropic",
            "anthropic_api_key": "sk-ant-test-12345",
            "sandbox_backend": "process",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let after: Value = reqwest::get(format!("{}/api/v1/setup/status", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(after["complete"], true);
    assert_eq!(after["ai_runtime"], "anthropic");
}

#[tokio::test]
async fn setup_submit_keeps_existing_anthropic_key_when_updating_other_settings() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let client = reqwest::Client::new();
    let first = client
        .post(format!("{}/api/v1/setup", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "anthropic",
            "anthropic_api_key": "sk-ant-test-12345",
            "sandbox_backend": "process",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post first");
    assert_eq!(first.status(), reqwest::StatusCode::OK);

    let second = client
        .post(format!("{}/api/v1/setup", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "anthropic",
            "sandbox_backend": "docker",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post second");
    assert_eq!(second.status(), reqwest::StatusCode::OK);

    let after: Value = reqwest::get(format!("{}/api/v1/setup/status", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(after["ai_runtime"], "anthropic");
    assert_eq!(after["sandbox_backend"], "docker");
}

#[tokio::test]
async fn setup_submit_persists_optional_ai_budget_cap() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/setup", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "claude-code",
            "default_run_budget_usd_micros": 42_500_000,
            "sandbox_backend": "process",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let after: Value = reqwest::get(format!("{}/api/v1/setup/status", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(after["default_run_budget_usd_micros"], 42_500_000);
}

#[tokio::test]
async fn setup_submit_rejects_non_positive_ai_budget_cap() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/setup", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "claude-code",
            "default_run_budget_usd_micros": 0,
            "sandbox_backend": "process",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn setup_doctor_fails_anthropic_when_key_is_missing() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let body: Value = reqwest::Client::new()
        .post(format!("{}/api/v1/setup/doctor", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "anthropic",
            "sandbox_backend": "auto",
        }))
        .send()
        .await
        .expect("post")
        .json()
        .await
        .expect("json");

    let ai = body["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|row| row["name"] == "ai-anthropic")
        .expect("ai-anthropic check");
    assert_eq!(ai["passed"], false);
    assert!(ai["message"].as_str().unwrap_or_default().contains("API key is not set"));
}

#[tokio::test]
async fn setup_doctor_accepts_unsaved_anthropic_key() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let body: Value = reqwest::Client::new()
        .post(format!("{}/api/v1/setup/doctor", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "anthropic",
            "anthropic_api_key": "sk-ant-test-12345",
            "sandbox_backend": "auto",
        }))
        .send()
        .await
        .expect("post")
        .json()
        .await
        .expect("json");

    let ai = body["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|row| row["name"] == "ai-anthropic")
        .expect("ai-anthropic check");
    assert_eq!(ai["passed"], true);
    assert!(ai["message"].as_str().unwrap_or_default().contains("provided for this check"));
}

#[tokio::test]
async fn setup_submit_accepts_codex_runtime_without_secrets() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/setup", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "codex",
            "sandbox_backend": "process",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let after: Value = reqwest::get(format!("{}/api/v1/setup/status", srv.base()))
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(after["ai_runtime"], "codex");
    assert_eq!(after["ai_provider"], "codex");
}

#[tokio::test]
async fn setup_doctor_handles_codex_runtime() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let body: Value = reqwest::Client::new()
        .post(format!("{}/api/v1/setup/doctor", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "codex",
            "sandbox_backend": "auto",
        }))
        .send()
        .await
        .expect("post")
        .json()
        .await
        .expect("json");

    let ai = body["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|row| row["name"] == "ai-codex")
        .expect("ai-codex check");
    assert!(ai["message"].as_str().unwrap_or_default().to_lowercase().contains("codex"));
}

#[tokio::test]
async fn setup_submit_rejects_without_ownership_attestation() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, false, false).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/setup", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "none",
            "sandbox_backend": "process",
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_middleware_rejects_missing_bearer_token() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, true, true).await;
    let resp = reqwest::get(format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID))
        .await
        .expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_middleware_allows_valid_bearer_token() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, true, true).await;
    let token = srv.token.clone().expect("auth on");
    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn auth_middleware_lets_setup_endpoints_through_without_token() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, true, false).await;
    let resp = reqwest::get(format!("{}/api/v1/setup/status", srv.base())).await.expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn auth_middleware_allows_setup_status_after_completion_without_token() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, true, true).await;
    let resp = reqwest::get(format!("{}/api/v1/setup/status", srv.base())).await.expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn auth_middleware_requires_token_for_setup_write_after_completion() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, true, true).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/setup", srv.base()))
        .json(&serde_json::json!({
            "ai_runtime": "none",
            "sandbox_backend": "process",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn patch_repo_updates_subset_and_returns_row() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let repos_url = format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID);
    client
        .post(&repos_url)
        .json(&serde_json::json!({
            "name": "billing",
            "source_kind": "local-path",
            "source_url_or_path": "/tmp/billing",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");

    let resp = client
        .patch(format!("{repos_url}/billing"))
        .json(&serde_json::json!({
            "source_kind": "git",
            "source_url_or_path": "https://example.com/billing.git",
            "branch": "dev",
        }))
        .send()
        .await
        .expect("patch");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let row: RepoRecord = resp.json().await.expect("json");
    assert_eq!(row.source_kind, "git");
    assert_eq!(row.source_url_or_path, "https://example.com/billing.git");
    assert_eq!(row.branch.as_deref(), Some("dev"));
}

#[tokio::test]
async fn patch_repo_returns_404_when_missing() {
    let srv = TestServer::start().await;
    let resp = reqwest::Client::new()
        .patch(format!("{}/api/v1/projects/{}/repos/ghost", srv.base(), DEFAULT_PROJECT_ID))
        .json(&serde_json::json!({ "source_kind": "git" }))
        .send()
        .await
        .expect("patch");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_repo_removes_workspace_dir_when_configured() {
    use nyx_agent_api::{
        build_router, AuthConfig, ScanTrigger, ScanTriggerError, ScanTriggerSource, ServerState,
        SetupContext,
    };
    use nyx_agent_core::{Config, SecretStore, Store};
    use tokio::sync::broadcast;

    struct Stub;
    impl ScanTrigger for Stub {
        fn trigger<'a>(
            &'a self,
            _source: ScanTriggerSource,
            _project_id: Option<String>,
            _repo: Option<String>,
            _run_overrides: Option<nyx_agent_api::ScanRunOverrides>,
        ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
            Box::pin(async { Ok("r".to_string()) })
        }
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let (events, _rx) = broadcast::channel::<AgentEvent>(8);
    let config_path = tmp.path().join("nyx-agent.toml");
    let setup = SetupContext::new(config_path, Config::default(), true, SecretStore::memory());
    let state_repos = tmp.path().join("repos");
    let billing_dir = state_repos.join("billing");
    std::fs::create_dir_all(&billing_dir).expect("mkdir");
    std::fs::write(billing_dir.join("marker"), b"x").expect("write");

    let state = ServerState::new(
        store.clone(),
        events,
        Arc::new(Stub) as Arc<dyn ScanTrigger>,
        setup,
        AuthConfig::default(),
    )
    .with_state_repos_dir(state_repos.clone());
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let repos_url = format!("{base}/api/v1/projects/{}/repos", DEFAULT_PROJECT_ID);
    client
        .post(&repos_url)
        .json(&serde_json::json!({
            "name": "billing",
            "source_kind": "local-path",
            "source_url_or_path": billing_dir.to_string_lossy(),
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert!(billing_dir.exists(), "workspace must exist before delete");
    let resp = client.delete(format!("{repos_url}/billing")).send().await.expect("del");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(!billing_dir.exists(), "workspace must be gone after delete");

    h.abort();
}

#[tokio::test]
async fn create_repo_rejects_malformed_git_auth_ref() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID);

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "name": "billing",
            "source_kind": "git",
            "source_url_or_path": "https://example.com/billing.git",
            "auth_ref": "no-colon-here",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap_or_default();
    assert!(body.contains("malformed"), "body did not name the malformed shape: {body}");

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "name": "billing-2",
            "source_kind": "github",
            "source_url_or_path": "https://example.com/billing.git",
            "auth_ref": "kerberos:realm",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap_or_default();
    assert!(body.contains("kerberos"), "body did not name the unknown scheme: {body}");

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "name": "billing-3",
            "source_kind": "git",
            "source_url_or_path": "https://example.com/billing.git",
            "auth_ref": "token-env:GH_TOKEN",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn create_repo_skips_auth_ref_validation_for_non_git_source_kind() {
    let srv = TestServer::start().await;
    let url = format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({
            "name": "logs",
            "source_kind": "local-path",
            "source_url_or_path": "/tmp/logs",
            "auth_ref": "this-would-be-rejected-for-git",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn patch_repo_rejects_setting_malformed_git_auth_ref() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let repos_url = format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID);
    client
        .post(&repos_url)
        .json(&serde_json::json!({
            "name": "svc",
            "source_kind": "git",
            "source_url_or_path": "https://example.com/svc.git",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");

    let resp = client
        .patch(format!("{repos_url}/svc"))
        .json(&serde_json::json!({ "auth_ref": "token-env" }))
        .send()
        .await
        .expect("patch");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn patch_repo_rejects_promoting_to_git_when_existing_auth_ref_is_invalid() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let repos_url = format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID);
    client
        .post(&repos_url)
        .json(&serde_json::json!({
            "name": "svc",
            "source_kind": "local-path",
            "source_url_or_path": "/tmp/svc",
            "auth_ref": "garbage-from-when-this-was-not-git",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");

    let resp = client
        .patch(format!("{repos_url}/svc"))
        .json(&serde_json::json!({
            "source_kind": "git",
            "source_url_or_path": "https://example.com/svc.git",
        }))
        .send()
        .await
        .expect("patch");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    let resp = client
        .patch(format!("{repos_url}/svc"))
        .json(&serde_json::json!({
            "source_kind": "git",
            "source_url_or_path": "https://example.com/svc.git",
            "auth_ref": null,
        }))
        .send()
        .await
        .expect("patch");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn test_repo_endpoint_rejects_unknown_source_kind() {
    let srv = TestServer::start().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/projects/{}/repos/test", srv.base(), DEFAULT_PROJECT_ID))
        .json(&serde_json::json!({
            "source_kind": "smb",
            "source_url_or_path": "//share/x",
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_repo_endpoint_stats_local_path() {
    let srv = TestServer::start().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let repo_dir = tmp.path().join("svc");
    std::fs::create_dir_all(repo_dir.join(".git")).expect("git dir");
    std::fs::write(
        repo_dir.join(".git").join("config"),
        b"[remote \"origin\"]\n\turl = https://example.com/svc.git\n",
    )
    .expect("write");

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/projects/{}/repos/test", srv.base(), DEFAULT_PROJECT_ID))
        .json(&serde_json::json!({
            "source_kind": "local-path",
            "source_url_or_path": repo_dir.to_string_lossy(),
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["ok"], true);
    assert_eq!(body["on_disk_git_remote"], "https://example.com/svc.git");
}

#[tokio::test]
async fn websocket_without_run_filter_receives_all_runs() {
    let srv = TestServer::start().await;
    let url = format!("{}/api/v1/events", srv.ws_base());
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.expect("ws connect");
    let (_, mut ws_rx) = ws_stream.split();

    let events = srv.events.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = events.send(AgentEvent::Run { data: RunEvent::Heartbeat { ts: 1 } });
    });

    let frame = tokio::time::timeout(Duration::from_secs(2), ws_rx.next())
        .await
        .expect("recv timeout")
        .expect("stream end")
        .expect("ws err");
    if let tokio_tungstenite::tungstenite::Message::Text(t) = frame {
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["data"]["kind"], "Heartbeat");
    } else {
        panic!("expected text frame, got {frame:?}");
    }
}

#[tokio::test]
async fn websocket_with_run_filter_replays_buffered_frames() {
    // Build the server inline so we can hold a handle to the per-run
    // replay buffer and pre-seed it with frames the WS upgrade path
    // should hand back before joining the live broadcast.
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let (events, _rx) = broadcast::channel::<AgentEvent>(16);
    let config_path = tmp.path().join("nyx-agent.toml");
    let setup = SetupContext::new(config_path, Config::default(), true, SecretStore::memory());
    let trigger: Arc<dyn ScanTrigger> = Arc::new(StubScanTrigger { run_id: "r-1".to_string() });
    let state =
        ServerState::new(store.clone(), events.clone(), trigger, setup, AuthConfig::default());

    // Pre-seed the replay buffer with the run's opening frames so the
    // WS upgrade reads them back via `snapshot()` before subscribing
    // to the live broadcast.
    let started = AgentEvent::Run {
        data: RunEvent::RunStarted {
            run_id: "r-1".to_string(),
            project_id: "test-project".to_string(),
            repos: vec!["alpha".to_string()],
            started_at_ms: 1,
        },
    };
    let repo_started = AgentEvent::Run {
        data: RunEvent::RepoStarted {
            run_id: "r-1".to_string(),
            project_id: "test-project".to_string(),
            repo: "alpha".to_string(),
            started_at_ms: 2,
        },
    };
    state.replay.push(&started).await;
    state.replay.push(&repo_started).await;

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let url = format!("ws://{addr}/api/v1/events?run_id=r-1");
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.expect("ws connect");
    let (_, mut ws_rx) = ws_stream.split();

    let first = tokio::time::timeout(Duration::from_secs(2), ws_rx.next())
        .await
        .expect("recv timeout")
        .expect("stream end")
        .expect("ws err");
    let second = tokio::time::timeout(Duration::from_secs(2), ws_rx.next())
        .await
        .expect("recv timeout")
        .expect("stream end")
        .expect("ws err");

    let frame_kind = |frame: tokio_tungstenite::tungstenite::Message| -> String {
        match frame {
            tokio_tungstenite::tungstenite::Message::Text(t) => {
                let v: Value = serde_json::from_str(&t).expect("json");
                v["data"]["kind"].as_str().unwrap_or("").to_string()
            }
            other => panic!("expected text frame, got {other:?}"),
        }
    };
    assert_eq!(frame_kind(first), "RunStarted");
    assert_eq!(frame_kind(second), "RepoStarted");

    h.abort();
}

#[tokio::test]
async fn run_summary_endpoint_returns_card() {
    let srv = TestServer::start().await;
    srv.store.repos().upsert(&sample_repo("alpha")).await.expect("repo");
    let mut run = sample_run("run-summary");
    run.status = "Succeeded".to_string();
    run.finished_at = Some(9_000);
    run.wall_clock_ms = Some(7_000);
    srv.store.runs().insert(&run).await.expect("run");
    let f = sample_finding("run-summary", "alpha", "src/a.py", "rule-1");
    srv.store.findings().upsert(&f).await.expect("finding");

    let resp =
        reqwest::get(format!("{}/api/v1/runs/run-summary/summary", srv.base())).await.expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["run_id"], "run-summary");
    assert_eq!(body["total_findings"], 1);
    assert_eq!(body["status"], "Succeeded");

    let md_resp = reqwest::get(format!("{}/api/v1/runs/run-summary/summary.md", srv.base()))
        .await
        .expect("get md");
    assert_eq!(md_resp.status(), reqwest::StatusCode::OK);
    let ct = md_resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(ct.contains("text/markdown"), "expected markdown content-type, got {ct}");
    let md_body = md_resp.text().await.expect("md text");
    assert!(md_body.contains("# Run `run-summary`"));

    let html_resp = reqwest::get(format!("{}/api/v1/runs/run-summary/summary.html", srv.base()))
        .await
        .expect("get html");
    assert_eq!(html_resp.status(), reqwest::StatusCode::OK);
    let html = html_resp.text().await.expect("html text");
    assert!(html.contains("<h2>Run run-summary</h2>"));
}

#[tokio::test]
async fn run_summary_endpoint_404s_for_missing_run() {
    let srv = TestServer::start().await;
    let resp =
        reqwest::get(format!("{}/api/v1/runs/ghost/summary", srv.base())).await.expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn repro_bundle_endpoint_builds_and_downloads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let bundles_dir = tmp.path().join("bundles");
    std::fs::create_dir_all(&bundles_dir).expect("mkdir bundles");

    let (events, _rx) = broadcast::channel::<AgentEvent>(8);
    let setup = SetupContext::new(
        tmp.path().join("nyx-agent.toml"),
        Config::default(),
        true,
        SecretStore::memory(),
    );
    let state = ServerState::new(
        store.clone(),
        events,
        Arc::new(StubScanTrigger { run_id: "x".to_string() }) as Arc<dyn ScanTrigger>,
        setup,
        AuthConfig::default(),
    )
    .with_state_bundles_dir(bundles_dir.clone());

    store.repos().upsert(&sample_repo("alpha")).await.expect("repo");
    store.runs().insert(&sample_run("run-bundle")).await.expect("run");
    let f = sample_finding("run-bundle", "alpha", "src/a.py", "rule-bundle");
    let fid = f.id.clone();
    store.findings().upsert(&f).await.expect("finding");

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Build the bundle.
    let post = client
        .post(format!("{base}/api/v1/findings/{fid}/repro-bundle"))
        .send()
        .await
        .expect("post");
    assert_eq!(post.status(), reqwest::StatusCode::OK);
    let manifest: Value = post.json().await.expect("manifest json");
    assert_eq!(manifest["finding_id"], fid);
    let bundle_path = manifest["bundle_path"].as_str().expect("path").to_string();
    assert!(std::path::Path::new(&bundle_path).exists());

    // Download the tar.
    let resp = client
        .get(format!("{base}/api/v1/findings/{fid}/repro-bundle.tar"))
        .send()
        .await
        .expect("get tar");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert_eq!(ct, "application/x-tar");
    let cd = resp.headers().get("content-disposition").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(cd.contains(&format!("filename=\"{fid}.tar\"")), "got: {cd}");
    let bytes = resp.bytes().await.expect("bytes");
    assert!(bytes.len() > 1024, "tar should have at least one entry + terminator");

    h.abort();
}

/// Parse a captured SSE body into (event, data) pairs.
///
/// Each frame is two consecutive lines (`event: NAME\ndata: PAYLOAD`)
/// terminated by a blank line. The axum/Sse keep-alive emits `:`
/// comment lines on a periodic timer; the placeholder repro script
/// completes well under that interval, so this parser only needs to
/// handle real `event:` frames.
fn parse_sse_frames(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for block in body.split("\n\n") {
        let mut event: Option<String> = None;
        let mut data: Vec<String> = Vec::new();
        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                event = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data.push(rest.trim_start().to_string());
            }
        }
        if let Some(e) = event {
            out.push((e, data.join("\n")));
        }
    }
    out
}

#[tokio::test]
async fn replay_endpoint_streams_repro_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let bundles_dir = tmp.path().join("bundles");
    std::fs::create_dir_all(&bundles_dir).expect("mkdir bundles");

    let (events, _rx) = broadcast::channel::<AgentEvent>(8);
    let setup = SetupContext::new(
        tmp.path().join("nyx-agent.toml"),
        Config::default(),
        true,
        SecretStore::memory(),
    );
    let state = ServerState::new(
        store.clone(),
        events,
        Arc::new(StubScanTrigger { run_id: "x".to_string() }) as Arc<dyn ScanTrigger>,
        setup,
        AuthConfig::default(),
    )
    .with_state_bundles_dir(bundles_dir.clone());

    store.repos().upsert(&sample_repo("alpha")).await.expect("repo");
    store.runs().insert(&sample_run("run-replay")).await.expect("run");
    let f = sample_finding("run-replay", "alpha", "src/a.py", "rule-replay");
    let fid = f.id.clone();
    store.findings().upsert(&f).await.expect("finding");

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    // Pre-build the bundle so `/replay` exercises only the replay path.
    let post = client
        .post(format!("{base}/api/v1/findings/{fid}/repro-bundle"))
        .send()
        .await
        .expect("build bundle");
    assert_eq!(post.status(), reqwest::StatusCode::OK);

    let replay = client
        .post(format!("{base}/api/v1/findings/{fid}/replay"))
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .expect("replay request");
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    let ct = replay.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(ct.starts_with("text/event-stream"), "got content-type {ct}");
    let body = replay.text().await.expect("body");
    let frames = parse_sse_frames(&body);

    let events_only: Vec<&str> = frames.iter().map(|(e, _)| e.as_str()).collect();
    assert!(events_only.contains(&"start"), "expected start frame, got {events_only:?}");
    assert!(events_only.contains(&"end"), "expected end frame, got {events_only:?}");
    assert!(
        events_only.contains(&"stdout"),
        "expected at least one stdout frame, got {events_only:?}"
    );

    let start_data = frames
        .iter()
        .find(|(e, _)| e == "start")
        .map(|(_, d)| d.as_str())
        .expect("start frame data");
    let start_json: Value = serde_json::from_str(start_data).expect("start json");
    assert_eq!(start_json["finding_id"], fid);

    let end_data =
        frames.iter().find(|(e, _)| e == "end").map(|(_, d)| d.as_str()).expect("end frame data");
    let end_json: Value = serde_json::from_str(end_data).expect("end json");
    assert_eq!(end_json["status"], "Pass");
    assert_eq!(end_json["exit_code"], 0);

    let stdout_lines: Vec<&str> =
        frames.iter().filter(|(e, _)| e == "stdout").map(|(_, d)| d.as_str()).collect();
    assert!(
        stdout_lines.iter().any(|line| line.contains("[repro] finding=")),
        "expected `[repro] finding=` line in stdout frames: {stdout_lines:?}"
    );

    h.abort();
}

#[tokio::test]
async fn replay_endpoint_broadcasts_repro_events_for_websocket_subscribers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let bundles_dir = tmp.path().join("bundles");
    std::fs::create_dir_all(&bundles_dir).expect("mkdir bundles");

    let (events, mut rx) = broadcast::channel::<AgentEvent>(64);
    let setup = SetupContext::new(
        tmp.path().join("nyx-agent.toml"),
        Config::default(),
        true,
        SecretStore::memory(),
    );
    let state = ServerState::new(
        store.clone(),
        events,
        Arc::new(StubScanTrigger { run_id: "x".to_string() }) as Arc<dyn ScanTrigger>,
        setup,
        AuthConfig::default(),
    )
    .with_state_bundles_dir(bundles_dir.clone());

    store.repos().upsert(&sample_repo("alpha")).await.expect("repo");
    store.runs().insert(&sample_run("run-replay-ws")).await.expect("run");
    let f = sample_finding("run-replay-ws", "alpha", "src/a.py", "rule-replay-ws");
    let fid = f.id.clone();
    store.findings().upsert(&f).await.expect("finding");

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/findings/{fid}/repro-bundle"))
        .send()
        .await
        .expect("build bundle");
    assert_eq!(post.status(), reqwest::StatusCode::OK);

    let replay = client
        .post(format!("{base}/api/v1/findings/{fid}/replay"))
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .expect("replay request");
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    // Drain the SSE body so the handler runs to completion and every
    // broadcast frame is emitted before we collect on the receiver.
    let _ = replay.text().await.expect("body");

    let mut collected: Vec<ReproEvent> = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let AgentEvent::Repro { data } = ev {
            collected.push(data);
        }
    }

    assert!(
        collected.iter().any(|e| matches!(
            e,
            ReproEvent::ReplayStarted { finding_id, .. } if *finding_id == fid
        )),
        "expected ReplayStarted scoped to {fid}, got {collected:?}"
    );
    assert!(
        collected.iter().any(|e| matches!(
            e,
            ReproEvent::ReplayStdout { finding_id, line }
                if *finding_id == fid && line.contains("[repro] finding=")
        )),
        "expected ReplayStdout carrying the repro template, got {collected:?}"
    );
    assert!(
        collected.iter().any(|e| matches!(
            e,
            ReproEvent::ReplayFinished {
                finding_id,
                status,
                exit_code,
                ..
            } if *finding_id == fid && status == "Pass" && *exit_code == 0
        )),
        "expected ReplayFinished with Pass/0, got {collected:?}"
    );
    assert!(
        !collected.iter().any(|e| matches!(e, ReproEvent::ReplayError { .. })),
        "no ReplayError expected on the happy path, got {collected:?}"
    );

    h.abort();
}

#[tokio::test]
async fn replay_endpoint_refuses_on_sha_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let bundles_dir = tmp.path().join("bundles");
    std::fs::create_dir_all(&bundles_dir).expect("mkdir bundles");

    let (events, _rx) = broadcast::channel::<AgentEvent>(8);
    let setup = SetupContext::new(
        tmp.path().join("nyx-agent.toml"),
        Config::default(),
        true,
        SecretStore::memory(),
    );
    let state = ServerState::new(
        store.clone(),
        events,
        Arc::new(StubScanTrigger { run_id: "x".to_string() }) as Arc<dyn ScanTrigger>,
        setup,
        AuthConfig::default(),
    )
    .with_state_bundles_dir(bundles_dir.clone());

    store.repos().upsert(&sample_repo("alpha")).await.expect("repo");
    store.runs().insert(&sample_run("run-mismatch")).await.expect("run");
    let f = sample_finding("run-mismatch", "alpha", "src/a.py", "rule-mismatch");
    let fid = f.id.clone();
    store.findings().upsert(&f).await.expect("finding");

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let post = client
        .post(format!("{base}/api/v1/findings/{fid}/repro-bundle"))
        .send()
        .await
        .expect("build bundle");
    assert_eq!(post.status(), reqwest::StatusCode::OK);
    let manifest: Value = post.json().await.expect("manifest json");
    let bundle_path = manifest["bundle_path"].as_str().expect("path").to_string();

    // Substitute the on-disk tar bytes after `repro_bundles.sha256` was
    // stamped. The replay handler must refuse to extract.
    std::fs::write(&bundle_path, b"corrupted-bytes\n").expect("overwrite tar");

    let replay = client
        .post(format!("{base}/api/v1/findings/{fid}/replay"))
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .expect("replay request");
    assert_eq!(replay.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    let body = replay.text().await.expect("body");
    assert!(
        body.contains("bundle integrity check failed"),
        "expected integrity check failure, got: {body}"
    );

    h.abort();
}

// ---- /webhook/git -----------------------------------------------------------

async fn start_webhook_server(
    secret: &[u8],
    branch: Option<&str>,
    repo: Option<&str>,
) -> (std::net::SocketAddr, Arc<RecordingTrigger>, tokio::task::JoinHandle<()>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let (events, _rx) = broadcast::channel::<AgentEvent>(64);
    let config_path = tmp.path().join("nyx-agent.toml");
    let setup = SetupContext::new(config_path, Config::default(), true, SecretStore::memory());
    let trigger = Arc::new(RecordingTrigger::default());
    let scan_trigger: Arc<dyn ScanTrigger> = trigger.clone();
    let state = ServerState::new(store, events, scan_trigger, setup, AuthConfig::default())
        .with_webhook(nyx_agent_api::WebhookConfig::new(
            Arc::new(nyx_agent_api::StaticSecretResolver { secret: Some(secret.to_vec()) }),
            branch.map(str::to_string),
            repo.map(str::to_string),
        ));
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, trigger, handle, tmp)
}

#[derive(Default)]
struct RecordingTrigger {
    calls: tokio::sync::Mutex<Vec<(ScanTriggerSource, Option<String>)>>,
}

impl ScanTrigger for RecordingTrigger {
    fn trigger<'a>(
        &'a self,
        source: ScanTriggerSource,
        _project_id: Option<String>,
        repo: Option<String>,
        _run_overrides: Option<nyx_agent_api::ScanRunOverrides>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
        Box::pin(async move {
            let mut g = self.calls.lock().await;
            let id = format!("run-{}", g.len());
            g.push((source, repo));
            Ok(id)
        })
    }
}

#[tokio::test]
async fn webhook_with_valid_hmac_triggers_scan() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, Some("main"), None).await;
    let body = br#"{"ref":"refs/heads/main","after":"deadbeef"}"#.to_vec();
    let sig = nyx_agent_api::sign_webhook(secret, &body);
    let url = format!("http://{}/webhook/git", addr);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-Hub-Signature-256", &sig)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let v: Value = resp.json().await.expect("json");
    assert_eq!(v["triggered"], Value::Bool(true));
    assert!(v["run_id"].as_str().is_some());
    let calls = trigger.calls.lock().await.clone();
    assert_eq!(calls.len(), 1, "trigger fired exactly once");
    assert_eq!(
        calls[0].0,
        ScanTriggerSource::Webhook,
        "webhook-triggered scan must stamp `Webhook` source for runs.triggered_by",
    );
    h.abort();
}

#[tokio::test]
async fn webhook_with_invalid_hmac_returns_401() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    let body = br#"{"ref":"refs/heads/main"}"#.to_vec();
    let bad_sig = nyx_agent_api::sign_webhook(b"wrong-secret", &body);
    let url = format!("http://{}/webhook/git", addr);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-Hub-Signature-256", &bad_sig)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let calls = trigger.calls.lock().await.clone();
    assert!(calls.is_empty(), "invalid HMAC must not trigger");
    h.abort();
}

#[tokio::test]
async fn webhook_missing_signature_returns_401() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    let url = format!("http://{}/webhook/git", addr);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/json")
        .body(br#"{"ref":"refs/heads/main"}"#.to_vec())
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let calls = trigger.calls.lock().await.clone();
    assert!(calls.is_empty());
    h.abort();
}

#[tokio::test]
async fn webhook_wrong_branch_is_skipped_not_triggered() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, Some("main"), None).await;
    let body = br#"{"ref":"refs/heads/topic-branch"}"#.to_vec();
    let sig = nyx_agent_api::sign_webhook(secret, &body);
    let url = format!("http://{}/webhook/git", addr);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-Hub-Signature-256", &sig)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let v: Value = resp.json().await.expect("json");
    assert_eq!(v["triggered"], Value::Bool(false));
    let calls = trigger.calls.lock().await.clone();
    assert!(calls.is_empty(), "branch filter must short-circuit");
    h.abort();
}

/// Send a raw HTTP/1.1 POST without writing the announced body and
/// return (status_code, response_body). Used to test webhook
/// short-circuit paths where the handler refuses the request before
/// reading the body, which would race with reqwest's body writer
/// closing the connection.
async fn raw_post_headers_only(
    addr: std::net::SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    content_length: usize,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {content_length}\r\n",
        host = addr,
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.expect("write headers");
    // Intentionally do NOT write the body. If the server short-circuits
    // on header inspection, it will respond and close; if it tries to
    // buffer the body, the test hangs (and we time out the read below).
    let mut buf = Vec::new();
    let read =
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    let bytes = match read {
        Ok(Ok(_)) => buf,
        Ok(Err(_)) => buf,
        Err(_) => panic!(
            "server did not respond within 5s; likely buffered body instead of short-circuiting"
        ),
    };
    let text = String::from_utf8_lossy(&bytes).to_string();
    let status_line = text.lines().next().unwrap_or("");
    let status_code: u16 =
        status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status_code, text)
}

#[tokio::test]
async fn webhook_malformed_signature_short_circuits_without_body_read() {
    // A malformed signature (e.g. wrong digest length) must 401 before
    // the handler buffers the body. Announce a body via Content-Length
    // but never write it. If the handler short-circuits on the header
    // shape, it responds + closes; if it tries to buffer the body, the
    // test deadlocks until the timeout fires.
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    let (status, _body) = raw_post_headers_only(
        addr,
        "/webhook/git",
        &[("X-Hub-Signature-256", "sha256=deadbeef"), ("Content-Type", "application/json")],
        1024,
    )
    .await;
    assert_eq!(status, 401, "malformed signature must 401");
    let calls = trigger.calls.lock().await.clone();
    assert!(calls.is_empty(), "malformed signature must not trigger");
    h.abort();
}

#[tokio::test]
async fn webhook_oversized_content_length_returns_413() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    // Well-formed signature so the handler reaches the size check.
    let well_formed_sig = format!("sha256={}", "0".repeat(64));
    let (status, _body) = raw_post_headers_only(
        addr,
        "/webhook/git",
        &[("X-Hub-Signature-256", &well_formed_sig), ("Content-Type", "application/json")],
        10 * 1024 * 1024, // 10 MiB; cap is 1 MiB
    )
    .await;
    assert_eq!(status, 413, "oversized Content-Length must 413");
    let calls = trigger.calls.lock().await.clone();
    assert!(calls.is_empty(), "413 must short-circuit before trigger");
    h.abort();
}

#[tokio::test]
async fn webhook_ping_event_does_not_trigger() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    let body = br#"{"zen":"Speak like a human."}"#.to_vec();
    let sig = nyx_agent_api::sign_webhook(secret, &body);
    let url = format!("http://{}/webhook/git", addr);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-Hub-Signature-256", &sig)
        .header("X-GitHub-Event", "ping")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let v: Value = resp.json().await.expect("json");
    assert_eq!(v["triggered"], Value::Bool(false));
    let calls = trigger.calls.lock().await.clone();
    assert!(calls.is_empty(), "ping must not trigger a scan");
    h.abort();
}

#[tokio::test]
async fn webhook_non_push_event_does_not_trigger() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    let body = br#"{"action":"opened","pull_request":{"number":1}}"#.to_vec();
    let sig = nyx_agent_api::sign_webhook(secret, &body);
    let url = format!("http://{}/webhook/git", addr);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-Hub-Signature-256", &sig)
        .header("X-GitHub-Event", "pull_request")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let v: Value = resp.json().await.expect("json");
    assert_eq!(v["triggered"], Value::Bool(false));
    assert!(
        v["message"].as_str().unwrap_or("").contains("pull_request"),
        "message must name the refused event"
    );
    let calls = trigger.calls.lock().await.clone();
    assert!(calls.is_empty(), "non-push event must not trigger a scan");
    h.abort();
}

#[tokio::test]
async fn webhook_push_event_with_explicit_header_triggers_scan() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, Some("main"), None).await;
    let body = br#"{"ref":"refs/heads/main","after":"deadbeef"}"#.to_vec();
    let sig = nyx_agent_api::sign_webhook(secret, &body);
    let url = format!("http://{}/webhook/git", addr);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-Hub-Signature-256", &sig)
        .header("X-GitHub-Event", "push")
        .header("X-GitHub-Delivery", "11111111-1111-1111-1111-111111111111")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::ACCEPTED);
    let calls = trigger.calls.lock().await.clone();
    assert_eq!(calls.len(), 1, "push event must trigger exactly once");
    h.abort();
}

#[tokio::test]
async fn webhook_replayed_delivery_id_is_dropped() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    let body = br#"{"ref":"refs/heads/main"}"#.to_vec();
    let sig = nyx_agent_api::sign_webhook(secret, &body);
    let url = format!("http://{}/webhook/git", addr);
    let client = reqwest::Client::new();
    let delivery = "22222222-2222-2222-2222-222222222222";

    let first = client
        .post(&url)
        .header("X-Hub-Signature-256", &sig)
        .header("X-GitHub-Event", "push")
        .header("X-GitHub-Delivery", delivery)
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .expect("post 1");
    assert_eq!(first.status(), reqwest::StatusCode::ACCEPTED);

    let second = client
        .post(&url)
        .header("X-Hub-Signature-256", &sig)
        .header("X-GitHub-Event", "push")
        .header("X-GitHub-Delivery", delivery)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post 2");
    assert_eq!(second.status(), reqwest::StatusCode::OK);
    let v: Value = second.json().await.expect("json");
    assert_eq!(v["triggered"], Value::Bool(false));
    assert!(
        v["message"].as_str().unwrap_or("").contains("already processed"),
        "second delivery must be dropped as a replay"
    );

    let calls = trigger.calls.lock().await.clone();
    assert_eq!(calls.len(), 1, "replayed delivery must not trigger a second scan");
    h.abort();
}

async fn start_webhook_server_with_limits(
    secret: &[u8],
    concurrency: Option<Arc<nyx_agent_api::WebhookConcurrencyLimit>>,
    rate_limit: Option<Arc<nyx_agent_api::WebhookRateLimiter>>,
) -> (std::net::SocketAddr, Arc<RecordingTrigger>, tokio::task::JoinHandle<()>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let (events, _rx) = broadcast::channel::<AgentEvent>(64);
    let config_path = tmp.path().join("nyx-agent.toml");
    let setup = SetupContext::new(config_path, Config::default(), true, SecretStore::memory());
    let trigger = Arc::new(RecordingTrigger::default());
    let scan_trigger: Arc<dyn ScanTrigger> = trigger.clone();
    let mut cfg = nyx_agent_api::WebhookConfig::new(
        Arc::new(nyx_agent_api::StaticSecretResolver { secret: Some(secret.to_vec()) }),
        None,
        None,
    );
    if let Some(c) = concurrency {
        cfg = cfg.with_concurrency_limit(c);
    }
    if let Some(r) = rate_limit {
        cfg = cfg.with_rate_limit(r);
    }
    let state = ServerState::new(store, events, scan_trigger, setup, AuthConfig::default())
        .with_webhook(cfg);
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    // Launch with ConnectInfo so the rate limiter can see the peer's IP.
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    (addr, trigger, handle, tmp)
}

#[tokio::test]
async fn webhook_rate_limit_refuses_burst_from_one_ip_with_429() {
    let secret = b"shared-secret";
    // Bucket size 2, refill 0 (no replenishment during the test).
    let limiter = Arc::new(nyx_agent_api::WebhookRateLimiter::new(2, 0.0, 32));
    let (addr, trigger, h, _tmp) =
        start_webhook_server_with_limits(secret, None, Some(limiter)).await;
    let body = br#"{"ref":"refs/heads/main"}"#.to_vec();
    let sig = nyx_agent_api::sign_webhook(secret, &body);
    let url = format!("http://{}/webhook/git", addr);
    let client = reqwest::Client::new();
    let mut statuses = Vec::new();
    for _ in 0..4 {
        let resp = client
            .post(&url)
            .header("X-Hub-Signature-256", &sig)
            .header("X-GitHub-Event", "push")
            .header("content-type", "application/json")
            .body(body.clone())
            .send()
            .await
            .expect("post");
        statuses.push(resp.status());
    }
    // First two requests fit in the bucket; the next two must be
    // refused with 429 without triggering a scan.
    assert_eq!(statuses[0], reqwest::StatusCode::ACCEPTED, "first request must succeed");
    assert_eq!(statuses[1], reqwest::StatusCode::ACCEPTED, "second request must succeed");
    assert_eq!(
        statuses[2],
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "third request must be rate-limited",
    );
    assert_eq!(
        statuses[3],
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "fourth request must remain rate-limited"
    );
    let calls = trigger.calls.lock().await.clone();
    assert_eq!(calls.len(), 2, "rate-limited requests must not reach the scan trigger",);
    h.abort();
}

#[tokio::test]
async fn webhook_concurrency_limit_refuses_overflow_with_429() {
    let secret = b"shared-secret";
    // One permit; the rate limiter is unset so the only gate is the
    // concurrency cap. We need a trigger that blocks long enough for
    // the second request to land while the first still holds the
    // permit.
    let trigger = Arc::new(BlockingTrigger::default());
    let limit = Arc::new(nyx_agent_api::WebhookConcurrencyLimit::new(1));
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let (events, _rx) = broadcast::channel::<AgentEvent>(64);
    let config_path = tmp.path().join("nyx-agent.toml");
    let setup = SetupContext::new(config_path, Config::default(), true, SecretStore::memory());
    let scan_trigger: Arc<dyn ScanTrigger> = trigger.clone();
    let cfg = nyx_agent_api::WebhookConfig::new(
        Arc::new(nyx_agent_api::StaticSecretResolver { secret: Some(secret.to_vec()) }),
        None,
        None,
    )
    .with_concurrency_limit(limit);
    let state = ServerState::new(store, events, scan_trigger, setup, AuthConfig::default())
        .with_webhook(cfg);
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let h = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let body = br#"{"ref":"refs/heads/main"}"#.to_vec();
    let sig = nyx_agent_api::sign_webhook(secret, &body);
    let url = format!("http://{}/webhook/git", addr);
    // Fire the first request without awaiting; it parks inside the
    // trigger waiting for our release signal.
    let url_a = url.clone();
    let sig_a = sig.clone();
    let body_a = body.clone();
    let in_flight = tokio::spawn(async move {
        reqwest::Client::new()
            .post(&url_a)
            .header("X-Hub-Signature-256", &sig_a)
            .header("X-GitHub-Event", "push")
            .header("content-type", "application/json")
            .body(body_a)
            .send()
            .await
            .expect("post")
    });
    // Wait until the trigger has been entered (and the permit is held).
    for _ in 0..200 {
        if trigger.is_blocking().await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(trigger.is_blocking().await, "first request did not reach the trigger within 2s");

    // Second request hits the saturated concurrency gate and is
    // refused with 429.
    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-Hub-Signature-256", &sig)
        .header("X-GitHub-Event", "push")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);

    trigger.release();
    let first = in_flight.await.expect("first request joined");
    assert_eq!(first.status(), reqwest::StatusCode::ACCEPTED);
    h.abort();
}

#[derive(Default)]
struct BlockingTrigger {
    calls: tokio::sync::Mutex<usize>,
    in_flight: tokio::sync::Mutex<bool>,
    gate: tokio::sync::Notify,
}

impl BlockingTrigger {
    async fn is_blocking(&self) -> bool {
        *self.in_flight.lock().await
    }

    fn release(&self) {
        self.gate.notify_waiters();
    }
}

impl ScanTrigger for BlockingTrigger {
    fn trigger<'a>(
        &'a self,
        _source: ScanTriggerSource,
        _project_id: Option<String>,
        _repo: Option<String>,
        _run_overrides: Option<nyx_agent_api::ScanRunOverrides>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
        Box::pin(async move {
            *self.in_flight.lock().await = true;
            self.gate.notified().await;
            *self.in_flight.lock().await = false;
            let mut g = self.calls.lock().await;
            *g += 1;
            Ok(format!("run-{}", *g))
        })
    }
}

#[tokio::test]
async fn webhook_refless_body_without_event_header_does_not_trigger() {
    // Signed body that has no `ref` field and no provider-specific
    // event header. The old code path would have triggered a scan
    // (because the branch filter was unset) for any HMAC-valid blob;
    // the push-event guard refuses it.
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    let body = br#"{"hello":"world"}"#.to_vec();
    let sig = nyx_agent_api::sign_webhook(secret, &body);
    let url = format!("http://{}/webhook/git", addr);
    let resp = reqwest::Client::new()
        .post(&url)
        .header("X-Hub-Signature-256", &sig)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let v: Value = resp.json().await.expect("json");
    assert_eq!(v["triggered"], Value::Bool(false));
    let calls = trigger.calls.lock().await.clone();
    assert!(calls.is_empty(), "refless body must not trigger a scan");
    h.abort();
}

// ---- /projects --------------------------------------------------------------

#[tokio::test]
async fn projects_crud_roundtrip() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();

    // Default project is seeded at store open; a fresh list returns it.
    let listed: Vec<Value> = client
        .get(format!("{}/api/v1/projects", srv.base()))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert!(
        listed.iter().any(|p| p["id"] == DEFAULT_PROJECT_ID),
        "default project must be present in listing"
    );

    let created: Value = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({
            "name": "acme",
            "description": "Acme web product",
            "target_base_url": "http://localhost:3000",
            "env_config": { "NODE_ENV": "test" },
            "runtime_profile": {
                "build_commands": [
                    { "command": "npm ci", "repo_name": "web", "timeout_seconds": 120 }
                ],
                "start_commands": [
                    { "command": "npm run dev", "repo_name": "web" }
                ],
                "health_check_url": "http://localhost:3000/health",
                "target_base_url": "http://localhost:3000",
                "allowed_hosts": ["localhost", "127.0.0.1"],
                "env_vars": [
                    { "name": "NODE_ENV", "value": "test", "secret": false }
                ],
                "env_file": ".env.test",
                "timeout_seconds": 300
            },
        }))
        .send()
        .await
        .expect("post")
        .json()
        .await
        .expect("json");
    assert_eq!(created["name"], "acme");
    let id = created["id"].as_str().expect("id").to_string();

    let got: Value = client
        .get(format!("{}/api/v1/projects/{id}", srv.base()))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(got["id"], id);
    assert_eq!(got["target_base_url"], "http://localhost:3000");
    assert_eq!(got["runtime_profile"]["build_commands"][0]["command"], "npm ci");
    assert_eq!(got["runtime_profile"]["start_commands"][0]["command"], "npm run dev");
    assert_eq!(got["runtime_profile"]["health_check_url"], "http://localhost:3000/health");
    assert_eq!(got["runtime_profile"]["allowed_hosts"][0], "localhost");

    let patched: Value = client
        .patch(format!("{}/api/v1/projects/{id}", srv.base()))
        .json(&serde_json::json!({
            "description": "rev2",
            "runtime_profile": {
                "build_commands": [],
                "start_commands": [
                    { "command": "cargo run", "working_directory": "server" }
                ],
                "health_check_command": { "command": "curl -f http://localhost:8000/health" },
                "target_base_url": "http://localhost:8000",
                "allowed_hosts": ["localhost"],
                "env_vars": [],
                "timeout_seconds": 180
            }
        }))
        .send()
        .await
        .expect("patch")
        .json()
        .await
        .expect("json");
    assert_eq!(patched["description"], "rev2");
    assert_eq!(patched["target_base_url"], "http://localhost:8000");
    assert_eq!(patched["runtime_profile"]["start_commands"][0]["working_directory"], "server");
    assert_eq!(
        patched["runtime_profile"]["health_check_command"]["command"],
        "curl -f http://localhost:8000/health"
    );

    let del =
        client.delete(format!("{}/api/v1/projects/{id}", srv.base())).send().await.expect("del");
    assert_eq!(del.status(), reqwest::StatusCode::OK);

    let missing =
        client.get(format!("{}/api/v1/projects/{id}", srv.base())).send().await.expect("get");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn auth_auto_setup_patches_runtime_profile_without_triggering_scan() {
    let trigger = Arc::new(RecordingOverridesTrigger::default());
    let srv = TestServer::start_with_trigger(trigger.clone() as Arc<dyn ScanTrigger>).await;
    let client = reqwest::Client::new();
    let created: Value = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({
            "name": "authz-app",
            "target_base_url": "http://localhost:3000"
        }))
        .send()
        .await
        .expect("post project")
        .json()
        .await
        .expect("project json");
    let project_id = created["id"].as_str().expect("project id");
    let repo_dir = srv._tmp.path().join("auth-source");
    std::fs::create_dir_all(repo_dir.join("src")).expect("mkdir");
    std::fs::write(
        repo_dir.join("src/routes.ts"),
        r#"router.post("/api/auth/login", login);
router.get("/api/projects/:id", requireUser, showProject);
router.get("/api/admin/report", requireAdmin, adminReport);
"#,
    )
    .expect("write source");
    std::fs::write(
        repo_dir.join("src/seed.ts"),
        r#"export const testUsers = {
  user_a: { email: "user-a@example.test", password: "user-a-pass" },
  user_b: { email: "user-b@example.test", password: "user-b-pass" },
  admin: { email: "admin@example.test", password: "admin-pass" },
};"#,
    )
    .expect("write seed");
    let now = nyx_agent_core::now_epoch_ms();
    srv.store
        .repos()
        .upsert(&RepoRecord {
            id: "repo-auth-source".to_string(),
            name: "auth-source".to_string(),
            project_id: project_id.to_string(),
            source_kind: "local".to_string(),
            source_url_or_path: repo_dir.display().to_string(),
            branch: None,
            auth_ref: None,
            i_own_this: true,
            last_scan_run_id: None,
            last_scan_finished_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("repo");

    let started: Value = client
        .post(format!("{}/api/v1/projects/{project_id}/auth/auto-setup", srv.base()))
        .json(&serde_json::json!({ "target_base_url": "http://localhost:3000" }))
        .send()
        .await
        .expect("post auth setup")
        .json()
        .await
        .expect("json");
    let job_id = started["job"]["id"].as_str().expect("job id");
    let job = wait_auth_setup_job(&client, &srv.base(), project_id, job_id).await;
    assert_eq!(job["status"], "succeeded");
    let response = &job["result"];

    assert_eq!(response["profiles_added"], 3);
    assert_eq!(response["agent_used"], false);
    assert_eq!(response["verification"]["status"], "verified");
    assert_eq!(response["roles"][0], "user_a");
    assert!(response["login_paths"].as_array().unwrap().iter().any(|v| v == "/api/auth/login"));
    assert!(response["object_routes"].as_array().unwrap().iter().any(|v| v == "/api/projects/:id"));
    let profiles =
        response["project"]["runtime_profile"]["auth_profiles"].as_array().expect("profiles");
    assert!(profiles.iter().any(|profile| {
        profile["role"] == "user_a"
            && profile["mode"] == "ai_auto"
            && profile["login_url"] == "/api/auth/login"
            && profile["username_env"] == "NYX_AGENT_USER_A_USERNAME"
            && profile["password_env"] == "NYX_AGENT_USER_A_PASSWORD"
    }));
    assert!(profiles.iter().any(|profile| profile["role"] == "admin"));
    let env_vars = response["project"]["runtime_profile"]["env_vars"].as_array().expect("env vars");
    assert!(env_vars.iter().any(|var| {
        var["name"] == "NYX_AGENT_USER_A_USERNAME"
            && var["value"] == "user-a@example.test"
            && var["secret"] == false
    }));
    assert!(env_vars.iter().any(|var| {
        var["name"] == "NYX_AGENT_USER_A_PASSWORD"
            && var["value"] == "user-a-pass"
            && var["secret"] == true
    }));
    assert!(trigger.calls.lock().await.is_empty(), "auth setup must not trigger a pentest");
}

#[tokio::test]
async fn ai_project_setup_agent_applies_launch_profile() {
    let srv = TestServer::start_with_project_setup_agent(Arc::new(StubProjectSetupAgent)).await;
    let client = reqwest::Client::new();
    let created: Value = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({
            "name": "wrangler-app",
            "target_base_url": "http://127.0.0.1:8787"
        }))
        .send()
        .await
        .expect("post project")
        .json()
        .await
        .expect("project json");
    let project_id = created["id"].as_str().expect("project id");
    let repo_dir = srv._tmp.path().join("wrangler-source");
    std::fs::create_dir_all(&repo_dir).expect("mkdir");
    std::fs::write(
        repo_dir.join("package.json"),
        r#"{"scripts":{"dev":"wrangler dev","dev:reset":"wrangler d1 migrations apply DB --local"}}"#,
    )
    .expect("write package");
    let now = nyx_agent_core::now_epoch_ms();
    srv.store
        .repos()
        .upsert(&RepoRecord {
            id: "repo-wrangler-source".to_string(),
            name: "web".to_string(),
            project_id: project_id.to_string(),
            source_kind: "local".to_string(),
            source_url_or_path: repo_dir.display().to_string(),
            branch: None,
            auth_ref: None,
            i_own_this: true,
            last_scan_run_id: None,
            last_scan_finished_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("repo");

    let started: Value = client
        .post(format!("{}/api/v1/projects/{project_id}/setup/ai", srv.base()))
        .json(&serde_json::json!({ "target_base_url": "http://127.0.0.1:8787" }))
        .send()
        .await
        .expect("post project setup")
        .json()
        .await
        .expect("json");
    let job_id = started["job"]["id"].as_str().expect("job id");
    let job = wait_project_setup_job(&client, &srv.base(), project_id, job_id).await;
    assert_eq!(job["status"], "succeeded");
    assert_eq!(job["result"]["verification"]["status"], "verified");
    assert_eq!(job["result"]["profile"]["reset_steps"][0]["stdin"], "y\n");
    let jobs: Value = client
        .get(format!("{}/api/v1/projects/{project_id}/setup/ai", srv.base()))
        .send()
        .await
        .expect("list project setup jobs")
        .json()
        .await
        .expect("jobs json");
    assert_eq!(jobs["jobs"][0]["id"], job_id);
    assert_eq!(jobs["jobs"][0]["status"], "succeeded");

    let project: Value = client
        .get(format!("{}/api/v1/projects/{project_id}", srv.base()))
        .send()
        .await
        .expect("get project")
        .json()
        .await
        .expect("project json");
    assert_eq!(project["default_launch_profile"]["target_urls"][0], "http://127.0.0.1:8787");
    assert_eq!(project["default_launch_profile"]["reset_steps"][0]["stdin"], "y\n");
}

#[tokio::test]
async fn ai_setup_runs_project_seed_and_auth_in_one_backend_job() {
    let srv = TestServer::start_with_setup_agents(
        Arc::new(StubProjectSetupAgent),
        Arc::new(StubSeedSetupAgent),
        Arc::new(StubAuthSetupAgent),
    )
    .await;
    let client = reqwest::Client::new();
    let created: Value = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({
            "name": "full-ai-setup-app",
            "target_base_url": "http://127.0.0.1:8787"
        }))
        .send()
        .await
        .expect("post project")
        .json()
        .await
        .expect("project json");
    let project_id = created["id"].as_str().expect("project id");
    let repo_dir = srv._tmp.path().join("full-ai-setup-source");
    std::fs::create_dir_all(repo_dir.join("src")).expect("mkdir");
    std::fs::write(
        repo_dir.join("package.json"),
        r#"{"scripts":{"dev":"wrangler dev","dev:reset":"wrangler d1 migrations apply DB --local","nyx-agent:seed":"tsx scripts/nyx-agent-seed.ts"}}"#,
    )
    .expect("write package");
    std::fs::write(
        repo_dir.join("src/routes.ts"),
        r#"router.post("/api/auth/sign-in", signIn);
router.get("/api/workspaces/{id}", requireManager, showWorkspace);
"#,
    )
    .expect("write source");
    std::fs::write(
        repo_dir.join("src/fixtures.ts"),
        r#"export const manager = { email: "manager@example.test", password: "manager-pass" };"#,
    )
    .expect("write fixtures");
    let now = nyx_agent_core::now_epoch_ms();
    srv.store
        .repos()
        .upsert(&RepoRecord {
            id: "repo-full-ai-setup-source".to_string(),
            name: "web".to_string(),
            project_id: project_id.to_string(),
            source_kind: "local".to_string(),
            source_url_or_path: repo_dir.display().to_string(),
            branch: None,
            auth_ref: None,
            i_own_this: true,
            last_scan_run_id: None,
            last_scan_finished_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("repo");

    let started: Value = client
        .post(format!("{}/api/v1/projects/{project_id}/setup/ai", srv.base()))
        .json(&serde_json::json!({
            "target_base_url": "http://127.0.0.1:8787",
            "project_setup": true,
            "seed_setup": true,
            "auth_setup": true
        }))
        .send()
        .await
        .expect("post project setup")
        .json()
        .await
        .expect("json");
    let job_id = started["job"]["id"].as_str().expect("job id");
    let job = wait_project_setup_job(&client, &srv.base(), project_id, job_id).await;
    assert_eq!(job["status"], "succeeded");
    let response = &job["result"];
    assert_eq!(response["seed_setup"]["verification"]["status"], "verified");
    assert_eq!(response["auth_setup"]["verification"]["status"], "verified");
    assert_eq!(response["profile"]["seed_steps"][0]["command"], "npm run nyx-agent:seed");
    assert_eq!(response["profile"]["reset_steps"][0]["stdin"], "y\n");

    let phases: Vec<_> = job["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter_map(|event| event["phase"].as_str())
        .collect();
    assert!(phases.contains(&"inspecting_project"));
    let seed_phase = phases.iter().position(|phase| *phase == "inspecting_seed").expect("seed");
    let auth_phase = phases.iter().position(|phase| *phase == "inspecting_auth").expect("auth");
    assert!(seed_phase < auth_phase);

    let env_vars = response["project"]["runtime_profile"]["env_vars"].as_array().expect("env vars");
    assert!(env_vars.iter().any(|var| {
        var["name"] == "NYX_AGENT_USER_A_EMAIL"
            && var["value"] == "user-a@example.test"
            && var["secret"] == false
    }));
    assert!(env_vars.iter().any(|var| {
        var["name"] == "NYX_AGENT_MANAGER_PASSWORD"
            && var["value"] == "manager-pass"
            && var["secret"] == true
    }));
    let profiles =
        response["project"]["runtime_profile"]["auth_profiles"].as_array().expect("profiles");
    assert!(profiles.iter().any(|profile| profile["role"] == "manager"));
}

#[tokio::test]
async fn auth_auto_setup_records_dev_mail_otp_profiles() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let created: Value = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({
            "name": "otp-auth-app",
            "target_base_url": "http://localhost:3000"
        }))
        .send()
        .await
        .expect("post project")
        .json()
        .await
        .expect("project json");
    let project_id = created["id"].as_str().expect("project id");
    let repo_dir = srv._tmp.path().join("otp-auth-source");
    std::fs::create_dir_all(repo_dir.join("src")).expect("mkdir");
    std::fs::write(
        repo_dir.join("src/routes.ts"),
        r#"router.post("/api/auth/login", sendLoginCode);
router.post("/api/auth/verify-code", verifyLoginCode);
router.get("/app/dev-mail", devMailInbox);
"#,
    )
    .expect("write source");
    std::fs::write(
        repo_dir.join("src/seed.ts"),
        r#"export const testUsers = {
  user_a: { email: "user-a@example.test" },
  user_b: { email: "user-b@example.test" },
};"#,
    )
    .expect("write seed");
    let now = nyx_agent_core::now_epoch_ms();
    srv.store
        .repos()
        .upsert(&RepoRecord {
            id: "repo-otp-auth-source".to_string(),
            name: "otp-auth-source".to_string(),
            project_id: project_id.to_string(),
            source_kind: "local".to_string(),
            source_url_or_path: repo_dir.display().to_string(),
            branch: None,
            auth_ref: None,
            i_own_this: true,
            last_scan_run_id: None,
            last_scan_finished_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("repo");

    let started: Value = client
        .post(format!("{}/api/v1/projects/{project_id}/auth/auto-setup", srv.base()))
        .json(&serde_json::json!({ "target_base_url": "http://localhost:3000" }))
        .send()
        .await
        .expect("post auth setup")
        .json()
        .await
        .expect("json");
    let job_id = started["job"]["id"].as_str().expect("job id");
    let job = wait_auth_setup_job(&client, &srv.base(), project_id, job_id).await;
    assert_eq!(job["status"], "succeeded");
    let response = &job["result"];

    assert_eq!(response["verification"]["status"], "needs_review");
    assert!(response["verification"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check.as_str().unwrap_or_default().contains("/app/dev-mail")));
    let profiles =
        response["project"]["runtime_profile"]["auth_profiles"].as_array().expect("profiles");
    assert!(profiles.iter().any(|profile| {
        profile["role"] == "user_a"
            && profile["mode"] == "otp_email_mailbox"
            && profile["otp_source"]["kind"] == "mailbox"
            && profile["otp_source"]["mailbox_url"] == "http://localhost:3000/app/dev-mail/"
            && profile["otp_source"]["email_env"] == "NYX_AGENT_USER_A_USERNAME"
    }));
}

#[tokio::test]
async fn auth_auto_setup_prefers_agent_profiles_when_available() {
    let srv = TestServer::start_with_auth_setup_agent(Arc::new(StubAuthSetupAgent)).await;
    let client = reqwest::Client::new();
    let created: Value = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({
            "name": "agent-authz-app",
            "target_base_url": "http://localhost:3000"
        }))
        .send()
        .await
        .expect("post project")
        .json()
        .await
        .expect("project json");
    let project_id = created["id"].as_str().expect("project id");
    let repo_dir = srv._tmp.path().join("agent-auth-source");
    std::fs::create_dir_all(repo_dir.join("src")).expect("mkdir");
    std::fs::write(
        repo_dir.join("src/routes.ts"),
        r#"router.post("/api/auth/sign-in", signIn);
router.get("/api/workspaces/{id}", requireManager, showWorkspace);
"#,
    )
    .expect("write source");
    std::fs::write(
        repo_dir.join("src/fixtures.ts"),
        r#"export const manager = { email: "manager@example.test", password: "manager-pass" };"#,
    )
    .expect("write fixtures");
    let now = nyx_agent_core::now_epoch_ms();
    srv.store
        .repos()
        .upsert(&RepoRecord {
            id: "repo-agent-auth-source".to_string(),
            name: "agent-auth-source".to_string(),
            project_id: project_id.to_string(),
            source_kind: "local".to_string(),
            source_url_or_path: repo_dir.display().to_string(),
            branch: None,
            auth_ref: None,
            i_own_this: true,
            last_scan_run_id: None,
            last_scan_finished_at: None,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("repo");

    let started: Value = client
        .post(format!("{}/api/v1/projects/{project_id}/auth/auto-setup", srv.base()))
        .json(&serde_json::json!({ "target_base_url": "http://localhost:3000" }))
        .send()
        .await
        .expect("post auth setup")
        .json()
        .await
        .expect("json");
    let job_id = started["job"]["id"].as_str().expect("job id");
    let job = wait_auth_setup_job(&client, &srv.base(), project_id, job_id).await;
    assert_eq!(job["status"], "succeeded");
    let response = &job["result"];

    assert_eq!(response["agent_used"], true);
    assert_eq!(response["roles"], serde_json::json!(["manager"]));
    assert_eq!(response["verification"]["status"], "verified");
    assert_eq!(
        response["project"]["runtime_profile"]["auth_profiles"][0]["login_email_env"],
        "NYX_AGENT_MANAGER_EMAIL"
    );
    let env_vars = response["project"]["runtime_profile"]["env_vars"].as_array().expect("env vars");
    assert!(env_vars.iter().any(|var| {
        var["name"] == "NYX_AGENT_MANAGER_EMAIL"
            && var["value"] == "manager@example.test"
            && var["secret"] == false
    }));
    assert!(env_vars.iter().any(|var| {
        var["name"] == "NYX_AGENT_MANAGER_PASSWORD"
            && var["value"] == "manager-pass"
            && var["secret"] == true
    }));
    assert_eq!(
        response["project"]["runtime_profile"]["auth_profiles"].as_array().unwrap().len(),
        1
    );
}

#[tokio::test]
async fn auth_auto_setup_surfaces_agent_transport_failure_as_job_error() {
    let srv = TestServer::start_with_auth_setup_agent(Arc::new(FailingAuthSetupAgent)).await;
    let client = reqwest::Client::new();
    let created: Value = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({
            "name": "network-fail-app",
            "target_base_url": "http://localhost:3000"
        }))
        .send()
        .await
        .expect("post project")
        .json()
        .await
        .expect("project json");
    let project_id = created["id"].as_str().expect("project id");

    let started: Value = client
        .post(format!("{}/api/v1/projects/{project_id}/auth/auto-setup", srv.base()))
        .json(&serde_json::json!({ "target_base_url": "http://localhost:3000" }))
        .send()
        .await
        .expect("post auth setup")
        .json()
        .await
        .expect("json");
    let job_id = started["job"]["id"].as_str().expect("job id");
    let job = wait_auth_setup_job(&client, &srv.base(), project_id, job_id).await;

    assert_eq!(job["status"], "failed");
    assert_eq!(job["phase"], "failed");
    assert_eq!(job["error"]["code"], "agent_upstream_network");
    assert!(job["error"]["detail"].as_str().unwrap().contains("DNS lookup failed"));
    assert_eq!(job["error"]["retryable"], true);
}

#[tokio::test]
async fn launch_target_test_reports_reachable_local_url() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();

    let body: Value = client
        .post(format!("{}/api/v1/launch-target/test", srv.base()))
        .json(&serde_json::json!({
            "url": format!("{}/api/v1/health", srv.base()),
            "timeout_seconds": 2
        }))
        .send()
        .await
        .expect("post")
        .json()
        .await
        .expect("json");

    assert_eq!(body["ok"], true);
    assert_eq!(body["status"], 200);
    assert!(body["message"].as_str().unwrap_or_default().contains("Reachable"));
}

#[tokio::test]
async fn launch_target_test_rejects_non_local_url() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/launch-target/test", srv.base()))
        .json(&serde_json::json!({
            "url": "https://localhost.example.com"
        }))
        .send()
        .await
        .expect("post");

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_project_refuses_duplicate_name() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let ok = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({ "name": "dup" }))
        .send()
        .await
        .expect("first");
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let dup = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({ "name": "dup" }))
        .send()
        .await
        .expect("second");
    assert_eq!(dup.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_project_repos_filters_by_project_id() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();

    // Create a second project and attach a repo to each.
    let proj_b: Value = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({ "name": "beta" }))
        .send()
        .await
        .expect("post")
        .json()
        .await
        .expect("json");
    let id_b = proj_b["id"].as_str().expect("id").to_string();

    client
        .post(format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID))
        .json(&serde_json::json!({
            "name": "repo-default",
            "source_kind": "local-path",
            "source_url_or_path": "/tmp/d",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("default post");
    client
        .post(format!("{}/api/v1/projects/{id_b}/repos", srv.base()))
        .json(&serde_json::json!({
            "name": "repo-beta",
            "source_kind": "local-path",
            "source_url_or_path": "/tmp/b",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("beta post");

    let default_repos: Vec<RepoRecord> = client
        .get(format!("{}/api/v1/projects/{}/repos", srv.base(), DEFAULT_PROJECT_ID))
        .send()
        .await
        .expect("list default")
        .json()
        .await
        .expect("json");
    let names: Vec<_> = default_repos.iter().map(|r| r.name.clone()).collect();
    assert_eq!(names, vec!["repo-default".to_string()]);

    let beta_repos: Vec<RepoRecord> = client
        .get(format!("{}/api/v1/projects/{id_b}/repos", srv.base()))
        .send()
        .await
        .expect("list beta")
        .json()
        .await
        .expect("json");
    let names: Vec<_> = beta_repos.iter().map(|r| r.name.clone()).collect();
    assert_eq!(names, vec!["repo-beta".to_string()]);
}

#[tokio::test]
async fn create_repo_under_unknown_project_returns_404() {
    let srv = TestServer::start().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/projects/ghost-project/repos", srv.base()))
        .json(&serde_json::json!({
            "name": "x",
            "source_kind": "local-path",
            "source_url_or_path": "/tmp/x",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_repo_404s_when_repo_belongs_to_other_project() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    let proj_b: Value = client
        .post(format!("{}/api/v1/projects", srv.base()))
        .json(&serde_json::json!({ "name": "other" }))
        .send()
        .await
        .expect("post")
        .json()
        .await
        .expect("json");
    let id_b = proj_b["id"].as_str().expect("id").to_string();

    client
        .post(format!("{}/api/v1/projects/{id_b}/repos", srv.base()))
        .json(&serde_json::json!({
            "name": "elsewhere",
            "source_kind": "local-path",
            "source_url_or_path": "/tmp/e",
            "i_own_this": true,
        }))
        .send()
        .await
        .expect("create");

    let cross = client
        .get(format!("{}/api/v1/projects/{}/repos/elsewhere", srv.base(), DEFAULT_PROJECT_ID))
        .send()
        .await
        .expect("cross-project get");
    assert_eq!(cross.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn scan_404s_unknown_project() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_trigger(trigger).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/projects/nope/scan", srv.base()))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn webhook_disabled_returns_500_envelope() {
    let server = TestServer::start().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/webhook/git", server.base()))
        .header("X-Hub-Signature-256", "sha256=00")
        .body("{}")
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    server.handle.abort();
}
