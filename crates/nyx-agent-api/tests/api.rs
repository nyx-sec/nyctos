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
    build_router, AuthConfig, ScanTrigger, ScanTriggerError, ServerState, SetupContext,
};
use nyx_agent_core::store::{ChainRecord, FindingRecord, RepoRecord, RunRecord};
use nyx_agent_core::{Config, SecretStore, Store};
use nyx_agent_types::event::{AgentEvent, EventSink, RepoOutcomeTag, RunEvent};

struct StubScanTrigger {
    run_id: String,
}

impl ScanTrigger for StubScanTrigger {
    fn trigger<'a>(
        &'a self,
        _repo: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
        let id = self.run_id.clone();
        Box::pin(async move { Ok(id) })
    }
}

struct TestServer {
    addr: std::net::SocketAddr,
    events: EventSink,
    store: Store,
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
        let state = ServerState::new(store.clone(), events.clone(), trigger, setup, auth);
        let app = build_router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        TestServer { addr, events, store, _tmp: tmp, handle, token }
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
        name: name.to_string(),
        source_kind: "local-path".to_string(),
        source_url_or_path: format!("/tmp/{name}"),
        branch: None,
        auth_ref: None,
        i_own_this: true,
        last_scan_run_id: None,
        created_at: 1_000,
        updated_at: 1_000,
    }
}

fn sample_run(id: &str) -> RunRecord {
    RunRecord {
        id: id.to_string(),
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
async fn repos_crud_roundtrip() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/repos", srv.base()))
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

    let listed: Vec<RepoRecord> = client
        .get(format!("{}/api/v1/repos", srv.base()))
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "alpha");

    let del = client
        .delete(format!("{}/api/v1/repos/alpha", srv.base()))
        .send()
        .await
        .expect("delete");
    assert_eq!(del.status(), reqwest::StatusCode::OK);

    let del_again = client
        .delete(format!("{}/api/v1/repos/alpha", srv.base()))
        .send()
        .await
        .expect("delete");
    assert_eq!(del_again.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn post_repos_refuses_without_ownership_attestation() {
    let srv = TestServer::start().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/repos", srv.base()))
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
    srv.store.runs().insert(&sample_run("run-A")).await.expect("insert");

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

    let missing = reqwest::get(format!("{}/api/v1/runs/does-not-exist", srv.base()))
        .await
        .expect("get");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
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

    let got: FindingRecord =
        reqwest::get(format!("{}/api/v1/findings/{}", srv.base(), finding.id))
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
async fn scan_endpoint_calls_trigger() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "run-from-scan".to_string() });
    let srv = TestServer::start_with_trigger(trigger).await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/scan?repo=foo", srv.base()))
        .send()
        .await
        .expect("post");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["run_id"], "run-from-scan");
}

#[tokio::test]
async fn websocket_receives_repo_started_and_finished() {
    let srv = TestServer::start().await;
    let url = format!("{}/api/v1/events?run_id=run-ws", srv.ws_base());

    let (ws_stream, _) =
        tokio_tungstenite::connect_async(&url).await.expect("ws connect");
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Push frames after the client has connected.
    let events = srv.events.clone();
    let publisher = tokio::spawn(async move {
        // Tiny delay so the subscriber is attached before broadcast goes
        // out — broadcast only delivers to receivers that exist at send
        // time; the WS task subscribes on upgrade, which is in flight
        // when `connect_async` returns.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = events.send(AgentEvent::Run {
            data: RunEvent::RunStarted {
                run_id: "run-ws".to_string(),
                repos: vec!["alpha".to_string()],
                started_at_ms: 1,
            },
        });
        let _ = events.send(AgentEvent::Run {
            data: RunEvent::RepoStarted {
                run_id: "run-ws".to_string(),
                repo: "alpha".to_string(),
                started_at_ms: 2,
            },
        });
        // Send a frame for an unrelated run; the filter should drop it.
        let _ = events.send(AgentEvent::Run {
            data: RunEvent::RepoStarted {
                run_id: "other-run".to_string(),
                repo: "beta".to_string(),
                started_at_ms: 3,
            },
        });
        let _ = events.send(AgentEvent::Run {
            data: RunEvent::RepoFinished {
                run_id: "run-ws".to_string(),
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
    let resp = reqwest::get(format!("{}/api/v1/repos", srv.base())).await.expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_middleware_allows_valid_bearer_token() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, true, true).await;
    let token = srv.token.clone().expect("auth on");
    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/repos", srv.base()))
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
async fn auth_middleware_requires_token_for_setup_after_completion() {
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "irrelevant".to_string() });
    let srv = TestServer::start_with_options(trigger, true, true).await;
    let resp = reqwest::get(format!("{}/api/v1/setup/status", srv.base())).await.expect("get");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn patch_repo_updates_subset_and_returns_row() {
    let srv = TestServer::start().await;
    let client = reqwest::Client::new();
    client
        .post(format!("{}/api/v1/repos", srv.base()))
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
        .patch(format!("{}/api/v1/repos/billing", srv.base()))
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
        .patch(format!("{}/api/v1/repos/ghost", srv.base()))
        .json(&serde_json::json!({ "source_kind": "git" }))
        .send()
        .await
        .expect("patch");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_repo_removes_workspace_dir_when_configured() {
    use nyx_agent_api::{build_router, AuthConfig, ScanTrigger, ScanTriggerError, ServerState, SetupContext};
    use nyx_agent_core::{Config, SecretStore, Store};
    use tokio::sync::broadcast;

    struct Stub;
    impl ScanTrigger for Stub {
        fn trigger<'a>(
            &'a self,
            _repo: Option<String>,
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
    client
        .post(format!("{base}/api/v1/repos"))
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
    let resp = client.delete(format!("{base}/api/v1/repos/billing")).send().await.expect("del");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(!billing_dir.exists(), "workspace must be gone after delete");

    h.abort();
}

#[tokio::test]
async fn test_repo_endpoint_rejects_unknown_source_kind() {
    let srv = TestServer::start().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/repos/test", srv.base()))
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
        .post(format!("{}/api/v1/repos/test", srv.base()))
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
    let (ws_stream, _) =
        tokio_tungstenite::connect_async(&url).await.expect("ws connect");
    let (_, mut ws_rx) = ws_stream.split();

    let events = srv.events.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = events.send(AgentEvent::Run {
            data: RunEvent::Heartbeat { ts: 1 },
        });
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
    let trigger: Arc<dyn ScanTrigger> =
        Arc::new(StubScanTrigger { run_id: "r-1".to_string() });
    let state =
        ServerState::new(store.clone(), events.clone(), trigger, setup, AuthConfig::default());

    // Pre-seed the replay buffer with the run's opening frames so the
    // WS upgrade reads them back via `snapshot()` before subscribing
    // to the live broadcast.
    let started = AgentEvent::Run {
        data: RunEvent::RunStarted {
            run_id: "r-1".to_string(),
            repos: vec!["alpha".to_string()],
            started_at_ms: 1,
        },
    };
    let repo_started = AgentEvent::Run {
        data: RunEvent::RepoStarted {
            run_id: "r-1".to_string(),
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
    let (ws_stream, _) =
        tokio_tungstenite::connect_async(&url).await.expect("ws connect");
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
