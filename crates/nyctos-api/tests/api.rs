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

use nyctos_api::{
    build_router, AuthConfig, ScanTrigger, ScanTriggerError, ServerState, SetupContext,
};
use nyctos_core::store::{ChainRecord, FindingRecord, RepoRecord, RunRecord, DEFAULT_PROJECT_ID};
use nyctos_core::{Config, SecretStore, Store};
use nyctos_types::event::{AgentEvent, EventSink, RepoOutcomeTag, RunEvent};

struct StubScanTrigger {
    run_id: String,
}

impl ScanTrigger for StubScanTrigger {
    fn trigger<'a>(
        &'a self,
        _project_id: Option<String>,
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
        let config_path = tmp.path().join("nyctos.toml");
        let setup = SetupContext::new(
            config_path,
            Config::default(),
            setup_complete,
            SecretStore::memory(),
        );
        let auth = if with_auth {
            AuthConfig::new(Some(nyctos_core::mint_token()))
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
    let id = nyctos_core::store::finding_id_hash(repo, path, Some(10), "sqli", rule);
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

    let missing =
        reqwest::get(format!("{}/api/v1/runs/does-not-exist", srv.base())).await.expect("get");
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

    let got: Vec<ChainRecord> = reqwest::get(format!("{}/api/v1/chains?run_id=run-A", srv.base()))
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
    use nyctos_api::{
        build_router, AuthConfig, ScanTrigger, ScanTriggerError, ServerState, SetupContext,
    };
    use nyctos_core::{Config, SecretStore, Store};
    use tokio::sync::broadcast;

    struct Stub;
    impl ScanTrigger for Stub {
        fn trigger<'a>(
            &'a self,
            _project_id: Option<String>,
            _repo: Option<String>,
        ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
            Box::pin(async { Ok("r".to_string()) })
        }
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let (events, _rx) = broadcast::channel::<AgentEvent>(8);
    let config_path = tmp.path().join("nyctos.toml");
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
    let config_path = tmp.path().join("nyctos.toml");
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
        tmp.path().join("nyctos.toml"),
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
        tmp.path().join("nyctos.toml"),
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
async fn replay_endpoint_refuses_on_sha_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = Store::open(tmp.path()).await.expect("open store");
    let bundles_dir = tmp.path().join("bundles");
    std::fs::create_dir_all(&bundles_dir).expect("mkdir bundles");

    let (events, _rx) = broadcast::channel::<AgentEvent>(8);
    let setup = SetupContext::new(
        tmp.path().join("nyctos.toml"),
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
    let config_path = tmp.path().join("nyctos.toml");
    let setup = SetupContext::new(config_path, Config::default(), true, SecretStore::memory());
    let trigger = Arc::new(RecordingTrigger::default());
    let scan_trigger: Arc<dyn ScanTrigger> = trigger.clone();
    let state = ServerState::new(store, events, scan_trigger, setup, AuthConfig::default())
        .with_webhook(nyctos_api::WebhookConfig::new(
            Arc::new(nyctos_api::StaticSecretResolver { secret: Some(secret.to_vec()) }),
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
    calls: tokio::sync::Mutex<Vec<Option<String>>>,
}

impl ScanTrigger for RecordingTrigger {
    fn trigger<'a>(
        &'a self,
        _project_id: Option<String>,
        repo: Option<String>,
    ) -> Pin<Box<dyn Future<Output = Result<String, ScanTriggerError>> + Send + 'a>> {
        Box::pin(async move {
            let mut g = self.calls.lock().await;
            let id = format!("run-{}", g.len());
            g.push(repo);
            Ok(id)
        })
    }
}

#[tokio::test]
async fn webhook_with_valid_hmac_triggers_scan() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, Some("main"), None).await;
    let body = br#"{"ref":"refs/heads/main","after":"deadbeef"}"#.to_vec();
    let sig = nyctos_api::sign_webhook(secret, &body);
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
    h.abort();
}

#[tokio::test]
async fn webhook_with_invalid_hmac_returns_401() {
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    let body = br#"{"ref":"refs/heads/main"}"#.to_vec();
    let bad_sig = nyctos_api::sign_webhook(b"wrong-secret", &body);
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
    let sig = nyctos_api::sign_webhook(secret, &body);
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
    let sig = nyctos_api::sign_webhook(secret, &body);
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
    let sig = nyctos_api::sign_webhook(secret, &body);
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
    let sig = nyctos_api::sign_webhook(secret, &body);
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
    let sig = nyctos_api::sign_webhook(secret, &body);
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

#[tokio::test]
async fn webhook_refless_body_without_event_header_does_not_trigger() {
    // Signed body that has no `ref` field and no provider-specific
    // event header. The old code path would have triggered a scan
    // (because the branch filter was unset) for any HMAC-valid blob;
    // the push-event guard refuses it.
    let secret = b"shared-secret";
    let (addr, trigger, h, _tmp) = start_webhook_server(secret, None, None).await;
    let body = br#"{"hello":"world"}"#.to_vec();
    let sig = nyctos_api::sign_webhook(secret, &body);
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

    let patched: Value = client
        .patch(format!("{}/api/v1/projects/{id}", srv.base()))
        .json(&serde_json::json!({ "description": "rev2" }))
        .send()
        .await
        .expect("patch")
        .json()
        .await
        .expect("json");
    assert_eq!(patched["description"], "rev2");

    let del =
        client.delete(format!("{}/api/v1/projects/{id}", srv.base())).send().await.expect("del");
    assert_eq!(del.status(), reqwest::StatusCode::OK);

    let missing =
        client.get(format!("{}/api/v1/projects/{id}", srv.base())).send().await.expect("get");
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
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
