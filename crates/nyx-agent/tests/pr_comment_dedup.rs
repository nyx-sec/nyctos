//! End-to-end test for the PR-comment dedup contract: a second run
//! against the same PR updates the marker-tagged comment instead of
//! creating a new one.
//!
//! Uses `wiremock` to stand up a fake GitHub REST server; no network
//! calls leak. The test exercises the whole `pr-comment` subcommand
//! through `assert_cmd`, including the env-var token plumbing.

#![cfg(unix)]

use std::fs;

use assert_cmd::Command;
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_report_json() -> String {
    let report = json!({
        "schema_version": 1,
        "run_id": "run-pr-dedup",
        "started_at": 100,
        "finished_at": 200,
        "status": "Succeeded",
        "triggered_by": "ci",
        "repos": ["self"],
        "since_ref": "main",
        "findings": [
            {
                "id": "fffffffffff1",
                "repo": "self",
                "path": "src/a.py",
                "line": 7,
                "cap": "sqli",
                "rule": "py.sqli",
                "severity": "High",
                "status": "Verified",
                "finding_origin": "Static",
                "chain_id": null
            }
        ],
        "chains": []
    });
    serde_json::to_string_pretty(&report).expect("serialise sample report")
}

const MARKER: &str = "<!-- nyx-agent:pr-comment v1 -->";

#[tokio::test]
async fn create_then_update_same_comment() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let report_path = tmp.path().join("report.json");
    fs::write(&report_path, sample_report_json()).expect("write report");

    let server = MockServer::start().await;

    // First run: the PR has no marker-tagged comment yet, so the
    // list endpoint returns an empty array. The agent then POSTs a
    // create.
    Mock::given(method("GET"))
        .and(path("/repos/octo/demo/issues/42/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/repos/octo/demo/issues/42/comments"))
        .and(header("authorization", "Bearer ghs_TESTTOKEN"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 9001,
            "body": MARKER,
            "user": {"login": "github-actions[bot]", "type": "Bot"}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let state_root = tempfile::tempdir().expect("state");
    let config_path = state_root.path().join("nyx-agent.toml");
    fs::write(&config_path, "[general]\nlog_level = \"info\"\n").expect("config");

    Command::cargo_bin("nyx-agent")
        .expect("nyx-agent binary")
        .env("GITHUB_TOKEN", "ghs_TESTTOKEN")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--state-dir",
            state_root.path().to_str().unwrap(),
            "pr-comment",
            "--report",
            report_path.to_str().unwrap(),
            "--repo",
            "octo/demo",
            "--pr",
            "42",
            "--gh-api",
            &server.uri(),
        ])
        .assert()
        .success();

    server.verify().await;
    server.reset().await;

    // Second run: the list endpoint returns the marker-tagged comment
    // from the first run; the agent must PATCH it in place rather
    // than create a new one. The `user` block is required because
    // `find_existing_comment` rejects marker-shadowing comments not
    // authored by a known bot identity (Phase-26 security fix).
    Mock::given(method("GET"))
        .and(path("/repos/octo/demo/issues/42/comments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "id": 9001,
                "body": format!("{}\nold body", MARKER),
                "user": {"login": "github-actions[bot]", "type": "Bot"}
            }
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/repos/octo/demo/issues/comments/9001"))
        .and(header("authorization", "Bearer ghs_TESTTOKEN"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 9001,
            "body": MARKER
        })))
        .expect(1)
        .mount(&server)
        .await;

    Command::cargo_bin("nyx-agent")
        .expect("nyx-agent binary")
        .env("GITHUB_TOKEN", "ghs_TESTTOKEN")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--state-dir",
            state_root.path().to_str().unwrap(),
            "pr-comment",
            "--report",
            report_path.to_str().unwrap(),
            "--repo",
            "octo/demo",
            "--pr",
            "42",
            "--gh-api",
            &server.uri(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("updated existing comment"));

    server.verify().await;
}

#[tokio::test]
async fn skips_when_report_has_no_pr_worthy_rows() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let report_path = tmp.path().join("report.json");
    // Only an Open finding without a cross-repo chain - filtered out.
    let report = json!({
        "schema_version": 1,
        "run_id": "run-empty",
        "started_at": 100,
        "finished_at": 200,
        "status": "Succeeded",
        "triggered_by": "ci",
        "repos": ["self"],
        "since_ref": null,
        "findings": [
            {
                "id": "ffffffffeeee",
                "repo": "self",
                "path": "src/a.py",
                "line": 7,
                "cap": "sqli",
                "rule": "py.sqli",
                "severity": "High",
                "status": "Open",
                "finding_origin": "Static",
                "chain_id": null
            }
        ],
        "chains": []
    });
    fs::write(&report_path, serde_json::to_string_pretty(&report).unwrap()).expect("write report");

    let server = MockServer::start().await;
    // No GET / POST / PATCH calls expected.
    let state_root = tempfile::tempdir().expect("state");
    let config_path = state_root.path().join("nyx-agent.toml");
    fs::write(&config_path, "[general]\nlog_level = \"info\"\n").expect("config");
    Command::cargo_bin("nyx-agent")
        .expect("nyx-agent binary")
        .env("GITHUB_TOKEN", "ghs_TESTTOKEN")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--state-dir",
            state_root.path().to_str().unwrap(),
            "pr-comment",
            "--report",
            report_path.to_str().unwrap(),
            "--repo",
            "octo/demo",
            "--pr",
            "42",
            "--gh-api",
            &server.uri(),
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains("no Confirmed or cross-repo"));

    server.verify().await;
}
