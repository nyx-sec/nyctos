//! End-to-end tests for `nyx-agent scan --project <name>` and the
//! `project` subcommand.
//!
//! Builds a fake `nyx` binary as a shell stub (responds to
//! `--version` and `scan ...`), then runs `nyx-agent` against a local
//! state directory and a local-path repo. The stub is platform-gated
//! to Unix; on other targets the test is skipped.

#![cfg(unix)]

use std::fs;
use std::path::Path;

use assert_cmd::Command;

fn stub_nyx_script() -> &'static str {
    "#!/usr/bin/env sh\n\
case \"$1\" in\n\
  --version) echo \"nyx 0.7.0\" ;;\n\
  scan)\n\
    shift\n\
    while [ \"$#\" -gt 0 ]; do\n\
      case \"$1\" in\n\
        --output|--out) shift; OUT=\"$1\" ;;\n\
        --format|--no-index|--verify) ;;\n\
      esac\n\
      shift || true\n\
    done\n\
    printf '[]' ;;\n\
  *) echo \"unknown command: $*\" 1>&2; exit 2 ;;\n\
esac\n"
}

fn write_stub(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let stub_path = dir.join("nyx");
    fs::write(&stub_path, stub_nyx_script()).expect("write stub");
    let mut perms = fs::metadata(&stub_path).expect("meta").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&stub_path, perms).expect("chmod stub");
    stub_path
}

fn write_config(state_root: &Path, stub: &Path, repo_src: &Path) -> std::path::PathBuf {
    let config_path = state_root.join("nyx-agent.toml");
    let toml = format!(
        "[general]\nlog_level = \"info\"\n\n[nyx]\nbinary_path = \"{}\"\nmin_version = \"0.1.0\"\n\n[[project]]\nname = \"demo-project\"\n\n  [[project.repo]]\n  name = \"demo\"\n  i_own_this = true\n  enabled = true\n  source = {{ kind = \"local-path\", path = \"{}\" }}\n",
        stub.display(),
        repo_src.display(),
    );
    fs::write(&config_path, toml).expect("write config");
    config_path
}

fn write_config_with_unreachable_launch(
    state_root: &Path,
    stub: &Path,
    repo_src: &Path,
) -> std::path::PathBuf {
    let config_path = state_root.join("nyx-agent.toml");
    let toml = format!(
        "[general]\nlog_level = \"info\"\n\n[nyx]\nbinary_path = \"{}\"\nmin_version = \"0.1.0\"\n\n[[project]]\nname = \"demo-project\"\ntarget_base_url = \"http://127.0.0.1:9\"\n\n  [project.launch]\n  mode = \"already-running\"\n  target_urls = [\"http://127.0.0.1:9\"]\n\n    [[project.launch.health]]\n    url = \"http://127.0.0.1:9/health\"\n    timeout_secs = 1\n\n  [[project.repo]]\n  name = \"demo\"\n  i_own_this = true\n  enabled = true\n  source = {{ kind = \"local-path\", path = \"{}\" }}\n",
        stub.display(),
        repo_src.display(),
    );
    fs::write(&config_path, toml).expect("write config");
    config_path
}

#[test]
fn scan_project_round_trips_against_stub() {
    let state_root = tempfile::tempdir().expect("state");
    let repo_src = tempfile::tempdir().expect("repo");
    fs::write(repo_src.path().join("README.md"), b"hi\n").expect("seed");

    let stub_dir = tempfile::tempdir().expect("stub");
    let stub_path = write_stub(stub_dir.path());
    let config_path = write_config(state_root.path(), &stub_path, repo_src.path());

    let assert = Command::cargo_bin("nyx-agent")
        .expect("nyx-agent binary")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--state-dir",
            state_root.path().to_str().unwrap(),
            "scan",
            "--project",
            "demo-project",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("scan: ingested demo"), "expected ingestion log line, got: {stdout}");
    assert!(
        stdout.contains("scan: project demo-project run "),
        "expected project-scoped run summary, got: {stdout}"
    );

    let rt =
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime");
    rt.block_on(async {
        let store = nyx_agent_core::Store::open(state_root.path()).await.expect("open store");
        let runs = store.runs().list_by_status("Succeeded").await.expect("list runs");
        assert_eq!(runs.len(), 1, "expected one succeeded run, got {runs:?}");
        let outcomes =
            store.run_repo_outcomes().list_for_run(&runs[0].id).await.expect("list outcomes");
        assert_eq!(outcomes.len(), 1, "expected one repo outcome row, got {outcomes:?}");
        assert_eq!(outcomes[0].repo, "demo");
        assert_eq!(outcomes[0].outcome, "Success");
        assert!(outcomes[0].reason.is_none(), "Success outcomes carry no reason");
        assert!(outcomes[0].elapsed_ms >= 0);
    });
}

#[test]
fn scan_headless_suppresses_human_progress() {
    let state_root = tempfile::tempdir().expect("state");
    let repo_src = tempfile::tempdir().expect("repo");
    fs::write(repo_src.path().join("README.md"), b"hi\n").expect("seed");

    let stub_dir = tempfile::tempdir().expect("stub");
    let stub_path = write_stub(stub_dir.path());
    let config_path = write_config(state_root.path(), &stub_path, repo_src.path());

    let assert = Command::cargo_bin("nyx-agent")
        .expect("nyx-agent binary")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--state-dir",
            state_root.path().to_str().unwrap(),
            "scan",
            "--project",
            "demo-project",
            "--headless",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        stdout.is_empty(),
        "expected --headless to suppress every stdout line, got: {stdout:?}"
    );
}

#[test]
fn scan_no_orchestration_skips_launch_profile() {
    let state_root = tempfile::tempdir().expect("state");
    let repo_src = tempfile::tempdir().expect("repo");
    fs::write(repo_src.path().join("README.md"), b"hi\n").expect("seed");

    let stub_dir = tempfile::tempdir().expect("stub");
    let stub_path = write_stub(stub_dir.path());
    let config_path =
        write_config_with_unreachable_launch(state_root.path(), &stub_path, repo_src.path());

    let assert = Command::cargo_bin("nyx-agent")
        .expect("nyx-agent binary")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--state-dir",
            state_root.path().to_str().unwrap(),
            "scan",
            "--project",
            "demo-project",
            "--no-orchestration",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(
        stdout.contains("scan: project demo-project run "),
        "expected project-scoped run summary, got: {stdout}"
    );
}

#[test]
fn scan_repo_without_project_is_rejected() {
    let state_root = tempfile::tempdir().expect("state");
    let repo_src = tempfile::tempdir().expect("repo");
    fs::write(repo_src.path().join("README.md"), b"hi\n").expect("seed");

    let stub_dir = tempfile::tempdir().expect("stub");
    let stub_path = write_stub(stub_dir.path());
    let config_path = write_config(state_root.path(), &stub_path, repo_src.path());

    let assert = Command::cargo_bin("nyx-agent")
        .expect("nyx-agent binary")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--state-dir",
            state_root.path().to_str().unwrap(),
            "scan",
            "--repo",
            "demo",
        ])
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains("--repo requires --project context"),
        "expected explicit-scope rejection, got: {stderr}"
    );
}

#[test]
fn project_create_then_list() {
    let state_root = tempfile::tempdir().expect("state");

    let create = Command::cargo_bin("nyx-agent")
        .expect("nyx-agent binary")
        .args([
            "--state-dir",
            state_root.path().to_str().unwrap(),
            "project",
            "create",
            "acme-app",
            "--description",
            "Acme web product",
        ])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&create.get_output().stdout).into_owned();
    assert!(stdout.contains("created project acme-app"), "expected creation line, got: {stdout}");

    let list = Command::cargo_bin("nyx-agent")
        .expect("nyx-agent binary")
        .args(["--state-dir", state_root.path().to_str().unwrap(), "project", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&list.get_output().stdout).into_owned();
    assert!(stdout.contains("acme-app"), "expected acme-app in listing, got: {stdout}");
}
