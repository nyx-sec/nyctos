//! End-to-end test for `nyx-agent scan --repo <name>`.
//!
//! Builds a fake `nyx` binary as a shell stub (responds to
//! `--version` and `scan ...`), then runs `nyx-agent` against a local
//! state directory and a local-path repo. The stub is platform-gated
//! to Unix; on other targets the test is skipped.

#![cfg(unix)]

use std::fs;

use assert_cmd::Command;

fn stub_nyx_script() -> &'static str {
    "#!/usr/bin/env sh\n\
case \"$1\" in\n\
  --version) echo \"nyx 0.1.0\" ;;\n\
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

#[test]
fn scan_repo_round_trips_against_stub() {
    use std::os::unix::fs::PermissionsExt;

    let state_root = tempfile::tempdir().expect("state");
    let repo_src = tempfile::tempdir().expect("repo");
    fs::write(repo_src.path().join("README.md"), b"hi\n").expect("seed");

    let stub_dir = tempfile::tempdir().expect("stub");
    let stub_path = stub_dir.path().join("nyx");
    fs::write(&stub_path, stub_nyx_script()).expect("write stub");
    let mut perms = fs::metadata(&stub_path).expect("meta").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&stub_path, perms).expect("chmod stub");

    let config_path = state_root.path().join("nyx-agent.toml");
    let toml = format!(
        "[general]\nlog_level = \"info\"\n\n[nyx]\nbinary_path = \"{}\"\nmin_version = \"0.1.0\"\n\n[[repo]]\nname = \"demo\"\ni_own_this = true\nenabled = true\nsource = {{ kind = \"local-path\", path = \"{}\" }}\n",
        stub_path.display(),
        repo_src.path().display(),
    );
    fs::write(&config_path, toml).expect("write config");

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
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout).into_owned();
    assert!(stdout.contains("scan: ingested demo"), "expected ingestion log line, got: {stdout}");
    assert!(stdout.contains("scan: run "), "expected run summary line, got: {stdout}");
}
