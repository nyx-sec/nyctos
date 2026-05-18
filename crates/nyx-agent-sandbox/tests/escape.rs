//! Sandbox-escape regression suite.
//!
//! Six fixtures ported from nyx's `tests/dynamic_fixtures/escape/`:
//!
//!   1. write to a path outside the workspace
//!   2. read a secret file outside the workspace
//!   3. open an outbound TCP connection
//!   4. send a UDP datagram
//!   5. fork+exec a child that retries the file-write escape
//!   6. plant a symlink in the workspace pointing outside, then write
//!      through it
//!
//! Each fixture executes inside the `escape-attempt` helper binary
//! launched under the [`BirdcageSandbox`] backend. The helper exits 0
//! when the operation succeeded (i.e. the sandbox *failed* to contain
//! it); each test asserts the run was contained AND that the intended
//! side-effect did not occur.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nyx_agent_sandbox::{
    BirdcageSandbox, Sandbox, SandboxOpts, SandboxOutcome, SandboxStatus,
};
use tempfile::tempdir;

const SHIM: &str = env!("CARGO_BIN_EXE_nyx-sandbox-shim");
const PROBE: &str = env!("CARGO_BIN_EXE_escape-attempt");

fn make_sandbox() -> BirdcageSandbox {
    BirdcageSandbox::with_shim_path(PathBuf::from(SHIM))
}

fn base_opts(workspace: &Path, args: Vec<String>) -> SandboxOpts {
    let mut argv = vec![PROBE.to_string()];
    argv.extend(args);
    let mut opts = SandboxOpts::new(workspace.to_path_buf(), argv);
    opts.timeout = Duration::from_secs(5);
    // The probe binary lives in the cargo target dir, which is outside
    // the workspace; grant a read+execute exception for it.
    opts.allow_read.push(PathBuf::from(PROBE));
    opts
}

async fn run(opts: SandboxOpts) -> SandboxOutcome {
    let mut sb = make_sandbox();
    sb.run(opts).await.expect("sandbox run");
    sb.wait().await.expect("sandbox wait")
}

// 1. fs_write_outside_workspace
#[tokio::test]
async fn write_outside_workspace_is_contained() {
    let scratch = tempdir().unwrap();
    let workspace = scratch.path().join("ws");
    std::fs::create_dir(&workspace).unwrap();
    let secret_dir = tempdir().unwrap();
    let target = secret_dir.path().join("escaped.txt");

    let opts = base_opts(
        &workspace,
        vec!["write-outside".into(), target.display().to_string()],
    );
    let outcome = run(opts).await;

    assert!(
        outcome.status.contained(),
        "write_outside escaped: {:?} stdout={:?} stderr={:?}",
        outcome.status,
        String::from_utf8_lossy(&outcome.stdout),
        String::from_utf8_lossy(&outcome.stderr),
    );
    assert!(
        !target.exists(),
        "escape file unexpectedly created at {}",
        target.display()
    );
}

// 2. fs_read_secret_outside_workspace
#[tokio::test]
async fn read_secret_outside_workspace_is_contained() {
    let scratch = tempdir().unwrap();
    let workspace = scratch.path().join("ws");
    std::fs::create_dir(&workspace).unwrap();
    let secret_dir = tempdir().unwrap();
    let secret = secret_dir.path().join("secret.txt");
    std::fs::write(&secret, b"top-secret-do-not-leak").unwrap();

    let opts = base_opts(
        &workspace,
        vec!["read-outside".into(), secret.display().to_string()],
    );
    let outcome = run(opts).await;

    assert!(
        outcome.status.contained(),
        "read_secret escaped: {:?}",
        outcome.status
    );
    assert!(
        !outcome.stdout.windows(4).any(|w| w == b"top-"),
        "secret leaked to stdout: {:?}",
        String::from_utf8_lossy(&outcome.stdout)
    );
}

// 3. network_tcp_egress
#[tokio::test]
async fn tcp_connect_is_contained() {
    let scratch = tempdir().unwrap();
    let workspace = scratch.path().join("ws");
    std::fs::create_dir(&workspace).unwrap();

    // 240.0.0.0/4 is reserved future-use space, guaranteed not to be
    // routed. Connect either fails immediately via seccomp/Seatbelt or
    // times out at the connect_timeout the probe sets.
    let opts = base_opts(
        &workspace,
        vec!["connect-tcp".into(), "240.0.0.1:80".into()],
    );
    let outcome = run(opts).await;
    assert!(
        outcome.status.contained(),
        "tcp_connect escaped: {:?}",
        outcome.status
    );
}

// 4. network_udp_egress
#[tokio::test]
async fn udp_send_is_contained() {
    let scratch = tempdir().unwrap();
    let workspace = scratch.path().join("ws");
    std::fs::create_dir(&workspace).unwrap();

    let opts = base_opts(
        &workspace,
        vec!["udp-send".into(), "240.0.0.1:53".into()],
    );
    let outcome = run(opts).await;
    assert!(
        outcome.status.contained(),
        "udp_send escaped: {:?}",
        outcome.status
    );
}

// 5. fork_exec_inherits_sandbox
#[tokio::test]
async fn forked_child_inherits_sandbox() {
    let scratch = tempdir().unwrap();
    let workspace = scratch.path().join("ws");
    std::fs::create_dir(&workspace).unwrap();
    let secret_dir = tempdir().unwrap();
    let target = secret_dir.path().join("forked-escape.txt");

    let opts = base_opts(
        &workspace,
        vec!["fork-write-outside".into(), target.display().to_string()],
    );
    let outcome = run(opts).await;
    assert!(
        outcome.status.contained(),
        "fork_write_outside escaped: {:?}",
        outcome.status
    );
    assert!(
        !target.exists(),
        "forked-escape file unexpectedly created at {}",
        target.display()
    );
}

// 6. symlink_redirect_outside_workspace
#[tokio::test]
async fn symlink_pointing_outside_workspace_is_contained() {
    let scratch = tempdir().unwrap();
    let workspace = scratch.path().join("ws");
    std::fs::create_dir(&workspace).unwrap();
    let secret_dir = tempdir().unwrap();
    let target = secret_dir.path().join("symlink-escape.txt");
    let link = workspace.join("link");

    let opts = base_opts(
        &workspace,
        vec![
            "symlink-write".into(),
            link.display().to_string(),
            target.display().to_string(),
        ],
    );
    let outcome = run(opts).await;
    assert!(
        outcome.status.contained(),
        "symlink_write escaped: {:?}",
        outcome.status
    );
    assert!(
        !target.exists(),
        "symlink-escape file unexpectedly created at {}",
        target.display()
    );
}

#[tokio::test]
async fn noop_harness_cold_start_under_50ms() {
    let scratch = tempdir().unwrap();
    let workspace = scratch.path().join("ws");
    std::fs::create_dir(&workspace).unwrap();

    let opts = base_opts(&workspace, vec!["noop".into()]);
    let start = Instant::now();
    let outcome = run(opts).await;
    let elapsed = start.elapsed();

    assert!(
        matches!(outcome.status, SandboxStatus::Exited(0)),
        "noop harness should exit 0, got {:?} stderr={:?}",
        outcome.status,
        String::from_utf8_lossy(&outcome.stderr)
    );
    // Phase 18 acceptance criterion. The harness is the
    // sandbox-shim → birdcage::spawn → escape-attempt noop chain.
    assert!(
        elapsed < Duration::from_millis(50),
        "noop harness cold start exceeded 50ms: {:?}",
        elapsed
    );
}
