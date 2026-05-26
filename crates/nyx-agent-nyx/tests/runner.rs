//! Integration test for the `NyxRunner` subprocess driver.
//!
//! Shells out to the real `nyx` binary against a checked-in single-file
//! fixture. Skips (and passes) when `nyx` is not on `PATH` so the workspace
//! still builds + tests cleanly in environments that do not bundle the
//! upstream scanner.

use std::path::PathBuf;

use nyx_agent_nyx::{NyxRunner, ScanOptions, MINIMUM_NYX_VERSION};
use semver::Version;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("single_file")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixture_yields_at_least_one_diag() {
    if which::which("nyx").is_err() {
        eprintln!("SKIP: `nyx` not on PATH; integration test bypassed.");
        return;
    }

    let min = Version::parse(MINIMUM_NYX_VERSION).expect("minimum version literal parses");
    let runner = NyxRunner::discover(None, &min).await.expect("discover nyx on PATH");

    let outcome = runner
        .scan(
            &fixture_root(),
            &ScanOptions { verify: false, timeout: Some(std::time::Duration::from_secs(60)) },
        )
        .await
        .expect("scan fixture");

    assert!(
        !outcome.diags.is_empty(),
        "fixture must produce at least one Diag (got 0); stderr: {}",
        outcome.stderr
    );

    // The fixture deliberately wires two sinks (`eval(sys.stdin.read())`
    // and `os.system(f"echo {sys.argv[1]}")`) so the rule IDs upstream
    // attaches to them have been stable across the nyx 0.7.x range. The
    // assertion stays additive: extra rules that future nyx releases bolt
    // on are fine; only a rename of one of these two would break it,
    // which is also the kind of breakage we want CI to catch deliberately.
    let rules: std::collections::HashSet<&str> =
        outcome.diags.iter().map(|d| d.rule.as_str()).collect();
    for required in ["py.code_exec.eval", "py.cmdi.os_system"] {
        assert!(
            rules.contains(required),
            "fixture should trigger {required}; saw rules {rules:?}; stderr: {}",
            outcome.stderr
        );
    }
}
