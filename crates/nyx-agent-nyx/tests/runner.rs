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
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("single_file")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixture_yields_at_least_one_diag() {
    if which::which("nyx").is_err() {
        eprintln!("SKIP: `nyx` not on PATH; integration test bypassed.");
        return;
    }

    let min = Version::parse(MINIMUM_NYX_VERSION).expect("minimum version literal parses");
    let runner = NyxRunner::discover(None, &min)
        .await
        .expect("discover nyx on PATH");

    let outcome = runner
        .scan(
            &fixture_root(),
            &ScanOptions {
                verify: false,
                timeout: Some(std::time::Duration::from_secs(60)),
            },
        )
        .await
        .expect("scan fixture");

    assert!(
        !outcome.diags.is_empty(),
        "fixture must produce at least one Diag (got 0); stderr: {}",
        outcome.stderr
    );
}
