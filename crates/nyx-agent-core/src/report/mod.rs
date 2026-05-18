//! Run-level reports and per-finding repro bundles.
//!
//! Phase 25 ships two surfaces:
//!
//! * [`run_card`] aggregates per-run statistics from the persisted
//!   store: finding counts by status/cap/origin/lang, AI spend split
//!   by `one_shot` vs `agent_loop` calls, and wall-clock per phase
//!   (static / payload / spec / chain / novel / exploration / verifier).
//!   The result renders as JSON for the HTTP API plus HTML and
//!   Markdown for download / export.
//!
//! * [`repro_bundle`] writes a self-contained tarball per finding so
//!   another operator can replay the dynamic verifier offline. The
//!   tarball mirrors the layout nyx's own repro bundles use
//!   (`repro.sh`, `payload.bin`, `expected/verdict.json`,
//!   `expected/trace.jsonl`, `README.md`) so the same replay tooling
//!   covers both.

pub mod repro_bundle;
pub mod run_card;

pub use repro_bundle::{
    build_bundle, verify_sha256, BundleArtifact, BundleError, BundleManifest,
    EXPECTED_TRACE_FILENAME, EXPECTED_VERDICT_FILENAME, PAYLOAD_FILENAME, README_FILENAME,
    REPRO_SCRIPT_FILENAME,
};
pub use run_card::{
    build_run_card, render_html, render_markdown, BySplit, PhaseDuration, RunCard, RunCardError,
    SpendSplit,
};
