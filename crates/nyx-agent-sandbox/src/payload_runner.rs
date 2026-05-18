//! Deterministic payload runner (Phase 19).
//!
//! Drives a known payload against a known harness inside a [`Sandbox`]
//! and emits a [`VerifyResult`] under differential rule v1: a finding is
//! [`VerifyVerdict::Confirmed`] iff the vuln payload trips the oracle
//! AND the benign control stays clean.
//!
//! The runner is generic over a sandbox factory so the same code path
//! drives both the unhardened [`crate::ProcessSandbox`] (used in the
//! regression tests because no shim binary is required) and the
//! [`crate::BirdcageSandbox`] in production.
//!
//! Harness source. The plan calls for two harness origins:
//!
//! * `OnDisk { rel_path }` — nyx's spec-derivation pipeline already
//!   vendored a runnable harness file under the workspace; the runner
//!   execs it directly.
//! * `Synthesised` — the harness body is materialised from the
//!   [`HarnessSpecInput`]'s `setup` / `invoke` / `teardown` lines. The
//!   runner writes `harness.<ext>` into the workspace, splices the
//!   payload into the invoke template, and execs `runtime harness.<ext>`.
//!
//! Languages supported in Phase 19: `python` / `python3` and
//! `sh` / `bash`. Anything else returns [`PayloadRunnerError::UnsupportedLang`].
//!
//! Oracle predicates ([`Oracle::OutputContains`] + [`Oracle::SinkProbe`])
//! are evaluated on the captured stdout/stderr and on workspace
//! sentinel files after the run.
//!
//! Replay stability: when [`PayloadRunner::replay_stable_check`] is
//! `true` the runner re-executes both runs in a fresh workspace
//! snapshot and stamps `replay_stable = Some(verdict_matches)` on the
//! result. The default is `false` so callers do not pay for a second
//! round of sandboxing on every verify.

use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

use nyctos_types::payload::AttackProvenance;
use nyctos_types::verify::{Oracle, VerifyResult, VerifyRun, VerifyVerdict};

use crate::{
    BackendKind, BirdcageSandbox, ProcessSandbox, Sandbox, SandboxError, SandboxOpts, SandboxStatus,
};

/// `@PAYLOAD` slot replaced by the literal payload bytes in the spec's
/// invoke template. Mirrors the vendored `HarnessSpec` schema.
const PAYLOAD_SLOT: &str = "@PAYLOAD";

/// Hard ceiling on how big a payload the runner is willing to splice.
/// Larger payloads almost certainly belong on disk (the on-disk
/// `harness.<ext>` form fast-paths reading a file the runner wrote
/// separately) rather than inline-quoted into a shell or python string.
const MAX_INLINE_PAYLOAD_BYTES: usize = 64 * 1024;

/// Inputs the runner needs from a vendored or AI-derived harness spec.
/// A trimmed copy of `nyx-agent-nyx::HarnessSpec` so the sandbox crate
/// can stay independent of the spec parser.
#[derive(Debug, Clone)]
pub struct HarnessSpecInput {
    pub cap: String,
    pub lang: String,
    /// Optional setup statements run before `invoke`, in order.
    pub setup: Vec<String>,
    /// Invocation template. Must contain `@PAYLOAD` exactly once.
    pub invoke: String,
    /// Optional teardown statements run after `invoke`, in order.
    pub teardown: Vec<String>,
}

/// Where the harness body comes from.
#[derive(Debug, Clone)]
pub enum HarnessSource {
    /// Already on disk under the sandbox workspace. The runner execs
    /// `runtime <rel_path>` (where `runtime` is picked from `spec.lang`).
    OnDisk { rel_path: PathBuf },
    /// Materialise from the spec's `setup` / `invoke` / `teardown`.
    Synthesised,
}

/// One verify call's inputs.
#[derive(Debug, Clone)]
pub struct PayloadRun {
    pub finding_id: String,
    pub spec: HarnessSpecInput,
    pub harness_source: HarnessSource,
    pub vuln_payload: Vec<u8>,
    pub benign_payload: Vec<u8>,
    pub oracle: Oracle,
    pub attack_provenance: AttackProvenance,
    /// Directory the sandbox uses as its workspace. The runner writes
    /// the materialised harness + payload files here.
    pub workspace: PathBuf,
}

/// Configuration shared across every [`PayloadRunner::verify`] call.
#[derive(Debug, Clone)]
pub struct PayloadRunner {
    pub backend: BackendKind,
    pub per_run_timeout: Duration,
    pub replay_stable_check: bool,
    /// Override path to `nyx-sandbox-shim` for [`BackendKind::Birdcage`].
    /// `None` defers to [`BirdcageSandbox::new`]'s default resolution.
    pub shim_path: Option<PathBuf>,
}

impl Default for PayloadRunner {
    fn default() -> Self {
        Self {
            backend: BackendKind::Process,
            per_run_timeout: Duration::from_secs(10),
            replay_stable_check: false,
            shim_path: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum PayloadRunnerError {
    #[error("unsupported harness lang: {0}")]
    UnsupportedLang(String),
    #[error("invoke template missing `@PAYLOAD` slot")]
    InvokeMissingPayloadSlot,
    #[error("payload too large to splice inline ({size} > {max})")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("workspace setup failed: {0}")]
    Workspace(#[source] std::io::Error),
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),
}

impl PayloadRunner {
    /// Drive a single verify call against `run`. Returns a verdict
    /// regardless of whether the sandboxed harness completed cleanly:
    /// setup / sandbox errors fold into
    /// [`VerifyVerdict::Errored`] with `error_message` populated.
    pub async fn verify(&self, run: PayloadRun) -> Result<VerifyResult, PayloadRunnerError> {
        let lang = pick_lang(&run.spec.lang)?;
        if matches!(run.harness_source, HarnessSource::Synthesised)
            && !run.spec.invoke.contains(PAYLOAD_SLOT)
        {
            return Err(PayloadRunnerError::InvokeMissingPayloadSlot);
        }
        if run.vuln_payload.len() > MAX_INLINE_PAYLOAD_BYTES {
            return Err(PayloadRunnerError::PayloadTooLarge {
                size: run.vuln_payload.len(),
                max: MAX_INLINE_PAYLOAD_BYTES,
            });
        }
        if run.benign_payload.len() > MAX_INLINE_PAYLOAD_BYTES {
            return Err(PayloadRunnerError::PayloadTooLarge {
                size: run.benign_payload.len(),
                max: MAX_INLINE_PAYLOAD_BYTES,
            });
        }

        let vuln_run = self.single_run(&run, lang, &run.vuln_payload, "vuln").await?;
        let benign_run = self.single_run(&run, lang, &run.benign_payload, "benign").await?;

        let error_message = vuln_run.error.clone().or_else(|| benign_run.error.clone());
        let mut result = if let Some(err) = error_message {
            VerifyResult::errored(
                run.finding_id.clone(),
                run.oracle.clone(),
                vuln_run.into_verify_run(&run.vuln_payload),
                benign_run.into_verify_run(&run.benign_payload),
                run.attack_provenance,
                err,
            )
        } else {
            VerifyResult::from_runs(
                run.finding_id.clone(),
                run.oracle.clone(),
                vuln_run.into_verify_run(&run.vuln_payload),
                benign_run.into_verify_run(&run.benign_payload),
                run.attack_provenance,
            )
        };

        if self.replay_stable_check && result.verdict != VerifyVerdict::Errored {
            // A clean re-run reaches a clean verdict iff the second pair
            // agrees with the first. An `Errored` second run flips
            // replay_stable to false rather than corrupting the verdict
            // we already published.
            let vuln_replay = self.single_run(&run, lang, &run.vuln_payload, "vuln-replay").await?;
            let benign_replay =
                self.single_run(&run, lang, &run.benign_payload, "benign-replay").await?;
            let stable = vuln_replay.error.is_none()
                && benign_replay.error.is_none()
                && vuln_replay.oracle_fired == result.vuln_run.oracle_fired
                && benign_replay.oracle_fired == result.benign_run.oracle_fired;
            result.replay_stable = Some(stable);
        }

        Ok(result)
    }

    async fn single_run(
        &self,
        run: &PayloadRun,
        lang: HarnessLang,
        payload: &[u8],
        label: &str,
    ) -> Result<RunCapture, PayloadRunnerError> {
        let harness_rel = match &run.harness_source {
            HarnessSource::OnDisk { rel_path } => rel_path.clone(),
            HarnessSource::Synthesised => {
                let body = render_synthesised(&run.spec, lang, payload);
                let name = format!("nyx_harness_{label}{}", lang.script_ext());
                let abs = run.workspace.join(&name);
                std::fs::write(&abs, body).map_err(PayloadRunnerError::Workspace)?;
                PathBuf::from(name)
            }
        };

        // For OnDisk harnesses with PAYLOAD-aware contents, we still
        // need to pass the payload — write a sibling `payload.bin` the
        // harness can read. For synthesised harnesses the payload is
        // already inlined, so this file is redundant but harmless.
        let payload_path = run.workspace.join(payload_filename(label));
        std::fs::write(&payload_path, payload).map_err(PayloadRunnerError::Workspace)?;

        // SinkProbe oracles observe a workspace-relative sentinel
        // file. Clear it between runs so the previous payload's flag
        // does not leak into the next run's verdict. Verifiers that
        // run each payload in a fresh workspace snapshot would not
        // need this, but Phase 19 reuses the workspace.
        if let Oracle::SinkProbe { sentinel_path, .. } = &run.oracle {
            let abs = run.workspace.join(sentinel_path);
            if abs.exists() {
                std::fs::remove_file(&abs).map_err(PayloadRunnerError::Workspace)?;
            }
        }

        let mut opts = SandboxOpts::new(run.workspace.clone(), lang.argv(&harness_rel));
        opts.timeout = self.per_run_timeout;
        // Surface workspace-relative payload path so OnDisk harnesses
        // can locate it deterministically.
        opts.env.push((
            "NYX_PAYLOAD_PATH".to_string(),
            payload_path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        ));

        let outcome = match self.run_sandbox(opts).await {
            Ok(o) => o,
            Err(SandboxError::Spawn(e)) => {
                return Ok(RunCapture {
                    oracle_fired: false,
                    exit_code: -1,
                    timed_out: false,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    duration_ms: 0,
                    error: Some(format!("sandbox spawn failed: {e}")),
                });
            }
            Err(SandboxError::BackendUnavailable { backend, reason }) => {
                return Ok(RunCapture {
                    oracle_fired: false,
                    exit_code: -1,
                    timed_out: false,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    duration_ms: 0,
                    error: Some(format!("backend {backend} unavailable: {reason}")),
                });
            }
            Err(err) => return Err(err.into()),
        };

        let oracle_fired = match &run.oracle {
            Oracle::OutputContains { marker } => {
                bytes_contains(&outcome.stdout, marker.as_bytes())
                    || bytes_contains(&outcome.stderr, marker.as_bytes())
            }
            Oracle::SinkProbe { sentinel_path, expect_contains } => {
                let abs: PathBuf = run.workspace.join(sentinel_path);
                if !abs.is_file() {
                    false
                } else if let Some(needle) = expect_contains {
                    match std::fs::read(&abs) {
                        Ok(body) => bytes_contains(&body, needle.as_bytes()),
                        Err(_) => false,
                    }
                } else {
                    true
                }
            }
        };

        let (exit_code, timed_out) = classify_status(outcome.status);
        Ok(RunCapture {
            oracle_fired,
            exit_code,
            timed_out,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
            duration_ms: outcome.duration.as_millis() as i64,
            error: None,
        })
    }

    async fn run_sandbox(&self, opts: SandboxOpts) -> Result<crate::SandboxOutcome, SandboxError> {
        match self.backend {
            BackendKind::Process => {
                let mut sb = ProcessSandbox::new();
                sb.run(opts).await?;
                sb.wait().await
            }
            BackendKind::Birdcage => {
                let mut sb = match &self.shim_path {
                    Some(p) => BirdcageSandbox::with_shim_path(p.clone()),
                    None => BirdcageSandbox::new()?,
                };
                sb.run(opts).await?;
                sb.wait().await
            }
            // The deterministic payload runner does not yet drive the
            // chain-lane VM backends — Phase 19's verifier is wired
            // only to the fast lane. Surfacing BackendUnavailable
            // keeps the error path uniform until the chain-lane
            // verifier lands.
            BackendKind::Libkrun => Err(SandboxError::BackendUnavailable {
                backend: "libkrun",
                reason: "payload runner is fast-lane only; libkrun is reserved for chain lane"
                    .into(),
            }),
            BackendKind::Firecracker => Err(SandboxError::BackendUnavailable {
                backend: "firecracker",
                reason: "payload runner is fast-lane only; firecracker is reserved for chain lane"
                    .into(),
            }),
            BackendKind::Docker => Err(SandboxError::BackendUnavailable {
                backend: "docker",
                reason: "payload runner is fast-lane only; docker is reserved for chain lane"
                    .into(),
            }),
        }
    }
}

#[derive(Debug)]
struct RunCapture {
    oracle_fired: bool,
    exit_code: i32,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration_ms: i64,
    error: Option<String>,
}

impl RunCapture {
    fn into_verify_run(self, payload: &[u8]) -> VerifyRun {
        VerifyRun {
            payload: payload.to_vec(),
            oracle_fired: self.oracle_fired,
            exit_code: self.exit_code,
            timed_out: self.timed_out,
            stdout: self.stdout,
            stderr: self.stderr,
            duration_ms: self.duration_ms,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum HarnessLang {
    Python,
    Shell,
}

impl HarnessLang {
    pub(crate) fn script_ext(self) -> &'static str {
        match self {
            HarnessLang::Python => ".py",
            HarnessLang::Shell => ".sh",
        }
    }

    pub(crate) fn argv(self, harness_rel: &Path) -> Vec<String> {
        let path = harness_rel.to_string_lossy().to_string();
        match self {
            HarnessLang::Python => vec!["python3".to_string(), path],
            HarnessLang::Shell => vec!["sh".to_string(), path],
        }
    }
}

pub(crate) fn pick_lang(lang: &str) -> Result<HarnessLang, PayloadRunnerError> {
    match lang.trim().to_lowercase().as_str() {
        "python" | "python3" | "py" => Ok(HarnessLang::Python),
        "sh" | "shell" | "bash" => Ok(HarnessLang::Shell),
        other => Err(PayloadRunnerError::UnsupportedLang(other.to_string())),
    }
}

fn payload_filename(label: &str) -> String {
    format!("nyx_payload_{label}.bin")
}

/// Render the synthesised harness body. Splices `payload` into the
/// `invoke` template at the `@PAYLOAD` slot using lang-appropriate
/// literal quoting.
pub(crate) fn render_synthesised(
    spec: &HarnessSpecInput,
    lang: HarnessLang,
    payload: &[u8],
) -> Vec<u8> {
    let literal = match lang {
        HarnessLang::Python => python_literal(payload),
        HarnessLang::Shell => shell_literal(payload),
    };
    let invoke = spec.invoke.replace(PAYLOAD_SLOT, &literal);

    let mut out = String::new();
    match lang {
        HarnessLang::Python => {
            out.push_str("# auto-generated by nyx-agent-sandbox::payload_runner\n")
        }
        HarnessLang::Shell => out
            .push_str("#!/bin/sh\n# auto-generated by nyx-agent-sandbox::payload_runner\nset -u\n"),
    }
    for line in &spec.setup {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&invoke);
    out.push('\n');
    for line in &spec.teardown {
        out.push_str(line);
        out.push('\n');
    }
    out.into_bytes()
}

/// Quote `payload` as a Python `bytes` literal: `b"..."` with non-ASCII
/// and quote characters escaped as `\xHH`.
fn python_literal(payload: &[u8]) -> String {
    let mut s = String::with_capacity(payload.len() + 4);
    s.push('b');
    s.push('"');
    for &b in payload {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s.push('"');
    s
}

/// Quote `payload` as a single-quoted shell string. Single quotes
/// inside the payload close-and-reopen via `'\''`.
fn shell_literal(payload: &[u8]) -> String {
    let mut s = String::with_capacity(payload.len() + 2);
    s.push('\'');
    for &b in payload {
        if b == b'\'' {
            s.push_str("'\\''");
        } else {
            s.push(b as char);
        }
    }
    s.push('\'');
    s
}

pub(crate) fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub(crate) fn classify_status(status: SandboxStatus) -> (i32, bool) {
    match status {
        SandboxStatus::Exited(code) => (code, false),
        SandboxStatus::Signaled(sig) => (128 + sig, false),
        SandboxStatus::TimedOut => (-1, true),
        SandboxStatus::Killed => (-1, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn shell_sqli_spec() -> HarnessSpecInput {
        // Canned SQLi-style harness: a tiny "user store" with a row for
        // `admin` carrying `TOP_SECRET`. The invoke template uses
        // grep against the literal payload as the search regex. A
        // benign payload like `^alice$` returns alice's row only; a
        // vuln payload like `.*` (regex wildcard) leaks every row,
        // including the secret.
        HarnessSpecInput {
            cap: "SQL_QUERY".to_string(),
            lang: "shell".to_string(),
            setup: vec!["STORED='alice:pw1\\nbob:pw2\\nadmin:TOP_SECRET'".to_string()],
            invoke: "printf '%b\\n' \"$STORED\" | grep -E @PAYLOAD || true".to_string(),
            teardown: vec![],
        }
    }

    fn ws() -> tempfile::TempDir {
        tempdir().unwrap()
    }

    fn oracle_marker() -> Oracle {
        Oracle::OutputContains { marker: "TOP_SECRET".to_string() }
    }

    #[tokio::test]
    async fn canned_sqli_vuln_payload_produces_confirmed() {
        // Acceptance #1 of Phase 19: canned SQLi harness + canned
        // vuln/benign pair yields Confirmed.
        let dir = ws();
        let runner = PayloadRunner::default();
        let result = runner
            .verify(PayloadRun {
                finding_id: "f-1".to_string(),
                spec: shell_sqli_spec(),
                harness_source: HarnessSource::Synthesised,
                vuln_payload: b".*".to_vec(),
                benign_payload: b"^alice$".to_vec(),
                oracle: oracle_marker(),
                attack_provenance: AttackProvenance::Curated,
                workspace: dir.path().to_path_buf(),
            })
            .await
            .expect("verify");
        assert_eq!(result.verdict, VerifyVerdict::Confirmed, "{result:?}");
        assert!(result.vuln_run.oracle_fired);
        assert!(!result.benign_run.oracle_fired);
        assert_eq!(result.attack_provenance, AttackProvenance::Curated);
        assert!(result.replay_stable.is_none(), "default off");
    }

    #[tokio::test]
    async fn swapping_vuln_for_benign_produces_not_confirmed() {
        // Acceptance #2 of Phase 19: replacing the vuln payload with
        // the benign one yields NotConfirmed.
        let dir = ws();
        let runner = PayloadRunner::default();
        let result = runner
            .verify(PayloadRun {
                finding_id: "f-2".to_string(),
                spec: shell_sqli_spec(),
                // Both payloads are the benign control: neither trips
                // the oracle so the differential cannot confirm.
                vuln_payload: b"^alice$".to_vec(),
                benign_payload: b"^alice$".to_vec(),
                oracle: oracle_marker(),
                attack_provenance: AttackProvenance::Curated,
                harness_source: HarnessSource::Synthesised,
                workspace: dir.path().to_path_buf(),
            })
            .await
            .expect("verify");
        assert_eq!(result.verdict, VerifyVerdict::NotConfirmed);
        assert!(!result.vuln_run.oracle_fired);
        assert!(!result.benign_run.oracle_fired);
    }

    #[tokio::test]
    async fn llm_synthesised_provenance_propagates_through_pipeline() {
        // Acceptance #3 of Phase 19: an LlmSynthesised payload pair
        // flows through and lands a verdict carrying the provenance.
        let dir = ws();
        let runner = PayloadRunner::default();
        let result = runner
            .verify(PayloadRun {
                finding_id: "f-3".to_string(),
                spec: shell_sqli_spec(),
                vuln_payload: b".*".to_vec(),
                benign_payload: b"^bob$".to_vec(),
                oracle: oracle_marker(),
                attack_provenance: AttackProvenance::LlmSynthesised,
                harness_source: HarnessSource::Synthesised,
                workspace: dir.path().to_path_buf(),
            })
            .await
            .expect("verify");
        assert_eq!(result.verdict, VerifyVerdict::Confirmed);
        assert_eq!(result.attack_provenance, AttackProvenance::LlmSynthesised);
    }

    #[tokio::test]
    async fn replay_stable_flag_stamped_when_check_enabled() {
        let dir = ws();
        let runner = PayloadRunner { replay_stable_check: true, ..PayloadRunner::default() };
        let result = runner
            .verify(PayloadRun {
                finding_id: "f-4".to_string(),
                spec: shell_sqli_spec(),
                vuln_payload: b".*".to_vec(),
                benign_payload: b"^alice$".to_vec(),
                oracle: oracle_marker(),
                attack_provenance: AttackProvenance::Curated,
                harness_source: HarnessSource::Synthesised,
                workspace: dir.path().to_path_buf(),
            })
            .await
            .expect("verify");
        assert_eq!(result.verdict, VerifyVerdict::Confirmed);
        assert_eq!(result.replay_stable, Some(true));
    }

    #[tokio::test]
    async fn sink_probe_oracle_observes_sentinel_file() {
        // The harness writes a sentinel file when the payload trips it.
        // Vuln payload writes the file; benign payload does not.
        let dir = ws();
        let spec = HarnessSpecInput {
            cap: "OS_COMMAND".to_string(),
            lang: "shell".to_string(),
            setup: vec![],
            // The grep pattern is the payload; if it matches, touch a
            // sentinel file the runner observes via SinkProbe.
            invoke: "printf 'leaked' | grep -E @PAYLOAD >/dev/null && : > sentinel.flag"
                .to_string(),
            teardown: vec![],
        };
        let runner = PayloadRunner::default();
        let oracle =
            Oracle::SinkProbe { sentinel_path: "sentinel.flag".to_string(), expect_contains: None };
        let result = runner
            .verify(PayloadRun {
                finding_id: "f-5".to_string(),
                spec,
                vuln_payload: b"leak".to_vec(),
                benign_payload: b"nope".to_vec(),
                oracle,
                attack_provenance: AttackProvenance::Curated,
                harness_source: HarnessSource::Synthesised,
                workspace: dir.path().to_path_buf(),
            })
            .await
            .expect("verify");
        assert_eq!(result.verdict, VerifyVerdict::Confirmed);
    }

    #[test]
    fn python_literal_escapes_quotes_and_high_bytes() {
        let lit = python_literal(b"a\"b\\c\x00\xffz");
        assert_eq!(lit, "b\"a\\\"b\\\\c\\x00\\xffz\"");
    }

    #[test]
    fn shell_literal_handles_internal_single_quote() {
        let lit = shell_literal(b"it's");
        assert_eq!(lit, "'it'\\''s'");
    }

    #[test]
    fn unsupported_lang_rejected_at_pick_lang() {
        assert!(matches!(
            pick_lang("ruby"),
            Err(PayloadRunnerError::UnsupportedLang(s)) if s == "ruby"
        ));
        assert!(matches!(pick_lang("python"), Ok(HarnessLang::Python)));
        assert!(matches!(pick_lang("Bash"), Ok(HarnessLang::Shell)));
    }

    #[tokio::test]
    async fn invoke_missing_payload_slot_is_rejected() {
        let dir = ws();
        let mut spec = shell_sqli_spec();
        spec.invoke = "echo no-slot".to_string();
        let runner = PayloadRunner::default();
        let err = runner
            .verify(PayloadRun {
                finding_id: "f-x".to_string(),
                spec,
                vuln_payload: b".*".to_vec(),
                benign_payload: b"x".to_vec(),
                oracle: oracle_marker(),
                attack_provenance: AttackProvenance::Curated,
                harness_source: HarnessSource::Synthesised,
                workspace: dir.path().to_path_buf(),
            })
            .await
            .expect_err("must refuse");
        assert!(matches!(err, PayloadRunnerError::InvokeMissingPayloadSlot));
    }
}
