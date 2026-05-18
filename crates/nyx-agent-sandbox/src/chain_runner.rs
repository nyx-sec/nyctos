//! Cross-repo chain attack runner (Phase 22).
//!
//! Drives an AI-reasoned chain step-by-step inside the chain lane,
//! threading prior-step output into next-step input via the
//! `NYX_PREV_OUTPUT` env var, and confirming the final sink-probe
//! sentinel fired.
//!
//! A [`ChainRun`] carries an ordered list of [`ChainStep`]s — each step
//! is one finding's harness (synthesised or vendored on disk) plus the
//! payload bytes to splice. The terminal step's verdict is gated on the
//! caller-supplied [`Oracle::SinkProbe`] sentinel: every non-terminal
//! step must exit cleanly (`exit(0)`, no timeout), AND the terminal
//! step must additionally trip its sink probe, for the runner to
//! return [`ChainVerdict::Confirmed`]. Any other outcome surfaces
//! [`ChainVerdict::Inconclusive`] carrying the index of the step that
//! broke the chain.
//!
//! Threading. Step 0 receives `NYX_PREV_OUTPUT=""`. Step `i+1` receives
//! the captured stdout of step `i` (UTF-8 lossy). Each step also gets a
//! workspace-relative `NYX_PAYLOAD_PATH` pointing at its payload file,
//! matching the payload runner's contract.
//!
//! Replay stability. When [`ChainRunner::replay_stable_check`] is set,
//! the runner re-executes the full chain a second time and stamps
//! [`ChainResult::replay_stable`] based on whether the second pass
//! reproduced the same verdict (same `Confirmed`, or the same
//! `Inconclusive { which }`).
//!
//! Backend dispatch. The chain runner exists to drive the chain lane —
//! libkrun (macOS) / firecracker (Linux) / docker / birdcage / process.
//! Today only `process` and `birdcage` route to real backends; the
//! microVM and container paths surface
//! [`SandboxError::BackendUnavailable`] because their helper binaries
//! (`libkrun-runner`, `nyx-fc-runner`) and the docker chain-lane
//! env-builder wiring are still deferred. The shape is in place so
//! callers can program against the chain runner today and the new
//! backends slot in without churning the public API.

use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

use nyx_agent_types::payload::AttackProvenance;
use nyx_agent_types::verify::Oracle;

use crate::payload_runner::{
    bytes_contains, classify_status, pick_lang, render_synthesised, HarnessLang, HarnessSource,
    HarnessSpecInput, PayloadRunnerError,
};
use crate::{BackendKind, BirdcageSandbox, ProcessSandbox, Sandbox, SandboxError, SandboxOpts};

/// Inline-payload ceiling. Mirrors the payload runner's limit so a
/// chain step cannot smuggle a larger blob through the chain lane than
/// the fast-lane verifier accepts. Applied to every step regardless of
/// harness source: synthesised harnesses splice the bytes literally,
/// and on-disk harnesses still write them to the workspace as a
/// sibling file the sandbox reads via `NYX_PAYLOAD_PATH`.
const MAX_INLINE_PAYLOAD_BYTES: usize = 64 * 1024;

/// One member of a chain. `finding_id` is the static-pass finding the
/// step expands; the chain runner does not query the store, the caller
/// has already resolved every member into a runnable harness.
#[derive(Debug, Clone)]
pub struct ChainStep {
    pub finding_id: String,
    pub spec: HarnessSpecInput,
    pub harness_source: HarnessSource,
    pub payload: Vec<u8>,
}

/// Inputs for one full chain replay.
#[derive(Debug, Clone)]
pub struct ChainRun {
    /// Stable id from the persisted [`nyx_agent_types::chain`] row, or
    /// any caller-chosen tag. The runner uses it only as a label on
    /// emitted diagnostics.
    pub chain_id: String,
    /// Steps in execution order (entry node first, sink last).
    pub members: Vec<ChainStep>,
    /// Sink probe the terminal step is gated against. Required to be a
    /// [`Oracle::SinkProbe`]; an [`Oracle::OutputContains`] terminal
    /// would mean "any step's stdout contains a marker", which the
    /// chain rule v1 does not honour.
    pub terminal_oracle: Oracle,
    /// Workspace shared across every step. Materialised harness and
    /// payload files land here; the chain runner clears the terminal
    /// sentinel before run-0 and (when replay-stable is enabled)
    /// before the replay's run-0 too.
    pub workspace: PathBuf,
    /// Provenance of the chain's payloads as a whole. Recorded on the
    /// result for trail-back; the runner does not gate verdicts on it.
    pub attack_provenance: AttackProvenance,
}

/// Configuration shared across [`ChainRunner::run`] calls.
#[derive(Debug, Clone)]
pub struct ChainRunner {
    pub backend: BackendKind,
    /// Wall-clock cap per step. Each step gets the same budget; a
    /// chain of N steps may take up to `N * per_step_timeout` of real
    /// time (plus serialisation overhead).
    pub per_step_timeout: Duration,
    /// When true, re-run the full chain after the first pass and
    /// stamp [`ChainResult::replay_stable`] based on whether the
    /// verdicts agree byte-for-byte.
    pub replay_stable_check: bool,
    /// Override path to `nyx-sandbox-shim` for [`BackendKind::Birdcage`].
    pub shim_path: Option<PathBuf>,
}

impl Default for ChainRunner {
    fn default() -> Self {
        Self {
            backend: BackendKind::Process,
            per_step_timeout: Duration::from_secs(10),
            replay_stable_check: false,
            shim_path: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum ChainRunnerError {
    #[error("chain has no members")]
    EmptyChain,
    #[error("terminal step must use Oracle::SinkProbe")]
    TerminalOracleWrongKind,
    #[error("payload runner error: {0}")]
    Payload(#[from] PayloadRunnerError),
    #[error("workspace setup failed: {0}")]
    Workspace(#[source] std::io::Error),
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxError),
}

/// Final verdict for a chain replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerdict {
    /// Every step exited cleanly AND the terminal sink-probe fired.
    Confirmed,
    /// At least one step broke the chain. `which` points at the
    /// 0-indexed step that failed.
    Inconclusive(InconclusiveReason),
}

/// Why a chain failed to confirm. Phase 22 collapses every "the step
/// broke" cause under one variant so callers only program against the
/// step index; richer cause reporting lands when a downstream consumer
/// needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InconclusiveReason {
    /// `which` is the 0-indexed step whose verdict was not clean.
    /// For non-terminal steps this means exit != 0 / timeout / sandbox
    /// error. For the terminal step this means the sink probe did not
    /// fire.
    ChainStepFailed { which: usize },
}

/// Captured outcome of one step.
#[derive(Debug, Clone)]
pub struct ChainStepCapture {
    pub finding_id: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: i64,
    /// `true` for the terminal step iff the sink probe fired. Always
    /// `false` for non-terminal steps (the runner does not evaluate a
    /// per-step oracle for them).
    pub probe_fired: bool,
    /// Free-form diagnostic, populated when the sandbox refused to
    /// launch or the workspace write failed. Empty on the happy path.
    pub error: Option<String>,
}

/// Output of one [`ChainRunner::run`] call.
#[derive(Debug, Clone)]
pub struct ChainResult {
    pub chain_id: String,
    pub verdict: ChainVerdict,
    pub steps: Vec<ChainStepCapture>,
    pub attack_provenance: AttackProvenance,
    /// `Some(true)` when a second replay produced the same verdict;
    /// `Some(false)` when the second pass disagreed; `None` when the
    /// replay-stable check was disabled.
    pub replay_stable: Option<bool>,
    /// Per-step captures from the replay pass. `Some` whenever the
    /// replay-stable check ran (regardless of agreement) so operators
    /// investigating a flaky chain can diff `steps` against
    /// `replay_steps` instead of only seeing the boolean verdict.
    /// `None` when the check was disabled.
    pub replay_steps: Option<Vec<ChainStepCapture>>,
}

impl ChainRunner {
    /// Drive `run` through every step. Returns a verdict regardless of
    /// whether intermediate steps blew up; setup / sandbox errors fold
    /// into [`ChainVerdict::Inconclusive`] and the offending step's
    /// `error` field carries the message.
    pub async fn run(&self, run: ChainRun) -> Result<ChainResult, ChainRunnerError> {
        if run.members.is_empty() {
            return Err(ChainRunnerError::EmptyChain);
        }
        if !matches!(run.terminal_oracle, Oracle::SinkProbe { .. }) {
            return Err(ChainRunnerError::TerminalOracleWrongKind);
        }

        // Validate every step's spec up-front so we can refuse a
        // malformed chain without spawning any sandbox.
        for step in &run.members {
            if matches!(step.harness_source, HarnessSource::Synthesised)
                && !step.spec.invoke.contains("@PAYLOAD")
            {
                return Err(ChainRunnerError::Payload(
                    PayloadRunnerError::InvokeMissingPayloadSlot,
                ));
            }
            if step.payload.len() > MAX_INLINE_PAYLOAD_BYTES {
                return Err(ChainRunnerError::Payload(PayloadRunnerError::PayloadTooLarge {
                    size: step.payload.len(),
                    max: MAX_INLINE_PAYLOAD_BYTES,
                }));
            }
            // Language pick is cheap; refuse early if any step uses an
            // unsupported runtime.
            pick_lang(&step.spec.lang)?;
        }

        let (verdict, steps) = self.execute_pass(&run, "pass0").await?;

        let (replay_stable, replay_steps) = if self.replay_stable_check {
            let (verdict_replay, steps_replay) = self.execute_pass(&run, "pass1").await?;
            (Some(verdict_replay == verdict), Some(steps_replay))
        } else {
            (None, None)
        };

        Ok(ChainResult {
            chain_id: run.chain_id.clone(),
            verdict,
            steps,
            attack_provenance: run.attack_provenance,
            replay_stable,
            replay_steps,
        })
    }

    async fn execute_pass(
        &self,
        run: &ChainRun,
        label: &str,
    ) -> Result<(ChainVerdict, Vec<ChainStepCapture>), ChainRunnerError> {
        clear_sentinel(&run.workspace, &run.terminal_oracle)?;

        let mut captures: Vec<ChainStepCapture> = Vec::with_capacity(run.members.len());
        let mut prev_output: Vec<u8> = Vec::new();
        let terminal_idx = run.members.len() - 1;

        for (idx, step) in run.members.iter().enumerate() {
            let is_terminal = idx == terminal_idx;
            let lang = pick_lang(&step.spec.lang)?;

            let capture = self.run_step(run, label, idx, step, lang, &prev_output).await?;

            // Non-terminal step: clean iff sandbox launched, did not
            // time out, and exit code is 0. Terminal step: additionally
            // requires the sink probe to fire.
            let clean_exit =
                capture.error.is_none() && !capture.timed_out && capture.exit_code == 0;
            let step_passed =
                if is_terminal { clean_exit && capture.probe_fired } else { clean_exit };

            prev_output = capture.stdout.clone();
            captures.push(capture);

            if !step_passed {
                return Ok((
                    ChainVerdict::Inconclusive(InconclusiveReason::ChainStepFailed { which: idx }),
                    captures,
                ));
            }
        }

        Ok((ChainVerdict::Confirmed, captures))
    }

    async fn run_step(
        &self,
        run: &ChainRun,
        pass_label: &str,
        idx: usize,
        step: &ChainStep,
        lang: HarnessLang,
        prev_output: &[u8],
    ) -> Result<ChainStepCapture, ChainRunnerError> {
        let label = format!("{pass_label}_step{idx}");
        let harness_rel = match &step.harness_source {
            HarnessSource::OnDisk { rel_path } => rel_path.clone(),
            HarnessSource::Synthesised => {
                let body = render_synthesised(&step.spec, lang, &step.payload);
                let name = format!("nyx_chain_harness_{label}{}", lang.script_ext());
                let abs = run.workspace.join(&name);
                std::fs::write(&abs, body).map_err(ChainRunnerError::Workspace)?;
                PathBuf::from(name)
            }
        };

        let payload_name = format!("nyx_chain_payload_{label}.bin");
        let payload_path = run.workspace.join(&payload_name);
        std::fs::write(&payload_path, &step.payload).map_err(ChainRunnerError::Workspace)?;

        let mut opts = SandboxOpts::new(run.workspace.clone(), lang.argv(&harness_rel));
        opts.timeout = self.per_step_timeout;
        opts.env.push(("NYX_PAYLOAD_PATH".to_string(), payload_name));
        opts.env.push((
            "NYX_PREV_OUTPUT".to_string(),
            String::from_utf8_lossy(prev_output).into_owned(),
        ));
        opts.env.push(("NYX_CHAIN_ID".to_string(), run.chain_id.clone()));
        opts.env.push(("NYX_CHAIN_STEP".to_string(), idx.to_string()));

        let outcome = match self.spawn(opts).await {
            Ok(o) => o,
            Err(SandboxError::Spawn(e)) => {
                return Ok(ChainStepCapture {
                    finding_id: step.finding_id.clone(),
                    exit_code: -1,
                    timed_out: false,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    duration_ms: 0,
                    probe_fired: false,
                    error: Some(format!("sandbox spawn failed: {e}")),
                });
            }
            Err(SandboxError::BackendUnavailable { backend, reason }) => {
                return Ok(ChainStepCapture {
                    finding_id: step.finding_id.clone(),
                    exit_code: -1,
                    timed_out: false,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    duration_ms: 0,
                    probe_fired: false,
                    error: Some(format!("backend {backend} unavailable: {reason}")),
                });
            }
            Err(err) => return Err(err.into()),
        };

        let (exit_code, timed_out) = classify_status(outcome.status);

        let is_terminal = idx == run.members.len() - 1;
        let probe_fired = if is_terminal {
            eval_terminal_probe(
                &run.workspace,
                &run.terminal_oracle,
                &outcome.stdout,
                &outcome.stderr,
            )
        } else {
            false
        };

        Ok(ChainStepCapture {
            finding_id: step.finding_id.clone(),
            exit_code,
            timed_out,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
            duration_ms: outcome.duration.as_millis() as i64,
            probe_fired,
            error: None,
        })
    }

    async fn spawn(&self, opts: SandboxOpts) -> Result<crate::SandboxOutcome, SandboxError> {
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
            // libkrun / firecracker / docker still need their helper
            // binaries and the env-builder spin-up wiring (deferred
            // items from Phase 21 / Phase 20). Surface a clean
            // BackendUnavailable so the chain lane can fall back to
            // birdcage / process under the auto-selector.
            BackendKind::Libkrun => Err(SandboxError::BackendUnavailable {
                backend: "libkrun",
                reason: "libkrun-runner helper binary not yet wired (Phase 21 deferred)".into(),
            }),
            BackendKind::Firecracker => Err(SandboxError::BackendUnavailable {
                backend: "firecracker",
                reason: "nyx-fc-runner helper binary not yet wired (Phase 21 deferred)".into(),
            }),
            BackendKind::Docker => Err(SandboxError::BackendUnavailable {
                backend: "docker",
                reason: "docker chain-lane spin-up not yet wired (Phase 20 deferred)".into(),
            }),
        }
    }
}

fn clear_sentinel(workspace: &Path, oracle: &Oracle) -> Result<(), ChainRunnerError> {
    if let Oracle::SinkProbe { sentinel_path, .. } = oracle {
        let abs = workspace.join(sentinel_path);
        if abs.exists() {
            std::fs::remove_file(&abs).map_err(ChainRunnerError::Workspace)?;
        }
    }
    Ok(())
}

fn eval_terminal_probe(workspace: &Path, oracle: &Oracle, stdout: &[u8], stderr: &[u8]) -> bool {
    match oracle {
        Oracle::SinkProbe { sentinel_path, expect_contains } => {
            let abs = workspace.join(sentinel_path);
            if !abs.is_file() {
                return false;
            }
            match expect_contains {
                None => true,
                Some(needle) => match std::fs::read(&abs) {
                    Ok(body) => bytes_contains(&body, needle.as_bytes()),
                    Err(_) => false,
                },
            }
        }
        // The constructor refuses non-SinkProbe oracles, but be
        // defensive against a future variant that slips past the
        // gate: fall back to a stdout/stderr marker scan so the
        // terminal step is still observed rather than silently
        // dropped.
        Oracle::OutputContains { marker } => {
            bytes_contains(stdout, marker.as_bytes()) || bytes_contains(stderr, marker.as_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn ws() -> tempfile::TempDir {
        tempdir().unwrap()
    }

    // Step 0 ("repo-A": auth bypass). Emits a session token on stdout
    // for the next step to read via `NYX_PREV_OUTPUT`. The harness has
    // a hard fail-fast guard: if the chain runner ran this step out of
    // order — meaning a non-empty NYX_PREV_OUTPUT was already present
    // (the sink step's stdout, which is empty by convention) OR the
    // payload was the SQLi probe instead of the auth probe — it exits
    // non-zero. That makes the "wrong order" acceptance test
    // deterministic.
    fn auth_bypass_step() -> ChainStep {
        ChainStep {
            finding_id: "repoA:auth-bypass".to_string(),
            spec: HarnessSpecInput {
                cap: "AUTH_BYPASS".to_string(),
                lang: "shell".to_string(),
                setup: vec![],
                // The payload IS the literal `bypass` marker — the
                // harness rejects any other body. If the chain is
                // replayed with steps reversed, the SQLi step's payload
                // (`'; LEAK--`) lands here instead and the grep fails.
                invoke: "INPUT=@PAYLOAD; \
                    echo \"$INPUT\" | grep -qx 'bypass' || { echo wrong-payload-for-auth >&2; exit 7; }; \
                    printf '%s' 'session=admin-token'"
                    .to_string(),
                teardown: vec![],
            },
            harness_source: HarnessSource::Synthesised,
            payload: b"bypass".to_vec(),
        }
    }

    // Step 1 ("repo-B": SQL injection sink in a different repo's
    // service). Requires the prior step's session-token output, then
    // splices the payload into a SQL-ish read that writes a sentinel
    // when the payload trips the sink. The token gate means: out of
    // order, this step gets an empty NYX_PREV_OUTPUT and exits 8.
    fn sqli_sink_step() -> ChainStep {
        ChainStep {
            finding_id: "repoB:sqli-sink".to_string(),
            spec: HarnessSpecInput {
                cap: "SQL_QUERY".to_string(),
                lang: "shell".to_string(),
                setup: vec![
                    "STORED='alice:pw1\\nbob:pw2\\nadmin:TOP_SECRET'".to_string(),
                ],
                // Require the auth-bypass step's stdout to look like
                // `session=admin-token`. Without it the sink refuses
                // to run.
                invoke: "case \"$NYX_PREV_OUTPUT\" in *session=admin-token*) ;; \
                    *) echo missing-session >&2; exit 8 ;; esac; \
                    PROBE=@PAYLOAD; \
                    printf '%b\\n' \"$STORED\" | grep -E \"$PROBE\" > sentinel.out && cp sentinel.out chain.sentinel"
                    .to_string(),
                teardown: vec![],
            },
            harness_source: HarnessSource::Synthesised,
            payload: b".*".to_vec(),
        }
    }

    fn sink_oracle() -> Oracle {
        Oracle::SinkProbe {
            sentinel_path: "chain.sentinel".to_string(),
            expect_contains: Some("TOP_SECRET".to_string()),
        }
    }

    #[tokio::test]
    async fn two_step_cross_repo_chain_confirms() {
        // Phase 22 acceptance #1: ordered (auth bypass -> sqli sink)
        // chain confirms via the terminal sink probe.
        let dir = ws();
        let runner = ChainRunner::default();
        let result = runner
            .run(ChainRun {
                chain_id: "chain-1".to_string(),
                members: vec![auth_bypass_step(), sqli_sink_step()],
                terminal_oracle: sink_oracle(),
                workspace: dir.path().to_path_buf(),
                attack_provenance: AttackProvenance::LlmSynthesised,
            })
            .await
            .expect("run");
        assert_eq!(result.verdict, ChainVerdict::Confirmed, "{result:?}");
        assert_eq!(result.steps.len(), 2);
        assert!(result.steps[0].error.is_none());
        assert_eq!(result.steps[0].exit_code, 0);
        assert!(result.steps[1].probe_fired);
        assert!(result.replay_stable.is_none(), "default off");
    }

    #[tokio::test]
    async fn wrong_order_yields_inconclusive_at_first_step() {
        // Phase 22 acceptance #2: swap the two steps. The (now-first)
        // SQLi sink step sees an empty NYX_PREV_OUTPUT, refuses to
        // proceed, and the chain breaks at step 0.
        let dir = ws();
        let runner = ChainRunner::default();
        let result = runner
            .run(ChainRun {
                chain_id: "chain-2".to_string(),
                members: vec![sqli_sink_step(), auth_bypass_step()],
                terminal_oracle: sink_oracle(),
                workspace: dir.path().to_path_buf(),
                attack_provenance: AttackProvenance::LlmSynthesised,
            })
            .await
            .expect("run");
        assert_eq!(
            result.verdict,
            ChainVerdict::Inconclusive(InconclusiveReason::ChainStepFailed { which: 0 }),
            "{result:?}"
        );
        // The runner stops at the failing step rather than draining
        // the rest of the chain.
        assert_eq!(result.steps.len(), 1);
        assert_eq!(result.steps[0].exit_code, 8);
    }

    #[tokio::test]
    async fn replay_stable_flag_stamped_when_check_enabled() {
        let dir = ws();
        let runner = ChainRunner { replay_stable_check: true, ..ChainRunner::default() };
        let result = runner
            .run(ChainRun {
                chain_id: "chain-3".to_string(),
                members: vec![auth_bypass_step(), sqli_sink_step()],
                terminal_oracle: sink_oracle(),
                workspace: dir.path().to_path_buf(),
                attack_provenance: AttackProvenance::LlmSynthesised,
            })
            .await
            .expect("run");
        assert_eq!(result.verdict, ChainVerdict::Confirmed);
        assert_eq!(result.replay_stable, Some(true));
        let replay_steps =
            result.replay_steps.as_ref().expect("replay_steps populated when check ran");
        assert_eq!(replay_steps.len(), result.steps.len());
    }

    #[tokio::test]
    async fn terminal_probe_miss_yields_inconclusive_at_last_step() {
        // The terminal step exits 0 but never writes the sentinel:
        // chain should fail at the terminal index with
        // ChainStepFailed { which: 1 }.
        let dir = ws();
        let mut sink = sqli_sink_step();
        // Defang the sentinel write so the step exits 0 without
        // tripping the sink probe.
        sink.spec.invoke = "case \"$NYX_PREV_OUTPUT\" in *session=admin-token*) ;; \
            *) echo missing-session >&2; exit 8 ;; esac; \
            PROBE=@PAYLOAD; \
            echo no-sentinel-written; true"
            .to_string();
        let runner = ChainRunner::default();
        let result = runner
            .run(ChainRun {
                chain_id: "chain-4".to_string(),
                members: vec![auth_bypass_step(), sink],
                terminal_oracle: sink_oracle(),
                workspace: dir.path().to_path_buf(),
                attack_provenance: AttackProvenance::LlmSynthesised,
            })
            .await
            .expect("run");
        assert_eq!(
            result.verdict,
            ChainVerdict::Inconclusive(InconclusiveReason::ChainStepFailed { which: 1 }),
        );
        assert_eq!(result.steps.len(), 2);
        assert_eq!(result.steps[1].exit_code, 0);
        assert!(!result.steps[1].probe_fired);
    }

    #[tokio::test]
    async fn empty_chain_is_refused() {
        let dir = ws();
        let runner = ChainRunner::default();
        let err = runner
            .run(ChainRun {
                chain_id: "empty".to_string(),
                members: vec![],
                terminal_oracle: sink_oracle(),
                workspace: dir.path().to_path_buf(),
                attack_provenance: AttackProvenance::LlmSynthesised,
            })
            .await
            .expect_err("must refuse");
        assert!(matches!(err, ChainRunnerError::EmptyChain));
    }

    #[tokio::test]
    async fn terminal_oracle_must_be_sink_probe() {
        let dir = ws();
        let runner = ChainRunner::default();
        let err = runner
            .run(ChainRun {
                chain_id: "bad-oracle".to_string(),
                members: vec![auth_bypass_step()],
                terminal_oracle: Oracle::OutputContains { marker: "x".to_string() },
                workspace: dir.path().to_path_buf(),
                attack_provenance: AttackProvenance::LlmSynthesised,
            })
            .await
            .expect_err("must refuse");
        assert!(matches!(err, ChainRunnerError::TerminalOracleWrongKind));
    }
}
