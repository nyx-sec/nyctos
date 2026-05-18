//! Verifier wire types (Phase 19).
//!
//! The deterministic payload runner emits a [`VerifyResult`] per
//! finding. The shape mirrors nyx's existing dynamic-verify schema: a
//! tagged verdict, the oracle predicate the runner evaluated, the two
//! per-payload runs (vuln + benign) that produced it, and the
//! `attack_provenance` of the payload pair (Curated upstream payloads
//! vs. LlmSynthesised pairs from PayloadSynthesis).
//!
//! Differential rule v1: a finding is [`VerifyVerdict::Confirmed`] iff
//! the vuln payload trips the oracle AND the benign control does not.
//! Any other combination is [`VerifyVerdict::NotConfirmed`]. Errors
//! (harness failed to set up, sandbox refused to launch, both runs
//! timed out before producing output) land as
//! [`VerifyVerdict::Errored`] so the operator-facing UI can distinguish
//! "we ran it and it did not exploit" from "we never got a clean
//! signal".
//!
//! `replay_stable` is set by the optional second run the payload
//! runner performs when `[run] replay_stable_check = true`. The default
//! configuration leaves it `None` so a single run does not have to lie
//! about determinism.

use serde::{Deserialize, Serialize};

use crate::payload::AttackProvenance;

/// Final verdict for a single finding under differential rule v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyVerdict {
    /// Vuln payload tripped the oracle AND benign control stayed clean.
    Confirmed,
    /// Neither payload tripped the oracle, both tripped, or only the
    /// benign control tripped.
    NotConfirmed,
    /// Harness setup failed, the sandbox refused to launch, or both
    /// runs produced no readable output before the per-run timeout.
    Errored,
}

impl VerifyVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyVerdict::Confirmed => "Confirmed",
            VerifyVerdict::NotConfirmed => "NotConfirmed",
            VerifyVerdict::Errored => "Errored",
        }
    }
}

/// Differential-rule oracle predicates the payload runner can evaluate.
///
/// `OutputContains` is the simplest sink probe: scan the sandboxed
/// child's stdout + stderr for a string marker. `SinkProbe` adds a
/// sentinel-file path the harness writes to when its instrumented sink
/// fires; the runner checks both the file's existence and (optionally)
/// its contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Oracle {
    /// Trip when `marker` appears in captured stdout/stderr.
    OutputContains { marker: String },
    /// Trip when `sentinel_path` exists after the run. When
    /// `expect_contains` is set, additionally require the file's
    /// contents to include that substring.
    SinkProbe {
        sentinel_path: String,
        #[serde(default)]
        expect_contains: Option<String>,
    },
}

/// Captured outcome of a single sandboxed payload run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRun {
    /// The payload bytes that were spliced into the harness.
    pub payload: Vec<u8>,
    /// `true` when the oracle predicate fired.
    pub oracle_fired: bool,
    /// Exit code observed by the sandbox. Signal-killed children carry
    /// the conventional `128 + signum`.
    pub exit_code: i32,
    /// `true` iff the sandbox tore the child down because the
    /// per-run timeout fired before the child exited on its own.
    pub timed_out: bool,
    /// Captured stdout, capped at the sandbox's `max_output_bytes`.
    pub stdout: Vec<u8>,
    /// Captured stderr, capped at the sandbox's `max_output_bytes`.
    pub stderr: Vec<u8>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: i64,
}

/// Phase 19 wire shape. The runner emits one [`VerifyResult`] per
/// finding it confirms or rejects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    pub finding_id: String,
    pub verdict: VerifyVerdict,
    pub oracle: Oracle,
    /// Vuln payload run.
    pub vuln_run: VerifyRun,
    /// Benign-control run. Required for differential rule v1; without
    /// it the runner refuses to emit `Confirmed`.
    pub benign_run: VerifyRun,
    /// Source of the payload pair the verifier consumed.
    pub attack_provenance: AttackProvenance,
    /// Stamped `true` when an optional second run produced an identical
    /// verdict. Stays `None` when the replay-stable check is disabled.
    #[serde(default)]
    pub replay_stable: Option<bool>,
    /// Free-form diagnostic for `Errored` verdicts. Empty on a clean
    /// `Confirmed` / `NotConfirmed` decision.
    #[serde(default)]
    pub error_message: Option<String>,
}

impl VerifyResult {
    /// Apply differential rule v1 to a fresh pair of runs.
    pub fn from_runs(
        finding_id: String,
        oracle: Oracle,
        vuln_run: VerifyRun,
        benign_run: VerifyRun,
        attack_provenance: AttackProvenance,
    ) -> Self {
        let verdict = if vuln_run.oracle_fired && !benign_run.oracle_fired {
            VerifyVerdict::Confirmed
        } else {
            VerifyVerdict::NotConfirmed
        };
        Self {
            finding_id,
            verdict,
            oracle,
            vuln_run,
            benign_run,
            attack_provenance,
            replay_stable: None,
            error_message: None,
        }
    }

    /// Construct an `Errored` verdict carrying `message`. Both runs are
    /// recorded for forensics; the caller is responsible for providing
    /// the best-effort capture they have.
    pub fn errored(
        finding_id: String,
        oracle: Oracle,
        vuln_run: VerifyRun,
        benign_run: VerifyRun,
        attack_provenance: AttackProvenance,
        message: String,
    ) -> Self {
        Self {
            finding_id,
            verdict: VerifyVerdict::Errored,
            oracle,
            vuln_run,
            benign_run,
            attack_provenance,
            replay_stable: None,
            error_message: Some(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(oracle_fired: bool) -> VerifyRun {
        VerifyRun {
            payload: b"x".to_vec(),
            oracle_fired,
            exit_code: 0,
            timed_out: false,
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration_ms: 5,
        }
    }

    #[test]
    fn confirmed_iff_vuln_fires_and_benign_clean() {
        let oracle = Oracle::OutputContains { marker: "X".into() };
        let v = VerifyResult::from_runs(
            "f".into(),
            oracle.clone(),
            run(true),
            run(false),
            AttackProvenance::Curated,
        );
        assert_eq!(v.verdict, VerifyVerdict::Confirmed);

        let v = VerifyResult::from_runs(
            "f".into(),
            oracle.clone(),
            run(false),
            run(false),
            AttackProvenance::Curated,
        );
        assert_eq!(v.verdict, VerifyVerdict::NotConfirmed);

        let v = VerifyResult::from_runs(
            "f".into(),
            oracle.clone(),
            run(true),
            run(true),
            AttackProvenance::Curated,
        );
        assert_eq!(
            v.verdict,
            VerifyVerdict::NotConfirmed,
            "benign trip ruins the differential"
        );

        let v = VerifyResult::from_runs(
            "f".into(),
            oracle,
            run(false),
            run(true),
            AttackProvenance::Curated,
        );
        assert_eq!(v.verdict, VerifyVerdict::NotConfirmed);
    }

    #[test]
    fn errored_carries_message_and_provenance() {
        let oracle = Oracle::SinkProbe {
            sentinel_path: ".nyx/sentinel".into(),
            expect_contains: None,
        };
        let v = VerifyResult::errored(
            "f".into(),
            oracle,
            run(false),
            run(false),
            AttackProvenance::LlmSynthesised,
            "harness setup failed".into(),
        );
        assert_eq!(v.verdict, VerifyVerdict::Errored);
        assert_eq!(v.error_message.as_deref(), Some("harness setup failed"));
        assert_eq!(v.attack_provenance, AttackProvenance::LlmSynthesised);
    }

    #[test]
    fn verify_result_roundtrips_through_serde() {
        let oracle = Oracle::OutputContains { marker: "leak".into() };
        let v = VerifyResult::from_runs(
            "fid".into(),
            oracle,
            run(true),
            run(false),
            AttackProvenance::LlmSynthesised,
        );
        let s = serde_json::to_string(&v).unwrap();
        let back: VerifyResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }
}
