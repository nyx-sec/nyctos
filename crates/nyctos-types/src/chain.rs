//! AI-derived chain-reasoning schemas + persisted `chains` row.
//!
//! Two distinct surfaces share this module:
//!
//! 1. The on-the-wire types the ChainReasoning task produces. The model
//!    is handed a compact graph (nodes + edges) drawn from the run's
//!    static-pass findings and asked to rank up to K candidate exploit
//!    chains by exploitability, with a written rationale per chain.
//!    These types are plain serde (no `ts-rs`); the chains explorer
//!    reaches them through a separate surface.
//!
//! 2. [`ChainRecord`] — the on-the-wire shape of a `chains` table row.
//!    Derives `ts-rs` so the SPA's chains explorer can name it
//!    directly. The store-side `nyctos_core::store::chain::ChainStore`
//!    reads and writes this shape.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Node kind tag the prompt carries so the model can distinguish the
/// role each finding plays in a candidate chain. Conventional values:
/// `entry`, `sink`, `framework`, `other`.
pub const NODE_KIND_ENTRY: &str = "entry";
pub const NODE_KIND_SINK: &str = "sink";
pub const NODE_KIND_FRAMEWORK: &str = "framework";
pub const NODE_KIND_OTHER: &str = "other";

/// One node in the finding graph. `id` is the stable finding hash;
/// `repo` lets the model recognise cross-repo spans without parsing the
/// edge list. `kind` is a coarse role tag derived from the static
/// pass's flow_steps (e.g. a diag whose flow has a `source` step is an
/// entry; a diag whose path looks like a vendored framework is a
/// framework binding).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReasoningNode {
    pub id: String,
    pub repo: String,
    pub path: String,
    #[serde(default)]
    pub line: Option<u32>,
    pub cap: String,
    pub rule: String,
    pub severity: String,
    pub kind: String,
}

/// One directed edge in the finding graph. `label` is typically
/// `Reaches` (taint/data-flow reachability between findings). The
/// `cross_repo` flag is pre-computed by the graph builder so the model
/// does not have to recover it from the per-node `repo` field on every
/// edge. Both views are available.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReasoningEdge {
    pub from: String,
    pub to: String,
    pub label: String,
    #[serde(default)]
    pub cross_repo: bool,
}

/// Input envelope for the ChainReasoning task. The agent never reaches
/// back to the store; the full graph the prompt needs lives here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReasoningInput {
    pub run_id: String,
    /// Repos that participated in this run, listed in dispatch order.
    /// The model uses this as the cross-repo ground truth and the
    /// binary uses it as a sanity check when computing the persisted
    /// `cross_repo` flag.
    pub repos: Vec<String>,
    pub nodes: Vec<ChainReasoningNode>,
    pub edges: Vec<ChainReasoningEdge>,
    /// Hard cap on the number of chains the model may return. Defaults
    /// to [`CHAIN_REASONING_DEFAULT_MAX`] when the binary does not
    /// override.
    pub max_chains: u32,
}

/// One ranked chain the model produced. `member_ids` are ordered from
/// entry to sink so the verifier can replay the chain in the same
/// direction the model reasoned about. `rationale` is a short
/// human-readable explanation; the binary stores it in the chain row's
/// `rationale_blob` column.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainCandidate {
    pub member_ids: Vec<String>,
    pub rationale: String,
}

/// Structured output the model is asked to produce. Plain `chains`
/// field carrying the ranked list; the validation gate rejects malformed
/// JSON, empty lists, empty member lists, and unknown member ids the
/// graph did not contain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReasoningOutput {
    pub chains: Vec<ChainCandidate>,
}

/// Default ceiling on the chain count the model may return. The phase
/// 16 plan calls for "up to K (default 10) chains".
pub const CHAIN_REASONING_DEFAULT_MAX: u32 = 10;

/// Stable identifier for the ChainReasoning prompt template. Bumped
/// whenever the prompt body changes; the task records this on every
/// chain row and AgentTrace so trail-back is unambiguous.
pub const CHAIN_REASONING_PROMPT_VERSION: &str = "phase16.chain_reasoning.v1";

/// On-the-wire shape of a `chains` table row. `member_ids` is the
/// stored comma-joined string column (the chains explorer splits it
/// client-side in `frontend/src/pages/Chains/memberIds.ts`); the
/// nullable blob columns carry the model's rationale and the
/// provenance tags the chain reasoner stamped at apply time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ChainRecord {
    pub id: String,
    pub run_id: String,
    pub cross_repo: bool,
    pub member_ids: String,
    pub rationale_blob: Option<String>,
    pub attack_provenance: Option<String>,
    pub prompt_version: Option<String>,
    pub status: String,
    pub verification_attempt_id: Option<String>,
    pub evidence_blob: Option<String>,
    pub severity: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_roundtrips_through_serde() {
        let inp = ChainReasoningInput {
            run_id: "run-1".into(),
            repos: vec!["repo-A".into(), "repo-B".into()],
            nodes: vec![
                ChainReasoningNode {
                    id: "abc123".into(),
                    repo: "repo-A".into(),
                    path: "src/router.py".into(),
                    line: Some(7),
                    cap: "SQL_QUERY".into(),
                    rule: "py.taint.flow".into(),
                    severity: "High".into(),
                    kind: NODE_KIND_ENTRY.into(),
                },
                ChainReasoningNode {
                    id: "def456".into(),
                    repo: "repo-B".into(),
                    path: "src/handlers.py".into(),
                    line: Some(19),
                    cap: "SQL_QUERY".into(),
                    rule: "py.sql.exec".into(),
                    severity: "Critical".into(),
                    kind: NODE_KIND_SINK.into(),
                },
            ],
            edges: vec![ChainReasoningEdge {
                from: "abc123".into(),
                to: "def456".into(),
                label: "Reaches".into(),
                cross_repo: true,
            }],
            max_chains: CHAIN_REASONING_DEFAULT_MAX,
        };
        let s = serde_json::to_string(&inp).unwrap();
        let back: ChainReasoningInput = serde_json::from_str(&s).unwrap();
        assert_eq!(inp, back);
    }

    #[test]
    fn output_roundtrips_through_serde() {
        let out = ChainReasoningOutput {
            chains: vec![ChainCandidate {
                member_ids: vec!["abc123".into(), "def456".into()],
                rationale: "controller in A reaches sink in B".into(),
            }],
        };
        let s = serde_json::to_string(&out).unwrap();
        let back: ChainReasoningOutput = serde_json::from_str(&s).unwrap();
        assert_eq!(out, back);
    }
}
