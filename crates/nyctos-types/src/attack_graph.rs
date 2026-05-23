//! Shared attack-graph row shapes.
//!
//! The graph is intentionally small and generic: concrete scan artifacts
//! keep living in their owning tables, while graph nodes and edges provide
//! a connected index across routes, endpoints, signals, candidates,
//! verification attempts, vulnerabilities, and chains.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub const NODE_ROUTE: &str = "route";
pub const NODE_ENDPOINT: &str = "endpoint";
pub const NODE_FORM: &str = "form";
pub const NODE_PARAMETER: &str = "parameter";
pub const NODE_ROLE: &str = "role";
pub const NODE_OBJECT: &str = "object";
pub const NODE_SIGNAL: &str = "signal";
pub const NODE_CANDIDATE: &str = "candidate";
pub const NODE_VERIFICATION_ATTEMPT: &str = "verification_attempt";
pub const NODE_VERIFIED_VULNERABILITY: &str = "verified_vulnerability";
pub const NODE_CHAIN: &str = "chain";

pub const EDGE_DISCOVERED_FROM: &str = "discovered_from";
pub const EDGE_TARGETS: &str = "targets";
pub const EDGE_USES_ROLE: &str = "uses_role";
pub const EDGE_TOUCHES_OBJECT: &str = "touches_object";
pub const EDGE_DERIVED_CANDIDATE: &str = "derived_candidate";
pub const EDGE_VERIFIED_AS: &str = "verified_as";
pub const EDGE_CHAINED_WITH: &str = "chained_with";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct AttackGraphNodeRecord {
    pub id: String,
    pub run_id: String,
    pub project_id: String,
    pub kind: String,
    pub stable_key: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub ref_id: Option<String>,
    #[serde(default)]
    #[ts(type = "unknown")]
    pub properties: serde_json::Value,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct AttackGraphEdgeRecord {
    pub id: String,
    pub run_id: String,
    pub project_id: String,
    pub kind: String,
    pub from_node_id: String,
    pub to_node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub evidence_ref: Option<String>,
    #[serde(default)]
    #[ts(type = "unknown")]
    pub properties: serde_json::Value,
    #[ts(type = "number")]
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct AttackGraphEvidenceTrail {
    pub focus: AttackGraphNodeRecord,
    #[serde(default)]
    pub nodes: Vec<AttackGraphNodeRecord>,
    #[serde(default)]
    pub edges: Vec<AttackGraphEdgeRecord>,
}
