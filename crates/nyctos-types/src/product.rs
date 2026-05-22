//! Product-reset DTOs: launch profiles, environment runs, internal
//! pentest signals/candidates, verification attempts, and verified
//! vulnerabilities.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct LaunchStep {
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub repo_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub repo_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub working_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct LaunchHealthCheck {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub command: Option<LaunchStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct LaunchEnvRef {
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct LaunchWorkingDir {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub repo_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub repo_name: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProjectLaunchProfile {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub mode: String,
    #[serde(default)]
    pub build_steps: Vec<LaunchStep>,
    #[serde(default)]
    pub start_steps: Vec<LaunchStep>,
    #[serde(default)]
    pub stop_steps: Vec<LaunchStep>,
    #[serde(default)]
    pub health_checks: Vec<LaunchHealthCheck>,
    #[serde(default)]
    pub target_urls: Vec<String>,
    #[serde(default)]
    pub env_refs: Vec<LaunchEnvRef>,
    #[serde(default)]
    pub working_dirs: Vec<LaunchWorkingDir>,
    pub readiness: String,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
    pub is_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProjectLaunchProfileInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub build_steps: Vec<LaunchStep>,
    #[serde(default)]
    pub start_steps: Vec<LaunchStep>,
    #[serde(default)]
    pub stop_steps: Vec<LaunchStep>,
    #[serde(default)]
    pub health_checks: Vec<LaunchHealthCheck>,
    #[serde(default)]
    pub target_urls: Vec<String>,
    #[serde(default)]
    pub env_refs: Vec<LaunchEnvRef>,
    #[serde(default)]
    pub working_dirs: Vec<LaunchWorkingDir>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct EnvironmentRunRecord {
    pub id: String,
    pub run_id: String,
    pub project_id: String,
    pub profile_id: String,
    pub status: String,
    #[ts(type = "number | null")]
    pub started_at: Option<i64>,
    #[ts(type = "number | null")]
    pub ready_at: Option<i64>,
    #[ts(type = "number | null")]
    pub stopped_at: Option<i64>,
    #[serde(default)]
    pub target_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub health: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub logs_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub teardown: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct NyxSignalRecord {
    pub id: String,
    pub run_id: String,
    pub project_id: String,
    pub repo_id: String,
    pub repo: String,
    pub path: String,
    #[ts(type = "number | null")]
    pub line: Option<i64>,
    pub cap: String,
    pub rule: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub evidence: Option<serde_json::Value>,
    pub signal_kind: String,
    pub meaningful: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub suppressed_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub agent_candidate_id: Option<String>,
    #[ts(type = "number")]
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct PentestCandidateRecord {
    pub id: String,
    pub run_id: String,
    pub project_id: String,
    pub source: String,
    #[serde(default)]
    pub source_ids: Vec<String>,
    pub title: String,
    pub vuln_class: String,
    pub severity_guess: String,
    #[serde(default)]
    #[ts(type = "Array<unknown>")]
    pub affected_components: Vec<serde_json::Value>,
    pub hypothesis: String,
    pub test_plan: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub rejection_reason: Option<String>,
    pub confidence: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub trace_id: Option<String>,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct VerificationAttemptRecord {
    pub id: String,
    pub run_id: String,
    pub project_id: String,
    pub environment_run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub candidate_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub chain_id: Option<String>,
    pub method: String,
    pub status: String,
    #[ts(type = "number")]
    pub started_at: i64,
    #[ts(type = "number | null")]
    pub finished_at: Option<i64>,
    #[ts(type = "number | null")]
    pub duration_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub request: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub response: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub oracle: Option<serde_json::Value>,
    #[serde(default)]
    pub artifact_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub replay_stable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct VerifiedVulnerabilityRecord {
    pub id: String,
    pub run_id: String,
    pub project_id: String,
    pub title: String,
    pub severity: String,
    pub confidence: f64,
    pub vuln_class: String,
    #[serde(default)]
    #[ts(type = "Array<unknown>")]
    pub affected_components: Vec<serde_json::Value>,
    pub business_impact: String,
    pub evidence_summary: String,
    pub repro_steps: String,
    pub remediation: String,
    #[serde(default)]
    pub source_candidate_ids: Vec<String>,
    #[serde(default)]
    pub source_signal_ids: Vec<String>,
    #[serde(default)]
    pub verification_attempt_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub chain_id: Option<String>,
    pub status: String,
    #[ts(type = "number")]
    pub first_seen: i64,
    #[ts(type = "number")]
    pub last_seen: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct RouteEvidence {
    pub path: String,
    #[ts(type = "number | null")]
    pub line: Option<i64>,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct RouteModelEndpoint {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub handler_file: Option<String>,
    #[ts(type = "number | null")]
    pub line: Option<i64>,
    #[serde(default)]
    pub params: Vec<String>,
    #[serde(default)]
    pub middleware: Vec<String>,
    #[serde(default)]
    pub auth_checks: Vec<String>,
    #[serde(default)]
    pub role_checks: Vec<String>,
    #[serde(default)]
    pub body_fields: Vec<String>,
    #[serde(default)]
    pub state_changing: bool,
    pub confidence: f64,
    #[serde(default)]
    pub evidence: Vec<RouteEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct FrontendRouteModel {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub file: Option<String>,
    #[ts(type = "number | null")]
    pub line: Option<i64>,
    pub confidence: f64,
    #[serde(default)]
    pub evidence: Vec<RouteEvidence>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct ApiClientCallModel {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub file: Option<String>,
    #[ts(type = "number | null")]
    pub line: Option<i64>,
    pub confidence: f64,
    #[serde(default)]
    pub evidence: Vec<RouteEvidence>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, TS)]
pub struct RouteModel {
    #[serde(default)]
    pub backend_routes: Vec<RouteModelEndpoint>,
    #[serde(default)]
    pub frontend_routes: Vec<FrontendRouteModel>,
    #[serde(default)]
    pub api_client_calls: Vec<ApiClientCallModel>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct RouteModelRecord {
    pub id: String,
    pub run_id: String,
    pub project_id: String,
    pub model: RouteModel,
    #[ts(type = "number")]
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct StartPentestResponse {
    pub run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct TestLaunchTargetRequest {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct TestLaunchTargetResponse {
    pub ok: bool,
    pub url: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub status: Option<u16>,
    #[ts(type = "number")]
    pub elapsed_ms: u64,
}
