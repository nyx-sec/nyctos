//! Typed live verification plans.
//!
//! These models are the internal contract between candidate synthesis,
//! payload planning, and the guarded verifier. Legacy JSON plans are still
//! accepted by the binary, but are normalized into this shape before any
//! live request/browser action runs.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::payload::{ContextualPayload, PayloadValidationError};

fn default_get() -> String {
    "GET".to_string()
}

fn default_anonymous() -> String {
    "anonymous".to_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoPlanReasonCode {
    BadEndpoint,
    AuthMissing,
    WeakOracle,
    BrowserDisabled,
    RuntimeUnavailable,
    MissingSeedData,
    StateChangingBlocked,
    TargetOutOfScope,
    NoExecutablePlan,
    DependencyReviewOnly,
    UnsupportedClass,
    UnsafeProbe,
    RouteNotInferred,
    Other,
}

impl NoPlanReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadEndpoint => "bad_endpoint",
            Self::AuthMissing => "auth_missing",
            Self::WeakOracle => "weak_oracle",
            Self::BrowserDisabled => "browser_disabled",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::MissingSeedData => "missing_seed_data",
            Self::StateChangingBlocked => "state_changing_blocked",
            Self::TargetOutOfScope => "target_out_of_scope",
            Self::NoExecutablePlan => "no_executable_plan",
            Self::DependencyReviewOnly => "dependency_review_only",
            Self::UnsupportedClass => "unsupported_class",
            Self::UnsafeProbe => "unsafe_probe",
            Self::RouteNotInferred => "route_not_inferred",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoPlanReason {
    pub code: NoPlanReasonCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
}

impl NoPlanReason {
    pub fn new(code: NoPlanReasonCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), context: BTreeMap::new() }
    }

    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LiveHttpRequest {
    #[serde(default = "default_get")]
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captures: Option<serde_json::Value>,
    #[serde(default = "default_anonymous", rename = "as", alias = "role")]
    pub role: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub destructive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<ContextualPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl LiveHttpRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: "GET".to_string(),
            url: url.into(),
            path: None,
            headers: BTreeMap::new(),
            body: None,
            json: None,
            captures: None,
            role: default_anonymous(),
            destructive: false,
            payload: None,
            label: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpOracle {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expect_status: Vec<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_range: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_contains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_not_contains: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub header_contains: BTreeMap<String, String>,
}

impl HttpOracle {
    pub fn has_positive_evidence(&self) -> bool {
        self.body_contains.iter().any(|s| !s.trim().is_empty())
            || self.header_contains.values().any(|s| !s.trim().is_empty())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SingleHttpPlan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<String>,
    #[serde(flatten)]
    pub request: LiveHttpRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<LiveHttpRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benign: Option<LiveHttpRequest>,
    #[serde(flatten)]
    pub oracle: HttpOracle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why_this_confirms: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HttpWorkflowPlan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<String>,
    #[serde(default)]
    pub steps: Vec<LiveHttpRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub benign_steps: Vec<LiveHttpRequest>,
    pub oracle: HttpOracle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_step: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why_this_confirms: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialOracle {
    #[serde(default = "default_differential_oracle_type", rename = "type")]
    pub oracle_type: String,
    #[serde(default)]
    pub expected_allowed_step: usize,
    #[serde(default = "default_forbidden_step")]
    pub expected_forbidden_step: usize,
    #[serde(default = "default_forbidden_statuses")]
    pub forbidden_status: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensitive_body_markers: Vec<String>,
}

impl DifferentialOracle {
    pub fn has_positive_evidence(&self) -> bool {
        self.sensitive_body_markers.iter().any(|s| !s.trim().is_empty())
    }
}

fn default_differential_oracle_type() -> String {
    "forbidden_equivalence_break".to_string()
}

fn default_forbidden_step() -> usize {
    1
}

fn default_forbidden_statuses() -> Vec<u16> {
    vec![401, 403, 404]
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DifferentialHttpPlan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<String>,
    #[serde(default)]
    pub steps: Vec<LiveHttpRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub benign_steps: Vec<LiveHttpRequest>,
    pub oracle: DifferentialOracle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why_this_confirms: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserStep {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_page: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BrowserOracle {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub text_contains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub html_contains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_not_contains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_exists: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selector_text_contains: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_contains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub title_contains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub console_contains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alert_contains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dialog_contains: Vec<String>,
}

impl BrowserOracle {
    pub fn has_positive_evidence(&self) -> bool {
        [
            &self.text_contains,
            &self.html_contains,
            &self.selector_exists,
            &self.url_contains,
            &self.title_contains,
            &self.console_contains,
            &self.alert_contains,
            &self.dialog_contains,
        ]
        .iter()
        .any(|items| items.iter().any(|s| !s.trim().is_empty()))
            || !self.selector_text_contains.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BrowserWorkflowPlan {
    pub url: String,
    #[serde(default, rename = "as", alias = "role")]
    pub role: String,
    #[serde(default)]
    pub steps: Vec<BrowserStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<Box<BrowserWorkflowPlan>>,
    pub oracle: BrowserOracle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<ContextualPayload>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub state_changing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why_this_confirms: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NoPlanLiveTestPlan {
    pub no_plan_reason: NoPlanReason,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LiveTestPlan {
    #[serde(rename = "single_http", alias = "http")]
    SingleHttp(SingleHttpPlan),
    #[serde(rename = "http_workflow", alias = "multi_step_http")]
    HttpWorkflow(HttpWorkflowPlan),
    DifferentialHttp(DifferentialHttpPlan),
    #[serde(rename = "browser_workflow", alias = "browser")]
    BrowserWorkflow(BrowserWorkflowPlan),
    #[serde(rename = "no_plan")]
    NoPlan(NoPlanLiveTestPlan),
}

impl LiveTestPlan {
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::SingleHttp(_) => "single_http",
            Self::HttpWorkflow(_) => "http_workflow",
            Self::DifferentialHttp(_) => "differential_http",
            Self::BrowserWorkflow(_) => "browser_workflow",
            Self::NoPlan(_) => "no_plan",
        }
    }

    pub fn no_plan(reason: NoPlanReason) -> Self {
        Self::NoPlan(NoPlanLiveTestPlan { no_plan_reason: reason })
    }

    pub fn no_plan_reason(&self) -> Option<&NoPlanReason> {
        match self {
            Self::NoPlan(plan) => Some(&plan.no_plan_reason),
            _ => None,
        }
    }

    pub fn validate(&self) -> Result<(), LivePlanValidationError> {
        match self {
            Self::SingleHttp(plan) => {
                validate_http_request(&plan.request)?;
                validate_optional_http_request(plan.baseline.as_ref())?;
                validate_optional_http_request(plan.benign.as_ref())?;
                validate_payload(plan.request.payload.as_ref())?;
                if !plan.oracle.has_positive_evidence() {
                    return Err(LivePlanValidationError::WeakOracle(
                        "single_http plans require body_contains or header_contains positive evidence"
                            .to_string(),
                    ));
                }
            }
            Self::HttpWorkflow(plan) => {
                if plan.steps.is_empty() {
                    return Err(LivePlanValidationError::MissingField("steps".to_string()));
                }
                for step in &plan.steps {
                    validate_http_request(step)?;
                    validate_payload(step.payload.as_ref())?;
                }
                for step in &plan.benign_steps {
                    validate_http_request(step)?;
                    validate_payload(step.payload.as_ref())?;
                }
                if !plan.oracle.has_positive_evidence() {
                    return Err(LivePlanValidationError::WeakOracle(
                        "http_workflow plans require body/header positive evidence".to_string(),
                    ));
                }
            }
            Self::DifferentialHttp(plan) => {
                if plan.steps.len() < 2 {
                    return Err(LivePlanValidationError::MissingField(
                        "at least two differential steps".to_string(),
                    ));
                }
                for step in &plan.steps {
                    validate_http_request(step)?;
                    validate_payload(step.payload.as_ref())?;
                }
                for step in &plan.benign_steps {
                    validate_http_request(step)?;
                    validate_payload(step.payload.as_ref())?;
                }
                if !plan.oracle.has_positive_evidence() {
                    return Err(LivePlanValidationError::WeakOracle(
                        "differential_http plans require sensitive_body_markers".to_string(),
                    ));
                }
            }
            Self::BrowserWorkflow(plan) => {
                if plan.url.trim().is_empty() {
                    return Err(LivePlanValidationError::MissingField("url".to_string()));
                }
                if !plan.oracle.has_positive_evidence() {
                    return Err(LivePlanValidationError::WeakOracle(
                        "browser_workflow plans require a DOM/browser positive oracle".to_string(),
                    ));
                }
                validate_payload(plan.payload.as_ref())?;
            }
            Self::NoPlan(plan) => {
                if plan.no_plan_reason.message.trim().is_empty() {
                    return Err(LivePlanValidationError::MissingField(
                        "no_plan_reason.message".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_optional_http_request(
    request: Option<&LiveHttpRequest>,
) -> Result<(), LivePlanValidationError> {
    if let Some(request) = request {
        validate_http_request(request)?;
    }
    Ok(())
}

fn validate_http_request(request: &LiveHttpRequest) -> Result<(), LivePlanValidationError> {
    if request.method.trim().is_empty() {
        return Err(LivePlanValidationError::MissingField("method".to_string()));
    }
    if request.url.trim().is_empty() {
        return Err(LivePlanValidationError::MissingField("url".to_string()));
    }
    Ok(())
}

fn validate_payload(payload: Option<&ContextualPayload>) -> Result<(), LivePlanValidationError> {
    if let Some(payload) = payload {
        payload.validate().map_err(LivePlanValidationError::Payload)?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LivePlanValidationError {
    MissingField(String),
    WeakOracle(String),
    Payload(PayloadValidationError),
}

impl fmt::Display for LivePlanValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "live test plan missing {field}"),
            Self::WeakOracle(reason) => write!(f, "weak live test oracle: {reason}"),
            Self::Payload(err) => write!(f, "invalid payload: {err}"),
        }
    }
}

impl std::error::Error for LivePlanValidationError {}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_http_plan_roundtrips_with_typed_kind() {
        let plan = LiveTestPlan::SingleHttp(SingleHttpPlan {
            hypothesis: Some("debug endpoint leaks diagnostic marker".to_string()),
            request: LiveHttpRequest::get("http://localhost:3000/api/debug"),
            baseline: Some(LiveHttpRequest::get("http://localhost:3000/")),
            benign: None,
            oracle: HttpOracle {
                body_contains: vec!["debug".to_string()],
                ..HttpOracle::default()
            },
            why_this_confirms: Some(
                "debug marker is only expected on the sensitive endpoint".to_string(),
            ),
        });
        plan.validate().unwrap();
        let raw = serde_json::to_string(&plan).unwrap();
        assert!(raw.contains("\"kind\":\"single_http\""));
        let back: LiveTestPlan = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.kind_str(), "single_http");
    }

    #[test]
    fn no_plan_carries_structured_reason() {
        let plan = LiveTestPlan::no_plan(
            NoPlanReason::new(
                NoPlanReasonCode::RouteNotInferred,
                "could not map source file to route",
            )
            .with_context("path", "src/handlers/admin.rs"),
        );
        plan.validate().unwrap();
        assert_eq!(plan.no_plan_reason().unwrap().code.as_str(), "route_not_inferred");
    }

    #[test]
    fn differential_requires_positive_marker() {
        let plan = LiveTestPlan::DifferentialHttp(DifferentialHttpPlan {
            hypothesis: None,
            steps: vec![
                LiveHttpRequest::get("http://localhost:3000/api/accounts/1"),
                LiveHttpRequest::get("http://localhost:3000/api/accounts/1"),
            ],
            benign_steps: Vec::new(),
            oracle: DifferentialOracle {
                sensitive_body_markers: Vec::new(),
                ..DifferentialOracle {
                    oracle_type: "forbidden_equivalence_break".to_string(),
                    expected_allowed_step: 0,
                    expected_forbidden_step: 1,
                    forbidden_status: vec![401, 403, 404],
                    sensitive_body_markers: Vec::new(),
                }
            },
            why_this_confirms: None,
        });
        assert!(matches!(plan.validate(), Err(LivePlanValidationError::WeakOracle(_))));
    }
}
