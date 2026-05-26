//! Project-scoped outbound integrations.
//!
//! These types are shared by the daemon API and the embedded SPA. The
//! public record deliberately exposes only a target summary, not raw
//! webhook URLs or SMTP passwords.

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ProjectIntegrationKind {
    Webhook,
    Slack,
    Smtp,
}

impl ProjectIntegrationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Slack => "slack",
            Self::Smtp => "smtp",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "webhook" => Some(Self::Webhook),
            "slack" => Some(Self::Slack),
            "smtp" => Some(Self::Smtp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ProjectIntegrationEvent {
    RunFinished,
    FindingVerified,
}

impl ProjectIntegrationEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunFinished => "run_finished",
            Self::FindingVerified => "finding_verified",
        }
    }
}

impl FromStr for ProjectIntegrationKind {
    type Err = ();

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw).ok_or(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum SmtpSecurity {
    #[default]
    StartTls,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProjectIntegrationRecord {
    pub id: String,
    pub project_id: String,
    pub kind: ProjectIntegrationKind,
    pub name: String,
    pub enabled: bool,
    pub events: Vec<ProjectIntegrationEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub min_severity: Option<String>,
    pub target: String,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub last_delivery_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub last_delivery_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub last_delivery_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProjectIntegrationConfigInput {
    Webhook {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        signing_secret: Option<String>,
    },
    Slack {
        webhook_url: String,
    },
    Smtp {
        host: String,
        #[ts(type = "number")]
        port: u16,
        #[serde(default)]
        security: SmtpSecurity,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        password: Option<String>,
        from: String,
        recipients: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct CreateProjectIntegrationRequest {
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    pub events: Vec<ProjectIntegrationEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub min_severity: Option<String>,
    pub config: ProjectIntegrationConfigInput,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct PatchProjectIntegrationRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub events: Option<Vec<ProjectIntegrationEvent>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub min_severity: Option<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub config: Option<ProjectIntegrationConfigInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct TestProjectIntegrationResponse {
    pub ok: bool,
    pub message: String,
}
