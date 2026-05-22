//! Shared project descriptor types.
//!
//! The cross-crate `ProjectId` newtype and the in-memory `Project`
//! descriptor live here so other workspace crates can name them without
//! pulling all of `nyctos-core` into their dep graph. `nyctos-core`
//! re-exports both under `nyctos_core::project::{Project, ProjectId}`
//! for the existing call sites.
//!
//! [`ProjectRecord`] is the on-the-wire shape of one row in the
//! `projects` table. [`CreateProjectRequest`] and [`PatchProjectRequest`]
//! are the matching API envelopes for `POST /projects` and
//! `PATCH /projects/:id`. Both the daemon router and the SPA depend on
//! these shapes; they live here so the TS frontend can
//! `import type { ... }` from `types.gen.ts` instead of hand-rolling
//! parallel interfaces.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::product::{ProjectLaunchProfile, ProjectLaunchProfileInput};

/// Stable identifier for a [`Project`]. Wraps the row id from the
/// `projects` table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectId(pub String);

impl ProjectId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ProjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// In-memory descriptor of a configured project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub name: String,
    pub description: Option<String>,
    pub target_base_url: Option<String>,
    pub env_config: Option<serde_json::Value>,
    pub runtime_profile: Option<ProjectRuntimeProfile>,
    pub default_launch_profile: Option<ProjectLaunchProfile>,
}

/// One command in the project runtime profile. Commands are intentionally
/// stored as operator-authored command lines for this first profile
/// version; the future launcher can decide whether to execute through a
/// shell, split arguments, or translate into compose/devcontainer steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProjectRuntimeCommand {
    pub command: String,
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

/// Environment variable material for the local test launch. Values are
/// persisted because this is still a local-dev profile, but callers can
/// mark sensitive entries so the UI and later loggers know to mask them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProjectRuntimeEnvVar {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub secret: bool,
}

/// Project-level build/run profile for launching the full local app before
/// pentest exploration and live verification. Stored in SQLite as JSON for
/// now, but kept as a typed API contract so the later normalized launch
/// profile table can reuse the same surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProjectRuntimeProfile {
    #[serde(default)]
    pub build_commands: Vec<ProjectRuntimeCommand>,
    #[serde(default)]
    pub start_commands: Vec<ProjectRuntimeCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub health_check_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub health_check_command: Option<ProjectRuntimeCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub target_base_url: Option<String>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub env_vars: Vec<ProjectRuntimeEnvVar>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub env_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub timeout_seconds: Option<u64>,
}

/// On-the-wire shape of a `projects` table row. `created_at` and
/// `updated_at` carry `#[ts(type = "number")]` so the generated TS
/// declaration uses `number` rather than `bigint` (`serde_json` emits
/// a JSON number for `i64`, which JS receives as `number`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProjectRecord {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub target_base_url: Option<String>,
    pub env_config_json: Option<String>,
    pub runtime_profile: Option<ProjectRuntimeProfile>,
    pub default_launch_profile: Option<ProjectLaunchProfile>,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
}

/// Request body for `POST /api/v1/projects`. `env_config` carries
/// `#[ts(type = "unknown")]` because `serde_json::Value` lifts to TS
/// `unknown` (callers shape the body client-side).
#[derive(Debug, Deserialize, TS)]
pub struct CreateProjectRequest {
    pub name: String,
    #[serde(default)]
    #[ts(optional)]
    pub description: Option<String>,
    #[serde(default)]
    #[ts(optional)]
    pub target_base_url: Option<String>,
    #[serde(default)]
    #[ts(optional, type = "unknown")]
    pub env_config: Option<serde_json::Value>,
    #[serde(default)]
    #[ts(optional)]
    pub runtime_profile: Option<ProjectRuntimeProfile>,
    #[serde(default)]
    #[ts(optional)]
    pub default_launch_profile: Option<ProjectLaunchProfileInput>,
}

/// Request body for `PATCH /api/v1/projects/:project_id`. Nullable
/// fields use tri-state semantics: omitted = no change, `null` =
/// clear, value = set. The `Option<Option<String>>` shape is paired
/// with [`deserialize_double_option_string`] to distinguish the three
/// JSON cases; `env_config` rides the same tri-state through
/// [`TriStateJson`].
#[derive(Debug, Deserialize, TS)]
pub struct PatchProjectRequest {
    #[serde(default, with = "double_option_string")]
    #[ts(optional, type = "string | null")]
    pub description: Option<Option<String>>,
    #[serde(default, with = "double_option_string")]
    #[ts(optional, type = "string | null")]
    pub target_base_url: Option<Option<String>>,
    /// Tri-state JSON value: omitted = no change, `null` = clear, value =
    /// set. The body is re-serialized verbatim into `env_config_json`.
    #[serde(default, with = "tri_state_json")]
    #[ts(optional, type = "unknown")]
    pub env_config: TriStateJson,
    /// Tri-state runtime profile: omitted = no change, `null` = clear,
    /// value = set. Serialized into the project row's JSON column.
    #[serde(default, with = "tri_state_runtime_profile")]
    #[ts(optional, type = "ProjectRuntimeProfile | null")]
    pub runtime_profile: TriStateProjectRuntimeProfile,
}

/// Tri-state wire shape used by [`PatchProjectRequest::env_config`].
#[derive(Debug, Default)]
pub enum TriStateJson {
    #[default]
    Unset,
    Null,
    Value(serde_json::Value),
}

/// Tri-state wire shape used by [`PatchProjectRequest::runtime_profile`].
#[derive(Debug, Default)]
pub enum TriStateProjectRuntimeProfile {
    #[default]
    Unset,
    Null,
    Value(ProjectRuntimeProfile),
}

/// Distinguish a missing JSON key (outer `None`) from `null`
/// (`Some(None)`) from a present string value (`Some(Some(_))`).
/// Paired with `#[serde(default)]` on the field so omitted keys
/// produce the outer `None`. Lifted into `nyctos-types` so both
/// `PatchProjectRequest` and the router's `PatchRepoRequest` share
/// one helper.
pub fn deserialize_double_option_string<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(d).map(Some)
}

pub(crate) mod double_option_string {
    pub(crate) fn deserialize<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        super::deserialize_double_option_string(d)
    }
}

/// Lift a JSON value into [`TriStateJson`]: `null` clears the value,
/// while a present non-null value becomes `TriStateJson::Value(v)`.
/// The caller pairs this with `#[serde(default)]` so an omitted field
/// becomes `TriStateJson::Unset`.
pub fn deserialize_tri_state_json<'de, D>(d: D) -> Result<TriStateJson, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match value {
        None => TriStateJson::Null,
        Some(serde_json::Value::Null) => TriStateJson::Null,
        Some(v) => TriStateJson::Value(v),
    })
}

pub(crate) mod tri_state_json {
    pub(crate) fn deserialize<'de, D>(d: D) -> Result<super::TriStateJson, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        super::deserialize_tri_state_json(d)
    }
}

pub fn deserialize_tri_state_runtime_profile<'de, D>(
    d: D,
) -> Result<TriStateProjectRuntimeProfile, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<ProjectRuntimeProfile>::deserialize(d)?;
    Ok(match value {
        None => TriStateProjectRuntimeProfile::Null,
        Some(v) => TriStateProjectRuntimeProfile::Value(v),
    })
}

pub(crate) mod tri_state_runtime_profile {
    pub(crate) fn deserialize<'de, D>(
        d: D,
    ) -> Result<super::TriStateProjectRuntimeProfile, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        super::deserialize_tri_state_runtime_profile(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_profile_deserializes_with_default_arrays() {
        let parsed: ProjectRuntimeProfile = serde_json::from_str(
            r#"{
                "target_base_url": "http://localhost:3000",
                "health_check_url": "http://localhost:3000/health"
            }"#,
        )
        .expect("profile");

        assert_eq!(parsed.target_base_url.as_deref(), Some("http://localhost:3000"));
        assert_eq!(parsed.health_check_url.as_deref(), Some("http://localhost:3000/health"));
        assert!(parsed.build_commands.is_empty());
        assert!(parsed.start_commands.is_empty());
        assert!(parsed.allowed_hosts.is_empty());
        assert!(parsed.env_vars.is_empty());
    }

    #[test]
    fn patch_runtime_profile_preserves_tri_state_semantics() {
        let missing: PatchProjectRequest =
            serde_json::from_str(r#"{"description":"only desc"}"#).expect("missing");
        assert!(matches!(missing.runtime_profile, TriStateProjectRuntimeProfile::Unset));

        let cleared: PatchProjectRequest =
            serde_json::from_str(r#"{"runtime_profile":null}"#).expect("null");
        assert!(matches!(cleared.runtime_profile, TriStateProjectRuntimeProfile::Null));

        let set: PatchProjectRequest = serde_json::from_str(
            r#"{"runtime_profile":{"start_commands":[{"command":"npm run dev"}]}}"#,
        )
        .expect("set");
        match set.runtime_profile {
            TriStateProjectRuntimeProfile::Value(profile) => {
                assert_eq!(profile.start_commands[0].command, "npm run dev");
            }
            other => panic!("expected profile value, got {other:?}"),
        }
    }
}
