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
}

/// Request body for `PATCH /api/v1/projects/:project_id`. Nullable
/// fields use tri-state semantics: omitted = no change, `null` =
/// clear, value = set. The `Option<Option<String>>` shape is paired
/// with [`deserialize_double_option_string`] to distinguish the three
/// JSON cases; `env_config` rides the same tri-state through
/// [`TriStateJson`].
#[derive(Debug, Deserialize, TS)]
pub struct PatchProjectRequest {
    #[serde(default, deserialize_with = "deserialize_double_option_string")]
    #[ts(optional, type = "string | null")]
    pub description: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_double_option_string")]
    #[ts(optional, type = "string | null")]
    pub target_base_url: Option<Option<String>>,
    /// Tri-state JSON value: omitted = no change, `null` = clear, value =
    /// set. The body is re-serialized verbatim into `env_config_json`.
    #[serde(default, deserialize_with = "deserialize_tri_state_json")]
    #[ts(type = "unknown")]
    pub env_config: TriStateJson,
}

/// Tri-state wire shape used by [`PatchProjectRequest::env_config`].
#[derive(Debug, Default)]
pub enum TriStateJson {
    #[default]
    Unset,
    Null,
    Value(serde_json::Value),
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

/// Lift a JSON value into [`TriStateJson`]: a missing key is treated
/// the same as an explicit `null` (`TriStateJson::Null`); a present
/// non-null value becomes `TriStateJson::Value(v)`. The caller pairs
/// this with `#[serde(default)]` so `TriStateJson::Unset` is reached
/// only when the deserializer never sees the field.
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
