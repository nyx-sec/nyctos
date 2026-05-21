//! Shared repo descriptor types.
//!
//! `Repo`, `RepoSource`, and `GitAuth` live here so other workspace
//! crates (and the TS frontend, via `#[derive(TS)]`) can name them
//! without depending on `nyctos-core`. The ingestion-side parsing and
//! `IngestError` stay in `nyctos-core::repo`; this crate only defines
//! the data shapes that cross crate or wire boundaries.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::project::ProjectId;

/// In-memory descriptor of a configured repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct Repo {
    pub name: String,
    pub source: RepoSource,
    pub i_own_this: bool,
    #[ts(type = "string")]
    pub project_id: ProjectId,
}

/// Source kind for a [`Repo`]. Mirrors the config shape but decodes the
/// auth descriptor string into a typed [`GitAuth`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub enum RepoSource {
    Git { url: String, branch: Option<String>, auth: Option<GitAuth> },
    LocalPath {
        #[ts(type = "string")]
        path: PathBuf,
    },
}

/// Auth descriptor for [`RepoSource::Git`]. Parsed from the config
/// `auth = "<scheme>:<value>"` string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub enum GitAuth {
    /// SSH private-key file. Used as `GIT_SSH_COMMAND="ssh -i <path>"`.
    SshKey(#[ts(type = "string")] PathBuf),
    /// Environment variable name that holds a personal access token.
    /// The token is sourced from the env at ingestion time, never
    /// persisted. Write-scoped tokens are refused.
    TokenEnv(String),
    /// GitHub App installation id. Token is minted at ingestion time via
    /// the upstream GH App; the app's installation must carry read-only
    /// scopes.
    GhApp(String),
}

impl GitAuth {
    /// Render this auth value back as the `<scheme>:<value>` descriptor
    /// string that the ingestion-side parser accepts. Used as a stable
    /// identifier for the `repos.auth_ref` audit column (the raw token
    /// or key bytes are never persisted; only the descriptor that
    /// names where they came from).
    pub fn descriptor(&self) -> String {
        match self {
            GitAuth::SshKey(p) => format!("ssh-key:{}", p.display()),
            GitAuth::TokenEnv(var) => format!("token-env:{var}"),
            GitAuth::GhApp(id) => format!("gh-app:{id}"),
        }
    }
}

/// On-the-wire shape of a `repos` table row. Denormalised: the four
/// columns `source_kind`, `source_url_or_path`, `branch`, and
/// `auth_ref` are the persisted form, distinct from the structured
/// [`Repo`] / [`RepoSource`] / [`GitAuth`] runtime descriptors above.
/// The store-side `nyctos_core::store::repo::RepoStore` reads and
/// writes this shape; the API and SPA share the same field layout
/// end-to-end via `#[derive(TS)]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct RepoRecord {
    pub name: String,
    pub project_id: String,
    pub source_kind: String,
    pub source_url_or_path: String,
    pub branch: Option<String>,
    pub auth_ref: Option<String>,
    pub i_own_this: bool,
    pub last_scan_run_id: Option<String>,
    /// `runs.finished_at` for the run pointed to by `last_scan_run_id`,
    /// resolved through a `LEFT JOIN` on read. `None` when no scan has
    /// completed yet (no row in `runs` with that id, or the run is still
    /// in flight). Distinct from `updated_at`, which a `PATCH` on this
    /// row also bumps.
    #[serde(default)]
    #[ts(type = "number | null")]
    pub last_scan_finished_at: Option<i64>,
    #[ts(type = "number")]
    pub created_at: i64,
    #[ts(type = "number")]
    pub updated_at: i64,
}
