//! Repository ingestion.
//!
//! Two source kinds are supported per the Nyx Pro spec:
//!
//! - [`RepoSource::Git`]: shallow clone or fetch into
//!   `<state>/repos/<name>/`. Subsequent runs reuse the checkout via a
//!   shallow `git fetch`.
//! - [`RepoSource::LocalPath`]: read-only snapshot of a directory
//!   already on disk. The snapshot is rebuilt per run and removed at end
//!   of run so concurrent local edits in an IDE never race the scan.
//!
//! Every ingestion path enforces an ownership attestation:
//! [`Repo::i_own_this`] must be `true`. For git sources the attested URL
//! is matched against the on-disk remote after clone. For local-path
//! sources the daemon surfaces the on-disk `.git/config` remote (if
//! present) so the operator can confirm at first run.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::{RepoConfig, RepoSourceConfig};

pub mod git;
pub mod local;

pub use git::{validate_token_scopes, GhScopeCheck};
pub use local::SnapshotBackend;

/// In-memory descriptor of a configured repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub name: String,
    pub source: RepoSource,
    pub i_own_this: bool,
}

/// Source kind for a [`Repo`]. Mirrors the config shape but decodes the
/// auth descriptor string into a typed [`GitAuth`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoSource {
    Git { url: String, branch: Option<String>, auth: Option<GitAuth> },
    LocalPath { path: PathBuf },
}

/// Auth descriptor for [`RepoSource::Git`]. Parsed from the config
/// `auth = "<scheme>:<value>"` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitAuth {
    /// SSH private-key file. Used as `GIT_SSH_COMMAND="ssh -i <path>"`.
    SshKey(PathBuf),
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
    /// string that [`GitAuth::parse`] accepts. Used as a stable
    /// identifier for the `repos.auth_ref` audit column (the raw token
    /// or key bytes are never persisted — only the descriptor that
    /// names where they came from).
    pub fn descriptor(&self) -> String {
        match self {
            GitAuth::SshKey(p) => format!("ssh-key:{}", p.display()),
            GitAuth::TokenEnv(var) => format!("token-env:{var}"),
            GitAuth::GhApp(id) => format!("gh-app:{id}"),
        }
    }

    /// Parse a config auth descriptor of the form `<scheme>:<value>`.
    pub fn parse(raw: &str) -> Result<Self, IngestError> {
        let (scheme, value) = raw
            .split_once(':')
            .ok_or_else(|| IngestError::AuthMalformed { raw: raw.to_string() })?;
        match scheme {
            "ssh-key" => Ok(GitAuth::SshKey(PathBuf::from(value))),
            "token-env" => {
                if value.is_empty() {
                    return Err(IngestError::AuthMalformed { raw: raw.to_string() });
                }
                Ok(GitAuth::TokenEnv(value.to_string()))
            }
            "gh-app" => {
                if value.is_empty() {
                    return Err(IngestError::AuthMalformed { raw: raw.to_string() });
                }
                Ok(GitAuth::GhApp(value.to_string()))
            }
            other => Err(IngestError::AuthUnknownScheme { scheme: other.to_string() }),
        }
    }
}

impl Repo {
    /// Build a [`Repo`] from a [`RepoConfig`] entry. Does not perform any
    /// IO; ownership is checked at ingestion time via [`ingest`].
    pub fn from_config(cfg: &RepoConfig) -> Result<Self, IngestError> {
        let source = match &cfg.source {
            RepoSourceConfig::Git { url, branch, auth } => {
                let auth = match auth.as_deref() {
                    Some(raw) => Some(GitAuth::parse(raw)?),
                    None => None,
                };
                RepoSource::Git { url: url.clone(), branch: branch.clone(), auth }
            }
            RepoSourceConfig::LocalPath { path } => RepoSource::LocalPath { path: path.clone() },
        };
        Ok(Repo { name: cfg.name.clone(), source, i_own_this: cfg.i_own_this })
    }
}

/// Errors returned from repo ingestion.
#[derive(Debug, Error)]
pub enum IngestError {
    #[error(
        "repo `{name}` is not attested: set `i_own_this = true` in nyx-agent.toml after \
         confirming you own the repository"
    )]
    NotAttested { name: String },

    #[error("malformed auth descriptor `{raw}`: expected `<scheme>:<value>`")]
    AuthMalformed { raw: String },

    #[error(
        "unknown auth scheme `{scheme}`: supported schemes are `ssh-key`, `token-env`, `gh-app`"
    )]
    AuthUnknownScheme { scheme: String },

    #[error("env var `{var}` for `token-env:{var}` auth is not set")]
    AuthEnvMissing { var: String },

    #[error(
        "GitHub token from env `{var}` carries write scope `{scope}`; only read-only tokens are \
         accepted"
    )]
    AuthTokenWriteScope { var: String, scope: String },

    #[error("failed to check GitHub token scopes: {source}")]
    AuthScopeCheck {
        #[source]
        source: anyhow::Error,
    },

    #[error(
        "GitHub token scope probe at `{url}` returned HTTP {status}; refusing to clone with an \
         unvetted token (token may be revoked, rate-limited, or GitHub may be degraded)"
    )]
    AuthScopeStatus { url: String, status: u16 },

    #[error("`gh-app` auth is not yet implemented; configure `token-env` or `ssh-key` instead")]
    AuthGhAppUnsupported,

    #[error(
        "git remote URL on disk (`{actual}`) does not match the attested URL `{attested}` for \
         repo `{name}`"
    )]
    RemoteMismatch { name: String, attested: String, actual: String },

    #[error("local-path `{path}` does not exist for repo `{name}`")]
    LocalPathMissing { name: String, path: PathBuf },

    #[error("local-path `{path}` for repo `{name}` is not a directory")]
    LocalPathNotDir { name: String, path: PathBuf },

    #[error("git command failed for repo `{name}`: {message}")]
    Git { name: String, message: String },

    #[error("snapshot backend failed for repo `{name}`: {message}")]
    Snapshot { name: String, message: String },

    #[error("filesystem error while ingesting repo `{name}` at {path}: {source}")]
    Io {
        name: String,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Cleanup hook attached to an [`IngestedRepo`]. Local-path ingestions
/// install one; git clones do not (the checkout is reused across runs).
pub(crate) enum Cleanup {
    /// Recursively remove a directory at drop time. Used for the
    /// per-run local-path snapshot.
    RemoveSnapshot(PathBuf),
}

/// Workspace produced by [`ingest`]. Drop releases any per-run state
/// (local-path snapshots) but never touches the persistent git
/// checkout.
pub struct IngestedRepo {
    pub name: String,
    pub workspace: PathBuf,
    pub source: RepoSource,
    pub snapshot_backend: Option<SnapshotBackend>,
    pub on_disk_git_remote: Option<String>,
    pub(crate) cleanup: Option<Cleanup>,
}

impl std::fmt::Debug for IngestedRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngestedRepo")
            .field("name", &self.name)
            .field("workspace", &self.workspace)
            .field("source", &self.source)
            .field("snapshot_backend", &self.snapshot_backend)
            .field("on_disk_git_remote", &self.on_disk_git_remote)
            .finish()
    }
}

impl IngestedRepo {
    /// Forget the cleanup hook so the workspace survives drop. Used by
    /// callers that want to inspect the workspace after ingestion in a
    /// test.
    pub fn leak_cleanup(&mut self) {
        self.cleanup = None;
    }
}

impl Drop for IngestedRepo {
    fn drop(&mut self) {
        if let Some(c) = self.cleanup.take() {
            match c {
                Cleanup::RemoveSnapshot(p) => {
                    let _ = local::force_remove_dir(&p);
                }
            }
        }
    }
}

/// Ingest one repository. Honours the ownership attestation, decodes
/// the auth descriptor, then dispatches to the git or local-path
/// backend. Writes only under `<state_repos>/<name>/`; never touches
/// other repos.
pub async fn ingest(
    repo: &Repo,
    state_repos: &Path,
    run_id: &str,
) -> Result<IngestedRepo, IngestError> {
    if !repo.i_own_this {
        return Err(IngestError::NotAttested { name: repo.name.clone() });
    }
    let per_repo = state_repos.join(&repo.name);
    std::fs::create_dir_all(&per_repo).map_err(|e| IngestError::Io {
        name: repo.name.clone(),
        path: per_repo.clone(),
        source: e,
    })?;

    match &repo.source {
        RepoSource::Git { url, branch, auth } => {
            git::ingest_git(&repo.name, url, branch.as_deref(), auth.as_ref(), &per_repo).await
        }
        RepoSource::LocalPath { path } => {
            local::ingest_local(&repo.name, path, &per_repo, run_id).await
        }
    }
}

pub(crate) fn install_snapshot_cleanup(repo: &mut IngestedRepo, snapshot_dir: PathBuf) {
    repo.cleanup = Some(Cleanup::RemoveSnapshot(snapshot_dir));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_parse_ssh_key() {
        let a = GitAuth::parse("ssh-key:/home/eli/.ssh/id_ed25519").expect("ok");
        assert_eq!(a, GitAuth::SshKey(PathBuf::from("/home/eli/.ssh/id_ed25519")));
    }

    #[test]
    fn auth_parse_token_env() {
        let a = GitAuth::parse("token-env:GH_TOKEN").expect("ok");
        assert_eq!(a, GitAuth::TokenEnv("GH_TOKEN".to_string()));
    }

    #[test]
    fn auth_parse_gh_app() {
        let a = GitAuth::parse("gh-app:12345").expect("ok");
        assert_eq!(a, GitAuth::GhApp("12345".to_string()));
    }

    #[test]
    fn auth_parse_rejects_unknown_scheme() {
        let err = GitAuth::parse("kerberos:realm").expect_err("must reject");
        assert!(matches!(err, IngestError::AuthUnknownScheme { .. }));
    }

    #[test]
    fn auth_parse_rejects_missing_colon() {
        let err = GitAuth::parse("token-env").expect_err("must reject");
        assert!(matches!(err, IngestError::AuthMalformed { .. }));
    }

    #[test]
    fn auth_descriptor_round_trips() {
        for raw in ["ssh-key:/home/eli/.ssh/key", "token-env:GH_TOKEN", "gh-app:12345"] {
            let parsed = GitAuth::parse(raw).expect("parse");
            assert_eq!(parsed.descriptor(), raw, "descriptor must echo original config string");
        }
    }

    #[test]
    fn auth_parse_rejects_empty_value() {
        assert!(matches!(
            GitAuth::parse("token-env:").expect_err("must reject"),
            IngestError::AuthMalformed { .. }
        ));
        assert!(matches!(
            GitAuth::parse("gh-app:").expect_err("must reject"),
            IngestError::AuthMalformed { .. }
        ));
    }

    #[test]
    fn from_config_decodes_git_with_auth() {
        let cfg = RepoConfig {
            name: "billing".to_string(),
            i_own_this: true,
            source: RepoSourceConfig::Git {
                url: "git@github.com:org/billing.git".to_string(),
                branch: Some("main".to_string()),
                auth: Some("ssh-key:/home/eli/.ssh/key".to_string()),
            },
            enabled: true,
        };
        let r = Repo::from_config(&cfg).expect("from_config");
        match r.source {
            RepoSource::Git { url, branch, auth } => {
                assert_eq!(url, "git@github.com:org/billing.git");
                assert_eq!(branch.as_deref(), Some("main"));
                assert_eq!(auth, Some(GitAuth::SshKey(PathBuf::from("/home/eli/.ssh/key"))));
            }
            other => panic!("unexpected source {other:?}"),
        }
    }

    #[tokio::test]
    async fn two_repos_ingest_into_separate_workspace_dirs() {
        // Acceptance: a git-source repo and a local-path repo both
        // produce separate workspace dirs under <state>/repos/<name>/.
        let bare_dir = tempfile::tempdir().expect("bare");
        let bare = bare_dir.path().join("upstream.git");
        std::fs::create_dir_all(&bare).expect("mk bare");
        assert!(std::process::Command::new("git")
            .args(["init", "--bare", "--initial-branch=main"])
            .arg(&bare)
            .status()
            .expect("git init")
            .success());
        // Push a seed commit so the clone has a HEAD on main.
        let work = tempfile::tempdir().expect("work");
        for args in [
            vec!["clone", bare.to_str().unwrap(), work.path().to_str().unwrap()],
            vec!["-C", work.path().to_str().unwrap(), "config", "user.email", "t@x.y"],
            vec!["-C", work.path().to_str().unwrap(), "config", "user.name", "t"],
        ] {
            assert!(std::process::Command::new("git")
                .args(&args)
                .status()
                .expect("git step")
                .success());
        }
        std::fs::write(work.path().join("README.md"), "hi\n").expect("write");
        for args in [
            vec!["-C", work.path().to_str().unwrap(), "add", "README.md"],
            vec!["-C", work.path().to_str().unwrap(), "commit", "-m", "i"],
            vec!["-C", work.path().to_str().unwrap(), "push", "origin", "main"],
        ] {
            assert!(std::process::Command::new("git")
                .args(&args)
                .status()
                .expect("git step")
                .success());
        }

        let local_src = tempfile::tempdir().expect("local-src");
        std::fs::write(local_src.path().join("svc.py"), b"print('hi')").expect("write");

        let state = tempfile::tempdir().expect("state");
        let state_repos = state.path().to_path_buf();
        let git_repo = Repo {
            name: "billing".to_string(),
            source: RepoSource::Git {
                url: format!("file://{}", bare.display()),
                branch: Some("main".to_string()),
                auth: None,
            },
            i_own_this: true,
        };
        let local_repo = Repo {
            name: "monolith".to_string(),
            source: RepoSource::LocalPath { path: local_src.path().to_path_buf() },
            i_own_this: true,
        };
        let g = ingest(&git_repo, &state_repos, "run-1").await.expect("git ingest");
        let l = ingest(&local_repo, &state_repos, "run-1").await.expect("local ingest");
        assert!(g.workspace.starts_with(state_repos.join("billing")));
        assert!(l.workspace.starts_with(state_repos.join("monolith")));
        assert_ne!(g.workspace, l.workspace);
        assert!(g.workspace.join("README.md").exists());
        assert!(l.workspace.join("svc.py").exists());
    }

    #[tokio::test]
    async fn ingest_refuses_unattested_repo() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = Repo {
            name: "unattested".to_string(),
            source: RepoSource::LocalPath { path: tmp.path().to_path_buf() },
            i_own_this: false,
        };
        let err = ingest(&repo, tmp.path(), "run-1").await.expect_err("unattested must be refused");
        match err {
            IngestError::NotAttested { name } => assert_eq!(name, "unattested"),
            other => panic!("expected NotAttested, got {other:?}"),
        }
    }
}
