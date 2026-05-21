//! Git source ingestion: shallow clone or fetch into `<state>/repos/<name>/`.
//!
//! - First run: `git clone --depth 1 [--branch <b>] --single-branch <url> <dest>`.
//! - Subsequent runs: `git -C <dest> fetch --depth 1 origin <branch>` followed
//!   by a hard reset to the fetched commit.
//!
//! Auth descriptors are decoded by [`super::GitAuth::parse`] and applied to
//! the spawned process:
//!
//! - `ssh-key:<path>` sets `GIT_SSH_COMMAND="ssh -i <path> -o IdentitiesOnly=yes"`.
//! - `token-env:<var>` injects an HTTPS bearer credential via
//!   `http.extraheader=Authorization: Bearer <token>` after first asking the
//!   GitHub API whether the token carries any write scope.
//! - `gh-app:<id>` returns an explicit unsupported error until a phase
//!   wires up the App-installation token-mint dance.
//!
//! After clone, the on-disk `origin` remote is compared against the
//! attested URL; mismatches fail closed.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Command;

use super::{GitAuth, IngestError, IngestedRepo, RepoSource};

/// Outcome of a GitHub token-scope probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhScopeCheck {
    /// All listed scopes are read-only. Token is safe to use.
    AllReadOnly { scopes: Vec<String> },
    /// At least one scope grants write access. Token is refused.
    HasWriteScope { write_scope: String, scopes: Vec<String> },
    /// No `x-oauth-scopes` header on the response. Treated as
    /// read-only (fine-grained tokens omit the header).
    NoScopeHeader,
}

/// Scopes that grant write or delete access to repositories or org
/// content. Any token carrying one of these is refused.
const WRITE_SCOPES: &[&str] = &[
    "repo",
    "public_repo",
    "write:packages",
    "delete:packages",
    "admin:org",
    "write:org",
    "admin:repo_hook",
    "write:repo_hook",
    "admin:org_hook",
    "delete_repo",
    "user",
    "write:user",
    "workflow",
    "write:discussion",
    "write:gpg_key",
    "admin:gpg_key",
    "write:ssh_signing_key",
    "admin:ssh_signing_key",
    "write:public_key",
    "admin:public_key",
    "codespace",
];

pub(super) async fn ingest_git(
    name: &str,
    url: &str,
    branch: Option<&str>,
    auth: Option<&GitAuth>,
    per_repo_dir: &Path,
) -> Result<IngestedRepo, IngestError> {
    let dest = per_repo_dir.join("checkout");
    let token = match auth {
        Some(GitAuth::TokenEnv(var)) => {
            let val =
                std::env::var(var).map_err(|_| IngestError::AuthEnvMissing { var: var.clone() })?;
            match validate_token_scopes(&val).await? {
                GhScopeCheck::HasWriteScope { write_scope, .. } => {
                    return Err(IngestError::AuthTokenWriteScope {
                        var: var.clone(),
                        scope: write_scope,
                    });
                }
                GhScopeCheck::AllReadOnly { .. } | GhScopeCheck::NoScopeHeader => {}
            }
            Some(val)
        }
        Some(GitAuth::GhApp(_)) => return Err(IngestError::AuthGhAppUnsupported),
        Some(GitAuth::SshKey(_)) | None => None,
    };

    let already_cloned = dest.join(".git").is_dir();
    if already_cloned {
        fetch_existing(name, &dest, branch, auth, token.as_deref()).await?;
    } else {
        clone_fresh(name, url, &dest, branch, auth, token.as_deref()).await?;
    }

    let actual_remote = read_remote_url(name, &dest).await?;
    if normalise_remote(&actual_remote) != normalise_remote(url) {
        return Err(IngestError::RemoteMismatch {
            name: name.to_string(),
            attested: url.to_string(),
            actual: actual_remote,
        });
    }

    Ok(IngestedRepo {
        name: name.to_string(),
        workspace: dest,
        source: RepoSource::Git {
            url: url.to_string(),
            branch: branch.map(str::to_string),
            auth: auth.cloned(),
        },
        snapshot_backend: None,
        on_disk_git_remote: Some(actual_remote),
        cleanup: None,
    })
}

async fn clone_fresh(
    name: &str,
    url: &str,
    dest: &Path,
    branch: Option<&str>,
    auth: Option<&GitAuth>,
    token: Option<&str>,
) -> Result<(), IngestError> {
    if dest.exists() {
        // Stale partial clone: remove before reattempting so git does not
        // refuse with "destination path already exists".
        std::fs::remove_dir_all(dest).map_err(|e| IngestError::Io {
            name: name.to_string(),
            path: dest.to_path_buf(),
            source: e,
        })?;
    }
    let mut cmd = Command::new("git");
    // Use top-level `-c` (ephemeral, applies to this invocation only) rather
    // than clone's `--config` (writes into the new repo's .git/config). The
    // latter would persist the bearer token to disk.
    if let Some(t) = token {
        cmd.arg("-c").arg("credential.helper=");
        cmd.arg("-c").arg(format!("http.extraheader=Authorization: Bearer {t}"));
    }
    cmd.arg("clone").arg("--depth").arg("1").arg("--single-branch");
    if let Some(b) = branch {
        cmd.arg("--branch").arg(b);
    }
    cmd.arg(url).arg(dest);
    apply_env(&mut cmd, auth);
    run_git(name, cmd).await
}

async fn fetch_existing(
    name: &str,
    dest: &Path,
    branch: Option<&str>,
    auth: Option<&GitAuth>,
    token: Option<&str>,
) -> Result<(), IngestError> {
    let mut fetch = Command::new("git");
    fetch.arg("-C").arg(dest);
    // `git fetch` does not accept `--config`; bearer-header config must come
    // via top-level `-c` BEFORE the subcommand. Re-supplied per invocation so
    // the token never lands in the on-disk .git/config.
    if let Some(t) = token {
        fetch.arg("-c").arg("credential.helper=");
        fetch.arg("-c").arg(format!("http.extraheader=Authorization: Bearer {t}"));
    }
    fetch.arg("fetch").arg("--depth").arg("1").arg("origin");
    let target_branch = branch.unwrap_or("HEAD");
    fetch.arg(target_branch);
    apply_env(&mut fetch, auth);
    run_git(name, fetch).await?;

    let mut reset = Command::new("git");
    reset.arg("-C").arg(dest).arg("reset").arg("--hard").arg("FETCH_HEAD");
    apply_env(&mut reset, auth);
    run_git(name, reset).await
}

async fn read_remote_url(name: &str, dest: &Path) -> Result<String, IngestError> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dest).arg("config").arg("--get").arg("remote.origin.url");
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
    let output = cmd.output().await.map_err(|e| IngestError::Io {
        name: name.to_string(),
        path: dest.to_path_buf(),
        source: e,
    })?;
    if !output.status.success() {
        return Err(IngestError::Git {
            name: name.to_string(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn apply_env(cmd: &mut Command, auth: Option<&GitAuth>) {
    if let Some(GitAuth::SshKey(p)) = auth {
        let ssh = format!(
            "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new",
            p.display()
        );
        cmd.env("GIT_SSH_COMMAND", ssh);
    }
    // Disable interactive credential prompts; we want fail-fast in the
    // daemon, never a stalled `git` blocked on a terminal.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    // Refuse to source credentials from any user-level helper. Auth
    // must come from the descriptor, not the operator's keychain.
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
}

async fn run_git(name: &str, mut cmd: Command) -> Result<(), IngestError> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
    let output = cmd.output().await.map_err(|e| IngestError::Io {
        name: name.to_string(),
        path: PathBuf::from("<git>"),
        source: e,
    })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(IngestError::Git {
            name: name.to_string(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn normalise_remote(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/').trim_end_matches(".git");
    trimmed.to_string()
}

/// Canonical GitHub API endpoint used to probe token scopes. Pulled out
/// as a constant so [`validate_token_scopes_at`] can be exercised by
/// hermetic tests pointing at a stubbed server.
const GITHUB_USER_PROBE_URL: &str = "https://api.github.com/user";

/// Query the GitHub API to check whether `token` carries any write
/// scope. Used by [`ingest_git`] to refuse write-capable credentials
/// before they touch the repo.
///
/// Returns [`GhScopeCheck::NoScopeHeader`] when the response omits the
/// `x-oauth-scopes` header. Fine-grained PATs and GitHub-App tokens do
/// not surface scopes this way, so they are conservatively treated as
/// read-only (the caller is still expected to provision them with
/// read-only permissions; the GH UI enforces that out-of-band).
pub async fn validate_token_scopes(token: &str) -> Result<GhScopeCheck, IngestError> {
    validate_token_scopes_at(GITHUB_USER_PROBE_URL, token).await
}

pub(crate) async fn validate_token_scopes_at(
    url: &str,
    token: &str,
) -> Result<GhScopeCheck, IngestError> {
    let resp = match reqwest::Client::builder()
        .user_agent(concat!("nyctos/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return Err(IngestError::AuthScopeCheck { source: anyhow::anyhow!(e) });
        }
    }
    .get(url)
    .bearer_auth(token)
    .header("Accept", "application/vnd.github+json")
    .send()
    .await
    .map_err(|e| IngestError::AuthScopeCheck { source: anyhow::anyhow!(e) })?;

    // Fail closed on any non-success status. A 401/403 means the token is
    // revoked or rate-limited; a 5xx means GitHub cannot tell us the
    // scopes right now. In all of those cases the safe move is to refuse
    // the clone rather than silently fall through to `NoScopeHeader` and
    // accept a token of unknown power.
    let status = resp.status();
    if !status.is_success() {
        return Err(IngestError::AuthScopeStatus { url: url.to_string(), status: status.as_u16() });
    }

    let header = resp.headers().get("x-oauth-scopes").cloned();
    match header {
        None => Ok(GhScopeCheck::NoScopeHeader),
        Some(h) => {
            let raw = h
                .to_str()
                .map_err(|e| IngestError::AuthScopeCheck { source: anyhow::anyhow!(e) })?;
            let scopes: Vec<String> =
                raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            for s in &scopes {
                if WRITE_SCOPES.iter().any(|w| s == w) {
                    return Ok(GhScopeCheck::HasWriteScope {
                        write_scope: s.clone(),
                        scopes: scopes.clone(),
                    });
                }
            }
            Ok(GhScopeCheck::AllReadOnly { scopes })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command as StdCommand;

    use super::*;
    use crate::project::ProjectId;
    use crate::repo::{ingest, Repo, RepoSource};

    fn test_project_id() -> ProjectId {
        ProjectId::new("test-project")
    }

    fn have_git() -> bool {
        let ok = StdCommand::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        // CI must catch missing-git regressions rather than silently
        // skip the suite. The `CI` env var is set by GitHub Actions and
        // virtually every other hosted runner; local dev keeps the
        // skip-on-missing behaviour.
        if !ok && std::env::var("CI").is_ok() {
            panic!(
                "CI=true but `git --version` did not succeed; install git in the test environment"
            );
        }
        ok
    }

    fn init_bare(path: &Path) {
        assert!(StdCommand::new("git")
            .args(["init", "--bare", "--initial-branch=main"])
            .arg(path)
            .status()
            .expect("git init --bare")
            .success());
    }

    fn seed_bare_with_commit(bare: &Path) {
        let work = tempfile::tempdir().expect("tempdir");
        assert!(StdCommand::new("git")
            .args(["clone"])
            .arg(bare)
            .arg(work.path())
            .status()
            .expect("clone")
            .success());
        std::fs::write(work.path().join("README.md"), "hi\n").expect("write");
        for (k, v) in [("user.email", "test@example.com"), ("user.name", "Test")] {
            assert!(StdCommand::new("git")
                .args(["-C"])
                .arg(work.path())
                .args(["config", k, v])
                .status()
                .expect("config")
                .success());
        }
        assert!(StdCommand::new("git")
            .args(["-C"])
            .arg(work.path())
            .args(["add", "README.md"])
            .status()
            .expect("add")
            .success());
        assert!(StdCommand::new("git")
            .args(["-C"])
            .arg(work.path())
            .args(["commit", "-m", "initial"])
            .status()
            .expect("commit")
            .success());
        assert!(StdCommand::new("git")
            .args(["-C"])
            .arg(work.path())
            .args(["push", "origin", "main"])
            .status()
            .expect("push")
            .success());
    }

    #[tokio::test]
    async fn clone_then_fetch_is_idempotent() {
        if !have_git() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let bare_dir = tempfile::tempdir().expect("bare");
        let bare = bare_dir.path().join("upstream.git");
        std::fs::create_dir_all(&bare).expect("mk bare");
        init_bare(&bare);
        seed_bare_with_commit(&bare);

        let state = tempfile::tempdir().expect("state");
        let repo = Repo {
            name: "demo".to_string(),
            source: RepoSource::Git {
                url: format!("file://{}", bare.display()),
                branch: Some("main".to_string()),
                auth: None,
            },
            i_own_this: true,
            project_id: test_project_id(),
        };

        let first = ingest(&repo, state.path(), "run-1").await.expect("first ingest");
        assert!(first.workspace.join("README.md").exists());
        let workspace_path = first.workspace.clone();
        drop(first);

        // Second ingest reuses the checkout via fetch + reset.
        let second = ingest(&repo, state.path(), "run-2").await.expect("second ingest");
        assert_eq!(second.workspace, workspace_path);
        assert!(second.workspace.join("README.md").exists());
        assert_eq!(
            second.on_disk_git_remote.as_deref().map(normalise_remote),
            Some(normalise_remote(&format!("file://{}", bare.display())))
        );
    }

    #[tokio::test]
    async fn refuses_remote_mismatch() {
        if !have_git() {
            return;
        }
        let bare_dir = tempfile::tempdir().expect("bare");
        let bare = bare_dir.path().join("upstream.git");
        std::fs::create_dir_all(&bare).expect("mk bare");
        init_bare(&bare);
        seed_bare_with_commit(&bare);

        let state = tempfile::tempdir().expect("state");
        let true_url = format!("file://{}", bare.display());

        // Seed the workspace with a clone from the real URL, then point
        // the config at a different URL so the post-clone mismatch
        // check fires.
        let prime = Repo {
            name: "demo".to_string(),
            source: RepoSource::Git { url: true_url.clone(), branch: None, auth: None },
            i_own_this: true,
            project_id: test_project_id(),
        };
        ingest(&prime, state.path(), "seed").await.expect("seed");

        let lying = Repo {
            name: "demo".to_string(),
            source: RepoSource::Git {
                url: "https://example.invalid/different.git".to_string(),
                branch: None,
                auth: None,
            },
            i_own_this: true,
            project_id: test_project_id(),
        };
        let err = ingest(&lying, state.path(), "run-bad").await.expect_err("must fail");
        assert!(matches!(err, IngestError::Git { .. } | IngestError::RemoteMismatch { .. }));
    }

    #[test]
    fn normalise_remote_strips_dotgit_and_trailing_slash() {
        assert_eq!(
            normalise_remote("https://github.com/org/repo.git"),
            normalise_remote("https://github.com/org/repo/")
        );
    }

    mod scope_probe {
        use super::*;
        use wiremock::matchers::{header, header_exists, method, path};
        use wiremock::{Mock, MockBuilder, MockServer, ResponseTemplate};

        async fn probe_at(server: &MockServer) -> Result<GhScopeCheck, IngestError> {
            let url = format!("{}/user", server.uri());
            validate_token_scopes_at(&url, "ghp_dummy").await
        }

        fn user_probe() -> MockBuilder {
            Mock::given(method("GET"))
                .and(path("/user"))
                .and(header("authorization", "Bearer ghp_dummy"))
                .and(header_exists("user-agent"))
        }

        #[tokio::test]
        async fn read_only_scopes_pass() {
            let server = MockServer::start().await;
            user_probe()
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("x-oauth-scopes", "read:user, read:org")
                        .set_body_string("{}"),
                )
                .mount(&server)
                .await;
            match probe_at(&server).await.expect("ok") {
                GhScopeCheck::AllReadOnly { scopes } => {
                    assert_eq!(scopes, vec!["read:user".to_string(), "read:org".to_string()]);
                }
                other => panic!("expected AllReadOnly, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn repo_scope_is_refused() {
            let server = MockServer::start().await;
            user_probe()
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("x-oauth-scopes", "repo, read:user")
                        .set_body_string("{}"),
                )
                .mount(&server)
                .await;
            match probe_at(&server).await.expect("ok") {
                GhScopeCheck::HasWriteScope { write_scope, scopes } => {
                    assert_eq!(write_scope, "repo");
                    assert!(scopes.iter().any(|s| s == "read:user"));
                }
                other => panic!("expected HasWriteScope, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn missing_scope_header_is_no_scope_header() {
            let server = MockServer::start().await;
            user_probe()
                .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
                .mount(&server)
                .await;
            assert!(matches!(probe_at(&server).await.expect("ok"), GhScopeCheck::NoScopeHeader));
        }

        #[tokio::test]
        async fn unauthorised_returns_scope_status_error() {
            let server = MockServer::start().await;
            user_probe()
                .respond_with(ResponseTemplate::new(401).set_body_string("Bad credentials"))
                .mount(&server)
                .await;
            let err = probe_at(&server).await.expect_err("must fail");
            match err {
                IngestError::AuthScopeStatus { status, .. } => assert_eq!(status, 401),
                other => panic!("expected AuthScopeStatus, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn server_error_returns_scope_status_error() {
            let server = MockServer::start().await;
            user_probe()
                .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
                .mount(&server)
                .await;
            let err = probe_at(&server).await.expect_err("must fail");
            match err {
                IngestError::AuthScopeStatus { status, .. } => assert_eq!(status, 503),
                other => panic!("expected AuthScopeStatus, got {other:?}"),
            }
        }
    }
}
