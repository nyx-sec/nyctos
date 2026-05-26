//! Git source ingestion: shallow clone or fetch into `<state>/repos/<name>/`.
//!
//! - First run: `git clone --depth 1 [--branch <b>] --single-branch <url> <dest>`.
//! - Subsequent runs: `git -C <dest> fetch --depth 1 origin <branch>` followed
//!   by a hard reset to the fetched commit.
//!
//! Auth descriptors are decoded by [`super::parse_git_auth`] and applied to
//! the spawned process:
//!
//! - `ssh-key:<path>` sets `GIT_SSH_COMMAND="ssh -i <path> -o IdentitiesOnly=yes"`.
//! - `token-env:<var>` injects an HTTPS bearer credential via runtime
//!   config env vars (`GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<N>` /
//!   `GIT_CONFIG_VALUE_<N>`, available since git 2.31). The token lives
//!   in the child process's environment, never in its argv, so it is
//!   not visible in `/proc/<pid>/cmdline`. Scope is probed against the
//!   GitHub API before any clone runs and write-scoped tokens are
//!   refused.
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

/// Minimum git release we are willing to invoke. Lower releases carry
/// known CVE exposures (e.g. CVE-2024-32002 path-attribute exploitation
/// on clones that materialise symlinks during checkout) and should be
/// refused at ingestion time. Bump in lockstep with upstream CVE
/// announcements.
pub(crate) const MINIMUM_GIT_VERSION: (u32, u32, u32) = (2, 45, 1);

pub(super) async fn ingest_git(
    name: &str,
    url: &str,
    branch: Option<&str>,
    auth: Option<&GitAuth>,
    per_repo_dir: &Path,
) -> Result<IngestedRepo, IngestError> {
    let git_bin = assert_git_path_allowed()?;
    assert_git_version_ok(&git_bin).await?;
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
        fetch_existing(&git_bin, name, &dest, branch, auth, token.as_deref()).await?;
    } else {
        clone_fresh(&git_bin, name, url, &dest, branch, auth, token.as_deref()).await?;
    }

    let actual_remote = read_remote_url(&git_bin, name, &dest).await?;
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
    git_bin: &Path,
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
    let mut cmd = Command::new(git_bin);
    cmd.arg("clone").arg("--depth").arg("1").arg("--single-branch");
    if let Some(b) = branch {
        cmd.arg("--branch").arg(b);
    }
    cmd.arg(url).arg(dest);
    apply_env(&mut cmd, auth);
    if let Some(t) = token {
        apply_bearer_token_env(&mut cmd, t);
    }
    run_git(name, cmd).await
}

async fn fetch_existing(
    git_bin: &Path,
    name: &str,
    dest: &Path,
    branch: Option<&str>,
    auth: Option<&GitAuth>,
    token: Option<&str>,
) -> Result<(), IngestError> {
    let mut fetch = Command::new(git_bin);
    fetch.arg("-C").arg(dest);
    fetch.arg("fetch").arg("--depth").arg("1").arg("origin");
    let target_branch = branch.unwrap_or("HEAD");
    fetch.arg(target_branch);
    apply_env(&mut fetch, auth);
    if let Some(t) = token {
        apply_bearer_token_env(&mut fetch, t);
    }
    run_git(name, fetch).await?;

    let mut reset = Command::new(git_bin);
    reset.arg("-C").arg(dest).arg("reset").arg("--hard").arg("FETCH_HEAD");
    apply_env(&mut reset, auth);
    run_git(name, reset).await
}

async fn read_remote_url(git_bin: &Path, name: &str, dest: &Path) -> Result<String, IngestError> {
    let mut cmd = Command::new(git_bin);
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

/// Inject the HTTPS bearer credential into the child git process via
/// the `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<N>` / `GIT_CONFIG_VALUE_<N>`
/// env-driven runtime config (available since git 2.31; the workspace
/// minimum is `MINIMUM_GIT_VERSION = 2.45.1`, well above the floor).
///
/// Why env instead of `git -c key=val ...`: the `-c` form leaves the
/// bearer string in argv, where it shows up in `/proc/<pid>/cmdline`
/// for the lifetime of the process and gets captured by every `ps` /
/// `htop` snapshot. The env-var form lives in `/proc/<pid>/environ`,
/// which is mode `0400` (only readable by the same uid) and is not
/// surfaced by `ps`-style tooling.
///
/// Clears `credential.helper` at slot 0 so the system / user keychain
/// helpers cannot smuggle a different credential in; slot 1 sets the
/// `http.extraheader` bearer the same way the previous `-c` shape did.
/// Two entries -> `GIT_CONFIG_COUNT=2`. The keys/values overwrite any
/// inherited `GIT_CONFIG_*_0` / `_1` pairs the operator may have set in
/// their shell env; remaining `_2+` pairs (if any) are ignored because
/// git only reads up to `COUNT`.
fn apply_bearer_token_env(cmd: &mut Command, token: &str) {
    cmd.env("GIT_CONFIG_COUNT", "2");
    cmd.env("GIT_CONFIG_KEY_0", "credential.helper");
    cmd.env("GIT_CONFIG_VALUE_0", "");
    cmd.env("GIT_CONFIG_KEY_1", "http.extraheader");
    cmd.env("GIT_CONFIG_VALUE_1", format!("Authorization: Bearer {token}"));
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

/// Parse a `git --version` line into a `(major, minor, patch)` triple,
/// tolerating vendor suffixes such as Apple Git's `(Apple Git-154)`
/// tail or the `2.46.0.windows.1` extra segment shipped on Git for
/// Windows. Returns `None` if the line does not begin with the
/// canonical `git version ` prefix or if `major`/`minor` are not
/// integers.
pub(crate) fn parse_git_version(raw: &str) -> Option<(u32, u32, u32)> {
    let body = raw.trim().strip_prefix("git version ")?;
    let semver = body.split_whitespace().next()?;
    let mut parts = semver.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch = match parts.next() {
        None => 0,
        Some(raw_patch) => {
            let digits: String = raw_patch.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                0
            } else {
                digits.parse().ok()?
            }
        }
    };
    Some((major, minor, patch))
}

/// Compare a parsed git version triple against [`MINIMUM_GIT_VERSION`].
pub(crate) fn version_satisfies_minimum(found: (u32, u32, u32)) -> bool {
    found >= MINIMUM_GIT_VERSION
}

/// Run `git --version`, parse the output, and refuse to proceed if the
/// resolved binary is older than [`MINIMUM_GIT_VERSION`]. Called once
/// at the top of [`ingest_git`] so vulnerable hosts fail fast rather
/// than mid-clone. Takes the binary path resolved by
/// [`assert_git_path_allowed`] so the version probe and the eventual
/// clone/fetch invoke the same binary.
async fn assert_git_version_ok(git_bin: &Path) -> Result<(), IngestError> {
    let mut cmd = Command::new(git_bin);
    cmd.arg("--version");
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
    let output = cmd.output().await.map_err(|e| IngestError::Io {
        name: "<git --version>".to_string(),
        path: PathBuf::from("<git>"),
        source: e,
    })?;
    if !output.status.success() {
        return Err(IngestError::Git {
            name: "<git --version>".to_string(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parsed = parse_git_version(&raw)
        .ok_or_else(|| IngestError::GitVersionUnparseable { raw: raw.clone() })?;
    if !version_satisfies_minimum(parsed) {
        let (mj, mn, p) = parsed;
        let (rmj, rmn, rp) = MINIMUM_GIT_VERSION;
        return Err(IngestError::GitVersionTooOld {
            found: format!("{mj}.{mn}.{p}"),
            required: format!("{rmj}.{rmn}.{rp}"),
        });
    }
    Ok(())
}

/// Env var operators set to override the default trusted-path
/// allowlist used by [`assert_git_path_allowed`]. Colon-separated on
/// unix, semicolon-separated on Windows. The literal value `*`
/// disables enforcement.
pub(crate) const GIT_ALLOWLIST_ENV_VAR: &str = "NYCTOS_GIT_BINARY_ALLOWLIST";

/// Sentinel value for [`GIT_ALLOWLIST_ENV_VAR`] that disables
/// allowlist enforcement entirely. Useful in development when the
/// host git lives outside the default vendor locations.
const GIT_ALLOWLIST_BYPASS: &str = "*";

/// Default trusted locations a vendor-shipped `git` is expected to
/// live at, per platform. Matches the paths the CVE-version bullet
/// called out as sensible defaults plus the standard Linux / Windows
/// installer drops.
pub(crate) fn default_git_allowlist() -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        vec![
            PathBuf::from("/usr/bin/git"),
            PathBuf::from("/usr/local/bin/git"),
            PathBuf::from("/opt/homebrew/bin/git"),
            PathBuf::from("/opt/local/bin/git"),
            PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/git"),
        ]
    } else if cfg!(target_os = "windows") {
        vec![
            PathBuf::from(r"C:\Program Files\Git\cmd\git.exe"),
            PathBuf::from(r"C:\Program Files\Git\bin\git.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Git\cmd\git.exe"),
        ]
    } else {
        // Linux / *BSD / fallback. Distros typically install to
        // /usr/bin/git; the libexec path is where some Linux
        // distributions wire the actual binary.
        vec![
            PathBuf::from("/usr/bin/git"),
            PathBuf::from("/usr/local/bin/git"),
            PathBuf::from("/usr/libexec/git-core/git"),
            PathBuf::from("/opt/git/bin/git"),
        ]
    }
}

/// Resolve the operator's configured allowlist. Returns `None` when
/// the operator opted out via the sentinel `*` value; otherwise
/// returns the parsed env-var list or [`default_git_allowlist`] if
/// the env var is unset / empty.
pub(crate) fn git_binary_allowlist() -> Option<Vec<PathBuf>> {
    git_binary_allowlist_from_raw(std::env::var(GIT_ALLOWLIST_ENV_VAR).ok().as_deref())
}

/// Pure half of [`git_binary_allowlist`]: takes the raw env value
/// (or `None` if unset) and returns the resolved allowlist. Split
/// out so unit tests do not need to mutate process-wide env state.
pub(crate) fn git_binary_allowlist_from_raw(raw: Option<&str>) -> Option<Vec<PathBuf>> {
    match raw {
        Some(s) if s.trim() == GIT_ALLOWLIST_BYPASS => None,
        Some(s) if !s.trim().is_empty() => Some(std::env::split_paths(s).collect()),
        _ => Some(default_git_allowlist()),
    }
}

/// Walk `$PATH` and return the first executable named `git` (or
/// `git.exe` on Windows). Returns `None` if no such entry exists; the
/// caller surfaces a typed [`IngestError::GitBinaryNotFound`].
pub(crate) fn resolve_git_on_path() -> Option<PathBuf> {
    let exe_name = if cfg!(windows) { "git.exe" } else { "git" };
    let path_var = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path_var) {
        let candidate = entry.join(exe_name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata().map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0).unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(p: &Path) -> bool {
    p.is_file()
}

/// Return true if `resolved` matches any allowlist entry. Both sides
/// are compared after attempting to canonicalise symlinks; an entry
/// that cannot be canonicalised is also matched lexically so a
/// non-existent allowlist entry does not silently become a hard no.
pub(crate) fn path_on_allowlist(resolved: &Path, allowlist: &[PathBuf]) -> bool {
    let canonical_resolved = resolved.canonicalize().unwrap_or_else(|_| resolved.to_path_buf());
    for entry in allowlist {
        if entry == resolved {
            return true;
        }
        if let Ok(canon) = entry.canonicalize() {
            if canon == canonical_resolved {
                return true;
            }
        }
    }
    false
}

/// Resolve the `git` binary on `$PATH`, refuse if it does not match
/// the operator-configured allowlist (see [`git_binary_allowlist`]).
/// Returns the resolved path so callers can hand it to subsequent
/// `Command::new` invocations and avoid TOCTOU drift between the
/// allowlist check and the eventual exec.
pub(crate) fn assert_git_path_allowed() -> Result<PathBuf, IngestError> {
    let resolved = resolve_git_on_path().ok_or(IngestError::GitBinaryNotFound)?;
    match git_binary_allowlist() {
        None => Ok(resolved),
        Some(allowlist) if path_on_allowlist(&resolved, &allowlist) => Ok(resolved),
        Some(allowlist) => Err(IngestError::GitBinaryNotAllowed { resolved, allowlist }),
    }
}

/// Canonical GitHub API endpoint used to probe token scopes. Pulled out
/// as a constant so [`validate_token_scopes_at`] can be exercised by
/// hermetic tests pointing at a stubbed server.
const GITHUB_USER_PROBE_URL: &str = "https://api.github.com/user";

/// Query the GitHub API to check whether `token` carries any write
/// scope. Used by `ingest_git` to refuse write-capable credentials
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
    fn parse_git_version_handles_plain_triple() {
        assert_eq!(parse_git_version("git version 2.45.1"), Some((2, 45, 1)));
    }

    #[test]
    fn parse_git_version_handles_apple_git_suffix() {
        assert_eq!(parse_git_version("git version 2.39.5 (Apple Git-154)"), Some((2, 39, 5)));
    }

    #[test]
    fn parse_git_version_handles_windows_extra_segment() {
        assert_eq!(parse_git_version("git version 2.46.0.windows.1"), Some((2, 46, 0)));
    }

    #[test]
    fn parse_git_version_handles_missing_patch() {
        assert_eq!(parse_git_version("git version 2.45"), Some((2, 45, 0)));
    }

    #[test]
    fn parse_git_version_handles_patch_with_non_digit_tail() {
        // Some downstream builds tag the patch segment with `-rc1` or
        // `~ppa1`. Strip the suffix rather than refuse.
        assert_eq!(parse_git_version("git version 2.45.1-rc1"), Some((2, 45, 1)));
    }

    #[test]
    fn parse_git_version_rejects_missing_prefix() {
        assert_eq!(parse_git_version("garbage 2.45.1"), None);
    }

    #[test]
    fn parse_git_version_rejects_non_numeric_major() {
        assert_eq!(parse_git_version("git version vNext"), None);
    }

    #[test]
    fn version_satisfies_minimum_accepts_floor_exact() {
        assert!(version_satisfies_minimum(MINIMUM_GIT_VERSION));
    }

    #[test]
    fn version_satisfies_minimum_accepts_higher_patch() {
        let (mj, mn, p) = MINIMUM_GIT_VERSION;
        assert!(version_satisfies_minimum((mj, mn, p + 1)));
    }

    #[test]
    fn version_satisfies_minimum_rejects_lower_minor() {
        let (mj, mn, _) = MINIMUM_GIT_VERSION;
        assert!(!version_satisfies_minimum((mj, mn.saturating_sub(1), 999)));
    }

    #[test]
    fn version_satisfies_minimum_rejects_below_floor_patch() {
        // CVE-2024-32002 was fixed in 2.45.1, so a 2.45.0 host must be
        // refused even though the minor matches.
        assert!(!version_satisfies_minimum((2, 45, 0)));
    }

    #[test]
    fn normalise_remote_strips_dotgit_and_trailing_slash() {
        assert_eq!(
            normalise_remote("https://github.com/org/repo.git"),
            normalise_remote("https://github.com/org/repo/")
        );
    }

    mod bearer_token_env {
        use super::*;
        use std::ffi::OsStr;

        fn collect_args(cmd: &Command) -> Vec<String> {
            cmd.as_std().get_args().map(|a| a.to_string_lossy().into_owned()).collect()
        }

        fn collect_envs(cmd: &Command) -> std::collections::HashMap<String, Option<String>> {
            cmd.as_std()
                .get_envs()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.map(|x: &OsStr| x.to_string_lossy().into_owned()),
                    )
                })
                .collect()
        }

        const SECRET: &str = "ghp_test_secret_token_must_not_appear_in_argv_0123456789";

        #[test]
        fn token_lives_in_env_not_argv() {
            let mut cmd = Command::new("git");
            cmd.arg("clone").arg("https://example.com/x.git");
            apply_bearer_token_env(&mut cmd, SECRET);

            let args = collect_args(&cmd);
            for a in &args {
                assert!(
                    !a.contains(SECRET),
                    "bearer token leaked into argv arg `{a}` (full argv: {args:?})"
                );
                assert!(
                    !a.contains("http.extraheader"),
                    "extraheader config string leaked into argv arg `{a}`"
                );
            }

            let envs = collect_envs(&cmd);
            assert_eq!(envs.get("GIT_CONFIG_COUNT").and_then(|v| v.as_deref()), Some("2"));
            assert_eq!(
                envs.get("GIT_CONFIG_KEY_0").and_then(|v| v.as_deref()),
                Some("credential.helper")
            );
            assert_eq!(envs.get("GIT_CONFIG_VALUE_0").and_then(|v| v.as_deref()), Some(""));
            assert_eq!(
                envs.get("GIT_CONFIG_KEY_1").and_then(|v| v.as_deref()),
                Some("http.extraheader")
            );
            let bearer = envs
                .get("GIT_CONFIG_VALUE_1")
                .and_then(|v| v.as_deref())
                .expect("bearer env var must be set");
            assert_eq!(bearer, &format!("Authorization: Bearer {SECRET}"));
        }

        #[test]
        fn helper_does_not_clobber_existing_unrelated_args() {
            let mut cmd = Command::new("git");
            cmd.arg("-C").arg("/tmp/x").arg("fetch").arg("origin").arg("HEAD");
            apply_bearer_token_env(&mut cmd, SECRET);
            let args = collect_args(&cmd);
            assert_eq!(args, vec!["-C", "/tmp/x", "fetch", "origin", "HEAD"]);
        }

        #[tokio::test]
        async fn git_honours_env_driven_extraheader() {
            // End-to-end against the real host git: stand up a tiny
            // HTTP listener that records the inbound `Authorization`
            // header, point `git ls-remote` at it through the env-
            // injected bearer, and assert the header arrived. Skips
            // when git is not on PATH (matches the other tests in
            // this mod).
            if !have_git() {
                eprintln!("skipping: git not on PATH");
                return;
            }
            use std::io::{Read, Write};
            use std::net::TcpListener;
            use std::sync::mpsc;

            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let (tx, rx) = mpsc::channel::<String>();
            let server = std::thread::spawn(move || {
                if let Ok((mut sock, _)) = listener.accept() {
                    let mut buf = [0u8; 4096];
                    let n = sock.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let _ = tx.send(req);
                    let _ = sock.write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                }
            });

            let mut cmd = Command::new("git");
            cmd.arg("ls-remote").arg(format!("http://127.0.0.1:{port}/repo.git"));
            apply_env(&mut cmd, None);
            apply_bearer_token_env(&mut cmd, SECRET);
            let _ = cmd.output().await;

            let req = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("request");
            let _ = server.join();

            let lower = req.to_lowercase();
            assert!(
                lower.contains("authorization: bearer ") && req.contains(SECRET),
                "expected `Authorization: Bearer {SECRET}` header in request, got: {req}"
            );
        }
    }

    mod allowlist {
        use super::*;

        #[test]
        fn default_allowlist_contains_platform_typical_paths() {
            let defaults = default_git_allowlist();
            assert!(!defaults.is_empty(), "default allowlist must be non-empty");
            if cfg!(target_os = "macos") {
                assert!(defaults.contains(&PathBuf::from("/usr/bin/git")));
                assert!(defaults.contains(&PathBuf::from("/opt/homebrew/bin/git")));
            } else if cfg!(target_os = "windows") {
                assert!(defaults.iter().any(|p| p.ends_with("git.exe")));
            } else {
                assert!(defaults.contains(&PathBuf::from("/usr/bin/git")));
            }
        }

        #[test]
        fn bypass_sentinel_disables_enforcement() {
            assert!(git_binary_allowlist_from_raw(Some("*")).is_none());
            assert!(git_binary_allowlist_from_raw(Some("  *  ")).is_none());
        }

        #[test]
        fn unset_env_yields_default_allowlist() {
            let resolved = git_binary_allowlist_from_raw(None).expect("default");
            assert_eq!(resolved, default_git_allowlist());
        }

        #[test]
        fn empty_env_yields_default_allowlist() {
            let resolved = git_binary_allowlist_from_raw(Some("")).expect("default");
            assert_eq!(resolved, default_git_allowlist());
            let resolved_ws = git_binary_allowlist_from_raw(Some("   ")).expect("default");
            assert_eq!(resolved_ws, default_git_allowlist());
        }

        #[test]
        fn explicit_env_overrides_default() {
            let sep = if cfg!(windows) { ";" } else { ":" };
            let raw = format!("/opt/custom/git{sep}/srv/bin/git");
            let resolved = git_binary_allowlist_from_raw(Some(&raw)).expect("list");
            assert_eq!(
                resolved,
                vec![PathBuf::from("/opt/custom/git"), PathBuf::from("/srv/bin/git")]
            );
        }

        #[test]
        fn path_on_allowlist_matches_lexical_entry() {
            let allowlist = vec![PathBuf::from("/usr/bin/git"), PathBuf::from("/opt/other/git")];
            assert!(path_on_allowlist(Path::new("/usr/bin/git"), &allowlist));
        }

        #[test]
        fn path_on_allowlist_rejects_unlisted_entry() {
            let allowlist = vec![PathBuf::from("/usr/bin/git")];
            assert!(!path_on_allowlist(Path::new("/tmp/evil/git"), &allowlist));
        }

        #[test]
        fn path_on_allowlist_matches_after_symlink_canonicalisation() {
            // Build a tempdir layout where the allowlist names a
            // symlink and the resolved path is the symlink target.
            // Both should canonicalise to the same file.
            let tmp = tempfile::tempdir().expect("tempdir");
            let real = tmp.path().join("real-git");
            std::fs::write(&real, b"#!/bin/sh\nexit 0\n").expect("seed real");
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                let link = tmp.path().join("link-git");
                symlink(&real, &link).expect("symlink");
                let allowlist = vec![link.clone()];
                assert!(path_on_allowlist(&real, &allowlist));
                let allowlist_real = vec![real.clone()];
                assert!(path_on_allowlist(&link, &allowlist_real));
            }
            #[cfg(not(unix))]
            {
                let allowlist = vec![real.clone()];
                assert!(path_on_allowlist(&real, &allowlist));
            }
        }

        #[test]
        fn assert_git_path_allowed_accepts_listed_resolved_path() {
            // Drive the public surface without env mutation: rely on
            // the dev / CI host having git at a default vendor path.
            // CI runners on macOS / Linux both install git at
            // /usr/bin/git which the default allowlist covers.
            let Some(resolved) = resolve_git_on_path() else {
                eprintln!("skipping: git not on PATH");
                return;
            };
            let allowlist = git_binary_allowlist_from_raw(None).expect("default list");
            // If the resolved binary is not on the default list this
            // is a packaging signal, not a test bug; surface it
            // loudly under CI but skip otherwise so a homebrew /
            // pyenv-style dev box does not red the suite.
            if !path_on_allowlist(&resolved, &allowlist) {
                if std::env::var("CI").is_ok() {
                    panic!(
                        "CI host's `{}` is not on the default allowlist {allowlist:?}; \
                         widen `default_git_allowlist`",
                        resolved.display()
                    );
                }
                eprintln!(
                    "skipping: resolved git `{}` not on default allowlist {:?}",
                    resolved.display(),
                    allowlist
                );
                return;
            }
            assert!(path_on_allowlist(&resolved, &allowlist));
        }

        #[test]
        fn assert_git_path_allowed_refuses_when_resolved_path_is_off_list() {
            // Pure surface test that does not touch env: exercise the
            // refusal branch via the explicit helpers.
            let resolved = PathBuf::from("/tmp/attacker/git");
            let allowlist = vec![PathBuf::from("/usr/bin/git")];
            assert!(!path_on_allowlist(&resolved, &allowlist));
        }
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
