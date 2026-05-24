use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nyctos_types::project::{
    ProjectAuthAssertion, ProjectAuthAssertionKind, ProjectAuthHeaderRef, ProjectAuthMode,
    ProjectAuthProfile, ProjectOtpSourceKind,
};
use regex::Regex;
use reqwest::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use tokio::sync::Mutex;

const DEFAULT_SESSION_TTL_SECONDS: u64 = 15 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSessionStatus {
    Acquired,
    Reused,
    Skipped,
    Failed,
}

impl AuthSessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthSessionStatus::Acquired => "acquired",
            AuthSessionStatus::Reused => "reused",
            AuthSessionStatus::Skipped => "skipped",
            AuthSessionStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthAssertionStatus {
    NotConfigured,
    Passed,
    Skipped,
    Failed,
}

impl AuthAssertionStatus {
    fn as_str(&self) -> &'static str {
        match self {
            AuthAssertionStatus::NotConfigured => "not_configured",
            AuthAssertionStatus::Passed => "passed",
            AuthAssertionStatus::Skipped => "skipped",
            AuthAssertionStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuthAssertionEvidence {
    pub status: AuthAssertionStatus,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub role: String,
    pub acquired_by: String,
    pub status: AuthSessionStatus,
    pub headers: BTreeMap<String, String>,
    pub storage_state_path: Option<PathBuf>,
    pub base_origin: String,
    pub expires_at_ms: Option<i64>,
    pub assertion: AuthAssertionEvidence,
    pub artifact_paths: Vec<PathBuf>,
    pub failure_reason: Option<String>,
    pub skip_reason: Option<String>,
    acquired_at_ms: i64,
    cookie_names: BTreeSet<String>,
}

impl AuthSession {
    pub fn redacted_evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "role": self.role,
            "status": self.status.as_str(),
            "acquired_by": self.acquired_by,
            "base_origin": self.base_origin,
            "expires_at_ms": self.expires_at_ms,
            "assertion": {
                "status": self.assertion.status.as_str(),
                "checks": self.assertion.checks,
            },
            "headers": self.headers.keys().cloned().collect::<Vec<_>>(),
            "cookies": {
                "names": self.cookie_names.iter().cloned().collect::<Vec<_>>(),
                "values": "[REDACTED]",
            },
            "storage_state_path": self.storage_state_path.as_ref().map(|p| p.display().to_string()),
            "artifact_paths": self.artifact_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "failure_reason": self.failure_reason,
            "skip_reason": self.skip_reason,
        })
    }

    fn cache_valid(&self, now_ms: i64, ttl_seconds: u64) -> bool {
        if ttl_seconds == 0 || !matches!(self.status, AuthSessionStatus::Acquired) {
            return false;
        }
        if now_ms.saturating_sub(self.acquired_at_ms) > (ttl_seconds as i64).saturating_mul(1000) {
            return false;
        }
        self.expires_at_ms.is_none_or(|expires| expires > now_ms)
    }
}

#[derive(Debug, Clone)]
pub struct AuthSessionResult {
    pub role: String,
    pub status: AuthSessionStatus,
    pub session: Option<AuthSession>,
    pub reason: Option<String>,
    pub evidence: serde_json::Value,
}

impl AuthSessionResult {
    pub fn available_session(&self) -> Option<&AuthSession> {
        match self.status {
            AuthSessionStatus::Acquired | AuthSessionStatus::Reused => self.session.as_ref(),
            AuthSessionStatus::Skipped | AuthSessionStatus::Failed => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthSessionOptions {
    pub browser_checks_enabled: bool,
    pub workspace_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct AuthSessionManager {
    cache: Arc<Mutex<AuthSessionCache>>,
}

#[derive(Debug, Default)]
struct AuthSessionCache {
    sessions: BTreeMap<String, AuthSession>,
}

impl AuthSessionManager {
    pub async fn acquire_session(
        &self,
        role: &str,
        profiles: &[ProjectAuthProfile],
        target_url: &str,
        artifact_dir: &Path,
        options: &AuthSessionOptions,
    ) -> AuthSessionResult {
        let normalized_role = if role.trim().is_empty() { "anonymous" } else { role.trim() };
        let base_origin = match target_origin(target_url) {
            Ok(origin) => origin,
            Err(reason) => {
                return result_without_session(
                    normalized_role,
                    AuthSessionStatus::Failed,
                    "unknown",
                    target_url,
                    reason,
                );
            }
        };
        if normalized_role == "anonymous" {
            let session = AuthSession {
                role: normalized_role.to_string(),
                acquired_by: "anonymous".to_string(),
                status: AuthSessionStatus::Acquired,
                headers: BTreeMap::new(),
                storage_state_path: None,
                base_origin,
                expires_at_ms: None,
                assertion: AuthAssertionEvidence {
                    status: AuthAssertionStatus::NotConfigured,
                    checks: Vec::new(),
                },
                artifact_paths: Vec::new(),
                failure_reason: None,
                skip_reason: None,
                acquired_at_ms: nyctos_core::now_epoch_ms(),
                cookie_names: BTreeSet::new(),
            };
            return result_from_session(AuthSessionStatus::Acquired, session, None);
        }

        let Some(profile) = profiles.iter().find(|p| p.role == normalized_role) else {
            return result_without_session(
                normalized_role,
                AuthSessionStatus::Failed,
                "missing_profile",
                &base_origin,
                format!("auth profile missing for role `{normalized_role}`"),
            );
        };

        let ttl = profile.session_cache_ttl_seconds.unwrap_or(DEFAULT_SESSION_TTL_SECONDS);
        let cache_key = format!("{base_origin}\n{normalized_role}");
        let now_ms = nyctos_core::now_epoch_ms();
        if let Some(cached) = self.cache.lock().await.sessions.get(&cache_key).cloned() {
            if cached.cache_valid(now_ms, ttl) {
                let mut session = cached;
                session.status = AuthSessionStatus::Reused;
                return result_from_session(AuthSessionStatus::Reused, session, None);
            }
        }

        let acquired = acquire_uncached_session(
            normalized_role,
            profile,
            target_url,
            &base_origin,
            artifact_dir,
            options,
        )
        .await;

        if let Some(session) = acquired.available_session().cloned() {
            self.cache.lock().await.sessions.insert(cache_key, session);
        }
        acquired
    }
}

async fn acquire_uncached_session(
    role: &str,
    profile: &ProjectAuthProfile,
    target_url: &str,
    base_origin: &str,
    artifact_dir: &Path,
    options: &AuthSessionOptions,
) -> AuthSessionResult {
    let mode = profile.mode;
    let mut session = AuthSession {
        role: role.to_string(),
        acquired_by: acquired_by(mode).to_string(),
        status: AuthSessionStatus::Acquired,
        headers: BTreeMap::new(),
        storage_state_path: None,
        base_origin: base_origin.to_string(),
        expires_at_ms: None,
        assertion: AuthAssertionEvidence {
            status: AuthAssertionStatus::NotConfigured,
            checks: Vec::new(),
        },
        artifact_paths: Vec::new(),
        failure_reason: None,
        skip_reason: None,
        acquired_at_ms: nyctos_core::now_epoch_ms(),
        cookie_names: BTreeSet::new(),
    };

    let acquisition = match mode {
        ProjectAuthMode::Anonymous => Ok(()),
        ProjectAuthMode::HeaderInjection => acquire_header_injection(profile, &mut session),
        ProjectAuthMode::SessionImport => {
            acquire_session_import(profile, &mut session, target_url, artifact_dir)
        }
        ProjectAuthMode::BrowserLogin => Err(skip_reason(if !options.browser_checks_enabled {
            "browser login skipped: browser verification disabled by run config"
        } else if !browser_runtime_available() {
            "browser login skipped: Playwright runtime unavailable"
        } else {
            "browser login skipped: browser session capture is not wired in this pass"
        })),
        ProjectAuthMode::ManualSso => Err(skip_reason(if !options.browser_checks_enabled {
            "manual SSO skipped: browser verification disabled by run config"
        } else if !browser_runtime_available() {
            "manual SSO skipped: Playwright runtime unavailable"
        } else {
            "manual SSO skipped: interactive browser capture is not wired in this pass"
        })),
        ProjectAuthMode::OtpEmailManual => Err(skip_reason(
            "manual email OTP skipped: interactive OTP entry is not available in this run",
        )),
        ProjectAuthMode::OtpEmailMailbox => {
            match mailbox_otp_readiness(profile).await {
                Ok(Some(_redacted)) => Err(skip_reason(
                    "email OTP mailbox source is reachable, but browser OTP login capture is not wired in this pass",
                )),
                Ok(None) => Err(skip_reason(
                    "email OTP mailbox skipped: no matching OTP message was found",
                )),
                Err(reason) => Err(failure_reason(reason)),
            }
        }
        ProjectAuthMode::AiAuto => acquire_ai_auto(profile, &mut session, target_url, options).await,
        ProjectAuthMode::OidcDevice => Err(skip_reason(
            "OIDC device auth skipped: device-flow session capture is not implemented in this pass",
        )),
        ProjectAuthMode::CustomCommand => Err(skip_reason(
            "custom auth command skipped: command execution is disabled unless explicitly wired by run config",
        )),
    };

    if let Err(reason) = acquisition {
        let status =
            if reason.skipped { AuthSessionStatus::Skipped } else { AuthSessionStatus::Failed };
        session.status = status;
        if reason.skipped {
            session.skip_reason = Some(reason.message.clone());
        } else {
            session.failure_reason = Some(reason.message.clone());
        }
        return result_from_session(status, session, Some(reason.message));
    }

    match evaluate_assertions(profile, &session, target_url).await {
        Ok(assertion) => {
            let status = match assertion.status {
                AuthAssertionStatus::Failed => AuthSessionStatus::Failed,
                AuthAssertionStatus::Skipped => AuthSessionStatus::Skipped,
                AuthAssertionStatus::NotConfigured | AuthAssertionStatus::Passed => {
                    AuthSessionStatus::Acquired
                }
            };
            session.assertion = assertion;
            session.status = status;
            if status == AuthSessionStatus::Acquired {
                result_from_session(AuthSessionStatus::Acquired, session, None)
            } else {
                let reason = format!(
                    "auth profile `{role}` post-login assertion {}",
                    session.assertion.status.as_str()
                );
                if status == AuthSessionStatus::Skipped {
                    session.skip_reason = Some(reason.clone());
                } else {
                    session.failure_reason = Some(reason.clone());
                }
                result_from_session(status, session, Some(reason))
            }
        }
        Err(reason) => {
            session.status = AuthSessionStatus::Failed;
            session.failure_reason = Some(reason.clone());
            result_from_session(AuthSessionStatus::Failed, session, Some(reason))
        }
    }
}

fn acquire_header_injection(
    profile: &ProjectAuthProfile,
    session: &mut AuthSession,
) -> Result<(), AcquisitionError> {
    let mut resolved_any = false;
    if let Some(env) = &profile.bearer_token_env {
        let token = resolve_env(env, &profile.role)?;
        session.headers.insert("Authorization".to_string(), format!("Bearer {token}"));
        resolved_any = true;
    }
    if let Some(env) = &profile.cookie_env {
        let cookie = resolve_env(env, &profile.role)?;
        session.cookie_names.extend(cookie_names_from_header(&cookie));
        session.headers.insert("Cookie".to_string(), cookie);
        resolved_any = true;
    }
    for header in &profile.headers {
        resolve_header_ref(header, &profile.role, &mut session.headers)?;
        resolved_any = true;
    }
    if !resolved_any {
        return Err(failure_reason(format!(
            "auth profile `{}` has no header, bearer token, or cookie env refs",
            profile.role
        )));
    }
    Ok(())
}

async fn acquire_ai_auto(
    profile: &ProjectAuthProfile,
    session: &mut AuthSession,
    target_url: &str,
    options: &AuthSessionOptions,
) -> Result<(), AcquisitionError> {
    if profile.bearer_token_env.is_some()
        || profile.cookie_env.is_some()
        || !profile.headers.is_empty()
    {
        acquire_header_injection(profile, session)?;
        session.acquired_by = "ai_auto_header_injection".to_string();
        return Ok(());
    }

    let username = resolve_login_identifier(profile)?;
    let password_env = profile.password_env.as_deref().ok_or_else(|| {
        failure_reason(format!(
            "AI auto auth profile `{}` needs password_env to attempt login safely",
            profile.role
        ))
    })?;
    let password = resolve_env(password_env, &profile.role)?;

    let discovery = discover_auth_from_workspaces(&options.workspace_paths);
    if options.workspace_paths.is_empty() && profile.login_url.as_deref().is_none() {
        return Err(skip_reason("AI auto auth skipped: no workspace paths available to inspect"));
    }
    let mut login_paths = Vec::new();
    if let Some(login_url) = profile.login_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        login_paths.push(login_url.to_string());
    }
    login_paths.extend(discovery.login_paths);
    login_paths.extend(default_login_paths().into_iter().map(str::to_string));
    login_paths = dedupe_login_paths(login_paths);
    if login_paths.is_empty() {
        return Err(skip_reason(
            "AI auto auth skipped: no candidate login endpoint was discovered",
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| failure_reason(format!("AI auto auth could not build HTTP client: {e}")))?;
    let mut last_error = None;
    for path in login_paths.iter().take(12) {
        let login_url = match login_url_for_path(target_url, path) {
            Ok(url) => url,
            Err(err) => {
                last_error = Some(err.message);
                continue;
            }
        };
        match attempt_login_endpoint(&client, &login_url, &username, &password).await {
            Ok(Some(material)) => {
                session.headers.extend(material.headers);
                session.cookie_names.extend(material.cookie_names);
                session.expires_at_ms = material.expires_at_ms;
                session.assertion.checks.push(format!(
                    "ai_auto inspected {} file(s) and used `{}`",
                    discovery.files_inspected,
                    safe_url_path(&login_url)
                ));
                return Ok(());
            }
            Ok(None) => {
                last_error = Some(format!(
                    "`{}` did not return a cookie or bearer token",
                    safe_url_path(&login_url)
                ));
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    Err(failure_reason(format!(
        "AI auto auth could not obtain a session from {} candidate endpoint(s){}",
        login_paths.len().min(12),
        last_error.map(|e| format!("; last result: {e}")).unwrap_or_default()
    )))
}

fn resolve_login_identifier(profile: &ProjectAuthProfile) -> Result<String, AcquisitionError> {
    if let Some(env) = profile.username_env.as_deref().or(profile.login_email_env.as_deref()) {
        return resolve_env(env, &profile.role);
    }
    profile
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            failure_reason(format!(
                "AI auto auth profile `{}` needs username_env, login_email_env, or username",
                profile.role
            ))
        })
}

#[derive(Debug, Default)]
struct AuthAutoDiscovery {
    login_paths: Vec<String>,
    files_inspected: usize,
}

fn discover_auth_from_workspaces(workspace_paths: &[PathBuf]) -> AuthAutoDiscovery {
    let mut discovery = AuthAutoDiscovery::default();
    let path_re =
        Regex::new(r#"(?i)["'`](/[^"'`\s]*?(?:login|signin|sign-in|session|auth)[^"'`\s]*)["'`]"#)
            .expect("auth path regex");
    for root in workspace_paths {
        discover_auth_paths_in_root(root, &path_re, &mut discovery);
    }
    discovery.login_paths = dedupe_login_paths(discovery.login_paths);
    discovery
}

fn discover_auth_paths_in_root(root: &Path, path_re: &Regex, discovery: &mut AuthAutoDiscovery) {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((path, depth)) = stack.pop() {
        if discovery.files_inspected >= 1_000 || depth > 8 {
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if should_skip_auth_scan_dir(&path) {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                stack.push((entry.path(), depth + 1));
            }
            continue;
        }
        if !meta.is_file()
            || meta.len() > 256 * 1024
            || !path.extension().and_then(|e| e.to_str()).is_some_and(is_auth_scan_extension)
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        discovery.files_inspected += 1;
        for cap in path_re.captures_iter(&text) {
            let Some(path) = cap.get(1).map(|m| m.as_str()) else {
                continue;
            };
            if path_is_login_candidate(path) {
                discovery.login_paths.push(path.to_string());
            }
        }
    }
}

fn should_skip_auth_scan_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    matches!(
        name,
        ".git" | "node_modules" | "target" | "dist" | "build" | ".next" | "coverage" | "vendor"
    )
}

fn is_auth_scan_extension(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "js" | "jsx"
            | "ts"
            | "tsx"
            | "mjs"
            | "cjs"
            | "rs"
            | "py"
            | "rb"
            | "go"
            | "php"
            | "java"
            | "kt"
            | "cs"
            | "html"
            | "vue"
            | "svelte"
    )
}

fn path_is_login_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("login")
        || lower.contains("signin")
        || lower.contains("sign-in")
        || lower.contains("/session")
        || lower.contains("/auth")
}

fn dedupe_login_paths(paths: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for path in paths {
        let trimmed = path.trim();
        if trimmed.is_empty() || trimmed.contains("..") || trimmed.contains('{') {
            continue;
        }
        let normalized = trimmed.trim_end_matches('/').to_string();
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out.sort_by_key(|p| {
        let lower = p.to_ascii_lowercase();
        (!lower.contains("login") && !lower.contains("signin"), !lower.contains("/api/"), p.len())
    });
    out
}

fn default_login_paths() -> Vec<&'static str> {
    vec![
        "/api/auth/login",
        "/api/login",
        "/auth/login",
        "/login",
        "/api/session",
        "/session",
        "/sessions",
    ]
}

fn login_url_for_path(target_url: &str, path: &str) -> Result<String, AcquisitionError> {
    let target = reqwest::Url::parse(target_url)
        .map_err(|_| failure_reason("AI auto auth target URL is invalid"))?;
    let url = if path.starts_with("http://") || path.starts_with("https://") {
        reqwest::Url::parse(path)
            .map_err(|_| failure_reason("AI auto auth discovered invalid login URL"))?
    } else if path.starts_with('/') {
        target
            .join(path)
            .map_err(|_| failure_reason("AI auto auth could not resolve login path"))?
    } else {
        target
            .join(&format!("/{path}"))
            .map_err(|_| failure_reason("AI auto auth could not resolve login path"))?
    };
    if !same_origin(&target, &url) {
        return Err(failure_reason("AI auto auth refused login URL outside target origin"));
    }
    Ok(url.to_string())
}

fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str().map(str::to_ascii_lowercase) == b.host_str().map(str::to_ascii_lowercase)
        && a.port_or_known_default() == b.port_or_known_default()
}

async fn attempt_login_endpoint(
    client: &reqwest::Client,
    login_url: &str,
    username: &str,
    password: &str,
) -> Result<Option<ImportedSessionMaterial>, String> {
    let json_payloads = [
        serde_json::json!({ "email": username, "password": password }),
        serde_json::json!({ "username": username, "password": password }),
        serde_json::json!({ "login": username, "password": password }),
    ];
    for payload in json_payloads {
        let response = client
            .post(login_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("{} request failed: {e}", safe_url_path(login_url)))?;
        if let Some(material) = material_from_login_response(response).await? {
            return Ok(Some(material));
        }
    }

    for user_field in ["email", "username", "login"] {
        let form = form_body(&[(user_field, username), ("password", password)]);
        let response = client
            .post(login_url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|e| format!("{} form request failed: {e}", safe_url_path(login_url)))?;
        if let Some(material) = material_from_login_response(response).await? {
            return Ok(Some(material));
        }
    }
    Ok(None)
}

fn form_body(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(name, value)| format!("{}={}", form_encode(name), form_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn form_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

async fn material_from_login_response(
    response: reqwest::Response,
) -> Result<Option<ImportedSessionMaterial>, String> {
    let status = response.status();
    if !status.is_success() && !status.is_redirection() {
        return Ok(None);
    }
    let mut headers = BTreeMap::new();
    let mut cookie_names = BTreeSet::new();
    let cookie_pairs = cookie_pairs_from_set_cookie(response.headers());
    if !cookie_pairs.is_empty() {
        cookie_names.extend(
            cookie_pairs
                .iter()
                .filter_map(|pair| pair.split_once('=').map(|(name, _)| name.trim().to_string())),
        );
        headers.insert("Cookie".to_string(), cookie_pairs.join("; "));
    }
    let body = response.text().await.unwrap_or_default();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(token) = find_bearer_token_in_json(&json) {
            headers.insert("Authorization".to_string(), format!("Bearer {token}"));
        }
    }
    if headers.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ImportedSessionMaterial { headers, cookie_names, expires_at_ms: None }))
    }
}

fn cookie_pairs_from_set_cookie(headers: &reqwest::header::HeaderMap) -> Vec<String> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|raw| raw.split(';').next())
        .map(str::trim)
        .filter(|pair| pair.contains('='))
        .map(str::to_string)
        .collect()
}

fn find_bearer_token_in_json(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "token" | "access_token" | "accesstoken" | "bearer_token" | "jwt" | "idtoken"
                ) {
                    if let Some(token) = value.as_str().filter(|s| s.len() >= 8) {
                        return Some(token.to_string());
                    }
                }
                if let Some(token) = find_bearer_token_in_json(value) {
                    return Some(token);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().find_map(find_bearer_token_in_json),
        _ => None,
    }
}

fn safe_url_path(url: &str) -> String {
    reqwest::Url::parse(url).map(|url| url.path().to_string()).unwrap_or_else(|_| url.to_string())
}

fn resolve_header_ref(
    header: &ProjectAuthHeaderRef,
    role: &str,
    headers: &mut BTreeMap<String, String>,
) -> Result<(), AcquisitionError> {
    let name = HeaderName::from_bytes(header.name.as_bytes())
        .map_err(|_| failure_reason(format!("auth profile `{role}` has invalid header name")))?;
    let Some(env) = &header.value_env else {
        if header.value_secret_ref.is_some() {
            return Err(failure_reason(format!(
                "auth profile `{role}` header `{}` uses an unresolved secret ref",
                header.name
            )));
        }
        return Ok(());
    };
    let value = resolve_env(env, role)?;
    HeaderValue::from_str(&value)
        .map_err(|_| failure_reason(format!("auth profile `{role}` has invalid header value")))?;
    headers.insert(name.as_str().to_string(), value);
    Ok(())
}

fn acquire_session_import(
    profile: &ProjectAuthProfile,
    session: &mut AuthSession,
    target_url: &str,
    artifact_dir: &Path,
) -> Result<(), AcquisitionError> {
    let raw_path = profile.session_import_path.as_deref().ok_or_else(|| {
        failure_reason(format!("auth profile `{}` missing session_import_path", profile.role))
    })?;
    let path = normalize_session_import_path(raw_path).map_err(failure_reason)?;
    let bytes = std::fs::read(&path).map_err(|_| {
        failure_reason(format!(
            "auth profile `{}` could not read configured session import path",
            profile.role
        ))
    })?;

    if let Ok(storage) = serde_json::from_slice::<PlaywrightStorageState>(&bytes) {
        let imported = session_from_playwright_storage(&storage, target_url)?;
        session.headers.extend(imported.headers);
        session.cookie_names.extend(imported.cookie_names);
        session.expires_at_ms = imported.expires_at_ms;
        let artifact =
            persist_session_artifact(artifact_dir, &profile.role, "storage-state.json", &bytes)?;
        session.storage_state_path = Some(artifact.clone());
        session.artifact_paths.push(artifact);
        return Ok(());
    }

    let text = std::str::from_utf8(&bytes).map_err(|_| {
        failure_reason(format!(
            "auth profile `{}` session import is neither Playwright storageState JSON nor a UTF-8 cookie jar",
            profile.role
        ))
    })?;
    let imported = session_from_cookie_jar(text, target_url)?;
    session.headers.extend(imported.headers);
    session.cookie_names.extend(imported.cookie_names);
    session.expires_at_ms = imported.expires_at_ms;
    let artifact = persist_session_artifact(artifact_dir, &profile.role, "cookie-jar.txt", &bytes)?;
    session.artifact_paths.push(artifact);
    Ok(())
}

#[derive(Debug)]
struct ImportedSessionMaterial {
    headers: BTreeMap<String, String>,
    cookie_names: BTreeSet<String>,
    expires_at_ms: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct PlaywrightStorageState {
    #[serde(default)]
    cookies: Vec<PlaywrightCookie>,
}

#[derive(Debug, Deserialize)]
struct PlaywrightCookie {
    name: String,
    value: String,
    domain: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    expires: f64,
    #[serde(default)]
    secure: bool,
}

fn session_from_playwright_storage(
    storage: &PlaywrightStorageState,
    target_url: &str,
) -> Result<ImportedSessionMaterial, AcquisitionError> {
    let url = reqwest::Url::parse(target_url)
        .map_err(|_| failure_reason("session import target URL is invalid"))?;
    let host = url.host_str().unwrap_or_default();
    let path = url.path();
    let now_seconds = nyctos_core::now_epoch_ms() as f64 / 1000.0;
    let mut pairs = Vec::new();
    let mut names = BTreeSet::new();
    let mut expires_at_ms: Option<i64> = None;
    for cookie in &storage.cookies {
        if cookie.secure && url.scheme() != "https" {
            continue;
        }
        if cookie.expires > 0.0 && cookie.expires <= now_seconds {
            continue;
        }
        if !cookie_domain_matches(host, &cookie.domain) {
            continue;
        }
        let cookie_path = if cookie.path.is_empty() { "/" } else { cookie.path.as_str() };
        if !path.starts_with(cookie_path) {
            continue;
        }
        pairs.push(format!("{}={}", cookie.name, cookie.value));
        names.insert(cookie.name.clone());
        if cookie.expires > 0.0 {
            let ms = (cookie.expires * 1000.0) as i64;
            expires_at_ms = Some(expires_at_ms.map_or(ms, |current| current.min(ms)));
        }
    }
    if pairs.is_empty() {
        return Err(failure_reason("session import contained no cookies for target origin"));
    }
    Ok(ImportedSessionMaterial {
        headers: BTreeMap::from([("Cookie".to_string(), pairs.join("; "))]),
        cookie_names: names,
        expires_at_ms,
    })
}

fn session_from_cookie_jar(
    text: &str,
    target_url: &str,
) -> Result<ImportedSessionMaterial, AcquisitionError> {
    let url = reqwest::Url::parse(target_url)
        .map_err(|_| failure_reason("cookie jar target URL is invalid"))?;
    let host = url.host_str().unwrap_or_default();
    let target_path = url.path();
    let now_seconds = nyctos_core::now_epoch_ms() / 1000;
    let mut pairs = Vec::new();
    let mut names = BTreeSet::new();
    let mut expires_at_ms: Option<i64> = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 7 {
            continue;
        }
        let domain = cols[0];
        let path = cols[2];
        let secure = cols[3].eq_ignore_ascii_case("TRUE");
        let expires = cols[4].parse::<i64>().unwrap_or(0);
        let name = cols[5];
        let value = cols[6];
        if secure && url.scheme() != "https" {
            continue;
        }
        if expires > 0 && expires <= now_seconds {
            continue;
        }
        if !cookie_domain_matches(host, domain) || !target_path.starts_with(path) {
            continue;
        }
        pairs.push(format!("{name}={value}"));
        names.insert(name.to_string());
        if expires > 0 {
            let ms = expires.saturating_mul(1000);
            expires_at_ms = Some(expires_at_ms.map_or(ms, |current| current.min(ms)));
        }
    }
    if pairs.is_empty() {
        return Err(failure_reason("cookie jar contained no cookies for target origin"));
    }
    Ok(ImportedSessionMaterial {
        headers: BTreeMap::from([("Cookie".to_string(), pairs.join("; "))]),
        cookie_names: names,
        expires_at_ms,
    })
}

fn cookie_domain_matches(host: &str, domain: &str) -> bool {
    let host = host.trim_matches('.').to_ascii_lowercase();
    let domain = domain.trim_start_matches('.').trim_matches('.').to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

pub fn normalize_session_import_path(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("session import path is empty".to_string());
    }
    let path = Path::new(trimmed);
    if path.components().any(|component| matches!(component, Component::ParentDir)) {
        return Err("session import path must not contain `..` components".to_string());
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("could not resolve current directory: {e}"))?
            .join(path)
    };
    let canonical = std::fs::canonicalize(&absolute)
        .map_err(|_| "session import path does not exist".to_string())?;
    let meta = std::fs::metadata(&canonical)
        .map_err(|_| "session import path cannot be inspected".to_string())?;
    if !meta.is_file() {
        return Err("session import path must be a file".to_string());
    }
    Ok(canonical)
}

fn persist_session_artifact(
    artifact_dir: &Path,
    role: &str,
    suffix: &str,
    bytes: &[u8],
) -> Result<PathBuf, AcquisitionError> {
    std::fs::create_dir_all(artifact_dir)
        .map_err(|e| failure_reason(format!("could not create auth artifact dir: {e}")))?;
    let path = artifact_dir.join(format!("{}-{suffix}", safe_filename(role)));
    write_sensitive_file(&path, bytes)
        .map_err(|e| failure_reason(format!("could not persist auth session artifact: {e}")))?;
    Ok(path)
}

#[cfg(unix)]
fn write_sensitive_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()
}

#[cfg(not(unix))]
fn write_sensitive_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

async fn evaluate_assertions(
    profile: &ProjectAuthProfile,
    session: &AuthSession,
    target_url: &str,
) -> Result<AuthAssertionEvidence, String> {
    let mut assertions = profile.post_login_assertions.clone();
    if let Some(legacy) =
        profile.post_login_assertion.as_deref().map(str::trim).filter(|s| !s.is_empty())
    {
        assertions.push(ProjectAuthAssertion {
            kind: ProjectAuthAssertionKind::DomTextContains,
            value: Some(legacy.to_string()),
            status: None,
        });
    }
    if assertions.is_empty() {
        return Ok(AuthAssertionEvidence {
            status: AuthAssertionStatus::NotConfigured,
            checks: Vec::new(),
        });
    }

    let mut checks = Vec::new();
    let mut any_failed = false;
    let mut any_skipped = false;
    for assertion in assertions {
        match assertion.kind {
            ProjectAuthAssertionKind::CookieExists => {
                let Some(name) =
                    assertion.value.as_deref().map(str::trim).filter(|s| !s.is_empty())
                else {
                    checks.push("cookie_exists missing cookie name".to_string());
                    any_failed = true;
                    continue;
                };
                if session.cookie_names.contains(name)
                    || cookie_header_contains(&session.headers, name)
                {
                    checks.push(format!("cookie_exists `{name}` passed"));
                } else {
                    checks.push(format!("cookie_exists `{name}` failed"));
                    any_failed = true;
                }
            }
            ProjectAuthAssertionKind::HttpStatus => {
                let Some(expected) = assertion.status else {
                    checks.push("http_status missing status".to_string());
                    any_failed = true;
                    continue;
                };
                let actual = assertion_http_status(target_url, &session.headers).await?;
                if actual == expected {
                    checks.push(format!("http_status {expected} passed"));
                } else {
                    checks.push(format!("http_status expected {expected}, got {actual}"));
                    any_failed = true;
                }
            }
            ProjectAuthAssertionKind::UrlContains => {
                checks
                    .push("url_contains skipped: browser session capture is not wired".to_string());
                any_skipped = true;
            }
            ProjectAuthAssertionKind::DomTextContains => {
                checks.push(
                    "dom_text_contains skipped: browser session capture is not wired".to_string(),
                );
                any_skipped = true;
            }
        }
    }
    let status = if any_failed {
        AuthAssertionStatus::Failed
    } else if any_skipped {
        AuthAssertionStatus::Skipped
    } else {
        AuthAssertionStatus::Passed
    };
    Ok(AuthAssertionEvidence { status, checks })
}

async fn assertion_http_status(
    target_url: &str,
    headers: &BTreeMap<String, String>,
) -> Result<u16, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("post-login HTTP status assertion could not build client: {e}"))?;
    let mut builder = client.get(target_url);
    for (name, value) in headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "post-login HTTP status assertion has invalid header name".to_string())?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| "post-login HTTP status assertion has invalid header value".to_string())?;
        builder = builder.header(header_name, header_value);
    }
    let response = builder
        .send()
        .await
        .map_err(|e| format!("post-login HTTP status assertion failed: {e}"))?;
    Ok(response.status().as_u16())
}

fn cookie_header_contains(headers: &BTreeMap<String, String>, expected: &str) -> bool {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
        .is_some_and(|(_, value)| cookie_names_from_header(value).contains(expected))
}

fn cookie_names_from_header(value: &str) -> BTreeSet<String> {
    value
        .split(';')
        .filter_map(|part| part.trim().split_once('=').map(|(name, _)| name.trim().to_string()))
        .filter(|name| !name.is_empty())
        .collect()
}

async fn mailbox_otp_readiness(profile: &ProjectAuthProfile) -> Result<Option<String>, String> {
    let Some(source) = &profile.otp_source else {
        return Err(format!("auth profile `{}` missing otp_source", profile.role));
    };
    if source.kind != ProjectOtpSourceKind::Mailbox {
        return Err(format!("auth profile `{}` OTP source is not mailbox", profile.role));
    }
    let mailbox_url = source
        .mailbox_url
        .as_deref()
        .ok_or_else(|| format!("auth profile `{}` missing OTP mailbox URL", profile.role))?;
    let email_env = source
        .email_env
        .as_deref()
        .or(profile.login_email_env.as_deref())
        .ok_or_else(|| format!("auth profile `{}` missing OTP email env ref", profile.role))?;
    let recipient = resolve_env(email_env, &profile.role).map_err(|e| e.message)?;
    let otp = extract_latest_otp_from_mailbox(
        mailbox_url,
        &recipient,
        source.subject_contains.as_deref(),
        source.body_regex.as_deref(),
    )
    .await?;
    Ok(otp.map(|_| "[REDACTED]".to_string()))
}

pub async fn extract_latest_otp_from_mailbox(
    mailbox_url: &str,
    recipient: &str,
    subject_contains: Option<&str>,
    body_regex: Option<&str>,
) -> Result<Option<String>, String> {
    let base = reqwest::Url::parse(mailbox_url.trim())
        .map_err(|_| "OTP mailbox URL is invalid".to_string())?;
    if !is_local_mailbox_url(&base) {
        return Err("OTP mailbox URL must point at localhost or loopback".to_string());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("OTP mailbox client failed: {e}"))?;

    for endpoint in ["api/v2/messages", "api/v1/messages"] {
        let Ok(url) = base.join(endpoint) else {
            continue;
        };
        let Ok(response) = client.get(url).send().await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(value) = response.json::<serde_json::Value>().await else {
            continue;
        };
        if let Some(otp) =
            extract_otp_from_mailbox_json(&value, recipient, subject_contains, body_regex)
        {
            return Ok(Some(otp));
        }
        if endpoint == "api/v1/messages" {
            for id in message_ids(&value) {
                let Ok(message_url) = base.join(&format!("api/v1/message/{id}")) else {
                    continue;
                };
                let Ok(message_response) = client.get(message_url).send().await else {
                    continue;
                };
                if !message_response.status().is_success() {
                    continue;
                }
                let Ok(message) = message_response.json::<serde_json::Value>().await else {
                    continue;
                };
                if let Some(otp) =
                    extract_otp_from_mailbox_json(&message, recipient, subject_contains, body_regex)
                {
                    return Ok(Some(otp));
                }
            }
        }
    }
    Ok(None)
}

fn is_local_mailbox_url(url: &reqwest::Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1" | "[::1]"))
}

fn message_ids(value: &serde_json::Value) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(items) =
        value.get("messages").or_else(|| value.get("items")).and_then(|v| v.as_array())
    {
        for item in items {
            if let Some(id) = item
                .get("ID")
                .or_else(|| item.get("Id"))
                .or_else(|| item.get("id"))
                .and_then(|v| v.as_str())
            {
                ids.push(id.to_string());
            }
        }
    }
    ids
}

pub fn extract_otp_from_mailbox_json(
    value: &serde_json::Value,
    recipient: &str,
    subject_contains: Option<&str>,
    body_regex: Option<&str>,
) -> Option<String> {
    let items = value.get("items").or_else(|| value.get("messages")).and_then(|v| v.as_array());
    if let Some(items) = items {
        for item in items {
            if let Some(otp) =
                extract_otp_from_message_value(item, recipient, subject_contains, body_regex)
            {
                return Some(otp);
            }
        }
        return None;
    }
    extract_otp_from_message_value(value, recipient, subject_contains, body_regex)
}

fn extract_otp_from_message_value(
    value: &serde_json::Value,
    recipient: &str,
    subject_contains: Option<&str>,
    body_regex: Option<&str>,
) -> Option<String> {
    let haystack = collect_json_strings(value).join("\n");
    let lower_haystack = haystack.to_ascii_lowercase();
    if !recipient.trim().is_empty()
        && !lower_haystack.contains(&recipient.trim().to_ascii_lowercase())
    {
        return None;
    }
    if let Some(subject) = subject_contains.map(str::trim).filter(|s| !s.is_empty()) {
        if !lower_haystack.contains(&subject.to_ascii_lowercase()) {
            return None;
        }
    }
    let pattern = body_regex.unwrap_or(r"\b([0-9]{6,8})\b");
    let re = Regex::new(pattern).ok()?;
    let captures = re.captures(&haystack)?;
    captures.get(1).or_else(|| captures.get(0)).map(|m| m.as_str().to_string())
}

fn collect_json_strings(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_json_strings_into(value, &mut out);
    out
}

fn collect_json_strings_into(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_strings_into(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values() {
                collect_json_strings_into(value, out);
            }
        }
        _ => {}
    }
}

fn target_origin(url: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(url).map_err(|_| format!("target URL `{url}` is invalid"))?;
    let host = url.host_str().ok_or_else(|| format!("target URL `{url}` has no host"))?;
    let mut origin = format!("{}://{host}", url.scheme());
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn resolve_env(env: &str, role: &str) -> Result<String, AcquisitionError> {
    std::env::var(env)
        .map_err(|_| failure_reason(format!("auth profile `{role}` missing env `{env}`")))
}

fn acquired_by(mode: ProjectAuthMode) -> &'static str {
    match mode {
        ProjectAuthMode::Anonymous => "anonymous",
        ProjectAuthMode::HeaderInjection => "header_injection",
        ProjectAuthMode::BrowserLogin => "browser_login",
        ProjectAuthMode::ManualSso => "manual_sso",
        ProjectAuthMode::SessionImport => "session_import",
        ProjectAuthMode::OtpEmailManual => "otp_email_manual",
        ProjectAuthMode::OtpEmailMailbox => "otp_email_mailbox",
        ProjectAuthMode::AiAuto => "ai_auto",
        ProjectAuthMode::OidcDevice => "oidc_device",
        ProjectAuthMode::CustomCommand => "custom_command",
    }
}

fn browser_runtime_available() -> bool {
    std::process::Command::new("node")
        .args(["-e", "require.resolve('playwright')"])
        .output()
        .is_ok_and(|out| out.status.success())
}

fn safe_filename(value: &str) -> String {
    let out = value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') { c } else { '-' })
        .collect::<String>();
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "role".to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug)]
struct AcquisitionError {
    message: String,
    skipped: bool,
}

fn failure_reason(message: impl Into<String>) -> AcquisitionError {
    AcquisitionError { message: message.into(), skipped: false }
}

fn skip_reason(message: impl Into<String>) -> AcquisitionError {
    AcquisitionError { message: message.into(), skipped: true }
}

fn result_without_session(
    role: &str,
    status: AuthSessionStatus,
    acquired_by: &str,
    base_origin: &str,
    reason: String,
) -> AuthSessionResult {
    let evidence = serde_json::json!({
        "role": role,
        "status": status.as_str(),
        "acquired_by": acquired_by,
        "base_origin": base_origin,
        "failure_reason": if status == AuthSessionStatus::Failed { Some(reason.as_str()) } else { None },
        "skip_reason": if status == AuthSessionStatus::Skipped { Some(reason.as_str()) } else { None },
        "headers": [],
        "cookies": { "values": "[REDACTED]" },
    });
    AuthSessionResult {
        role: role.to_string(),
        status,
        session: None,
        reason: Some(reason),
        evidence,
    }
}

fn result_from_session(
    status: AuthSessionStatus,
    session: AuthSession,
    reason: Option<String>,
) -> AuthSessionResult {
    let evidence = session.redacted_evidence();
    AuthSessionResult {
        role: session.role.clone(),
        status,
        session: Some(session),
        reason,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nyctos_types::project::ProjectAuthProfile;

    fn storage_state(cookie_value: &str) -> String {
        format!(
            r#"{{
                "cookies": [{{
                    "name": "sid",
                    "value": "{cookie_value}",
                    "domain": "localhost",
                    "path": "/",
                    "expires": 4102444800,
                    "secure": false
                }}],
                "origins": []
            }}"#
        )
    }

    #[test]
    fn session_import_rejects_parent_dir_paths() {
        let err = normalize_session_import_path("../session.json").expect_err("reject");
        assert!(err.contains(".."));
    }

    #[test]
    fn redacted_evidence_does_not_include_cookie_values() {
        let mut session = AuthSession {
            role: "user_a".to_string(),
            acquired_by: "session_import".to_string(),
            status: AuthSessionStatus::Acquired,
            headers: BTreeMap::from([("Cookie".to_string(), "sid=super-secret".to_string())]),
            storage_state_path: None,
            base_origin: "http://localhost:3000".to_string(),
            expires_at_ms: None,
            assertion: AuthAssertionEvidence {
                status: AuthAssertionStatus::NotConfigured,
                checks: Vec::new(),
            },
            artifact_paths: Vec::new(),
            failure_reason: None,
            skip_reason: None,
            acquired_at_ms: 1,
            cookie_names: BTreeSet::new(),
        };
        session.cookie_names.insert("sid".to_string());
        let body = serde_json::to_string(&session.redacted_evidence()).unwrap();
        assert!(body.contains("[REDACTED]"));
        assert!(body.contains("sid"));
        assert!(!body.contains("super-secret"));
    }

    #[tokio::test]
    async fn missing_env_secret_is_explicit_auth_failure() {
        let manager = AuthSessionManager::default();
        let profile = ProjectAuthProfile {
            role: "user_a".to_string(),
            bearer_token_env: Some("NYCTOS_TEST_MISSING_TOKEN".to_string()),
            ..empty_profile(ProjectAuthMode::HeaderInjection)
        };
        let res = manager
            .acquire_session(
                "user_a",
                &[profile],
                "http://localhost:3000/api/me",
                Path::new("/tmp"),
                &AuthSessionOptions { browser_checks_enabled: false, workspace_paths: Vec::new() },
            )
            .await;
        assert_eq!(res.status, AuthSessionStatus::Failed);
        assert!(res.reason.unwrap().contains("NYCTOS_TEST_MISSING_TOKEN"));
    }

    #[tokio::test]
    async fn manual_sso_unavailable_is_skipped() {
        let manager = AuthSessionManager::default();
        let profile = ProjectAuthProfile {
            role: "sso".to_string(),
            ..empty_profile(ProjectAuthMode::ManualSso)
        };
        let res = manager
            .acquire_session(
                "sso",
                &[profile],
                "http://localhost:3000/",
                Path::new("/tmp"),
                &AuthSessionOptions { browser_checks_enabled: false, workspace_paths: Vec::new() },
            )
            .await;
        assert_eq!(res.status, AuthSessionStatus::Skipped);
        assert!(res.reason.unwrap().contains("manual SSO skipped"));
    }

    #[test]
    fn ai_auto_discovers_login_paths_from_repo_source() {
        let tmp = tempfile::tempdir().expect("tmp");
        std::fs::write(
            tmp.path().join("routes.ts"),
            r#"router.post("/api/auth/login", loginController);"#,
        )
        .expect("fixture");
        let discovery = discover_auth_from_workspaces(&[tmp.path().to_path_buf()]);
        assert_eq!(discovery.files_inspected, 1);
        assert_eq!(discovery.login_paths, vec!["/api/auth/login"]);
    }

    #[tokio::test]
    async fn ai_auto_fails_closed_without_password_env() {
        let profile = ProjectAuthProfile {
            role: "user_a".to_string(),
            username: Some("alice@example.test".to_string()),
            ..empty_profile(ProjectAuthMode::AiAuto)
        };

        let res = AuthSessionManager::default()
            .acquire_session(
                "user_a",
                &[profile],
                "http://localhost:3000/dashboard",
                Path::new("/tmp"),
                &AuthSessionOptions { browser_checks_enabled: false, workspace_paths: Vec::new() },
            )
            .await;
        assert_eq!(res.status, AuthSessionStatus::Failed);
        assert!(res.reason.unwrap().contains("password_env"));
    }

    #[test]
    fn playwright_storage_state_maps_to_cookie_header_without_logging_secret() {
        let storage: PlaywrightStorageState =
            serde_json::from_str(&storage_state("super-secret")).unwrap();
        let material =
            session_from_playwright_storage(&storage, "http://localhost:3000/app").unwrap();
        assert_eq!(material.headers.get("Cookie").unwrap(), "sid=super-secret");
        assert!(material.cookie_names.contains("sid"));
    }

    #[test]
    fn extracts_otp_from_mailhog_sample_message() {
        let sample = serde_json::json!({
            "items": [{
                "ID": "abc",
                "Content": {
                    "Headers": {
                        "To": ["alice@example.test"],
                        "Subject": ["Your login code"]
                    },
                    "Body": "Use 123456 to finish signing in."
                }
            }]
        });
        let otp =
            extract_otp_from_mailbox_json(&sample, "alice@example.test", Some("login code"), None);
        assert_eq!(otp.as_deref(), Some("123456"));
    }

    fn empty_profile(mode: ProjectAuthMode) -> ProjectAuthProfile {
        ProjectAuthProfile {
            role: String::new(),
            mode,
            label: None,
            session_cache_ttl_seconds: None,
            session_import_path: None,
            login_url: None,
            username: None,
            username_env: None,
            login_email_env: None,
            password_env: None,
            password_secret_ref: None,
            cookie_env: None,
            bearer_token_env: None,
            headers: Vec::new(),
            otp_source: None,
            post_login_assertions: Vec::new(),
            post_login_assertion: None,
            custom_command: None,
            owned_objects: Vec::new(),
        }
    }
}
