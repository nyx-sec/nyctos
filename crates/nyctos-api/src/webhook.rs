//! `POST /webhook/git` route.
//!
//! Accepts a GitHub-shaped push payload, verifies the HMAC-SHA256
//! signature against the operator's configured shared secret, applies
//! the optional branch filter, and triggers a scan via the same
//! [`ScanTrigger`] handle the manual `/api/v1/scan` endpoint uses.
//!
//! Layout chosen for maximum compatibility with self-hosted git
//! servers:
//!
//! - Header: `X-Hub-Signature-256: sha256=<hex>` (the GitHub /
//!   Gitea / Forgejo / Sourcehut convention).
//! - Body: any JSON object carrying a `"ref": "refs/heads/<branch>"`
//!   field. Other fields are ignored so a thin Gitea / Bitbucket
//!   payload also works.
//! - HMAC: the signature is computed over the raw body bytes; we use
//!   `subtle::ConstantTimeEq` to avoid timing leaks.
//! - The webhook bypasses bearer auth because HMAC IS the auth.
//!
//! Errors:
//! - Missing / invalid signature → HTTP 401.
//! - Missing / unset secret → HTTP 503 (operator must configure
//!   `triggers.webhook_secret_ref`).
//! - Wrong branch → HTTP 200 with `triggered=false` so the upstream
//!   git server records a successful delivery and stops retrying.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::header::CONTENT_LENGTH;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::state::{ApiError, ScanTrigger, ServerState};

type HmacSha256 = Hmac<Sha256>;

/// Maximum webhook body the handler will buffer before bailing out
/// with 413. 1 MiB covers every observed git-server payload comfortably
/// while still bounding peak memory under a malicious caller.
pub const MAX_WEBHOOK_BODY_BYTES: usize = 1024 * 1024;

const SIGNATURE_HEADER: &str = "X-Hub-Signature-256";
const SIGNATURE_PREFIX: &str = "sha256=";

/// `sha256` produces a 32-byte digest, which encodes to 64 hex chars.
const SIGNATURE_HEX_LEN: usize = 64;

/// Headers we consult to identify the upstream event type. Order is
/// the precedence used when more than one is present (which never
/// happens in practice but stays deterministic if it does).
const EVENT_HEADERS: &[&str] =
    &["X-GitHub-Event", "X-Gitea-Event", "X-Forgejo-Event", "X-Gogs-Event", "X-Gitlab-Event"];

/// Headers we consult for a delivery / replay id. Same provider order
/// as [`EVENT_HEADERS`].
const DELIVERY_HEADERS: &[&str] = &[
    "X-GitHub-Delivery",
    "X-Gitea-Delivery",
    "X-Forgejo-Delivery",
    "X-Gogs-Delivery",
    "X-Gitlab-Event-UUID",
];

/// Bounded cap on the in-memory replay-dedup cache. Each entry is the
/// raw delivery id string from the upstream provider (typically a
/// UUID, ~36 bytes); 1024 entries caps memory at well under 100 KiB
/// and covers the largest plausible burst window before older
/// deliveries naturally roll off.
pub const DELIVERY_DEDUP_CAP: usize = 1024;

/// Quick syntactic check on the signature header. Refuses anything that
/// is not `sha256=` + exactly 64 lowercase-or-uppercase hex chars. Lets
/// the handler 401 a forged delivery without buffering the body or
/// running a full HMAC pass.
fn signature_header_is_well_formed(header: &str) -> bool {
    let Some(rest) = header.trim().strip_prefix(SIGNATURE_PREFIX) else { return false };
    let rest = rest.trim();
    rest.len() == SIGNATURE_HEX_LEN && rest.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What kind of event the upstream advertised. Read from the
/// provider-specific event header; `Unknown` when no recognised header
/// is present so the handler can fall through to the legacy
/// best-effort path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    /// A real push event we want to scan.
    Push,
    /// GitHub's webhook-creation ping. Should be accepted at the
    /// transport layer (so the upstream marks the webhook healthy) but
    /// never trigger a scan.
    Ping,
    /// Anything else the upstream named (issues / pull_request /
    /// workflow_run / ...). Acknowledged 200 so the upstream stops
    /// retrying, never triggers a scan.
    Other(String),
    /// No recognised event header was present. Conservative fallback
    /// for unknown providers; the handler then requires a `ref`-shaped
    /// JSON body before triggering a scan.
    Unknown,
}

/// Read the provider-specific event header into an [`EventKind`].
pub fn classify_event(headers: &HeaderMap) -> EventKind {
    for name in EVENT_HEADERS {
        let Some(raw) = headers.get(*name).and_then(|v| v.to_str().ok()) else { continue };
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }
        if value.eq_ignore_ascii_case("push") || value.eq_ignore_ascii_case("push hook") {
            return EventKind::Push;
        }
        if value.eq_ignore_ascii_case("ping") {
            return EventKind::Ping;
        }
        return EventKind::Other(value.to_string());
    }
    EventKind::Unknown
}

/// Read the provider-specific delivery id (if any). Returned trimmed
/// so trailing whitespace from misbehaving clients does not split the
/// dedup cache.
pub fn delivery_id(headers: &HeaderMap) -> Option<String> {
    for name in DELIVERY_HEADERS {
        let Some(raw) = headers.get(*name).and_then(|v| v.to_str().ok()) else { continue };
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Bounded LRU-ish set of delivery ids we have already processed.
/// Insertion is O(1) amortised: a `HashSet` answers membership, a
/// `VecDeque` records arrival order so the oldest entry rolls off
/// once the cap is reached. The cap is [`DELIVERY_DEDUP_CAP`].
#[derive(Default)]
pub struct DeliveryDedupCache {
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl DeliveryDedupCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a delivery id. Returns `true` if the id is new, `false`
    /// if it has already been seen within the cap window.
    pub fn record(&mut self, id: &str) -> bool {
        if self.seen.contains(id) {
            return false;
        }
        if self.order.len() >= DELIVERY_DEDUP_CAP {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(id.to_string());
        self.order.push_back(id.to_string());
        true
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Pluggable resolver that turns the operator's
/// `triggers.webhook_secret_ref` value into the raw bytes used as the
/// HMAC key. Production maps `env:<NAME>` to `$NAME`, but tests
/// substitute an in-process stub so they don't have to mutate the
/// environment.
pub trait WebhookSecretResolver: Send + Sync + 'static {
    fn resolve(&self) -> Option<Vec<u8>>;
}

/// Resolves `env:<NAME>` against the process environment. Any other
/// shape is treated as the literal secret. Returns `None` when the
/// referenced environment variable is unset (so the handler returns
/// 503 rather than accepting unauthenticated triggers).
pub struct EnvSecretResolver {
    /// Raw value of `triggers.webhook_secret_ref` (e.g.
    /// `env:NYX_WEBHOOK_SECRET` or a literal). `None` when the
    /// operator has not configured the webhook.
    pub spec: Option<String>,
}

impl WebhookSecretResolver for EnvSecretResolver {
    fn resolve(&self) -> Option<Vec<u8>> {
        let spec = self.spec.as_deref()?;
        let raw = if let Some(var) = spec.strip_prefix("env:") {
            std::env::var(var).ok()?.into_bytes()
        } else {
            spec.as_bytes().to_vec()
        };
        // Refuse empty secrets. An empty key satisfies the HMAC API
        // but accepts any HMAC over the empty byte string, which is
        // not authentication.
        if raw.is_empty() {
            None
        } else {
            Some(raw)
        }
    }
}

/// In-memory secret resolver for tests.
#[derive(Clone)]
pub struct StaticSecretResolver {
    pub secret: Option<Vec<u8>>,
}

impl WebhookSecretResolver for StaticSecretResolver {
    fn resolve(&self) -> Option<Vec<u8>> {
        self.secret.clone()
    }
}

/// Per-route config attached to the webhook handler.
#[derive(Clone)]
pub struct WebhookConfig {
    /// Resolves the shared secret on every request so a wizard rotate
    /// flow doesn't require a router rebuild.
    pub secret: Arc<dyn WebhookSecretResolver>,
    /// When `Some(branch)`, only payloads whose `ref` equals
    /// `refs/heads/<branch>` trigger a scan. `None` accepts any branch.
    pub branch: Option<String>,
    /// Optional repo filter forwarded to the [`ScanTrigger`]. `None`
    /// scans every enabled repo, matching the API's manual-trigger
    /// behaviour.
    pub repo: Option<String>,
    /// Bounded set of delivery ids already processed, so a webhook-UI
    /// redelivery (or a hostile replay of a captured-and-still-valid
    /// HMAC body) does not retrigger the dispatcher. Shared across
    /// clones of the config so a router rebuild keeps the cache hot.
    pub dedup: Arc<Mutex<DeliveryDedupCache>>,
    /// Provider-specific decoder for the verified push body. Operators
    /// pick this via `[triggers].webhook_provider`; the default
    /// (`refheads`) covers GitHub / Gitea / Forgejo / Gogs / GitLab,
    /// which all ship the branch under top-level `ref`.
    pub extractor: Arc<dyn WebhookPayloadExtractor>,
}

impl WebhookConfig {
    /// Build a webhook config with a fresh dedup cache and the default
    /// `ref: refs/heads/<branch>` extractor.
    pub fn new(
        secret: Arc<dyn WebhookSecretResolver>,
        branch: Option<String>,
        repo: Option<String>,
    ) -> Self {
        Self::with_extractor(secret, branch, repo, Arc::new(RefHeadsExtractor))
    }

    /// Build a webhook config with a fresh dedup cache and an explicit
    /// extractor. Used when the operator's `[triggers].webhook_provider`
    /// names a non-default shape (Bitbucket Server, Sourcehut, ...).
    pub fn with_extractor(
        secret: Arc<dyn WebhookSecretResolver>,
        branch: Option<String>,
        repo: Option<String>,
        extractor: Arc<dyn WebhookPayloadExtractor>,
    ) -> Self {
        Self {
            secret,
            branch,
            repo,
            dedup: Arc::new(Mutex::new(DeliveryDedupCache::new())),
            extractor,
        }
    }
}

/// Outcome of pulling the push fields out of an upstream-signed body.
/// `branch` carries the bare branch name (e.g. `main`, not the full
/// `refs/heads/main` ref). `repo_hint` is the upstream-reported repo
/// identifier when present; reserved for the future per-repo trigger
/// path (today the handler scope-alls and ignores the hint).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedPush {
    pub branch: Option<String>,
    pub repo_hint: Option<String>,
}

/// Provider-specific decoder for the verified webhook body. Implementors
/// receive the raw headers (so they can pick a payload shape per
/// `Content-Type` or X-Event-Key) and the byte slice the HMAC already
/// covered. Returning `None` signals "this body is not a push we can
/// route" and the handler responds 200 + `triggered=false`.
pub trait WebhookPayloadExtractor: Send + Sync + 'static {
    fn extract(&self, headers: &HeaderMap, body: &[u8]) -> Option<ParsedPush>;
}

/// Decodes the top-level `"ref": "refs/heads/<branch>"` shape shipped by
/// GitHub, Gitea, Forgejo, Gogs, and GitLab. Tolerates extra fields and
/// reads `repository.full_name` when present so future per-repo routing
/// has a hint to work with.
pub struct RefHeadsExtractor;

impl WebhookPayloadExtractor for RefHeadsExtractor {
    fn extract(&self, _headers: &HeaderMap, body: &[u8]) -> Option<ParsedPush> {
        let value: serde_json::Value = serde_json::from_slice(body).ok()?;
        let branch = value
            .get("ref")
            .and_then(|v| v.as_str())
            .and_then(|r| r.strip_prefix("refs/heads/"))
            .map(|s| s.to_string());
        let repo_hint = value
            .get("repository")
            .and_then(|r| r.get("full_name").or_else(|| r.get("name")))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Some(ParsedPush { branch, repo_hint })
    }
}

/// Decodes the Bitbucket Server / Data Center push shape:
/// `{ "changes": [ { "refId": "refs/heads/<branch>", ... } ], "repository": { "slug": "..." } }`.
pub struct BitbucketServerExtractor;

impl WebhookPayloadExtractor for BitbucketServerExtractor {
    fn extract(&self, _headers: &HeaderMap, body: &[u8]) -> Option<ParsedPush> {
        let value: serde_json::Value = serde_json::from_slice(body).ok()?;
        let branch = value
            .get("changes")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| first.get("refId"))
            .and_then(|v| v.as_str())
            .and_then(|r| r.strip_prefix("refs/heads/"))
            .map(|s| s.to_string());
        let repo_hint = value
            .get("repository")
            .and_then(|r| r.get("slug").or_else(|| r.get("name")))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Some(ParsedPush { branch, repo_hint })
    }
}

/// Decodes the Sourcehut `hgmail`/builds shape that nests the refs under
/// `event.refs[0].name`. Repo hint comes from `event.repo.name`.
pub struct SourcehutExtractor;

impl WebhookPayloadExtractor for SourcehutExtractor {
    fn extract(&self, _headers: &HeaderMap, body: &[u8]) -> Option<ParsedPush> {
        let value: serde_json::Value = serde_json::from_slice(body).ok()?;
        let event = value.get("event")?;
        let branch = event
            .get("refs")
            .and_then(|r| r.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| first.get("name"))
            .and_then(|v| v.as_str())
            .and_then(|r| r.strip_prefix("refs/heads/").or(Some(r)))
            .map(|s| s.to_string());
        let repo_hint = event
            .get("repo")
            .and_then(|r| r.get("name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Some(ParsedPush { branch, repo_hint })
    }
}

/// Parse the operator's `[triggers].webhook_provider` string into an
/// extractor. Unknown / empty strings fall back to the default
/// (`RefHeadsExtractor`) so a typo never silently disables webhooks.
pub fn extractor_for_provider(name: Option<&str>) -> Arc<dyn WebhookPayloadExtractor> {
    let Some(raw) = name else { return Arc::new(RefHeadsExtractor) };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "github" | "gitea" | "forgejo" | "gogs" | "gitlab" | "refheads" => {
            Arc::new(RefHeadsExtractor)
        }
        "bitbucket" | "bitbucket-server" | "bitbucket_data_center" => {
            Arc::new(BitbucketServerExtractor)
        }
        "sourcehut" | "srht" => Arc::new(SourcehutExtractor),
        // Unknown provider falls back to the default but is worth a
        // log line so the operator can spot the typo in their config.
        other => {
            tracing::warn!(
                provider = other,
                "unknown `[triggers].webhook_provider`; defaulting to `refheads`"
            );
            Arc::new(RefHeadsExtractor)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    pub triggered: bool,
    /// Run id when `triggered=true`; `None` when the branch filter
    /// rejected the payload.
    pub run_id: Option<String>,
    /// Operator-readable explanation for an accepted-but-skipped
    /// delivery (wrong branch). Empty on a triggered scan.
    pub message: String,
}

/// `POST /webhook/git` handler.
pub async fn webhook_git(
    State(state): State<ServerState>,
    req: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(cfg) = state.webhook.as_ref() else {
        return Err(ApiError::Internal(
            "webhook not enabled; set [triggers].webhook_secret_ref in nyctos.toml".to_string(),
        ));
    };

    let Some(secret) = cfg.secret.resolve() else {
        // Webhook is configured but the secret cannot be resolved
        // (e.g. unset env var). Refuse the delivery: accepting it
        // would be unauthenticated.
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(WebhookResponse {
                triggered: false,
                run_id: None,
                message: "webhook secret is not configured".to_string(),
            }),
        )
            .into_response());
    };

    // Pull the signature header BEFORE consuming the body so a missing
    // or syntactically-malformed header short-circuits without
    // buffering and without burning an HMAC pass per forged delivery.
    let sig_header = req
        .headers()
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(ApiError::Unauthorized)?;
    if !signature_header_is_well_formed(&sig_header) {
        return Err(ApiError::Unauthorized);
    }

    // Refuse non-push event types we can identify by header before
    // buffering the body. A GitHub `ping` (sent on webhook creation),
    // `issues`, `pull_request`, `workflow_run`, ... all carry valid
    // HMAC over the body but must not trigger a scan. The transport
    // status stays 200 so the upstream marks the delivery healthy and
    // does not retry.
    let event = classify_event(req.headers());
    match &event {
        EventKind::Push | EventKind::Unknown => {}
        EventKind::Ping => {
            return Ok((
                StatusCode::OK,
                Json(WebhookResponse {
                    triggered: false,
                    run_id: None,
                    message: "ping event acknowledged".to_string(),
                }),
            )
                .into_response());
        }
        EventKind::Other(name) => {
            return Ok((
                StatusCode::OK,
                Json(WebhookResponse {
                    triggered: false,
                    run_id: None,
                    message: format!("event `{name}` is not a push; ignored"),
                }),
            )
                .into_response());
        }
    }

    // Reject oversized payloads on the advertised Content-Length before
    // buffering. `to_bytes` enforces the same cap (covering chunked
    // transfer encoding where Content-Length is absent), but the
    // header-side check refuses a hostile sender before any body read.
    if let Some(declared) = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if declared > MAX_WEBHOOK_BODY_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "webhook body {declared} bytes exceeds {MAX_WEBHOOK_BODY_BYTES} byte limit"
            )));
        }
    }

    let (parts, body) = req.into_parts();
    let headers = parts.headers;
    let body_bytes = to_bytes(body, MAX_WEBHOOK_BODY_BYTES).await.map_err(|e| {
        ApiError::PayloadTooLarge(format!("webhook body exceeded limit or failed to read: {e}"))
    })?;

    if !verify_signature(&secret, body_bytes.as_ref(), &sig_header) {
        return Err(ApiError::Unauthorized);
    }

    // Replay drop: only after HMAC verified, so a hostile sender
    // without the secret cannot poison the cache by spraying random
    // delivery ids. Providers that do not emit a delivery header
    // skip dedup; the HMAC + push-event filter is the floor in that
    // case.
    if let Some(delivery) = delivery_id(&headers) {
        let fresh = match cfg.dedup.lock() {
            Ok(mut guard) => guard.record(&delivery),
            // A poisoned mutex means a previous insert panicked. The
            // safe response is to fail open (treat the delivery as
            // new) rather than reject every subsequent request.
            Err(poisoned) => {
                tracing::warn!("webhook dedup cache poisoned: {poisoned}");
                true
            }
        };
        if !fresh {
            return Ok((
                StatusCode::OK,
                Json(WebhookResponse {
                    triggered: false,
                    run_id: None,
                    message: format!("delivery `{delivery}` already processed"),
                }),
            )
                .into_response());
        }
    }

    // Best-effort decode via the operator-selected extractor. A body
    // the extractor cannot parse is accepted (some upstream form-encoded
    // payloads include a JSON value as the `payload` form field; we
    // tolerate that by reading the branch only when the extractor
    // recognises the shape).
    let parsed = cfg.extractor.extract(&headers, body_bytes.as_ref());
    let branch = parsed.as_ref().and_then(|p| p.branch.clone());

    // A signed-but-branchless body for an Unknown-event provider is not
    // a push; refuse to trigger. (Push events for known providers were
    // already classified above; this guard catches the legacy
    // best-effort path so it stops accepting non-push deliveries
    // whose provider did not set an event header.)
    if matches!(event, EventKind::Unknown) && branch.is_none() {
        return Ok((
            StatusCode::OK,
            Json(WebhookResponse {
                triggered: false,
                run_id: None,
                message: "payload carried no recognised ref; not a push event".to_string(),
            }),
        )
            .into_response());
    }

    if let Some(want) = cfg.branch.as_deref() {
        match branch.as_deref() {
            Some(actual) if actual == want => {}
            other => {
                return Ok((
                    StatusCode::OK,
                    Json(WebhookResponse {
                        triggered: false,
                        run_id: None,
                        message: format!(
                            "branch filter rejected delivery (want `{want}`, got `{}`)",
                            other.unwrap_or("<unknown>")
                        ),
                    }),
                )
                    .into_response());
            }
        }
    }

    let trigger: Arc<dyn ScanTrigger> = Arc::clone(&state.scan);
    // Webhook config does not yet plumb a project filter; scope-all is
    // preserved by passing `None` for project_id. An optional
    // `project = "..."` field in the trigger config block could narrow
    // this later.
    let run_id = trigger.trigger(None, cfg.repo.clone()).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(WebhookResponse { triggered: true, run_id: Some(run_id), message: String::new() }),
    )
        .into_response())
}

/// Constant-time HMAC-SHA256 verification.
pub fn verify_signature(secret: &[u8], body: &[u8], header: &str) -> bool {
    let Some(hex_sig) = header.trim().strip_prefix(SIGNATURE_PREFIX) else { return false };
    let Ok(provided) = hex::decode(hex_sig.trim()) else { return false };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else { return false };
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    provided.as_slice().ct_eq(expected.as_slice()).into()
}

/// Helper used by the daemon's wiring + the test harness to mint the
/// `sha256=<hex>` header for a given (secret, body).
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    format!("{}{}", SIGNATURE_PREFIX, hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_roundtrip() {
        let secret = b"hunter2";
        let body = br#"{"ref":"refs/heads/main"}"#;
        let header = sign(secret, body);
        assert!(header.starts_with(SIGNATURE_PREFIX));
        assert!(verify_signature(secret, body, &header));
    }

    #[test]
    fn signature_rejects_modified_body() {
        let secret = b"hunter2";
        let body = br#"{"ref":"refs/heads/main"}"#;
        let header = sign(secret, body);
        assert!(!verify_signature(secret, br#"{"ref":"refs/heads/evil"}"#, &header));
    }

    #[test]
    fn signature_rejects_wrong_secret() {
        let secret = b"hunter2";
        let body = br#"{"ref":"refs/heads/main"}"#;
        let header = sign(secret, body);
        assert!(!verify_signature(b"wrong-secret", body, &header));
    }

    #[test]
    fn signature_rejects_missing_prefix() {
        let secret = b"hunter2";
        let body = b"{}";
        let mut header = sign(secret, body);
        // Strip the `sha256=` prefix.
        header.replace_range(..SIGNATURE_PREFIX.len(), "");
        assert!(!verify_signature(secret, body, &header));
    }

    #[test]
    fn env_resolver_reads_from_environment() {
        // Use a randomised env var name so concurrent test runs do not
        // race on a shared name.
        let var = format!("NYX_TEST_WEBHOOK_{}", std::process::id());
        std::env::set_var(&var, "shh");
        let resolver = EnvSecretResolver { spec: Some(format!("env:{var}")) };
        assert_eq!(resolver.resolve().as_deref(), Some(b"shh".as_slice()));
        std::env::remove_var(&var);
        assert!(resolver.resolve().is_none());
    }

    #[test]
    fn env_resolver_passes_literal_through() {
        let resolver = EnvSecretResolver { spec: Some("literal-secret".to_string()) };
        assert_eq!(resolver.resolve().as_deref(), Some(b"literal-secret".as_slice()));
    }

    #[test]
    fn env_resolver_returns_none_when_unset() {
        let resolver = EnvSecretResolver { spec: None };
        assert!(resolver.resolve().is_none());
    }

    #[test]
    fn env_resolver_refuses_empty_literal() {
        let resolver = EnvSecretResolver { spec: Some(String::new()) };
        assert!(resolver.resolve().is_none(), "empty literal secret must not pass HMAC auth");
    }

    #[test]
    fn env_resolver_refuses_empty_env_value() {
        let var = format!("NYX_TEST_WEBHOOK_EMPTY_{}", std::process::id());
        std::env::set_var(&var, "");
        let resolver = EnvSecretResolver { spec: Some(format!("env:{var}")) };
        assert!(resolver.resolve().is_none(), "empty env-backed secret must not pass HMAC auth");
        std::env::remove_var(&var);
    }

    #[test]
    fn signature_header_shape_accepts_canonical_form() {
        let header = format!("sha256={}", "a".repeat(SIGNATURE_HEX_LEN));
        assert!(signature_header_is_well_formed(&header));
    }

    #[test]
    fn signature_header_shape_accepts_mixed_case_hex() {
        let header = format!("sha256={}", "AbCdEf0123456789".repeat(4));
        assert!(signature_header_is_well_formed(&header));
    }

    #[test]
    fn signature_header_shape_rejects_missing_prefix() {
        let header = "a".repeat(SIGNATURE_HEX_LEN);
        assert!(!signature_header_is_well_formed(&header));
    }

    #[test]
    fn signature_header_shape_rejects_short_digest() {
        let header = format!("sha256={}", "a".repeat(SIGNATURE_HEX_LEN - 1));
        assert!(!signature_header_is_well_formed(&header));
    }

    #[test]
    fn signature_header_shape_rejects_long_digest() {
        let header = format!("sha256={}", "a".repeat(SIGNATURE_HEX_LEN + 1));
        assert!(!signature_header_is_well_formed(&header));
    }

    #[test]
    fn signature_header_shape_rejects_non_hex_chars() {
        let header = format!("sha256={}", "z".repeat(SIGNATURE_HEX_LEN));
        assert!(!signature_header_is_well_formed(&header));
    }

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).expect("header name"),
                axum::http::HeaderValue::from_str(v).expect("header value"),
            );
        }
        m
    }

    #[test]
    fn classify_event_recognises_github_push() {
        assert_eq!(classify_event(&map(&[("X-GitHub-Event", "push")])), EventKind::Push);
    }

    #[test]
    fn classify_event_is_case_insensitive() {
        assert_eq!(classify_event(&map(&[("X-GitHub-Event", "PuSh")])), EventKind::Push);
    }

    #[test]
    fn classify_event_recognises_gitlab_push_hook() {
        assert_eq!(classify_event(&map(&[("X-Gitlab-Event", "Push Hook")])), EventKind::Push);
    }

    #[test]
    fn classify_event_recognises_ping() {
        assert_eq!(classify_event(&map(&[("X-GitHub-Event", "ping")])), EventKind::Ping);
    }

    #[test]
    fn classify_event_returns_other_for_unknown_event_name() {
        match classify_event(&map(&[("X-GitHub-Event", "issues")])) {
            EventKind::Other(name) => assert_eq!(name, "issues"),
            other => panic!("expected Other(\"issues\"), got {other:?}"),
        }
    }

    #[test]
    fn classify_event_returns_unknown_when_no_provider_header() {
        assert_eq!(classify_event(&HeaderMap::new()), EventKind::Unknown);
    }

    #[test]
    fn classify_event_ignores_empty_header_value() {
        assert_eq!(classify_event(&map(&[("X-GitHub-Event", "")])), EventKind::Unknown);
    }

    #[test]
    fn delivery_id_reads_github_header() {
        let id = delivery_id(&map(&[("X-GitHub-Delivery", "abc-123")]));
        assert_eq!(id.as_deref(), Some("abc-123"));
    }

    #[test]
    fn delivery_id_reads_gitea_header_when_github_absent() {
        let id = delivery_id(&map(&[("X-Gitea-Delivery", "xyz-789")]));
        assert_eq!(id.as_deref(), Some("xyz-789"));
    }

    #[test]
    fn delivery_id_is_none_when_no_header() {
        assert!(delivery_id(&HeaderMap::new()).is_none());
    }

    #[test]
    fn dedup_cache_records_new_id() {
        let mut cache = DeliveryDedupCache::new();
        assert!(cache.record("a"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn dedup_cache_drops_repeat() {
        let mut cache = DeliveryDedupCache::new();
        assert!(cache.record("a"));
        assert!(!cache.record("a"), "second insert must report duplicate");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn refheads_extractor_reads_github_push() {
        let body = br#"{"ref":"refs/heads/main","repository":{"full_name":"acme/api"}}"#;
        let parsed = RefHeadsExtractor.extract(&HeaderMap::new(), body).expect("parsed");
        assert_eq!(parsed.branch.as_deref(), Some("main"));
        assert_eq!(parsed.repo_hint.as_deref(), Some("acme/api"));
    }

    #[test]
    fn refheads_extractor_returns_none_branch_for_tag_push() {
        let body = br#"{"ref":"refs/tags/v1.2.3"}"#;
        let parsed = RefHeadsExtractor.extract(&HeaderMap::new(), body).expect("parsed");
        assert!(parsed.branch.is_none(), "tag pushes are not branch pushes");
    }

    #[test]
    fn refheads_extractor_falls_back_to_repo_name() {
        let body = br#"{"ref":"refs/heads/dev","repository":{"name":"api"}}"#;
        let parsed = RefHeadsExtractor.extract(&HeaderMap::new(), body).expect("parsed");
        assert_eq!(parsed.repo_hint.as_deref(), Some("api"));
    }

    #[test]
    fn refheads_extractor_returns_none_on_garbage() {
        assert!(RefHeadsExtractor.extract(&HeaderMap::new(), b"not-json").is_none());
    }

    #[test]
    fn bitbucket_server_extractor_reads_changes_array() {
        let body = br#"{
            "changes":[{"refId":"refs/heads/develop","type":"UPDATE"}],
            "repository":{"slug":"api","name":"Api Service"}
        }"#;
        let parsed = BitbucketServerExtractor.extract(&HeaderMap::new(), body).expect("parsed");
        assert_eq!(parsed.branch.as_deref(), Some("develop"));
        assert_eq!(parsed.repo_hint.as_deref(), Some("api"));
    }

    #[test]
    fn bitbucket_server_extractor_returns_none_branch_when_changes_empty() {
        let body = br#"{"changes":[],"repository":{"slug":"api"}}"#;
        let parsed = BitbucketServerExtractor.extract(&HeaderMap::new(), body).expect("parsed");
        assert!(parsed.branch.is_none());
        assert_eq!(parsed.repo_hint.as_deref(), Some("api"));
    }

    #[test]
    fn sourcehut_extractor_reads_nested_event_refs() {
        let body =
            br#"{"event":{"refs":[{"name":"refs/heads/main"}],"repo":{"name":"~user/proj"}}}"#;
        let parsed = SourcehutExtractor.extract(&HeaderMap::new(), body).expect("parsed");
        assert_eq!(parsed.branch.as_deref(), Some("main"));
        assert_eq!(parsed.repo_hint.as_deref(), Some("~user/proj"));
    }

    #[test]
    fn sourcehut_extractor_keeps_bare_branch_names() {
        // Some sr.ht builds emit just the branch name without the
        // `refs/heads/` prefix.
        let body = br#"{"event":{"refs":[{"name":"main"}]}}"#;
        let parsed = SourcehutExtractor.extract(&HeaderMap::new(), body).expect("parsed");
        assert_eq!(parsed.branch.as_deref(), Some("main"));
    }

    #[test]
    fn extractor_for_provider_defaults_when_missing() {
        let body = br#"{"ref":"refs/heads/main"}"#;
        let ex = extractor_for_provider(None);
        assert_eq!(
            ex.extract(&HeaderMap::new(), body).and_then(|p| p.branch).as_deref(),
            Some("main"),
        );
    }

    #[test]
    fn extractor_for_provider_matches_known_aliases() {
        for name in ["github", "GITHUB", " gitea ", "forgejo", "gogs", "gitlab", "refheads"] {
            let ex = extractor_for_provider(Some(name));
            let body = br#"{"ref":"refs/heads/main"}"#;
            assert_eq!(
                ex.extract(&HeaderMap::new(), body).and_then(|p| p.branch).as_deref(),
                Some("main"),
                "alias `{name}` should map to RefHeadsExtractor",
            );
        }
    }

    #[test]
    fn extractor_for_provider_picks_bitbucket() {
        let ex = extractor_for_provider(Some("bitbucket"));
        let body = br#"{"changes":[{"refId":"refs/heads/main"}]}"#;
        assert_eq!(
            ex.extract(&HeaderMap::new(), body).and_then(|p| p.branch).as_deref(),
            Some("main"),
        );
    }

    #[test]
    fn extractor_for_provider_picks_sourcehut() {
        let ex = extractor_for_provider(Some("sourcehut"));
        let body = br#"{"event":{"refs":[{"name":"refs/heads/main"}]}}"#;
        assert_eq!(
            ex.extract(&HeaderMap::new(), body).and_then(|p| p.branch).as_deref(),
            Some("main"),
        );
    }

    #[test]
    fn extractor_for_provider_falls_back_on_unknown() {
        let ex = extractor_for_provider(Some("notarealthing"));
        let body = br#"{"ref":"refs/heads/main"}"#;
        // Unknown provider warns + falls back to RefHeads.
        assert_eq!(
            ex.extract(&HeaderMap::new(), body).and_then(|p| p.branch).as_deref(),
            Some("main"),
        );
    }

    #[test]
    fn dedup_cache_evicts_oldest_at_cap() {
        let mut cache = DeliveryDedupCache::new();
        for i in 0..DELIVERY_DEDUP_CAP {
            assert!(cache.record(&format!("d-{i}")));
        }
        assert_eq!(cache.len(), DELIVERY_DEDUP_CAP);
        // Push one more; the oldest entry rolls off.
        assert!(cache.record("d-new"));
        assert_eq!(cache.len(), DELIVERY_DEDUP_CAP);
        // The id we just evicted is now `record()`-able again.
        assert!(cache.record("d-0"));
    }
}
