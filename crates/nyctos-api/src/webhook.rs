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

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, State};
use axum::http::header::CONTENT_LENGTH;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::state::{ApiError, ScanTrigger, ScanTriggerSource, ServerState};

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

/// Default cap on simultaneous in-flight webhook handlers. Set above
/// the dispatcher's scan-request queue depth so legitimate bursts are
/// absorbed, but bounded so a flood of valid-HMAC deliveries cannot
/// peg every tokio worker on HMAC verification + body read in
/// parallel. Operators tune via `[triggers].webhook_max_concurrent`.
pub const DEFAULT_WEBHOOK_MAX_CONCURRENT: usize = 8;

/// Default per-source-IP token bucket size. One push every two seconds
/// sustained, with bursts up to [`DEFAULT_WEBHOOK_RATE_LIMIT_BURST`]
/// allowed. Operators tune via `[triggers].webhook_rate_limit_per_minute`.
pub const DEFAULT_WEBHOOK_RATE_LIMIT_PER_MINUTE: u32 = 30;

/// Burst depth for the per-IP token bucket. Matches the default
/// per-minute rate so a fresh sender can fire up to this many
/// deliveries back-to-back before the bucket drains.
pub const DEFAULT_WEBHOOK_RATE_LIMIT_BURST: u32 = 30;

/// Maximum number of IPs the per-IP rate limiter tracks before it
/// evicts the least-recently-seen entry. Caps memory under a flood of
/// unique source addresses.
pub const DEFAULT_WEBHOOK_RATE_LIMIT_MAX_IPS: usize = 1024;

/// Hand-rolled semaphore-backed concurrency cap on `webhook_git`.
/// Lives on [`WebhookConfig`] so a router rebuild keeps the live
/// permit count intact. Wraps an `Arc<Semaphore>` directly rather
/// than depending on `tower::limit::ConcurrencyLimitLayer` so the
/// workspace stays off the `tower` base crate.
pub struct WebhookConcurrencyLimit {
    inner: Arc<tokio::sync::Semaphore>,
    permits: usize,
}

impl WebhookConcurrencyLimit {
    pub fn new(permits: usize) -> Self {
        let permits = permits.max(1);
        Self { inner: Arc::new(tokio::sync::Semaphore::new(permits)), permits }
    }

    /// Total permits configured. Used by tests and for operator
    /// reporting.
    pub fn permits(&self) -> usize {
        self.permits
    }

    /// Try to acquire one permit without waiting. Returns
    /// `Some(permit)` on success; the caller must hold the permit
    /// until the response is sent. Returns `None` when every permit
    /// is in flight so the handler can refuse with 429.
    pub fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.inner).try_acquire_owned().ok()
    }
}

/// Per-source-IP token bucket. `capacity` tokens refill at
/// `refill_per_sec` tokens/second; each admitted request consumes
/// one. When the bucket empties the next call to
/// [`WebhookRateLimiter::admit`] returns `false` so the handler can
/// refuse with 429.
///
/// The map is bounded at `max_ips`: when an unknown IP would push
/// the map past the cap, the entry with the oldest `last_refill`
/// timestamp is evicted. That keeps memory bounded under a flood of
/// unique source addresses while letting a steady stream of senders
/// keep their state warm.
pub struct WebhookRateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    max_ips: usize,
    inner: Mutex<HashMap<IpAddr, TokenBucket>>,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl WebhookRateLimiter {
    /// Build a limiter that admits `capacity` requests up front and
    /// then refills at `refill_per_sec` tokens per second. `max_ips`
    /// caps the tracked set; entries past the cap are evicted oldest
    /// first.
    pub fn new(capacity: u32, refill_per_sec: f64, max_ips: usize) -> Self {
        Self {
            capacity: f64::from(capacity.max(1)),
            refill_per_sec: refill_per_sec.max(0.0),
            max_ips: max_ips.max(1),
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Build a limiter from the operator-facing
    /// `webhook_rate_limit_per_minute` knob. The burst depth is
    /// the same value (so a fresh sender can fire that many requests
    /// back-to-back before throttling kicks in).
    pub fn per_minute(rate_per_minute: u32, max_ips: usize) -> Self {
        let rate = rate_per_minute.max(1);
        Self::new(rate, f64::from(rate) / 60.0, max_ips)
    }

    /// Consume one token for `ip`. Returns `true` when the request is
    /// admitted and `false` when the bucket is empty.
    pub fn admit(&self, ip: IpAddr) -> bool {
        self.admit_at(ip, Instant::now())
    }

    /// Same as [`Self::admit`] but with an explicit `now` so tests
    /// can drive the refill clock deterministically without sleeping.
    pub fn admit_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned mutex means a prior insert panicked. Recover
            // by taking the inner data; the next caller starts with
            // whatever state was visible at the panic. Failing open
            // here is wrong for a rate limiter (it would defeat the
            // throttle), so we proceed but the existing entries stay
            // intact.
            Err(p) => p.into_inner(),
        };

        // Evict oldest if at capacity AND ip is not already tracked.
        if !g.contains_key(&ip) && g.len() >= self.max_ips {
            if let Some(victim) =
                g.iter().min_by_key(|(_, b)| b.last_refill).map(|(k, _)| *k)
            {
                g.remove(&victim);
            }
        }

        let bucket = g
            .entry(ip)
            .or_insert_with(|| TokenBucket { tokens: self.capacity, last_refill: now });

        // Clock can jump backwards on a leap-second / clock-drift
        // event; clamp the elapsed delta to zero so we don't add a
        // negative refill.
        let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Number of currently tracked IPs. Used by tests.
    #[cfg(test)]
    pub fn tracked_ips(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }
}

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
    /// Optional cap on simultaneous in-flight handler invocations.
    /// `None` disables the gate (every request is admitted). When
    /// set, requests past the cap return 429 before HMAC verification
    /// so a flood of valid-signed pushes cannot peg the executor.
    pub concurrency: Option<Arc<WebhookConcurrencyLimit>>,
    /// Optional per-source-IP token bucket. `None` disables the gate
    /// (every IP is admitted). When set, requests past the per-IP
    /// budget return 429 before HMAC verification. The handler
    /// reads the source IP from the request's [`ConnectInfo`]
    /// extension; deployments that route through a reverse proxy
    /// without preserving the peer address will not see per-IP
    /// throttling and fall back to the global concurrency cap.
    pub rate_limit: Option<Arc<WebhookRateLimiter>>,
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
            concurrency: None,
            rate_limit: None,
        }
    }

    /// Attach a concurrency cap. Subsequent requests past the cap
    /// return 429 before HMAC verification.
    pub fn with_concurrency_limit(mut self, limit: Arc<WebhookConcurrencyLimit>) -> Self {
        self.concurrency = Some(limit);
        self
    }

    /// Attach a per-source-IP rate limiter. Requests past the per-IP
    /// budget return 429 before HMAC verification.
    pub fn with_rate_limit(mut self, limit: Arc<WebhookRateLimiter>) -> Self {
        self.rate_limit = Some(limit);
        self
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

/// Read the peer's IP from the request extensions. Populated by
/// `axum::serve(_, app.into_make_service_with_connect_info::<SocketAddr>())`.
/// Returns `None` when the server was launched without
/// `into_make_service_with_connect_info`, in which case the per-IP
/// rate limiter is skipped (the global concurrency gate still
/// applies).
fn peer_ip_from_request(req: &Request<Body>) -> Option<IpAddr> {
    req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip())
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

    // Per-source-IP rate limit. Runs first so a hostile sender's
    // CPU spend per delivery stays at "header parse" before we even
    // resolve the secret. Skipped when the server was not launched
    // with `into_make_service_with_connect_info` (peer IP absent).
    if let Some(limiter) = cfg.rate_limit.as_ref() {
        if let Some(ip) = peer_ip_from_request(&req) {
            if !limiter.admit(ip) {
                return Err(ApiError::TooManyRequests(format!(
                    "webhook rate limit exceeded for `{ip}`"
                )));
            }
        }
    }

    // Global concurrency cap on the handler. Holding the permit
    // until end-of-handler covers HMAC verification + body buffer +
    // scan-trigger dispatch.
    let _permit = if let Some(limit) = cfg.concurrency.as_ref() {
        match limit.try_acquire() {
            Some(permit) => Some(permit),
            None => {
                return Err(ApiError::TooManyRequests(
                    "webhook concurrency limit reached".to_string(),
                ));
            }
        }
    } else {
        None
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
    let run_id = trigger.trigger(ScanTriggerSource::Webhook, None, cfg.repo.clone()).await?;
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
    fn rate_limiter_admits_until_bucket_empty() {
        let limiter = WebhookRateLimiter::new(3, 0.0, 16);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.admit(ip));
        assert!(limiter.admit(ip));
        assert!(limiter.admit(ip));
        assert!(!limiter.admit(ip), "fourth request must be refused");
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        // 1 token / second refill. Bucket size 2.
        let limiter = WebhookRateLimiter::new(2, 1.0, 16);
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let t0 = Instant::now();
        assert!(limiter.admit_at(ip, t0));
        assert!(limiter.admit_at(ip, t0));
        // Same instant: bucket empty.
        assert!(!limiter.admit_at(ip, t0));
        // One second later: one token regenerated.
        let t1 = t0 + std::time::Duration::from_secs(1);
        assert!(limiter.admit_at(ip, t1));
        // Immediately after: empty again.
        assert!(!limiter.admit_at(ip, t1));
        // Five seconds later: bucket fully refilled, but cap at 2.
        let t6 = t1 + std::time::Duration::from_secs(5);
        assert!(limiter.admit_at(ip, t6));
        assert!(limiter.admit_at(ip, t6));
        assert!(!limiter.admit_at(ip, t6));
    }

    #[test]
    fn rate_limiter_per_ip_buckets_are_independent() {
        let limiter = WebhookRateLimiter::new(1, 0.0, 16);
        let a: IpAddr = "127.0.0.1".parse().unwrap();
        let b: IpAddr = "127.0.0.2".parse().unwrap();
        assert!(limiter.admit(a));
        // a is exhausted; b still has its own token.
        assert!(!limiter.admit(a));
        assert!(limiter.admit(b));
    }

    #[test]
    fn rate_limiter_per_minute_helper_matches_rate() {
        // 60/min == 1 token / second refill, with burst depth 60.
        let limiter = WebhookRateLimiter::per_minute(60, 64);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..60 {
            assert!(limiter.admit_at(ip, t0));
        }
        assert!(!limiter.admit_at(ip, t0));
    }

    #[test]
    fn rate_limiter_evicts_oldest_ip_at_cap() {
        let limiter = WebhookRateLimiter::new(1, 0.0, 2);
        let t0 = Instant::now();
        let a: IpAddr = "127.0.0.1".parse().unwrap();
        let b: IpAddr = "127.0.0.2".parse().unwrap();
        let c: IpAddr = "127.0.0.3".parse().unwrap();
        assert!(limiter.admit_at(a, t0));
        assert!(limiter.admit_at(b, t0 + std::time::Duration::from_secs(1)));
        assert!(limiter.admit_at(c, t0 + std::time::Duration::from_secs(2)));
        // `a` was oldest; it should have been evicted to make room
        // for `c`, so the map carries `b` and `c` only.
        assert_eq!(limiter.tracked_ips(), 2);
    }

    #[test]
    fn concurrency_limit_refuses_past_cap() {
        let limit = WebhookConcurrencyLimit::new(2);
        let p1 = limit.try_acquire().expect("first permit");
        let p2 = limit.try_acquire().expect("second permit");
        assert!(limit.try_acquire().is_none(), "third acquire must fail when cap is reached");
        drop(p1);
        assert!(limit.try_acquire().is_some(), "releasing a permit must make one available again");
        drop(p2);
    }

    #[test]
    fn concurrency_limit_floor_is_one() {
        let limit = WebhookConcurrencyLimit::new(0);
        assert_eq!(limit.permits(), 1);
        assert!(limit.try_acquire().is_some());
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
