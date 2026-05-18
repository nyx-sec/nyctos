//! Phase 27: `POST /webhook/git` route.
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

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
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
        // Refuse empty secrets — an empty key satisfies the HMAC API
        // but trivially accepts any HMAC over the empty byte string,
        // which is not authentication.
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
}

/// Body shape we extract. Extra fields are tolerated.
#[derive(Debug, Deserialize)]
struct WebhookPayload {
    /// `refs/heads/<branch>` for push events.
    #[serde(rename = "ref", default)]
    pub ref_: Option<String>,
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
            "webhook not enabled; set [triggers].webhook_secret_ref in nyx-agent.toml".to_string(),
        ));
    };

    let Some(secret) = cfg.secret.resolve() else {
        // Webhook is configured but the secret cannot be resolved
        // (e.g. unset env var). Refuse the delivery — accepting it
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
    // header short-circuits without buffering.
    let sig_header = req
        .headers()
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(ApiError::Unauthorized)?;

    let (_parts, body) = req.into_parts();
    let body_bytes = to_bytes(body, MAX_WEBHOOK_BODY_BYTES).await.map_err(|e| {
        ApiError::BadRequest(format!("webhook body exceeded limit or failed to read: {e}"))
    })?;

    if !verify_signature(&secret, body_bytes.as_ref(), &sig_header) {
        return Err(ApiError::Unauthorized);
    }

    // Best-effort decode. A non-JSON body that still verified is
    // accepted (some upstream form-encoded payloads include a JSON
    // value as the `payload` form field; we tolerate that by reading
    // `ref` only when the top-level body is JSON-shaped).
    let parsed: Option<WebhookPayload> = serde_json::from_slice(body_bytes.as_ref()).ok();
    let branch = parsed
        .as_ref()
        .and_then(|p| p.ref_.as_deref())
        .and_then(|r| r.strip_prefix("refs/heads/"))
        .map(|s| s.to_string());

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
    let run_id = trigger.trigger(cfg.repo.clone()).await?;
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
}
