//! Loopback HTTP + WebSocket surface for the nyctos daemon.
//!
//! The binary in [`nyctos`] owns the long-lived daemon process and
//! wires three things into [`ServerState`]:
//!
//! - a connected [`nyctos_core::Store`] for read-only queries,
//! - a tokio broadcast sink ([`nyctos_types::event::EventSink`])
//!   that the run dispatcher publishes lifecycle events through,
//! - a [`ScanTrigger`] handle the API uses to kick off a manual scan.
//!
//! Subscribers attach to the broadcast sink through the
//! `/api/v1/events?run_id=<id>` WebSocket endpoint without the
//! dispatcher knowing about them.

pub mod router;
pub mod state;
pub mod webhook;

pub use router::build_router;
pub use state::{
    ApiError, AuthConfig, EventReplay, ScanRunOverrides, ScanTrigger, ScanTriggerError,
    ScanTriggerSource, ServerState, SetupContext,
};
pub use webhook::{
    sign as sign_webhook, verify_signature as verify_webhook_signature, EnvSecretResolver,
    StaticSecretResolver, WebhookConcurrencyLimit, WebhookConfig, WebhookRateLimiter,
    WebhookResponse, WebhookSecretResolver, DEFAULT_WEBHOOK_MAX_CONCURRENT,
    DEFAULT_WEBHOOK_RATE_LIMIT_BURST, DEFAULT_WEBHOOK_RATE_LIMIT_MAX_IPS,
    DEFAULT_WEBHOOK_RATE_LIMIT_PER_MINUTE, MAX_WEBHOOK_BODY_BYTES,
};
