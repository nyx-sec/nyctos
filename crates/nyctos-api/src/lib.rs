//! Loopback HTTP + WebSocket surface for the nyx-agent daemon.
//!
//! The binary in [`nyx-agent`] owns the long-lived daemon process and
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
    ApiError, AuthConfig, EventReplay, ScanTrigger, ScanTriggerError, ServerState, SetupContext,
};
pub use webhook::{
    sign as sign_webhook, verify_signature as verify_webhook_signature, EnvSecretResolver,
    StaticSecretResolver, WebhookConfig, WebhookResponse, WebhookSecretResolver,
    MAX_WEBHOOK_BODY_BYTES,
};
