//! Loopback HTTP + WebSocket surface for the nyx-agent daemon.
//!
//! The binary in [`nyx-agent`] owns the long-lived daemon process and
//! wires three things into [`ServerState`]:
//!
//! - a connected [`nyx_agent_core::Store`] for read-only queries,
//! - a tokio broadcast sink ([`nyx_agent_types::event::EventSink`])
//!   that the run dispatcher publishes lifecycle events through,
//! - a [`ScanTrigger`] handle the API uses to kick off a manual scan.
//!
//! Subscribers attach to the broadcast sink through the
//! `/api/v1/events?run_id=<id>` WebSocket endpoint without the
//! dispatcher knowing about them.

pub mod router;
pub mod state;

pub use router::build_router;
pub use state::{ApiError, ScanTrigger, ScanTriggerError, ServerState};
