// Shared serde structs, enums, and event-bus types used by every other
// nyx-agent crate. No logic lives here. Each placeholder module gets
// populated by the phase that owns its surface area.

pub mod agent;
pub mod budget;
pub mod chain;
pub mod event;
pub mod finding;
pub mod novel;
pub mod payload;
pub mod repo;
pub mod run;
pub mod spec;
pub mod verify;

pub use event::{
    AgentEvent, AiEvent, BudgetEvent, EventSink, EventStream, FindingEvent, QuarantineEvent,
    RepoOutcomeTag, ReproEvent, RunEvent, SandboxEvent,
};
pub use verify::{Oracle, VerifyResult, VerifyRun, VerifyVerdict};
