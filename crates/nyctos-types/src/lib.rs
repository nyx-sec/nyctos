// Shared serde structs, enums, and event-bus types used by every other
// nyctos crate. No logic lives here. Each placeholder module gets
// populated by the phase that owns its surface area.

pub mod agent;
pub mod api;
pub mod attack_graph;
pub mod budget;
pub mod business_logic;
pub mod chain;
pub mod event;
pub mod finding;
pub mod live_plan;
pub mod novel;
pub mod payload;
pub mod product;
pub mod project;
pub mod repo;
pub mod run;
pub mod spec;
pub mod trace;
pub mod verify;

pub use event::{
    AgentEvent, AiEvent, BudgetEvent, EventSink, EventStream, FindingEvent, QuarantineEvent,
    RepoOutcomeTag, ReproEvent, RunEvent, SandboxEvent,
};
pub use live_plan::{
    BrowserOracle, BrowserStep, BrowserWorkflowPlan, DifferentialHttpPlan, DifferentialOracle,
    HttpOracle, HttpWorkflowPlan, LiveHttpRequest, LivePlanValidationError, LiveTestPlan,
    NoPlanReason, NoPlanReasonCode, SingleHttpPlan,
};
pub use verify::{Oracle, VerifyResult, VerifyRun, VerifyVerdict};
