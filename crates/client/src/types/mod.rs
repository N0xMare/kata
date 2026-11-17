//! Wire types of the kata REST + SSE API.
//!
//! Every type that crosses the wire lives in `kata-types`, so the SDK
//! re-exports them rather than carrying per-field mirrors that would have
//! to be kept byte-identical to the server's serde definition — the SDK's
//! job is just to pin the canonical types into a stable namespace.
//!
//! The pure re-export surfaces (agent-run, ledger/SSE, execution,
//! health, memory, worker, workspace-awareness) are grouped as
//! `pub use kata_types::…` blocks below, so `kata_client::types::*`
//! stays the stable façade without a shim file per wire type.
//!
//! Two sub-modules stay locally defined because their JSON shapes
//! are built ad-hoc by the relevant axum handlers (no canonical Rust
//! type to share), so the SDK keeps owning those structs:
//!
//! * [`workflow`]   — `GET /api/v1/workflows` and `GET /api/v1/workflows/{name}`
//!   payloads.
//! * [`system`]     — `GET /api/v1/system/status` payload.

pub mod system;
pub mod workflow;

pub use crate::error::DiagnosticContextValue;
pub use system::SystemStatus;
pub use workflow::{WorkflowFormat, WorkflowLibraryEntry, WorkflowSummary};

// Pure re-exports of canonical `kata-types` wire surfaces. Grouped
// here instead of a shim file per surface; external paths stay
// `kata_client::types::*`.
pub use kata_types::agent_run::{
    AgentRunAgentCapability, AgentRunCapabilities, AgentRunFeatureFlags, AgentRunId,
    AgentRunLocalCapacity, AgentRunOutput, AgentRunRequest, AgentRunResult, AgentRunStatus,
};
pub use kata_types::approval::PendingApproval;
pub use kata_types::execution::{
    CHECK_ARTIFACT_EVIDENCE_SCHEMA_VERSION, CHECKED_RUNTIME_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION, CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION,
    EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION, EXTERNAL_INPUT_TEXT_MAX_CHARS,
    ExecutionCheckArtifactEvidence, ExecutionCheckedRuntimeAuthorityEvidence,
    ExecutionCloseoutEvidence, ExecutionControllerApplicationContext,
    ExecutionControllerApplicationEvidence, ExecutionControllerApplicationRecoveryEvidence,
    ExecutionControllerApplyFinalizeRequest, ExecutionControllerApplyRequest,
    ExecutionControllerApplyResponse, ExecutionControllerCompletionEvidence,
    ExecutionControllerDecisionEvidence, ExecutionControllerDecisionScopeEvidence,
    ExecutionControllerMemoryPolicyEvidence, ExecutionControllerRuntimePolicyEvidence,
    ExecutionEvidence, ExecutionExternalInputAppendRequest, ExecutionExternalInputAppendResponse,
    ExecutionExternalInputEvidence, ExecutionHumanRequestAnswerRequest,
    ExecutionHumanRequestAnswerResponse, ExecutionHumanRequestEvidence,
    ExecutionMemorySelectorEvidence, ExecutionMemoryWritebackEvidence, ExecutionProgramIdentity,
    ExecutionRecord, ExecutionStatus, ExecutionValidationCandidateEvidence,
    ExecutionValidationCriterionEvidence, ExecutionValidationCriterionStatus,
    ExecutionValidationEvidence, HUMAN_REQUEST_ANSWER_SUMMARY_MAX_CHARS,
    HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION, MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION,
    ParkedExecution, VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
};
pub use kata_types::health::{HealthSnapshot, SubsystemHealth};
pub use kata_types::ledger::{LedgerEvent, ProgressEvent};
pub use kata_types::memory::{
    MemoryObject, MemoryObjectKind, MemoryObjectStatus, MemoryProposal, MemoryProposalResponse,
    MemorySnapshot,
};
pub use kata_types::worker::WorkerInventory;
pub use kata_types::workspace_awareness::{
    ExecutionWorkspacePromotion, ExecutionWorkspaceSnapshot, ExecutionWorkspaceWorktree,
    WORKSPACE_AWARENESS_SCHEMA_VERSION, WorkspaceAwarenessSnapshot,
};
