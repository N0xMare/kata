//! Typed Rust SDK for the kata REST + SSE API.
//!
//! ```no_run
//! use kata_client::KataClient;
//! use std::time::Duration;
//!
//! # async fn run() -> Result<(), kata_client::KataClientError> {
//! let client = KataClient::new("http://127.0.0.1:8400")?;
//!
//! // Health probe
//! let health = client.health().await?;
//! assert!(health.is_healthy() || health.is_unavailable());
//!
//! // Submit and wait
//! let execution = client.run("self-review").await?;
//! let record = execution.wait_for_terminal(Duration::from_secs(60)).await?;
//! println!("status: {:?}", record.status);
//! # Ok(())
//! # }
//! ```
//!
//! ## Surface
//!
//! * [`KataClient`] — every REST endpoint kata speaks today
//!   (`/health`, `/system/status`, `/workflows`, `/executions`,
//!   `/approvals`, `/agents/run`, `/workers`, `/events`).
//! * [`Execution`] — typed handle to a submitted workflow. Knows how
//!   to poll for terminal status and subscribe to filtered SSE.
//! * [`EventStream`] — `futures::Stream` of typed
//!   [`types::LedgerEvent`]s.
//! * [`EventFrameStream`] — frame-level SSE stream that preserves
//!   ledger and progress frames for live observability.
//! * [`KataClientError`] — every failure mode the SDK can surface.
//!
//! ## The operation vocabulary is the contract's
//!
//! Where a method fronts a class-A operation, it
//! is SPELLED with that operation's own word from `kata_op_contract::Operation`
//! — `run`, `observe`, `list`, `approve`, `reject`, `cancel`, `promote`. The
//! contract's spelling won because it is the only VERSIONED one of the three
//! agent-facing vocabularies (SDK, MCP `tools/list`, `Operation::ALL`), so it
//! is the only one on which changing a name has a compatibility story. So the
//! SDK follows it: [`KataClient::run`], [`KataClient::observe`],
//! [`KataClient::list`], with the argument-shape variants following their stems
//! (`run_with_params`, `run_starlark`, `list_filtered`).
//!
//! Two bounds a reader should hold:
//!
//! * It is a SPELLING convergence, not a payload one. [`KataClient::observe`]
//!   still returns an `ExecutionRecord`, not the contract's `ObserveResponse`,
//!   and [`KataClient::list`] returns full records rather than `ListResponse`.
//!   These methods call the bespoke REST routes, not `POST /ops/{operation}`.
//! * [`KataClient::run_agent`] is `POST /api/v1/agents/run` — ONE agent call.
//!   It is not the `run` operation and not a shape of it.
//!
//! Three operations have no method here at all: `author` and `check` are
//! workstation-local, and `discharge_stop` is reachable only through the
//! untyped [`KataClient::invoke_op`]. [`KataClient::forge_reconcile`] is the
//! one typed method over `POST /ops/{operation}`: it decodes the operation's
//! envelope, a refusal as [`KataClientError::OperationRefused`]. The convention
//! fixes what the operations this SDK fronts are CALLED, not which ones it
//! fronts.
//!
//! ## What this SDK does NOT do
//!
//! * No `unix://` support. The kata API only binds TCP today; the
//!   only Unix-socket transport in the workspace is the worker
//!   transport, which speaks a different protocol.
//! * No SSE auto-reconnect. `EventStream` ends on transport close;
//!   callers wrap their own retry loop if they want resilience.
//! * The SDK carries an opaque bearer token, it does not mint one.
//!   When the server runs in `ApiAuthConfig::SignedToken` mode, use
//!   [`KataClient::with_bearer_token`] or
//!   [`KataClient::new_with_env_token`] to inject a scoped signed
//!   token (minted by the main) as the `Authorization` header.

#![allow(clippy::doc_overindented_list_items)]

pub mod client;
pub mod error;
pub mod events;
pub mod execution;
pub mod operator_projection;
pub mod types;

pub use client::{CancelOutcome, CurrentExecution, KataClient, VersionInfo};
pub use error::KataClientError;
pub use events::{EventFrame, EventFrameStream, EventStream};
pub use execution::Execution;
pub use kata_op_contract::responses::{ReconciledForgeExport, ReconciledForgeIntent};
pub use types::{
    AgentRunAgentCapability, AgentRunCapabilities, AgentRunFeatureFlags, AgentRunId,
    AgentRunLocalCapacity, AgentRunOutput, AgentRunRequest, AgentRunResult, AgentRunStatus,
    CHECK_ARTIFACT_EVIDENCE_SCHEMA_VERSION, CHECKED_RUNTIME_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION, EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION,
    EXTERNAL_INPUT_TEXT_MAX_CHARS, ExecutionCheckArtifactEvidence,
    ExecutionCheckedRuntimeAuthorityEvidence, ExecutionCloseoutEvidence,
    ExecutionControllerApplyFinalizeRequest, ExecutionControllerApplyRequest,
    ExecutionControllerApplyResponse, ExecutionControllerDecisionEvidence, ExecutionEvidence,
    ExecutionExternalInputAppendRequest, ExecutionExternalInputAppendResponse,
    ExecutionExternalInputEvidence, ExecutionHumanRequestAnswerRequest,
    ExecutionHumanRequestAnswerResponse, ExecutionHumanRequestEvidence,
    ExecutionMemoryWritebackEvidence, ExecutionProgramIdentity, ExecutionRecord, ExecutionStatus,
    ExecutionValidationCandidateEvidence, ExecutionValidationCriterionEvidence,
    ExecutionValidationCriterionStatus, ExecutionValidationEvidence,
    HUMAN_REQUEST_ANSWER_SUMMARY_MAX_CHARS, HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION, HealthSnapshot,
    LedgerEvent, MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION, MemoryObject, MemoryObjectKind,
    MemoryObjectStatus, MemoryProposal, MemoryProposalResponse, MemorySnapshot, PendingApproval,
    ProgressEvent, SubsystemHealth, SystemStatus, VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION,
    WorkerInventory, WorkflowFormat, WorkflowLibraryEntry, WorkflowSummary,
};
