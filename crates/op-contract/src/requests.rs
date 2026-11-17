//! Typed request struct per class-A operation.
//!
//! Minimal + owned (only primitives) so the struct derives `JsonSchema`
//! cleanly and stays a pure leaf. The shared dispatch
//! (`kata_api::op_dispatch`) deserializes the `POST /api/v1/ops/{operation}`
//! body into them, and the MCP server deserializes `tools/call` params into them
//! for the forms it serves at the caller. The REST resource routes and the Rust
//! SDK's typed methods have request types of their own (`KataClient::approve`
//! posts an `assignment_id` to `/executions/{id}/approve`), so these structs bind
//! the `/ops` and MCP faces, not every face.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `Operation::Author` — scaffold project-local config (`kata init`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuthorRequest {
    /// Config file to create (e.g. `.kata/kata.toml`).
    pub config: String,
    /// Replace an existing config after writing a timestamped backup.
    #[serde(default)]
    pub force: bool,
    /// Render the generated TOML without touching the filesystem.
    #[serde(default)]
    pub print: bool,
}

/// `Operation::Check` — compile + check a workflow into the checked IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CheckRequest {
    /// Workflow library name or path to a `.star` workflow. A name resolves
    /// against the serving face's library: the node's on the REST `/ops` face
    /// and for an attached `kata mcp`. A path, which only a face running on the
    /// caller's machine can read, is checked there (the CLI, `kata mcp`); the
    /// REST face answers it `not_found`. `None` with `all == true` checks every
    /// effective library workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    /// Check every effective workflow in the layered library. Served on the
    /// caller's machine (the CLI, `kata mcp`); the REST face refuses it `usage`.
    #[serde(default)]
    pub all: bool,
    /// Treat verifier warnings as a failure.
    #[serde(default)]
    pub deny_warnings: bool,
}

/// Default bound on [`RunRequest::wait`], in seconds, when the request sets
/// `wait` without a [`RunRequest::wait_timeout_secs`].
///
/// 30s is chosen so the *node's* bound always fires before the caller's. The
/// common transport floor is 60s (an nginx `proxy_read_timeout` and an AWS ALB
/// idle timeout are both 60s by default), and the CLI's own `--timeout-secs`
/// default is 60. A wait that outlives the transport hands the agent a dropped
/// connection instead of the structured "still running" envelope this bound
/// exists to produce — strictly worse than not honoring `wait` at all. 30s
/// leaves 2x headroom for boot and dispatch.
///
/// The transport floor is the LOAD-BEARING reason and the only one the number is
/// derived from. Head-of-line blocking reinforces it but does not set it:
/// `kata mcp`'s JSON-RPC loop awaits each request before reading the next line,
/// so a blocking `run` holds the agent's every other call — an `observe` or a
/// `list` — until the wait returns.
pub const DEFAULT_RUN_WAIT_SECS: u64 = 30;

/// Ceiling on [`RunRequest::wait_timeout_secs`], in seconds. A larger value is
/// REFUSED with a usage error naming the field — never silently clamped, since
/// silently honoring less than the caller asked for is the same false
/// advertisement the bounded wait exists to remove.
///
/// 50s sits inside the 60s transport floor described on
/// [`DEFAULT_RUN_WAIT_SECS`] with margin. This is a judgement about deployments
/// kata does not own, not a measurement: nothing in this repo pins how long an
/// operator's reverse proxy will hold a POST open.
pub const MAX_RUN_WAIT_SECS: u64 = 50;

/// `Operation::Run` — submit a workflow for execution.
///
/// A run carries EXACTLY ONE workflow source: either a library reference
/// (`workflow`) or an inline Starlark body (`workflow_starlark`). The inline
/// body lets a pure-MCP agent author and submit a BRAND-NEW workflow through the
/// contract — it is compiled through the same checked frontend the REST
/// `workflow_starlark` submission uses (`load()` resolves against the node's
/// library roots), so a bad body returns structured compile diagnostics instead
/// of booting. Setting both sources, or neither, is a usage error.
///
/// `wait` is a BOUNDED wait, honored by the shared dispatch itself. It
/// never blocks indefinitely — see [`DEFAULT_RUN_WAIT_SECS`] and
/// [`MAX_RUN_WAIT_SECS`] — and a wait that expires is a SUCCESS carrying
/// [`crate::responses::RunResponse::wait_timed_out`], not an error, because the
/// submission did happen and the caller still needs the `execution_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunRequest {
    /// Workflow library name or path to a `.star` workflow. A path is read on
    /// the caller's machine and submitted as `workflow_starlark` by the faces
    /// that run there (the CLI, `kata mcp`); the REST face resolves only names.
    /// Mutually exclusive with `workflow_starlark`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    /// Inline Starlark workflow source to author + submit in one call. Compiled
    /// through the checked frontend; `load()` statements resolve against the
    /// node's configured workflow library roots. Mutually exclusive with
    /// `workflow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_starlark: Option<String>,
    /// Diagnostic filename for inline-Starlark parse errors and import
    /// provenance. Ignored unless `workflow_starlark` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_filename: Option<String>,
    /// Typed invocation params as a `{name: value}` object, resolved +
    /// default-filled against the workflow's declared `workflow(params=..)`
    /// contract at admission. Omitting it (or `{}`) submits with no supplied
    /// params — a workflow with a required param then fails with the stable
    /// `param.missing_required` code. Same object shape and same resolution as
    /// every other face.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub params: serde_json::Map<String, serde_json::Value>,
    /// What an isolated run works on: `trunk`, the default when omitted, or
    /// `pr:<N>`, the forge's pull request N. Parsed by the one target parser
    /// every face uses and resolved and frozen at admission; a target on a
    /// workflow that forks no isolated workspace is refused
    /// (`target_requires_isolated_workspace`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Poll until the execution reaches a terminal state OR the bound elapses,
    /// then return. The bound is [`DEFAULT_RUN_WAIT_SECS`] unless
    /// `wait_timeout_secs` overrides it. When the bound elapses first the call
    /// still SUCCEEDS, with `terminal: false` and `wait_timed_out: true`, and
    /// the caller resumes with `observe` on the returned `execution_id`.
    ///
    /// This shares its shape — not its code — with the client SDK poller
    /// (`kata_client::execution::Execution::wait_for_terminal_with`): same
    /// 500ms cadence, same "the deadline is not a run failure" polarity. There
    /// is deliberately no shared helper; `kata-client` does not depend on
    /// `kata-api` and the reverse would drag an HTTP client into the server.
    #[serde(default)]
    pub wait: bool,
    /// Bound on `wait`, in seconds. Ignored — and REFUSED — unless `wait` is
    /// set. Must be `1..=`[`MAX_RUN_WAIT_SECS`]; `0` or a larger value is a
    /// usage error rather than a silent clamp. Omitted means
    /// [`DEFAULT_RUN_WAIT_SECS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_timeout_secs: Option<u64>,
}

/// `Operation::Observe` — read an execution's state projection
/// ([`crate::responses::ObserveResponse`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ObserveRequest {
    /// Execution id (Ulid as a string).
    pub execution_id: String,
}

/// `Operation::List` — enumerate recent executions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ListRequest {
    /// Maximum number of executions to return, most-recently-submitted first.
    /// `None` uses the default cap ([`crate::responses::DEFAULT_LIST_LIMIT`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `Operation::Approve` — approve the execution's ONE parked human gate. An
/// execution with two or more parked gates is refused `conflict`; each is approved
/// by its assignment id on `POST /api/v1/executions/{id}/approve`.
///
/// Unknown fields are refused: a field the dispatch would not read must not ride
/// along on an authorizing request as if it narrowed what is approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    /// Execution id whose gate is being approved.
    pub execution_id: String,
}

/// `Operation::Reject` — reject a parked human gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RejectRequest {
    /// Execution id whose gate is being rejected.
    pub execution_id: String,
    /// Operator-supplied rejection reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `Operation::Cancel` — cancel an in-flight execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CancelRequest {
    /// Execution id to cancel.
    pub execution_id: String,
}

/// `Operation::Promote` — promote a candidate execution's workspace.
///
/// Unknown fields are refused: a field the dispatch would not read must not ride
/// along on an authorizing request as if it were checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PromoteRequest {
    /// Execution id to promote.
    pub execution_id: String,
}

/// `Operation::ForgeReconcile` — drive an execution's pending forge exports
/// now, each open intent's observer asked at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ForgeReconcileRequest {
    /// Execution id whose pending `forge_export`s to reconcile.
    pub execution_id: String,
}

/// `Operation::DischargeStop` — discharge an outstanding worker stop on an
/// attributed operator assertion.
///
/// # There is no probe mode
///
/// Nothing in kata can prove a worker PROCESS has exited — heartbeat loss is not
/// proof of process exit, which is the premise of the second conjunct
/// `require_terminal_lifecycle_for_parking` had to add. So the only honest
/// provenance here is a human's, `operator` is unconditionally REQUIRED rather
/// than conditionally, and the durable record carries `rests_on_a_proof: false`
/// always.
///
/// The consequence worth stating: this operation cannot be automated against. A
/// caller wanting to clear stops in bulk on a worker-death signal is asking for
/// an automatic discharge, and kata has none: every discharge rests on an
/// attributed operator's assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DischargeStopRequest {
    /// Execution id holding the outstanding stop.
    pub execution_id: String,
    /// The attempt the stop was addressed to — copied from the `attempt_id` field
    /// of the `worker_stops` evidence row that carries
    /// `awaiting_worker_acknowledgement: true`.
    pub attempt_id: String,
    /// The GENERATION the stop was addressed to, from the same evidence row's
    /// `lease_epoch`.
    ///
    /// Required, and not defaulted to the attempt's current epoch: a stop is
    /// keyed by `(attempt_id, lease_epoch)`, and the discharge names the exact
    /// row the evidence showed rather than one resolved on the operator's behalf.
    pub lease_epoch: i64,
    /// Who is asserting. Required — an unattributed assertion is indistinguishable
    /// from a machine observation to everyone reading the record later, which is
    /// the whole reason the provenance is recorded at all.
    ///
    /// Under a signed-token API it must be the token's `issued_for` — the name the
    /// transport proved — and any other is refused `usage`. Where no identity is
    /// proved (a loopback listener with auth disabled) it is the caller's word.
    pub operator: String,
    /// What the operator established, in their own words (e.g. "worker host
    /// terminated; PID 4711 is gone"). Recorded verbatim in the durable discharge.
    ///
    /// Required and non-empty: a discharge whose record says only that an operator
    /// did it tells the next reader nothing about what was checked.
    pub assertion: String,
}
