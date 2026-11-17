//! The shared operation dispatch behind every face.
//!
//! [`invoke_operation`] is the single anti-drift seam: one exhaustive `match`
//! over [`Operation`] that binds each class-A operation to its
//! [`WorkflowExecutor`] method. The faces that reach it are the REST
//! `POST /ops/{operation}` route ([`crate::rest::ops`]) and what rides that route:
//! the attached `kata mcp` binding's proxy (`kata::cli::mcp`),
//! `kata run discharge-stop`, and `kata run forge-reconcile` through the Rust
//! SDK's `forge_reconcile`. The CLI's other verbs (`kata run approve`,
//! `reject`, `cancel`, `promote`, …) and the SDK's other typed methods use the
//! REST resource routes, which call the executor themselves, and the workstation-local
//! forms (`author`, a path-form or `all` `check`) are served by the CLI and the
//! MCP binding without it. Because the `match` is exhaustive, adding an
//! [`Operation`] variant fails to compile until it is bound here.
//!
//! `op-contract` is a serde/schemars leaf and cannot depend on the executor, so
//! the dispatch that actually reaches an `Arc<WorkflowExecutor>` lives here in
//! `kata-api` (which depends on both). The faces deserialize the *same*
//! `op-contract` request/response structs, so payload drift is already
//! structurally impossible; this dispatch adds the single runtime binding they
//! all share.
//!
//! ## Operation → executor binding
//!
//! | Operation | Executor method | Notes |
//! |-----------|-----------------|-------|
//! | `Check`   | [`WorkflowExecutor::compile_ref_artifact`] | compile + verify a single named workflow into a [`kata_op_contract::responses::CheckResponse`]; `all == true` is a workstation-local operation and returns a usage error on the engine face. |
//! | `Run`     | [`WorkflowExecutor::compile_ref_execution_program`] (library ref) or [`crate::executor::compile_inline_starlark_execution_program`] (inline `.star` body) + [`WorkflowExecutor::submit_execution_program`] | submit a compiled program; returns the new execution id + status. A run carries exactly one source (ref XOR inline body); a bad inline body returns structured compile diagnostics as a `usage` error. `wait` is honored HERE, bounded by `wait_timeout_secs` (default [`kata_op_contract::requests::DEFAULT_RUN_WAIT_SECS`], ceiling [`kata_op_contract::requests::MAX_RUN_WAIT_SECS`]); an expired bound is a SUCCESS carrying `wait_timed_out: true`, never an error. |
//! | `Observe` | [`WorkflowExecutor::get_execution`] | read one execution record projection, enriched with current/last stage, failure reason, stage outputs, wave/iteration, and terminal detail. |
//! | `List`    | [`WorkflowExecutor::list_executions`] | enumerate recent executions (id, status, workflow name, started) so a caller that lost an `execution_id` can recover it. |
//! | `Approve` | [`WorkflowExecutor::approve`] | resolves the parked assignment for the execution first. |
//! | `Reject`  | [`WorkflowExecutor::reject`] | as approve, then records a rejection reason. |
//! | `Cancel`  | [`WorkflowExecutor::cancel`] | Asks every live attempt's worker to stop, recording the ask durably first; returns whether any was ASKED (`stop_requested`). Terminal runs are idempotent (`false`). The worker's own terminal frame is the acknowledgement, and parking refuses until it lands. |
//! | `Promote` | [`WorkflowExecutor::promote`] | promote a candidate execution workspace. |
//! | `ForgeReconcile` | [`WorkflowExecutor::reconcile_forge_exports`] | Drive the execution's pending forge exports now, each open intent's observer asked at once; answers each export as it then stands. Refused (`conflict`) for an execution whose authoritative lifecycle is not `Running`, or that has no pending export. |
//! | `DischargeStop` | [`WorkflowExecutor::discharge_worker_stop`] | Discharge one outstanding worker stop on an ATTRIBUTED operator assertion — the exit from the outstanding-stop latch, which otherwise refuses the execution's workspace reclaim forever. There is NO probe mode: nothing can prove a worker process exited. |
//! | `Author`  | (none) | project scaffolding is a workstation-local CLI/MCP operation (`kata init`), not served by an execution node; the engine face returns a usage error. |

use std::sync::Arc;

use kata_op_contract::requests::{
    ApproveRequest, CancelRequest, CheckRequest, DEFAULT_RUN_WAIT_SECS, DischargeStopRequest,
    ForgeReconcileRequest, ListRequest, MAX_RUN_WAIT_SECS, ObserveRequest, PromoteRequest,
    RejectRequest, RunRequest,
};
use kata_op_contract::responses::{
    ApproveResponse, CancelResponse, CheckResponse, DEFAULT_LIST_LIMIT, DischargeStopResponse,
    ExecutionSummary, ForgeReconcileResponse, ListResponse, ObserveResponse, PromoteResponse,
    ReconciledForgeExport, ReconciledForgeIntent, RejectResponse, RunResponse, StageCapsuleNetwork,
};
use kata_op_contract::{OpEnvelope, OpError, Operation};
use kata_program::execution_program::{
    ExecutionProgram, VerifierReport, VerifierSeverity, VerifierStatus,
};
use kata_types::approval::ApprovalPrincipal;
use kata_types::execution::{ExecutionRecord, ExecutionStatus};
use kata_types::identity::ApiScope;
use kata_types::ledger::AgentInvocationStatus;
use kata_types::target::TargetSpec;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use ulid::Ulid;

use crate::executor::{
    ApprovalFailure, ExecutorError, StopDischargeAssertion, WorkflowExecutor, WorktreeFailure,
};

/// Dispatch one operation against a booted engine, returning the operation's
/// typed response payload as a JSON value (the caller wraps it in an
/// [`OpEnvelope`]) or a machine-classified [`OpError`].
///
/// The `match` over [`Operation`] is exhaustive: a new variant does not compile
/// until it is bound here. That is the structural anti-drift guarantee — no face
/// can silently ship an operation the shared dispatch has not bound.
///
/// # Errors
///
/// Returns an [`OpError`] with a deterministic [`kata_op_contract::OpErrorCode`]
/// for a malformed request (`usage`), a missing execution/workflow
/// (`not_found`), a state conflict (`conflict`), or an engine-internal failure
/// (`engine`).
pub async fn invoke_operation(
    engine: &Arc<WorkflowExecutor>,
    op: Operation,
    arguments: Value,
) -> Result<Value, OpError> {
    invoke_operation_as(engine, op, arguments, None).await
}

/// [`invoke_operation`] on behalf of the `principal` the calling TRANSPORT proved.
///
/// A gate's decision records the principal, so approving or rejecting one through a
/// face that proves none (`None` — [`invoke_operation`]'s callers, the MCP face of the
/// CLI/MCP/API conformance test among them) is refused
/// `approval_principal_unproven`. A `discharge_stop` under a proved token must name
/// that token's `issued_for` as its `operator` ([`discharge_stop`]). The REST `/ops`
/// face passes the principal its auth layer attached (`crate::auth::ApiPrincipal`).
///
/// # Errors
///
/// [`invoke_operation`]'s.
async fn invoke_operation_as(
    engine: &Arc<WorkflowExecutor>,
    op: Operation,
    arguments: Value,
    principal: Option<&kata_types::approval::ApprovalPrincipal>,
) -> Result<Value, OpError> {
    match op {
        // Author (project scaffolding) is a workstation-local operation: its
        // starter templates and `ConfigManager` wiring live in the CLI/MCP local
        // binding (`kata init`), not in the execution engine. The engine face
        // classifies it as a usage error rather than pretending to serve it.
        Operation::Author => Err(OpError::usage(
            "author (project scaffolding) is a workstation-local operation served \
             by the CLI (`kata init`) and the MCP local binding; an execution \
             node does not scaffold project config",
        )),
        Operation::Check => check(engine, arguments),
        Operation::Run => run(engine, arguments).await,
        Operation::Observe => observe(engine, arguments),
        Operation::List => list(engine, arguments),
        Operation::Approve => approve(engine, arguments, principal).await,
        Operation::Reject => reject(engine, arguments, principal),
        Operation::Cancel => cancel(engine, arguments).await,
        Operation::Promote => promote(engine, arguments),
        Operation::DischargeStop => discharge_stop(engine, arguments, principal),
        Operation::ForgeReconcile => forge_reconcile(engine, arguments).await,
    }
}

/// The [`ApiScope`] an operation requires to execute. This is the
/// single source of truth the `/ops/{operation}` REST route classifier and the
/// `kata mcp` agent surface both consult, so the scope an operation demands
/// cannot drift between the HTTP face and the embedded MCP face.
///
/// The `match` is exhaustive over [`Operation`]: adding a variant fails to
/// compile until its scope is declared here — the same anti-drift guarantee
/// [`invoke_operation`] gives for the executor binding. Read/scaffold/submit
/// operations are `Operate`; the human-gate mutations are `Approve`.
#[must_use]
pub const fn operation_required_scope(op: Operation) -> ApiScope {
    match op {
        // Workstation scaffolding, compile, submit-for-execution, and read.
        // An agent legitimately drives all of these.
        Operation::Author
        | Operation::Check
        | Operation::Run
        | Operation::Observe
        | Operation::List => ApiScope::Operate,
        // Human-gate mutations: resolving a parked gate, cancelling an
        // in-flight execution, or promoting a candidate workspace. The workload
        // must never authorize these for itself.
        Operation::Approve
        | Operation::Reject
        | Operation::Cancel
        | Operation::Promote
        // `DischargeStop` belongs here: it DISCHARGES a safety latch that
        // refuses a destructive workspace reclaim, on nothing but the caller's
        // own word — there is no probe to check it against. A workload that
        // could discharge its own stops could assert its way out of the refusal
        // that exists to stop it writing to a workspace kata is about to
        // reclaim.
        | Operation::DischargeStop
        // `ForgeReconcile` drives a forge export's wire effects: after an
        // observer's NOT PERFORMED it pushes or opens a pull request. The sweep
        // would issue the same, but the workload must not choose when.
        | Operation::ForgeReconcile => ApiScope::Approve,
    }
}

/// [`invoke_operation`] wrapped in the shared [`OpEnvelope`] every face emits.
/// Success and failure both produce a well-formed envelope carrying `op`.
pub async fn invoke_operation_enveloped(
    engine: &Arc<WorkflowExecutor>,
    op: Operation,
    arguments: Value,
) -> OpEnvelope<Value> {
    invoke_operation_enveloped_as(engine, op, arguments, None).await
}

/// [`invoke_operation_as`] wrapped in the shared [`OpEnvelope`].
pub async fn invoke_operation_enveloped_as(
    engine: &Arc<WorkflowExecutor>,
    op: Operation,
    arguments: Value,
    principal: Option<&kata_types::approval::ApprovalPrincipal>,
) -> OpEnvelope<Value> {
    match invoke_operation_as(engine, op, arguments, principal).await {
        Ok(data) => OpEnvelope::ok(op, data),
        Err(error) => OpEnvelope::err(op, error),
    }
}

/// One stage's capsule network as the operation contract states it — the
/// [`kata_types::execution_contract::CapsuleNetworkPosture`]'s label and exact
/// authorities, verbatim. The one projection both `check` faces (this engine's
/// and the CLI's local one) and `observe` use.
#[must_use]
pub fn stage_capsule_network(
    stage: &str,
    agent: Option<&str>,
    network: &kata_types::execution_contract::CapsuleNetworkPosture,
) -> StageCapsuleNetwork {
    StageCapsuleNetwork {
        stage: stage.to_owned(),
        agent: agent.map(str::to_owned),
        posture: network.label().to_owned(),
        allowlist: network.allowlist().to_vec(),
    }
}

/// The `check` response's capsule networks: every capsule the compile
/// described, by preflight stage, primary agent then each fallback member.
#[must_use]
pub fn checked_capsule_networks(
    artifact: &kata_program::preflight::WorkflowCompiledArtifact,
) -> Vec<StageCapsuleNetwork> {
    artifact
        .preflight
        .stages
        .iter()
        .flat_map(|stage| {
            stage.capsule_networks.iter().map(|checked| {
                stage_capsule_network(&stage.stage, checked.agent.as_deref(), &checked.network)
            })
        })
        .collect()
}

// --- per-operation bindings ------------------------------------------------

fn check(engine: &Arc<WorkflowExecutor>, arguments: Value) -> Result<Value, OpError> {
    let req: CheckRequest = deserialize(arguments)?;
    match (req.workflow.as_deref(), req.all) {
        (Some(_), true) => Err(OpError::usage(
            "`check` accepts either a workflow argument or all=true, not both",
        )),
        (None, false) => Err(OpError::usage(
            "`check` requires a workflow argument or all=true",
        )),
        // Whole-library check enumerates the effective library — a workstation
        // operation covered by the CLI/MCP local `check --all`; the engine face
        // checks a single named workflow.
        (None, true) => Err(OpError::usage(
            "`check` with all=true is a workstation-local operation; use the CLI \
             or MCP local `check --all`. The engine face checks a single named workflow",
        )),
        (Some(workflow), false) => {
            let artifact = engine
                .compile_ref_artifact(workflow)
                .map_err(executor_error_to_op_error)?;
            let summary =
                summarize_verifier(&artifact.execution_program.verifier, req.deny_warnings);
            to_value(CheckResponse {
                deferred_node_facts: artifact.deferred_node_facts.clone(),
                capsule_networks: checked_capsule_networks(&artifact),
                name: artifact.name,
                passed: summary.passed,
                status: summary.status.label().to_string(),
                error_count: summary.error_count,
                warning_count: summary.warning_count,
                info_count: summary.info_count,
            })
        }
    }
}

/// Cadence of the bounded `wait` poll. Deliberately the same 500ms as
/// the client SDK's `DEFAULT_POLL_INTERVAL`, so an operator comparing CLI
/// `--wait` against MCP `run --wait` sees the same responsiveness on both sides
/// of the wire.
const RUN_WAIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

async fn run(engine: &Arc<WorkflowExecutor>, arguments: Value) -> Result<Value, OpError> {
    let req: RunRequest = deserialize(arguments)?;
    let wait_budget = run_wait_budget(&req)?;
    // The target spelling is parsed at the face, by the one parser, before
    // anything compiles.
    let target = req
        .target
        .as_deref()
        .map(TargetSpec::parse)
        .transpose()
        .map_err(|refusal| OpError::usage(format!("target refused: {refusal}")))?;
    let program = compile_run_program(engine, &req)?;
    // Every face of `run` (`POST /ops/run`, and MCP `tools/call name=run` proxied
    // to it) funnels the typed params through the ONE params-aware submit
    // surface — on a blocking task, because resolving the target reads the
    // repository.
    let submit_engine = Arc::clone(engine);
    let params = req.params;
    let execution_id = tokio::task::spawn_blocking(move || {
        submit_engine.submit_execution_program_with_inputs(
            program,
            Vec::new(),
            params,
            // The op-contract face is `POST /ops`, which MCP tools/call proxies
            // to; `mcp` is recorded as the canonical op-contract consumer.
            kata_types::params::ParamProvenance::Mcp,
            target,
        )
    })
    .await
    .map_err(|error| OpError::engine(format!("the run submission task failed: {error}")))?
    .map_err(executor_error_to_op_error)?;

    let Some(budget) = wait_budget else {
        // No wait requested: read the submit-time status once and return so the caller can begin
        // observing.
        let status = read_run_status(engine, &execution_id)?;
        return to_value(RunResponse {
            terminal: status.terminal,
            wait_timed_out: false,
            execution_id,
            status: status.label,
        });
    };

    // `wait` is honored HERE, in the shared dispatch, so every face
    // (`POST /ops/run`, and MCP `tools/call name=run` proxied to it) gets the
    // same bounded behaviour. It is bounded because nothing else bounds it: the
    // `/ops` route carries no tower timeout and the client's `reqwest` builder
    // sets no request timeout, so this deadline is the ONLY one.
    //
    // Deliberately NOT copied from the client poller: its terminal-settle
    // re-read. That exists so a client re-reads a settled record for its
    // outputs; `RunResponse` carries only the id, a status, and two flags, so a
    // settle would buy nothing and cost every waiter an extra interval.
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let status = read_run_status(engine, &execution_id)?;
        if status.terminal {
            return to_value(RunResponse {
                terminal: true,
                wait_timed_out: false,
                execution_id,
                status: status.label,
            });
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return to_value(RunResponse {
                terminal: false,
                wait_timed_out: true,
                execution_id,
                status: status.label,
            });
        }
        tokio::time::sleep(RUN_WAIT_POLL_INTERVAL.min(deadline - now)).await;
    }
}

/// One `try_get_execution` read projected into the two things a
/// [`RunResponse`] needs.
///
/// An `Err` here is a lifecycle-store failure and PROPAGATES as an `engine`
/// error; it is never folded into another poll iteration. Swallowing it would
/// turn an unreadable durability plane into a wait timeout — reporting "still
/// running" about an execution whose record cannot be read at all. `Ok(None)`
/// is different and benign: a just-submitted id can briefly have no record, so
/// it reads as the non-terminal `"pending"`.
struct RunStatus {
    label: String,
    terminal: bool,
}

fn read_run_status(
    engine: &Arc<WorkflowExecutor>,
    execution_id: &str,
) -> Result<RunStatus, OpError> {
    let record = engine
        .try_get_execution(execution_id)
        .map_err(executor_error_to_op_error)?;
    Ok(record.map_or_else(
        || RunStatus {
            label: "pending".to_string(),
            terminal: false,
        },
        |record| RunStatus {
            label: status_label(&record.status),
            terminal: record.status.is_terminal(),
        },
    ))
}

/// Resolve a [`RunRequest`]'s wait pairing into an optional poll budget.
///
/// `None` means "do not wait". Every refusal is a `usage` error naming the
/// field, because a bound the node cannot honor must be reported, not clamped —
/// a silent clamp is as false an advertisement as an ignored `wait`.
fn run_wait_budget(req: &RunRequest) -> Result<Option<std::time::Duration>, OpError> {
    match (req.wait, req.wait_timeout_secs) {
        (false, Some(_)) => Err(OpError::usage(
            "`wait_timeout_secs` bounds `wait` and is meaningless without it; set `wait: true` \
             or drop `wait_timeout_secs`",
        )),
        (false, None) => Ok(None),
        (true, None) => Ok(Some(std::time::Duration::from_secs(DEFAULT_RUN_WAIT_SECS))),
        (true, Some(0)) => Err(OpError::usage(
            "`wait_timeout_secs` must be at least 1 second; use `wait: false` to return \
             immediately after submission",
        )),
        (true, Some(secs)) if secs > MAX_RUN_WAIT_SECS => Err(OpError::usage(format!(
            "`wait_timeout_secs` is {secs}, above the {MAX_RUN_WAIT_SECS}s ceiling this face \
             can honor; a longer wait outlives the common 60s proxy/transport idle timeout and \
             would return a dropped connection instead of a structured response. Wait up to \
             {MAX_RUN_WAIT_SECS}s and resume with `observe`."
        ))),
        (true, Some(secs)) => Ok(Some(std::time::Duration::from_secs(secs))),
    }
}

/// Resolve a [`RunRequest`]'s single workflow source into a compiled program
/// A run carries EXACTLY ONE source: a library reference (`workflow`)
/// or an inline Starlark body (`workflow_starlark`). Setting both, or neither,
/// is a usage error. The inline body compiles through the SAME checked frontend
/// (`compile_inline_starlark_execution_program`) the REST `workflow_starlark`
/// submission uses, so a malformed body surfaces its compile diagnostics as a
/// `usage` error (`InvalidDefinition` → `OpError::usage`) rather than booting.
fn compile_run_program(
    engine: &Arc<WorkflowExecutor>,
    req: &RunRequest,
) -> Result<ExecutionProgram, OpError> {
    let workflow_ref = req
        .workflow
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let inline_body = req
        .workflow_starlark
        .as_deref()
        .filter(|s| !s.trim().is_empty());
    match (workflow_ref, inline_body) {
        (Some(_), Some(_)) => Err(OpError::usage(
            "`run` accepts exactly one workflow source: a `workflow` reference OR an inline \
             `workflow_starlark` body, not both",
        )),
        (None, None) => Err(OpError::usage(
            "`run` requires a workflow source: a `workflow` reference or an inline \
             `workflow_starlark` body",
        )),
        (Some(name), None) => engine
            .compile_ref_execution_program(name)
            .map_err(executor_error_to_op_error),
        (None, Some(body)) => {
            let filename = req
                .workflow_filename
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("<inline>");
            crate::executor::compile_inline_starlark_execution_program(
                body,
                filename,
                engine.library().roots(),
            )
            .map_err(executor_error_to_op_error)
        }
    }
}

fn observe(engine: &Arc<WorkflowExecutor>, arguments: Value) -> Result<Value, OpError> {
    let req: ObserveRequest = deserialize(arguments)?;
    // Match the REST `GET /executions/{id}` semantics: a malformed or unknown id
    // is a not-found, not a usage error.
    let record = engine
        .try_get_execution(&req.execution_id)
        .map_err(executor_error_to_op_error)?
        .ok_or_else(|| OpError::not_found(format!("execution {} not found", req.execution_id)))?;
    let req_id = Ulid::from_string(&req.execution_id)
        .map_err(|error| OpError::engine(format!("served execution id does not parse: {error}")))?;
    // The invocation graph folds over the assignment population;
    // capsule attempts carry their stage liveness on the chain's own rows, so
    // `last_stage`/`current_stage` merge them in rather than reading absent.
    let attempts = engine
        .execution_lifecycle()
        .db()
        .attempts_for_execution(req_id)
        .map_err(|error| OpError::engine(format!("read attempts for {req_id}: {error}")))?;
    let program = engine
        .execution_program_for_execution(req_id)
        .map_err(executor_error_to_op_error)?;
    let iterations = capsule_loop_iterations(engine, req_id, &attempts, &program)
        .map_err(executor_error_to_op_error)?;
    to_value(observe_response(record, &attempts, &iterations))
}

/// The loop iteration each capsule attempt's occurrence path belongs to —
/// [`OUTSIDE_EVERY_LOOP`] when the attempt sits outside every loop. One decode for every surface that reports a capsule
/// attempt's loop position: the memory-writeback matcher reads the same
/// coordinate through
/// [`kata_program::execution_program::loop_iteration_coordinate`].
fn capsule_loop_iterations(
    engine: &Arc<WorkflowExecutor>,
    execution_id: Ulid,
    attempts: &[kata_core::operational::RecoveredAttempt],
    program: &kata_program::execution_program::ExecutionProgram,
) -> Result<std::collections::BTreeMap<Ulid, u32>, ExecutorError> {
    let db = engine.execution_lifecycle().db();
    let mut iterations = std::collections::BTreeMap::new();
    for attempt in attempts {
        let Ok(kata_core::operational::AttemptArm::Capsule(occurrence_id)) = attempt.arm() else {
            continue;
        };
        let iteration = match db.occurrence(occurrence_id.0.0).map_err(|error| {
            ExecutorError::DurabilityFailed(format!(
                "read the occurrence of attempt {} in execution {execution_id}: {error}",
                attempt.row.attempt_id,
            ))
        })? {
            Some(occurrence) => {
                kata_types::execution_contract::OperationPath::from_canonical_bytes(
                    &occurrence.operation_path,
                )
                .and_then(|path| {
                    kata_program::execution_program::loop_iteration_coordinate(&path, program)
                })
                .unwrap_or(OUTSIDE_EVERY_LOOP)
            }
            None => OUTSIDE_EVERY_LOOP,
        };
        iterations.insert(attempt.row.attempt_id, iteration);
    }
    Ok(iterations)
}

/// List op: enumerate recent executions so an agent that lost its
/// `execution_id` can recover it. Projects [`WorkflowExecutor::list_executions`]
/// (oldest-first) into most-recently-submitted-first, capped at `limit` (or
/// [`DEFAULT_LIST_LIMIT`]).
fn list(engine: &Arc<WorkflowExecutor>, arguments: Value) -> Result<Value, OpError> {
    let req: ListRequest = deserialize(arguments)?;
    let limit = req.limit.unwrap_or(DEFAULT_LIST_LIMIT) as usize;
    let mut executions = engine
        .try_list_executions()
        .map_err(executor_error_to_op_error)?;
    // `list_executions` is oldest-first (Ulid order); an agent recovering a
    // lost execution id wants the most recent ones, so reverse before capping.
    executions.reverse();
    let executions = executions
        .into_iter()
        .take(limit)
        .map(|record| ExecutionSummary {
            execution_id: record.id,
            workflow_name: record.workflow_name,
            status: status_label(&record.status),
            submitted_at_ms: record.submitted_at_ms,
        })
        .collect();
    to_value(ListResponse { executions })
}

/// The `iteration` the observe contract reports for a stage outside every loop.
const OUTSIDE_EVERY_LOOP: u32 = 0;

/// Project a rich [`ExecutionRecord`] into the [`ObserveResponse`] contract.
/// No new engine state is invented: every field is derived from data
/// the executor already reconstructs (the record's `outputs`/`error`, and the
/// agent-invocation graph / controller-decision evidence it already carries).
fn observe_response(
    record: ExecutionRecord,
    attempts: &[kata_core::operational::RecoveredAttempt],
    iterations: &std::collections::BTreeMap<Ulid, u32>,
) -> ObserveResponse {
    let terminal = record.status.is_terminal();
    let status = status_label(&record.status);

    let nodes = match record.agent_invocation_graph.as_ref() {
        Some(graph) => graph.nodes.as_slice(),
        None => &[],
    };

    // The stage currently dispatched/running, if any — the most-recently
    // created node whose status has not yet reached a terminal state.
    let current_stage = nodes
        .iter()
        .filter(|node| {
            !matches!(
                node.status,
                AgentInvocationStatus::Completed
                    | AgentInvocationStatus::Failed
                    | AgentInvocationStatus::Orphaned
            )
        })
        .max_by_key(|node| node.created_at_ms)
        .map(|node| node.stage_name.to_string());

    // The most-recently-touched stage overall (running or terminal), keyed by
    // the latest of its recorded timestamps.
    let last_active_node = nodes.iter().max_by_key(|node| {
        node.finished_at_ms
            .or(node.started_at_ms)
            .or(node.dispatched_at_ms)
            .unwrap_or(node.created_at_ms)
    });
    // The capsule half of "most-recently-touched stage": an attempt's row
    // carries the same finished/started/dispatched instants the graph nodes
    // read off the assignment fold.
    // Millisecond keys only — a chain `seq` is an order within the attempt
    // plane, never a time comparable to a node's `*_at_ms`.
    let capsule_ms_of = |attempt: &kata_core::operational::RecoveredAttempt| {
        attempt
            .row
            .finished_at_ms
            .or(attempt.row.started_at_ms)
            .or(attempt.row.dispatched_at_ms)
    };
    let last_capsule = attempts
        .iter()
        .filter(|attempt| {
            matches!(
                attempt.arm(),
                Ok(kata_core::operational::AttemptArm::Capsule(_))
            )
        })
        .max_by_key(|attempt| capsule_ms_of(attempt).unwrap_or(attempt.row.source_seq));
    let node_ms = last_active_node.map(|node| {
        node.finished_at_ms
            .or(node.started_at_ms)
            .or(node.dispatched_at_ms)
            .unwrap_or(node.created_at_ms)
    });
    let capsule_ms = last_capsule.and_then(capsule_ms_of);
    let iteration_of = |attempt: &kata_core::operational::RecoveredAttempt| {
        iterations
            .get(&attempt.row.attempt_id)
            .copied()
            .unwrap_or(OUTSIDE_EVERY_LOOP)
    };
    let (last_stage, iteration) = match (last_active_node, last_capsule) {
        (Some(_), Some(attempt))
            if capsule_ms.is_some_and(|capsule_ms| {
                u64::try_from(capsule_ms).unwrap_or(0) >= node_ms.unwrap_or(0)
            }) =>
        {
            (
                Some(attempt.row.stage_id.clone()),
                Some(iteration_of(attempt)),
            )
        }
        (Some(node), _) => (Some(node.stage_name.to_string()), Some(OUTSIDE_EVERY_LOOP)),
        (None, Some(attempt)) => (
            Some(attempt.row.stage_id.clone()),
            Some(iteration_of(attempt)),
        ),
        (None, None) => (None, None),
    };
    // Same merge for "stage currently in flight": a non-terminal attempt —
    // CAPSULE or MAIN-RESOLVED alike (a parked `awaiting_input`, a durable
    // sleep, a parent waiting on its child — all genuinely block the run) —
    // is what an operator is watching. The newer candidate between the
    // assignment-fold graph node and the attempt wins by timestamp; an attempt with
    // no ms stamps yet loses to any timestamped node but beats `None`.
    let current_attempt = attempts
        .iter()
        .filter(|attempt| {
            matches!(
                attempt.arm(),
                Ok(kata_core::operational::AttemptArm::Capsule(_)
                    | kata_core::operational::AttemptArm::Main(_))
            )
        })
        .filter(|attempt| {
            !attempt.state.as_deref().is_some_and(|state| {
                kata_core::operational::ATTEMPT_TERMINAL_STATES.contains(&state)
            })
        })
        .max_by_key(|attempt| {
            (
                attempt
                    .row
                    .dispatched_at_ms
                    .or(attempt.row.started_at_ms)
                    .unwrap_or(0),
                attempt.row.source_seq,
            )
        });
    let current_stage = match (&current_stage, current_attempt) {
        (Some(_), Some(attempt)) => {
            let attempt_ms = attempt
                .row
                .dispatched_at_ms
                .or(attempt.row.started_at_ms)
                .unwrap_or(0);
            let node_ms = nodes
                .iter()
                .filter(|node| {
                    !matches!(
                        node.status,
                        AgentInvocationStatus::Completed
                            | AgentInvocationStatus::Failed
                            | AgentInvocationStatus::Orphaned
                    )
                })
                .map(|node| node.created_at_ms)
                .max()
                .unwrap_or(0);
            if u64::try_from(attempt_ms).unwrap_or(0) >= node_ms {
                Some(attempt.row.stage_id.clone())
            } else {
                current_stage
            }
        }
        (None, Some(attempt)) => Some(attempt.row.stage_id.clone()),
        _ => current_stage,
    };

    let wave = record
        .evidence
        .controller_decisions
        .last()
        .and_then(|decision| decision.wave_id.clone());

    let failure_reason = record.error.clone();
    let stage_outputs = record.outputs.clone().unwrap_or_default();

    let terminal_detail = terminal.then(|| match &record.status {
        ExecutionStatus::Failed => format!(
            "failed: {}",
            record
                .error
                .as_deref()
                .unwrap_or("no failure reason recorded")
        ),
        ExecutionStatus::Completed => format!(
            "completed with {} stage output(s){}",
            stage_outputs.len(),
            if record.warnings.is_empty() {
                String::new()
            } else {
                format!(" ({} warning(s))", record.warnings.len())
            }
        ),
        ExecutionStatus::Cancelled => match record.error.as_deref() {
            Some(reason) => format!("cancelled: {reason}"),
            None => "cancelled".to_string(),
        },
        ExecutionStatus::Pending | ExecutionStatus::Running => unreachable!(
            "terminal_detail is only computed when `terminal` is true, and \
             Pending/Running are never terminal"
        ),
    });

    let mut capsule_networks: Vec<StageCapsuleNetwork> = Vec::new();
    for declared in &record.capsule_networks {
        let row = stage_capsule_network(&declared.stage, None, &declared.network);
        if !capsule_networks.contains(&row) {
            capsule_networks.push(row);
        }
    }

    ObserveResponse {
        execution_id: record.id,
        workflow_name: record.workflow_name,
        status,
        terminal,
        current_stage,
        last_stage,
        failure_reason,
        stage_outputs,
        wave,
        iteration,
        terminal_detail,
        capsule_networks,
    }
}

async fn approve(
    engine: &Arc<WorkflowExecutor>,
    arguments: Value,
    principal: Option<&kata_types::approval::ApprovalPrincipal>,
) -> Result<Value, OpError> {
    let req: ApproveRequest = deserialize(arguments)?;
    let execution = parse_execution_id(&req.execution_id)?;
    let assignment = resolve_parked_assignment(engine, &req.execution_id)?;
    engine
        .approve(execution, assignment, principal)
        .await
        .map_err(executor_error_to_op_error)?;
    to_value(ApproveResponse {
        execution_id: req.execution_id,
        approved: true,
    })
}

fn reject(
    engine: &Arc<WorkflowExecutor>,
    arguments: Value,
    principal: Option<&kata_types::approval::ApprovalPrincipal>,
) -> Result<Value, OpError> {
    let req: RejectRequest = deserialize(arguments)?;
    let execution = parse_execution_id(&req.execution_id)?;
    let assignment = resolve_parked_assignment(engine, &req.execution_id)?;
    let reason = req
        .reason
        .unwrap_or_else(|| "operator-initiated rejection".to_string());
    engine
        .reject(execution, assignment, reason, principal)
        .map_err(executor_error_to_op_error)?;
    to_value(RejectResponse {
        execution_id: req.execution_id,
        rejected: true,
    })
}

async fn cancel(engine: &Arc<WorkflowExecutor>, arguments: Value) -> Result<Value, OpError> {
    let req: CancelRequest = deserialize(arguments)?;
    let execution = parse_execution_id(&req.execution_id)?;
    // Unknown/terminal executions are idempotent (nothing live to ask). Running
    // executions are asked to stop, and the acknowledgement is a separate,
    // later event carried on the execution record.
    // `main_side_settled` and `child_executions_cancelled` have no field here: this derived surface answers the worker-stop
    // SUBSET (a derived surface may expose a subset of its principal), and the REST principal
    // carries both counts.
    let outcome = engine
        .cancel(execution, "operator-initiated cancel".to_string())
        .await
        .map_err(executor_error_to_op_error)?;
    to_value(CancelResponse {
        execution_id: req.execution_id,
        stop_requested: outcome.assignments_asked_to_stop > 0,
    })
}

fn promote(engine: &Arc<WorkflowExecutor>, arguments: Value) -> Result<Value, OpError> {
    let req: PromoteRequest = deserialize(arguments)?;
    let execution = parse_execution_id(&req.execution_id)?;
    engine
        .promote(execution)
        .map_err(executor_error_to_op_error)?;
    to_value(PromoteResponse {
        execution_id: req.execution_id,
        promoted: true,
    })
}

/// The `forge_reconcile` binding: the executor's reconcile, each export
/// projected as the store records it. The reconcile reads the remote and may
/// push or run `gh` — minutes against a remote that hangs — so it runs on a
/// blocking task, never on the async handler's worker.
async fn forge_reconcile(
    engine: &Arc<WorkflowExecutor>,
    arguments: Value,
) -> Result<Value, OpError> {
    let req: ForgeReconcileRequest = deserialize(arguments)?;
    let execution = parse_execution_id(&req.execution_id)?;
    let reconcile_engine = Arc::clone(engine);
    let exports =
        tokio::task::spawn_blocking(move || reconcile_engine.reconcile_forge_exports(execution))
            .await
            .map_err(|error| OpError::engine(format!("the forge reconcile task failed: {error}")))?
            .map_err(executor_error_to_op_error)?
            .into_iter()
            .map(|export| ReconciledForgeExport {
                attempt_id: export.attempt_id.to_string(),
                stage_id: export.stage_id,
                state: export.state,
                intent: export.intent.map(|intent| ReconciledForgeIntent {
                    effect_index: intent.id.effect_index,
                    effect: intent.effect.as_str().to_owned(),
                    verdict: intent.verdict().map(|verdict| verdict.as_str().to_owned()),
                    unanswered_reads: intent.unanswered.as_ref().map_or(0, |reads| reads.count),
                    last_read_error: intent.unanswered.map(|reads| reads.last_error),
                    command_error: intent.command_error,
                }),
            })
            .collect();
    to_value(ForgeReconcileResponse {
        execution_id: req.execution_id,
        exports,
    })
}

/// The `discharge_stop` binding.
///
/// # Why the attribution is validated HERE as well as in the executor
///
/// A missing or blank `operator`/`assertion` is a malformed REQUEST the caller
/// can fix, so it is classified `usage` at the contract boundary where every
/// other shape error is. The executor refuses it independently —
/// `StopDischarge::from_provenance` is the constructor that can return `None` —
/// and both must hold. This one is not a substitute for that one; it is the
/// difference between an operator being told which field to fill in and being
/// told the node denied their request.
///
/// # The attribution is the principal the transport proved, when it proved one
///
/// Under a verified token ([`ApprovalPrincipal::Token`]) the `operator` must be the
/// token's own `issued_for`, the label its signature binds, both compared trimmed;
/// any other name is refused `usage`, so the durable record never names someone the
/// token was not issued for. A token whose label is blank names no one, and its
/// discharge is refused `usage` whatever `operator` says (`kata api-token mint`
/// mints no such token). On a face that proves no identity — a loopback listener with auth
/// disabled, or no principal at all — the `operator` is the caller's word, and the
/// record says so by what it is: an operator ASSERTION, `rests_on_a_proof: false`.
fn discharge_stop(
    engine: &Arc<WorkflowExecutor>,
    arguments: Value,
    principal: Option<&ApprovalPrincipal>,
) -> Result<Value, OpError> {
    let req: DischargeStopRequest = deserialize(arguments)?;
    let execution = parse_execution_id(&req.execution_id)?;
    let attempt = Ulid::from_string(req.attempt_id.trim()).map_err(|_| {
        OpError::usage(format!(
            "`discharge_stop` requires `attempt_id` as a ULID, copied from the `attempt_id` field \
             of the worker_stops evidence row: {} is not one",
            req.attempt_id
        ))
    })?;
    if req.lease_epoch < 0 {
        return Err(OpError::usage(
            "`discharge_stop` requires a non-negative `lease_epoch`, copied from the same \
             worker_stops evidence row as `attempt_id`",
        ));
    }
    let operator = non_blank(&req.operator).ok_or_else(|| {
        OpError::usage(
            "`discharge_stop` requires `operator`: the discharge is admissible ONLY because it is \
             attributed, and an unattributed one is indistinguishable from a machine observation \
             in the durable record",
        )
    })?;
    let assertion = non_blank(&req.assertion).ok_or_else(|| {
        OpError::usage(
            "`discharge_stop` requires a non-empty `assertion` stating what was established (e.g. \
             \"worker host terminated; PID 4711 is gone\"): a record saying only that an operator \
             did this tells the next reader nothing about what was checked",
        )
    })?;
    if let Some(ApprovalPrincipal::Token { issued_for }) = principal {
        // The same normal form as `operator`'s: a label is compared trimmed, so a
        // padded one is the label it pads, and a blank one names no one.
        let Some(label) = non_blank(issued_for) else {
            return Err(OpError::usage(
                "`discharge_stop` is attributed to the principal your token proves, and your \
                 token carries a blank `issued_for`, which names no one: discharge with a token \
                 minted with a non-blank `kata api-token mint --issued-for`",
            ));
        };
        if operator != label {
            return Err(OpError::usage(format!(
                "`discharge_stop` is attributed to the principal your token proves: `operator` \
                 must be `{label}`, the token's issued_for, not `{operator}`"
            )));
        }
    }

    let outcome = engine
        .discharge_worker_stop(
            execution,
            attempt,
            req.lease_epoch,
            &StopDischargeAssertion {
                operator,
                assertion,
            },
        )
        .map_err(executor_error_to_op_error)?;
    to_value(DischargeStopResponse {
        execution_id: req.execution_id,
        attempt_id: outcome.attempt_id.to_string(),
        lease_epoch: outcome.lease_epoch,
        discharged: outcome.discharged,
        // From the RECORD THAT STANDS, not from the request: on a re-submission
        // the first operator's attribution is the durable one, and echoing the
        // caller's own would tell a second operator their name landed when it
        // did not.
        operator: outcome.record.operator().unwrap_or_default().to_string(),
        provenance: outcome.record.provenance.as_str().to_string(),
        rests_on_a_proof: outcome.record.rests_on_a_proof(),
        assertion: outcome.record.assertion.clone(),
        outstanding_stops_remaining: outcome.outstanding_remaining,
    })
}

// --- shared helpers --------------------------------------------------------

/// A trimmed, non-empty copy of `value`, or `None`.
fn non_blank(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Deserialize the raw arguments into a typed request. A shape mismatch is a
/// caller/usage error (exit 2), never an engine failure.
fn deserialize<T: DeserializeOwned>(arguments: Value) -> Result<T, OpError> {
    serde_json::from_value(arguments)
        .map_err(|e| OpError::usage(format!("invalid arguments for operation: {e}")))
}

/// Serialize a typed response into the JSON payload carried as the envelope's
/// `data`. A serialization failure is an internal engine fault (exit 5).
fn to_value<T: Serialize>(resp: T) -> Result<Value, OpError> {
    serde_json::to_value(resp).map_err(|e| OpError::engine(format!("serializing response: {e}")))
}

/// Parse an execution id, mapping a malformed id to `not_found` (the addressed
/// execution does not exist) to match the REST route semantics.
fn parse_execution_id(id: &str) -> Result<Ulid, OpError> {
    Ulid::from_string(id).map_err(|_| OpError::not_found(format!("execution {id} not found")))
}

/// Resolve the single parked approval-gate assignment for an execution. Zero
/// gates is a not-found; more than one is a conflict the (assignment-free)
/// contract request cannot disambiguate.
fn resolve_parked_assignment(
    engine: &Arc<WorkflowExecutor>,
    execution_id: &str,
) -> Result<Ulid, OpError> {
    // The gate list PROPAGATES an unreadable plane rather than
    // degrading to empty, and this resolver keeps that polarity — an empty list here
    // becomes "no pending approval gate", which would tell the caller a durably
    // parked gate does not exist.
    let mut matching: Vec<String> = engine
        .pending_approvals()
        .map_err(|error| {
            OpError::engine(format!(
                "the deciding planes could not be read for execution {execution_id}'s approval \
                 gates: {error}"
            ))
        })?
        .into_iter()
        .filter(|pending| pending.execution_id == execution_id)
        .map(|pending| pending.assignment_id)
        .collect();
    match matching.len() {
        0 => Err(OpError::not_found(format!(
            "no pending approval gate for execution {execution_id}"
        ))),
        1 => {
            let assignment = matching.remove(0);
            Ulid::from_string(&assignment)
                .map_err(|_| OpError::engine(format!("malformed assignment id {assignment}")))
        }
        _ => Err(OpError::conflict(format!(
            "execution {execution_id} has multiple pending approval gates; \
             resolve them individually via the approvals list"
        ))),
    }
}

/// The wire status label for an execution status, matching the serde
/// snake_case representation the REST record uses.
fn status_label(status: &ExecutionStatus) -> String {
    match status {
        ExecutionStatus::Pending => "pending",
        ExecutionStatus::Running => "running",
        ExecutionStatus::Completed => "completed",
        ExecutionStatus::Failed => "failed",
        ExecutionStatus::Cancelled => "cancelled",
    }
    .to_string()
}

/// The verifier rollup shared by the `Check` binding, computed identically to
/// the CLI/MCP local `check` binding so all three faces agree byte-for-byte.
struct VerifierSummary {
    status: VerifierStatus,
    passed: bool,
    error_count: usize,
    warning_count: usize,
    info_count: usize,
}

fn summarize_verifier(report: &VerifierReport, deny_warnings: bool) -> VerifierSummary {
    let mut error_count = 0;
    let mut warning_count = 0;
    let mut info_count = 0;
    for diagnostic in &report.diagnostics {
        match diagnostic.severity {
            VerifierSeverity::Error => error_count += 1,
            VerifierSeverity::Warning => warning_count += 1,
            VerifierSeverity::Info => info_count += 1,
        }
    }
    let failure = report.status == VerifierStatus::Error
        || (deny_warnings && report.status == VerifierStatus::Warn);
    VerifierSummary {
        status: report.status,
        passed: !failure,
        error_count,
        warning_count,
        info_count,
    }
}

/// Map an [`ExecutorError`] onto a machine-classified [`OpError`]. This is the
/// single classification every face shares — the REST `/ops` route, and the MCP
/// engine binding, `kata run discharge-stop` and `kata run forge-reconcile` that
/// call it, all surface the
/// identical code, so an
/// agent driver never has to parse prose. The mapping mirrors the status codes
/// the dedicated REST handlers return (400→usage, 404→not_found,
/// 409/412→conflict, 500→engine, 503→capacity).
fn executor_error_to_op_error(err: ExecutorError) -> OpError {
    match err {
        ExecutorError::RefNotFound(_)
        | ExecutorError::ExecutionNotFound(_)
        | ExecutorError::HumanRequestNotFound { .. } => OpError::not_found(err.to_string()),
        ExecutorError::InvalidDefinition(_)
        | ExecutorError::UnsupportedAgent(_)
        | ExecutorError::InvalidParams { .. }
        | ExecutorError::InvalidTarget(_)
        | ExecutorError::TargetUnresolved(_)
        | ExecutorError::ExternalInputChannelNotFound { .. } => OpError::usage(err.to_string()),
        ExecutorError::PolicyDenied(_)
        | ExecutorError::InputRequestConflict(_)
        | ExecutorError::TargetConflict(_) => OpError::conflict(err.to_string()),
        ExecutorError::ApprovalFailed { kind, .. } => match kind {
            ApprovalFailure::UnknownAssignment => OpError::not_found(err.to_string()),
            ApprovalFailure::Conflict => OpError::conflict(err.to_string()),
            ApprovalFailure::Internal => OpError::engine(err.to_string()),
        },
        ExecutorError::WorktreeIsolation { kind, .. } => match kind {
            WorktreeFailure::Missing => OpError::not_found(err.to_string()),
            WorktreeFailure::Unavailable => OpError::capacity(err.to_string()),
            WorktreeFailure::Internal => OpError::engine(err.to_string()),
        },
        ExecutorError::AdmissionClosed
        | ExecutorError::ActiveExecutionCapacity(_)
        | ExecutorError::NoWorkers
        | ExecutorError::WorkerCapacityUnavailable(_) => OpError::capacity(err.to_string()),
        ExecutorError::RunnerBuildFailed(_) | ExecutorError::DurabilityFailed(_) => {
            OpError::engine(err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kata_op_contract::OpErrorCode;

    /// Every approval and worktree failure kind reads the same class on the op
    /// face and the REST face, whatever its detail says: the detail is prose and
    /// a kind is never read back out of it. Each detail below is the message
    /// form the OTHER kind's prose triage once keyed on.
    #[test]
    fn approval_and_worktree_kinds_agree_on_every_face_whatever_the_detail() {
        use axum::response::IntoResponse as _;

        let approvals = [
            (
                ApprovalFailure::UnknownAssignment,
                "belongs to execution",
                OpErrorCode::NotFound,
                404,
            ),
            (
                ApprovalFailure::Conflict,
                "unknown assignment",
                OpErrorCode::Conflict,
                409,
            ),
            (
                ApprovalFailure::Internal,
                "approval_already_decided: attempt 01H",
                OpErrorCode::Engine,
                500,
            ),
        ];
        let worktrees = [
            (
                WorktreeFailure::Missing,
                "no workspace provider",
                OpErrorCode::NotFound,
                404,
            ),
            (
                WorktreeFailure::Unavailable,
                "does not exist",
                OpErrorCode::Capacity,
                503,
            ),
            (
                WorktreeFailure::Internal,
                "no worktree registered",
                OpErrorCode::Engine,
                500,
            ),
        ];
        let faces = |make: &dyn Fn() -> ExecutorError, code: OpErrorCode, status: u16| {
            let shown = format!("{:?}", make());
            let op = executor_error_to_op_error(make());
            assert_eq!(op.code, code, "{shown}");
            assert_eq!(op.message, make().to_string(), "{shown}");
            assert_eq!(make().into_response().status().as_u16(), status, "{shown}");
        };
        for (kind, detail, code, status) in approvals {
            faces(&|| ExecutorError::approval(kind, detail), code, status);
        }
        for (kind, detail, code, status) in worktrees {
            faces(&|| ExecutorError::worktree(kind, detail), code, status);
        }
    }

    /// The deciding doors' refusal tokens are a conflict EXACTLY when the token
    /// leads a `Validation` error's text; another class, another token, or the
    /// token anywhere else is an engine failure.
    #[test]
    fn a_deciding_door_refusal_is_a_conflict_only_when_its_token_leads() {
        use kata_core::operational::{APPROVAL_ALREADY_DECIDED, APPROVAL_GATE_NOT_PARKED};
        use kata_types::error::KataError;

        let kind = |error: KataError| match crate::executor::approval_door_error(error) {
            ExecutorError::ApprovalFailed { kind, .. } => kind,
            other => panic!("not an approval failure: {other:?}"),
        };
        for code in [APPROVAL_ALREADY_DECIDED, APPROVAL_GATE_NOT_PARKED] {
            assert_eq!(
                kind(KataError::Validation(format!("{code}: attempt 01H"))),
                ApprovalFailure::Conflict
            );
            for outside in [
                KataError::Validation(format!("dispatcher: {code}: attempt 01H")),
                KataError::Validation(format!("{code} without its colon")),
                KataError::Internal(format!("{code}: attempt 01H")),
            ] {
                let shown = format!("{outside:?}");
                assert_eq!(kind(outside), ApprovalFailure::Internal, "{shown}");
            }
        }
        assert_eq!(
            kind(KataError::Validation(
                "approval_execution_not_running: attempt 01H".to_owned()
            )),
            ApprovalFailure::Internal
        );
    }

    #[test]
    fn status_label_matches_serde_representation() {
        for status in [
            ExecutionStatus::Pending,
            ExecutionStatus::Running,
            ExecutionStatus::Completed,
            ExecutionStatus::Failed,
            ExecutionStatus::Cancelled,
        ] {
            let via_serde = serde_json::to_value(&status).unwrap();
            assert_eq!(via_serde.as_str().unwrap(), status_label(&status));
        }
    }

    #[test]
    fn executor_errors_map_to_deterministic_codes() {
        let cases = [
            (
                ExecutorError::RefNotFound("x".into()),
                OpErrorCode::NotFound,
            ),
            (
                ExecutorError::ExecutionNotFound("x".into()),
                OpErrorCode::NotFound,
            ),
            (
                ExecutorError::InvalidDefinition("x".into()),
                OpErrorCode::Usage,
            ),
            (
                ExecutorError::PolicyDenied("x".into()),
                OpErrorCode::Conflict,
            ),
            (ExecutorError::NoWorkers, OpErrorCode::Capacity),
            (
                ExecutorError::WorkerCapacityUnavailable("x".into()),
                OpErrorCode::Capacity,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(
                executor_error_to_op_error(err).code,
                expected,
                "unexpected code",
            );
        }
    }

    /// An operator promote refused `target_trunk_renamed` or
    /// `target_trunk_raced` by the landing ladder is a CONFLICT on every face
    /// that carries it — the op/MCP/CLI code and the REST status — with the code
    /// in the message; a provider failure that is not exactly one of those
    /// refusals keeps the worktree triage. The refused set of
    /// `WorkflowExecutor::operator_promote_error`, case by case.
    #[test]
    fn a_trunk_renamed_or_raced_promote_refusal_is_a_conflict_on_every_face() {
        use axum::response::IntoResponse as _;
        use kata_types::error::KataError;
        use kata_types::target::{TARGET_NOT_LANDABLE, TARGET_TRUNK_RACED, TARGET_TRUNK_RENAMED};

        for code in [TARGET_TRUNK_RENAMED, TARGET_TRUNK_RACED] {
            let refused = WorkflowExecutor::operator_promote_error(KataError::Validation(format!(
                "{code}: execution 01H's trunk `main` moved; nothing lands"
            )));
            assert!(
                matches!(&refused, ExecutorError::TargetConflict(refusal)
                    if refusal.code() == code),
                "{refused:?}"
            );
            let message = refused.to_string();
            assert!(
                message.contains(&format!("{code}: execution 01H's trunk")),
                "the face's message carries the code and the detail: {message}"
            );
            assert_eq!(refused.into_response().status().as_u16(), 409);
            let op = executor_error_to_op_error(WorkflowExecutor::operator_promote_error(
                KataError::Validation(format!("{code}: `main`")),
            ));
            assert_eq!(op.code, OpErrorCode::Conflict);
            assert!(op.message.contains(code), "{}", op.message);

            // Outside the refused set: the code not leading the message, the
            // code without its `:`, and the code on another error class.
            for other in [
                KataError::Validation(format!("promote failed: {code}: x")),
                KataError::Validation(format!("{code} without a colon")),
                KataError::Internal(format!("{code}: x")),
            ] {
                let shown = format!("{other:?}");
                assert!(
                    matches!(
                        WorkflowExecutor::operator_promote_error(other),
                        ExecutorError::WorktreeIsolation {
                            kind: WorktreeFailure::Internal,
                            ..
                        }
                    ),
                    "{shown} is not the landing ladder's refusal"
                );
            }
        }
        // Another `target_*` code is not a landing conflict either.
        assert!(matches!(
            WorkflowExecutor::operator_promote_error(KataError::Validation(format!(
                "{TARGET_NOT_LANDABLE}: x"
            ))),
            ExecutorError::WorktreeIsolation {
                kind: WorktreeFailure::Internal,
                ..
            }
        ));
    }
}
