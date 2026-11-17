//! Approval-gate endpoints.
//!
//! ## Routes
//!
//! - `GET  /approvals` — list every parked assignment currently
//!   in `AwaitingApproval`, sorted oldest-first.
//! - `POST /executions/{id}/approve` — body `{"assignment_id": "…"}`;
//!   transitions the parked assignment back to the dispatch path
//!   (dispatcher validates state and picks a worker).
//! - `POST /executions/{id}/reject`  — body
//!   `{"assignment_id": "…", "reason": "…"}`; transitions the
//!   parked assignment to `Failed { reason: "rejected: <reason>" }`.
//! - `POST /executions/{id}/park`    — optional body
//!   `{"ref_name": "…"}`; snapshots an isolated execution worktree to
//!   `refs/heads/parked/<ref_name>` and tears the worktree down.
//! - `POST /executions/{id}/factory/apply` — body is
//!   `ExecutionControllerApplyRequest`; applies one recorded factory
//!   controller decision through a server-owned idempotent replay primitive.
//! - `POST /executions/{id}/factory/finalize` — body is
//!   `ExecutionControllerApplyFinalizeRequest`; finalizes an incomplete
//!   controller application claim after an operator verifies the side effect.
//!
//! ## Status codes
//!
//! `200 OK`            — approve / reject accepted, ledger transitioned.
//! `400 Bad Request`   — malformed id in path or body.
//! `412 Precondition Failed` — approve / reject on an execution whose
//!                       authoritative lifecycle is no longer `Running`
//!                       (`… cannot dispatch after workflow terminalization`);
//!                       nothing is decided or sent.
//! `409 Conflict`      — assignment is no longer parked, does not belong
//!                       to the path execution id, or lacks checked gate
//!                       authority for the requested mutation. The body
//!                       carries the dispatcher's reason.
//! `503 Service Unavailable` — this node has no `WorkflowExecutor`
//!                       configured (stateless worker-only node).
//! `500 Internal Server Error` — unexpected executor failure; the
//!                       body carries the error string for debugging.

use axum::Json;
use axum::Router;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use kata_types::execution::{
    ExecutionControllerApplyFinalizeRequest, ExecutionControllerApplyRequest,
};
use serde::Deserialize;
use serde_json::json;
use ulid::Ulid;

use super::{err_json, parse_execution_id, require_executor};
use crate::executor::ExecutorError;
use crate::state::AppState;

/// Build the approvals sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/executions/{id}/approve", post(approve_execution))
        .route("/executions/{id}/reject", post(reject_execution))
        .route("/executions/{id}/cancel", post(cancel_execution))
        .route("/executions/{id}/promote", post(promote_execution))
        .route("/executions/{id}/park", post(park_execution))
        .route(
            "/executions/{id}/factory/apply",
            post(apply_factory_controller_decision),
        )
        .route(
            "/executions/{id}/factory/finalize",
            post(finalize_factory_controller_application_claim),
        )
        .route("/approvals", get(list_approvals))
}

/// Body of `POST /executions/{id}/approve`.
#[derive(Debug, Deserialize)]
struct ApproveBody {
    assignment_id: String,
}

/// Body of `POST /executions/{id}/reject`.
#[derive(Debug, Deserialize)]
struct RejectBody {
    assignment_id: String,
    reason: String,
}

/// Body of `POST /executions/{id}/park`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParkBody {
    ref_name: Option<String>,
}

/// Body of `POST /executions/{id}/promote`.
///
/// Promotion takes no request parameters, but the route still parses a
/// body with `deny_unknown_fields` so mutation payloads (e.g. a
/// smuggled `controller_application`) are rejected with `422` rather
/// than silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromoteBody {}

/// The principal the transport proved (`crate::auth::ApiPrincipal`): the verified
/// token's label, or `unauthenticated_loopback` on the auth-disabled loopback layer. Every
/// production router attaches one; a capsule gate refuses to record a decision without
/// it (`approval_principal_unproven`), and so does every other decidable gate.
fn proved_principal(
    principal: Option<Extension<crate::auth::ApiPrincipal>>,
) -> Option<kata_types::approval::ApprovalPrincipal> {
    principal.map(|Extension(crate::auth::ApiPrincipal(principal))| principal)
}

async fn approve_execution(
    State(state): State<AppState>,
    principal: Option<Extension<crate::auth::ApiPrincipal>>,
    Path(id): Path<String>,
    Json(body): Json<ApproveBody>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow executor unavailable") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    let execution_id = match parse_execution_id(&id) {
        Ok(execution_id) => execution_id,
        Err(response) => return response,
    };
    let Ok(assignment_id) = Ulid::from_string(&body.assignment_id) else {
        return err_json(
            StatusCode::BAD_REQUEST,
            format!("invalid assignment id {:?}", body.assignment_id),
        );
    };
    let principal = proved_principal(principal);
    // `ExecutorError::ApprovalFailed` and every other executor error carry their
    // own canonical status via `impl IntoResponse for ExecutorError`.
    match executor
        .approve(execution_id, assignment_id, principal.as_ref())
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "approved" }))).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn reject_execution(
    State(state): State<AppState>,
    principal: Option<Extension<crate::auth::ApiPrincipal>>,
    Path(id): Path<String>,
    Json(body): Json<RejectBody>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow executor unavailable") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    let execution_id = match parse_execution_id(&id) {
        Ok(execution_id) => execution_id,
        Err(response) => return response,
    };
    let Ok(assignment_id) = Ulid::from_string(&body.assignment_id) else {
        return err_json(
            StatusCode::BAD_REQUEST,
            format!("invalid assignment id {:?}", body.assignment_id),
        );
    };
    let principal = proved_principal(principal);
    match executor.reject(execution_id, assignment_id, body.reason, principal.as_ref()) {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "rejected" }))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /api/v1/approvals` — every gate awaiting an operator decision.
///
/// # An unreadable plane is a 500, never an empty list
///
/// `pending_approvals` propagates rather than degrading, and this
/// handler keeps that polarity on the wire. An empty array means *"nothing is
/// parked"*, and answering it for a plane that could not be read tells the operator
/// there is nothing to approve while gates sit parked — a plausible answer that
/// reads as a real one. The no-executor arm above is genuinely a different fact:
/// this node runs no workflow executor, so it holds no gates.
async fn list_approvals(State(state): State<AppState>) -> impl IntoResponse {
    let Some(executor) = state.workflow_executor.as_ref() else {
        return Json(json!([])).into_response();
    };
    match executor.pending_approvals() {
        Ok(approvals) => {
            Json(serde_json::to_value(approvals).unwrap_or_else(|_| json!([]))).into_response()
        }
        Err(error) => err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the deciding planes could not be read for the approval gate list: {error}"),
        ),
    }
}

/// Body of `POST /executions/{id}/cancel`. `reason` is
/// optional; when omitted, defaults to "operator-initiated cancel".
#[derive(Debug, Deserialize)]
struct CancelBody {
    #[serde(default)]
    reason: Option<String>,
}

/// `POST /executions/{id}/cancel` — cancellation request surface.
///
/// **No 412 is reachable here** —
/// [`WorkflowExecutor::cancel`](crate::executor::WorkflowExecutor::cancel)
/// returns `AdmissionClosed` (503) and `DurabilityFailed` (500) and never
/// `PolicyDenied`, which is the only variant this crate maps to 412. A RUNNING
/// execution is the case the route acts on rather than refuses: it writes the
/// durable stop request BEFORE the frame leaves and answers 200.
///
/// What it answers:
/// - **503** when this node holds no workflow executor, or admission is closed.
/// - **400** when the execution id is malformed.
/// - **500** when a durable read, or the stop-request write that precedes the
///   frame, fails.
/// - **200** otherwise, the execution's outcome latched `cancelled` with the reason (unless
///   it had already latched one — then nothing is written), `{"status": "stop_requested",
///   "assignments_asked_to_stop": N, "main_side_settled": M,
///   "child_executions_cancelled": C}` — `N` worker attempts ASKED to stop (a durable stop
///   request written for each), `M` parked main-resolved waits (timers, input waits) and
///   never-dispatched approval gates the main settled `cancelled` itself, `C` child executions a
///   subworkflow `Invoke` waited on, cancelled in turn — each one's outcome latched
///   `cancelled`, so it claims nothing more — (their own asks and settlements are in `N`
///   and `M`). Idempotence is carried by the counts, not by a status code: an
///   unknown or already-terminal execution has nothing live, so it answers `0` and `0`
///   on every repeat.
async fn cancel_execution(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<CancelBody>>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow executor unavailable") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    let execution_id = match parse_execution_id(&id) {
        Ok(execution_id) => execution_id,
        Err(response) => return response,
    };
    let reason = body
        .and_then(|Json(b)| b.reason)
        .unwrap_or_else(|| "operator-initiated cancel".to_string());
    match executor.cancel(execution_id, reason).await {
        // THE FIELD NAMES SAY "ASKED", BECAUSE ASKED IS ALL THIS KNOWS.
        //
        // A field like `"assignments_terminated": N` would tell an operator the
        // stage ENDED, when what happened is that a stop frame was accepted by a
        // transport. Whether the
        // work stopped is answered by the worker's own terminal frame, which
        // arrives later or not at all, and is readable at
        // `ExecutionRecord.evidence.worker_stops`.
        //
        // `main_side_settled` is the other half, and it IS an ending: a parked main-resolved
        // wait (a durable timer, an input wait) or a never-dispatched approval gate has no
        // worker to ask, so the cancel settles it `cancelled` itself and counts it here. `child_executions_cancelled` counts the
        // subworkflow children the cancel propagated to; each child's own terminal
        // publication then resolves its parent's `Invoke` `cancelled`.
        Ok(outcome) => (
            StatusCode::OK,
            Json(json!({
                "status": "stop_requested",
                "assignments_asked_to_stop": outcome.assignments_asked_to_stop,
                "main_side_settled": outcome.main_side_settled,
                "child_executions_cancelled": outcome.child_executions_cancelled,
            })),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /executions/{id}/promote` — operator-driven
/// fast-forward of the operator's base branch from the
/// per-execution worktree's HEAD. Errors:
/// - 503 when no executor / no workspace provider attached.
/// - 400 when the id is malformed.
/// - 404 when no execution exists under the id (it has no durable lifecycle
///   record), or no workspace is registered for it, or its path is gone.
/// - 412 when the execution's lifecycle is not `completed`, when its checked
///   program declares no required validation criterion, or when a required
///   criterion is not satisfied (`validation_criterion:<id>:<why>`); nothing
///   moves.
/// - 409 `target_trunk_renamed` when the node's trunk now resolves to a branch
///   other than the one the execution froze (nothing moves).
/// - 409 `target_trunk_raced` when a writer outside kata moved trunk between
///   the landing ladder's read and its fast-forward (nothing moves; a re-issued
///   promote judges trunk as it is then).
/// - 500 for every other error the workspace provider itself returns.
async fn promote_execution(
    State(state): State<AppState>,
    Path(id): Path<String>,
    _body: Option<Json<PromoteBody>>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow executor unavailable") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    let execution_id = match parse_execution_id(&id) {
        Ok(execution_id) => execution_id,
        Err(response) => return response,
    };
    // Every promote failure (not-found / policy / worktree-isolation triage)
    // is classified by `impl IntoResponse for ExecutorError`.
    match executor.promote(execution_id) {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "promoted" }))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /executions/{id}/factory/apply` — apply one recorded factory
/// controller decision once through the main.
async fn apply_factory_controller_decision(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ExecutionControllerApplyRequest>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow executor unavailable") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    let execution_id = match parse_execution_id(&id) {
        Ok(execution_id) => execution_id,
        Err(response) => return response,
    };
    // The full apply error surface (not-found / usage / policy / capacity /
    // worktree-isolation triage) is classified by
    // `impl IntoResponse for ExecutorError`.
    match executor.apply_controller_decision_once(execution_id, request) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `POST /executions/{id}/factory/finalize` — finalize a previously claimed
/// controller application after an operator has verified the side effect.
async fn finalize_factory_controller_application_claim(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ExecutionControllerApplyFinalizeRequest>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow executor unavailable") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    let execution_id = match parse_execution_id(&id) {
        Ok(execution_id) => execution_id,
        Err(response) => return response,
    };
    // Only PolicyDenied's "no durable claim" form differs from canonical triage.
    match executor.finalize_controller_application_claim(execution_id, request) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(ExecutorError::ExecutionNotFound(msg)) => err_json(StatusCode::NOT_FOUND, msg),
        Err(ExecutorError::InvalidDefinition(msg)) => err_json(StatusCode::BAD_REQUEST, msg),
        Err(ExecutorError::PolicyDenied(msg)) => {
            let status = if msg.contains("has no durable claim to finalize") {
                StatusCode::CONFLICT
            } else {
                StatusCode::PRECONDITION_FAILED
            };
            err_json(status, msg)
        }
        Err(error @ ExecutorError::WorktreeIsolation { .. }) => error.into_response(),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// `POST /executions/{id}/park` — preserve an isolated execution candidate
/// under `refs/heads/parked/...` without merging it into the base branch.
async fn park_execution(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<ParkBody>>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow executor unavailable") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    let execution_id = match parse_execution_id(&id) {
        Ok(execution_id) => execution_id,
        Err(response) => return response,
    };
    let ref_name = body
        .as_ref()
        .and_then(|Json(body)| body.ref_name.as_deref())
        .filter(|value| !value.trim().is_empty());
    // Worktree failures use the same classification as promote and finalize.
    match executor.park_candidate(execution_id, ref_name) {
        Ok(candidate) => (
            StatusCode::OK,
            Json(kata_types::execution::ParkedExecution {
                status: "parked".to_string(),
                parked_ref: candidate.ref_name,
                commit_sha: candidate.commit_sha,
                identity: candidate.identity,
            }),
        )
            .into_response(),
        Err(error @ ExecutorError::WorktreeIsolation { .. }) => error.into_response(),
        Err(ExecutorError::InvalidDefinition(msg)) => err_json(StatusCode::BAD_REQUEST, msg),
        Err(ExecutorError::PolicyDenied(msg)) => err_json(StatusCode::PRECONDITION_FAILED, msg),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
