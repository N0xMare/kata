//! REST router assembly.
//!
//! Gathers all REST endpoint routers and merges them into a single
//! `axum::Router` under `/api/v1`.

pub mod agents;
pub mod approvals;
pub mod events;
pub mod memory;
pub mod ops;
pub(crate) mod page;
pub mod system;
pub mod version;
pub mod workers;
pub mod workflows;
pub mod workspace;

use std::fmt::Display;

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use ulid::Ulid;

use crate::executor::{ApprovalFailure, ExecutorError, WorkflowExecutor, WorktreeFailure};
use crate::state::AppState;

// --- shared REST error-response helpers ------------------------------------
//
// Three response shapes serve ~120 REST handler sites: a `{"error": "<msg>"}`
// JSON body, the "no executor on this node" 503 guard, and the "malformed
// execution id" 400 guard. These helpers are the one place each shape is
// constructed so the wire contract (status + body) cannot drift between
// handlers.

/// Build a `{"error": "<msg>"}` JSON error response with the given status.
///
/// This is the single constructor for the REST error-envelope shape every
/// handler returns; the body is byte-identical to the previous inline
/// `Json(json!({ "error": msg }))`.
pub(crate) fn err_json(status: StatusCode, msg: impl Display) -> Response {
    (status, Json(json!({ "error": msg.to_string() }))).into_response()
}

/// Borrow this node's [`WorkflowExecutor`], or return a `503` error response
/// carrying `unavailable_msg` when the node is stateless / worker-only.
///
/// Callers that instead degrade to an empty collection on a stateless node
/// (the `GET` list routes) keep their own `Option` handling — this helper is
/// only for the sites that surface `503 Service Unavailable`.
// The `Err` is an already-built `axum` `Response` a handler returns verbatim;
// boxing it would only add a deref at every guard site for no gain.
#[allow(clippy::result_large_err)]
pub(crate) fn require_executor<'a>(
    state: &'a AppState,
    unavailable_msg: &str,
) -> Result<&'a WorkflowExecutor, Response> {
    state
        .workflow_executor
        .as_deref()
        .ok_or_else(|| err_json(StatusCode::SERVICE_UNAVAILABLE, unavailable_msg))
}

/// Parse a path execution id, or return a `400` error response with the
/// canonical `invalid execution id "<id>"` body.
///
/// The one route that instead treats a malformed id as `404`
/// (`GET /executions/{id}/workspace`) keeps its own inline parse.
// `Err` is an already-built `Response` returned verbatim; see `require_executor`.
#[allow(clippy::result_large_err)]
pub(crate) fn parse_execution_id(id: &str) -> Result<Ulid, Response> {
    Ulid::from_string(id).map_err(|_| {
        err_json(
            StatusCode::BAD_REQUEST,
            format!("invalid execution id {id:?}"),
        )
    })
}

/// The canonical [`ExecutorError`] → HTTP response mapping shared by the
/// resource routes. Each variant's status is of the class the `/ops` face gives
/// it (`op_dispatch::executor_error_to_op_error`): 400 usage, 404 not found,
/// 409 (approval, input or target conflict) and 412 (policy) conflict, 503
/// capacity, 500 engine — the class a client reads back off the status
/// (`kata_client::KataClientError::op_error_code`). A handler whose full
/// error surface is covered here can delegate with `Err(e) => e.into_response()`
/// instead of re-listing every arm. Handlers that return a *different* status or
/// body for a given variant (e.g. `agents` custom `NoWorkers` text, `append`'s
/// 409 policy / 404 channel) keep those arms explicit
/// ahead of the delegating tail.
impl IntoResponse for ExecutorError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ExecutorError::AdmissionClosed => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            ExecutorError::ActiveExecutionCapacity(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
            ExecutorError::NoWorkers => (
                StatusCode::SERVICE_UNAVAILABLE,
                "no worker is currently available; retry shortly".to_string(),
            ),
            ExecutorError::WorkerCapacityUnavailable(msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, msg.clone())
            }
            ExecutorError::InvalidDefinition(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            // A rejected invocation-param set is a 400; the stable
            // `param.*` code is carried in the message via the error's Display.
            ExecutorError::InvalidParams { .. }
            | ExecutorError::UnsupportedAgent(_)
            | ExecutorError::InvalidTarget(_)
            | ExecutorError::TargetUnresolved(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            ExecutorError::RefNotFound(name) => (
                StatusCode::NOT_FOUND,
                format!("workflow {name:?} not found in library"),
            ),
            ExecutorError::ExecutionNotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ExecutorError::PolicyDenied(msg) => (StatusCode::PRECONDITION_FAILED, msg.clone()),
            ExecutorError::ExternalInputChannelNotFound { channel, .. } => (
                StatusCode::BAD_REQUEST,
                format!("external input channel {channel:?} is not declared by this workflow"),
            ),
            ExecutorError::ApprovalFailed { kind, detail } => {
                let status = match kind {
                    ApprovalFailure::UnknownAssignment => StatusCode::NOT_FOUND,
                    ApprovalFailure::Conflict => StatusCode::CONFLICT,
                    ApprovalFailure::Internal => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, detail.clone())
            }
            ExecutorError::InputRequestConflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            ExecutorError::TargetConflict(_) => (StatusCode::CONFLICT, self.to_string()),
            ExecutorError::WorktreeIsolation { kind, detail } => {
                let status = match kind {
                    WorktreeFailure::Missing => StatusCode::NOT_FOUND,
                    WorktreeFailure::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                    WorktreeFailure::Internal => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, detail.clone())
            }
            ExecutorError::HumanRequestNotFound { .. } => (StatusCode::NOT_FOUND, self.to_string()),
            ExecutorError::RunnerBuildFailed(_) | ExecutorError::DurabilityFailed(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        err_json(status, body)
    }
}

/// Build the combined REST router for `/api/v1`.
pub fn rest_router() -> Router<AppState> {
    Router::new()
        .merge(workflows::router())
        .merge(approvals::router())
        .merge(ops::router())
        .merge(agents::router())
        .merge(events::router())
        .merge(memory::router())
        .merge(version::router())
        .merge(workers::router())
        .merge(workspace::router())
}
