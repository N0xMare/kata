//! Workflow and execution endpoints.
//!
//! ## Routes
//!
//! - `GET  /workflows`           — list entries in the workflow library
//!   (paginated: `?limit=`/`?offset=`; `?status=` is rejected 400 — library
//!   entries have no lifecycle status)
//! - `GET  /workflows/{name}`    — inspect a named library entry
//! - `GET  /executions`          — list submitted executions, paginated
//!   (`?limit=`/`?offset=`) and filterable by lifecycle status
//!   (`?status=pending,running,completed,failed,cancelled`, comma-separated; unknown
//!   tags → 400). `?limit=` is clamped server-side; see [`super::page`].
//! - `POST /executions`          — submit a workflow for execution
//! - `GET  /executions/{id}`     — fetch the current state of an execution
//! - `GET  /executions/{id}/workspace` — fetch execution workspace detail
//! - `POST /executions/{id}/human-request-answer` — attach an exact-id
//!   operator answer
//! - `POST /executions/{id}/external-inputs` — append prompt/context input
//!
//! ## Submission schema
//!
//! `POST /executions` accepts exactly one workflow source: a library
//! reference or inline Starlark. Sending more than one
//! returns 400:
//!
//! ```json
//! { "workflow_ref": "self-review" }
//! ```
//!
//! ```json
//! {
//!   "workflow_starlark": "only = stage(id = \"only\", prompt = \"hi\")\nworkflow(\"demo\", root = [only])\n",
//!   "workflow_filename": "demo.star"
//! }
//! ```
//!
//! The response carries the assigned execution id and the initial
//! status (`pending`). Clients then poll `GET /executions/{id}` until
//! the status reaches `completed` or `failed`.

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use kata_types::execution::{
    ExecutionExternalInputAppendRequest, ExecutionHumanRequestAnswerRequest,
};
use kata_types::target::TargetSpec;
use serde::Deserialize;
use serde_json::json;
use tracing::warn;
use ulid::Ulid;

use super::page::PageParams;
use super::{err_json, parse_execution_id, require_executor};
use crate::executor::{ExecutorError, StageOutputResult};

/// Serde status tags a listed [`kata_types::execution::ExecutionRecord`] can
/// carry — the whitelist the `GET /executions?status=` filter validates against.
/// Kept in lockstep with [`kata_types::execution::ExecutionStatus::as_tag`].
const EXECUTION_STATUS_TAGS: &[&str] = &["pending", "running", "completed", "failed", "cancelled"];
use crate::state::AppState;

/// Build the workflow + execution sub-router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/workflows", get(list_workflows))
        .route("/workflows/{name}", get(get_workflow))
        .route("/executions", get(list_executions).post(create_execution))
        .route("/executions/{id}", get(get_execution))
        .route("/executions/{id}/workspace", get(get_execution_workspace))
        .route(
            "/executions/{id}/human-request-answer",
            post(answer_human_request),
        )
        .route(
            "/executions/{id}/external-inputs",
            post(append_external_input),
        )
        .route(
            "/executions/{id}/stages/{stage}/output",
            get(get_stage_output),
        )
}

// ---------------------------------------------------------------------------
// GET /workflows — list library entries
// ---------------------------------------------------------------------------

async fn list_workflows(
    State(state): State<AppState>,
    Query(page): Query<PageParams>,
) -> impl IntoResponse {
    // Library entries are files on disk, not runs — they carry no lifecycle
    // status. Refuse a `?status=` here rather than silently ignoring the shared
    // param.
    if let Err(response) = page.reject_status_if_unsupported("the workflow library") {
        return response;
    }
    let Some(executor) = state.workflow_executor.as_ref() else {
        // Stateless nodes cannot enumerate a library. Preserve the
        // old "empty array" behaviour so clients that scraped the
        // stub endpoint still parse cleanly.
        return Json(json!([])).into_response();
    };
    let entries: Vec<serde_json::Value> = executor
        .library()
        .list_effective()
        .into_iter()
        .map(|e| {
            json!({
                "name": e.name,
                "format": kata_program::library::WorkflowEntry::FORMAT,
                "path": e.path.display().to_string(),
                "root_priority": e.root_priority,
            })
        })
        .collect();
    Json(serde_json::Value::Array(page.paginate(entries))).into_response()
}

// ---------------------------------------------------------------------------
// GET /workflows/{name} — inspect a library entry
// ---------------------------------------------------------------------------

async fn get_workflow(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow library not configured on this node") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    match executor.compile_ref_artifact(&name) {
        Ok(artifact) => Json(json!({
            "name": artifact.name,
            "stages": artifact.stage_count,
            "edges": artifact.edge_count,
            "format": artifact.source_format_label(),
            "provenance": artifact.provenance,
            "stage_names": artifact.stage_names,
            "invocation_plan": artifact.invocation_plan,
            "execution_program": artifact.execution_program,
            "preflight": artifact.preflight,
        }))
        .into_response(),
        // Custom not-found body (no "in library" suffix), so this stays explicit
        // rather than delegating to the canonical `ExecutorError` mapping.
        Err(ExecutorError::RefNotFound(_)) => err_json(
            StatusCode::NOT_FOUND,
            format!("workflow {name:?} not found"),
        ),
        Err(e) => err_json(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// POST /executions — submit a workflow
//
// Not idempotent: the route takes no idempotency key. A reply lost after the
// admission committed leaves the execution admitted (a restarted main runs it
// to completion), and a client that retries admits a second one.
// ---------------------------------------------------------------------------

/// Body of `POST /executions`. Exactly one of `workflow_ref`
/// or `workflow_starlark`
/// must be set; omitting all
/// source fields or setting more than one is a 400. Using a
/// struct-with-options rather than a tagged enum makes the API more
/// forgiving to clients that send extra fields and gives us one
/// shared deserializer error path. `external_inputs` may seed checked
/// prompt/context rows before the runner starts.
#[derive(Debug, Deserialize)]
struct CreateExecutionBody {
    /// Library reference — looked up through the executor's
    /// `WorkflowLibrary`.
    #[serde(default, rename = "workflow_ref")]
    ref_name: Option<String>,
    /// Inline Starlark workflow definition. `load()` statements are
    /// resolved against the API node's configured workflow library roots.
    #[serde(default, rename = "workflow_starlark")]
    starlark: Option<String>,
    /// Optional diagnostic filename for inline Starlark parse errors
    /// and import provenance.
    #[serde(default, rename = "workflow_filename")]
    filename: Option<String>,
    /// Checked external-input rows to append before the first stage can render.
    #[serde(default)]
    external_inputs: Vec<ExecutionExternalInputAppendRequest>,
    /// Typed invocation params as a `{name: value}` object, resolved +
    /// default-filled against the workflow's declared `workflow(params=..)`
    /// contract at admission (the same resolution every face shares). Omitting it
    /// submits with no supplied params.
    #[serde(default)]
    params: serde_json::Map<String, serde_json::Value>,
    /// What an isolated run works on: `trunk`, the default when omitted, or
    /// `pr:<N>`, the forge's pull request N; parsed by the one target parser
    /// every face uses.
    #[serde(default)]
    target: Option<String>,
}

async fn create_execution(
    State(state): State<AppState>,
    Json(body): Json<CreateExecutionBody>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow execution not available on this node") {
        Ok(executor) => executor,
        Err(response) => return response,
    };

    let source_count = usize::from(
        body.ref_name
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty()),
    ) + usize::from(
        body.starlark
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty()),
    );
    if source_count > 1 {
        return err_json(
            StatusCode::BAD_REQUEST,
            "exactly one of workflow_ref or workflow_starlark must be set",
        );
    }
    if source_count == 0 {
        return err_json(
            StatusCode::BAD_REQUEST,
            "body must include workflow_ref or workflow_starlark",
        );
    }
    let target = match body.target.as_deref().map(TargetSpec::parse).transpose() {
        Ok(target) => target,
        Err(refusal) => {
            return err_json(
                StatusCode::BAD_REQUEST,
                ExecutorError::InvalidTarget(refusal).to_string(),
            );
        }
    };

    let execution_program = if let Some(name) = body
        .ref_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match executor.compile_ref_execution_program(name) {
            Ok(execution_program) => execution_program,
            Err(ExecutorError::RefNotFound(_)) => {
                return err_json(
                    StatusCode::NOT_FOUND,
                    format!("workflow {name:?} not found in library"),
                );
            }
            Err(e) => {
                return err_json(StatusCode::BAD_REQUEST, e.to_string());
            }
        }
    } else if let Some(starlark_text) = body.starlark.as_deref().filter(|s| !s.trim().is_empty()) {
        let filename = body.filename.as_deref().unwrap_or("<inline>");
        match crate::executor::compile_inline_starlark_execution_program(
            starlark_text,
            filename,
            executor.library().roots(),
        ) {
            Ok(execution_program) => execution_program,
            Err(e) => {
                return err_json(StatusCode::BAD_REQUEST, e.to_string());
            }
        }
    } else {
        unreachable!("source_count guarantees exactly one non-empty source")
    };

    // On a blocking task: resolving the target reads the repository before the
    // admission permit is taken.
    let Some(submit_executor) = state.workflow_executor.clone() else {
        return err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "workflow execution not available on this node",
        );
    };
    let submitted = tokio::task::spawn_blocking(move || {
        submit_executor.submit_execution_program_with_inputs(
            execution_program,
            body.external_inputs,
            body.params,
            kata_types::params::ParamProvenance::Rest,
            target,
        )
    })
    .await;
    let submitted = match submitted {
        Ok(submitted) => submitted,
        Err(error) => {
            warn!(error = %error, "workflow submission task failed");
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("the submission task failed: {error}"),
            );
        }
    };
    // Every refusal takes the canonical mapping (`ExecutorError as
    // IntoResponse`), whose status is of the class the `/ops` `run` gives the
    // same refusal — a shutting-down main, a spent active-execution budget or a
    // main with no workspace provider for an isolated pack 503 (retriable) — so
    // `kata run`'s exit status and the MCP face's code agree. The stable `param.*` code of a rejected param set
    // rides in the error string every face surfaces verbatim.
    match submitted {
        Ok(id) => (
            StatusCode::ACCEPTED,
            Json(json!({ "id": id, "status": "pending" })),
        )
            .into_response(),
        Err(e) => {
            let message = e.to_string();
            let response = e.into_response();
            if response.status().is_server_error() {
                warn!(error = %message, "workflow submission failed");
            }
            response
        }
    }
}

// ---------------------------------------------------------------------------
// GET /executions — list all
// ---------------------------------------------------------------------------

async fn list_executions(
    State(state): State<AppState>,
    Query(page): Query<PageParams>,
) -> impl IntoResponse {
    // Validate `?status=` up front so an unknown tag is a 400 with the
    // valid-values list even on a degraded node (mirrors the events endpoint).
    let status_filter = match page.resolve_status(EXECUTION_STATUS_TAGS) {
        Ok(filter) => filter,
        Err(response) => return response,
    };
    let Some(executor) = state.workflow_executor.as_ref() else {
        return Json(json!([])).into_response();
    };
    let mut records = match executor.try_list_executions() {
        Ok(records) => records,
        Err(error) => {
            warn!(%error, "execution list unavailable: lifecycle authority read failed");
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
        }
    };
    if let Some(allowed) = &status_filter {
        records.retain(|record| allowed.contains(record.status.as_tag()));
    }
    let page = page.paginate(records);
    Json(serde_json::to_value(page).unwrap_or(json!([]))).into_response()
}

// ---------------------------------------------------------------------------
// GET /executions/{id} — fetch one
// ---------------------------------------------------------------------------

async fn get_execution(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow execution not available on this node") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    match executor.try_get_execution(&id) {
        Ok(Some(record)) => {
            Json(serde_json::to_value(record).unwrap_or(json!(null))).into_response()
        }
        Ok(None) => err_json(StatusCode::NOT_FOUND, format!("execution {id} not found")),
        Err(error) => {
            warn!(%error, %id, "execution unavailable: lifecycle authority read failed");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// GET /executions/{id}/workspace — execution workspace detail
// ---------------------------------------------------------------------------

async fn get_execution_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow execution not available on this node") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    // This route maps a malformed id to 404 (not the 400 the shared
    // `parse_execution_id` helper returns), so it keeps its own parse.
    let Ok(execution_id) = Ulid::from_string(&id) else {
        return err_json(StatusCode::NOT_FOUND, format!("execution {id} not found"));
    };
    match executor.execution_workspace_snapshot(execution_id) {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(ExecutorError::ExecutionNotFound(msg)) => err_json(StatusCode::NOT_FOUND, msg),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// POST /executions/{id}/human-request-answer — exact-id HRQ answer evidence
// ---------------------------------------------------------------------------

async fn answer_human_request(
    State(state): State<AppState>,
    principal: Option<axum::Extension<crate::auth::ApiPrincipal>>,
    Path(id): Path<String>,
    Json(body): Json<ExecutionHumanRequestAnswerRequest>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow execution not available on this node") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    let execution_id = match parse_execution_id(&id) {
        Ok(execution_id) => execution_id,
        Err(response) => return response,
    };
    // The principal the transport proved: an answer that resolves an `oci` input wait
    // records it, and is refused without one.
    let principal =
        principal.map(|axum::Extension(crate::auth::ApiPrincipal(principal))| principal);
    match executor.answer_human_request(execution_id, body, principal.as_ref()) {
        Ok(answered) => (StatusCode::OK, Json(answered)).into_response(),
        Err(ExecutorError::InvalidDefinition(msg)) => err_json(StatusCode::BAD_REQUEST, msg),
        Err(ExecutorError::ExecutionNotFound(msg)) => err_json(StatusCode::NOT_FOUND, msg),
        // Custom body re-keyed on the path id, so this arm stays explicit.
        Err(ExecutorError::HumanRequestNotFound {
            execution_id: _,
            request_id,
        }) => err_json(
            StatusCode::NOT_FOUND,
            format!("human request {request_id:?} not found in execution {id}"),
        ),
        // The input wait already has its one outcome (named), or its
        // execution's outcome is published.
        Err(ExecutorError::InputRequestConflict(msg)) => err_json(StatusCode::CONFLICT, msg),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// POST /executions/{id}/external-inputs — append prompt/context input evidence
// ---------------------------------------------------------------------------

async fn append_external_input(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ExecutionExternalInputAppendRequest>,
) -> impl IntoResponse {
    let executor = match require_executor(&state, "workflow execution not available on this node") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    let execution_id = match parse_execution_id(&id) {
        Ok(execution_id) => execution_id,
        Err(response) => return response,
    };
    // This route diverges from the canonical mapping for two variants: an
    // unknown channel is a 404 re-keyed on the path id (not the 400 "not
    // declared" form), and PolicyDenied is a 409 (not 412). Those stay explicit.
    match executor.append_external_input(execution_id, body) {
        Ok(appended) => (StatusCode::OK, Json(appended)).into_response(),
        Err(ExecutorError::InvalidDefinition(msg)) => err_json(StatusCode::BAD_REQUEST, msg),
        Err(ExecutorError::ExecutionNotFound(msg)) => err_json(StatusCode::NOT_FOUND, msg),
        Err(ExecutorError::ExternalInputChannelNotFound {
            execution_id: _,
            channel,
        }) => err_json(
            StatusCode::NOT_FOUND,
            format!("external input channel {channel:?} not found in execution {id}"),
        ),
        Err(ExecutorError::PolicyDenied(msg)) => err_json(StatusCode::CONFLICT, msg),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// GET /executions/{id}/stages/{stage}/output — single stage output
// ---------------------------------------------------------------------------

async fn get_stage_output(
    State(app): State<AppState>,
    Path((id, stage_name)): Path<(String, String)>,
) -> impl IntoResponse {
    let executor = match require_executor(&app, "workflow execution not available on this node") {
        Ok(executor) => executor,
        Err(response) => return response,
    };
    match executor.try_get_stage_output(&id, &stage_name) {
        Ok(StageOutputResult::ExecutionNotFound) => {
            err_json(StatusCode::NOT_FOUND, format!("execution {id} not found"))
        }
        Ok(StageOutputResult::StageNotFound) => err_json(
            StatusCode::NOT_FOUND,
            format!("stage {stage_name:?} not found in execution {id}"),
        ),
        Ok(StageOutputResult::NotYetComplete) => err_json(
            // 425 Too Early — stage is in the ledger but not yet done.
            StatusCode::from_u16(425).unwrap(),
            format!("stage {stage_name:?} has not yet completed"),
        ),
        Ok(StageOutputResult::Completed(output)) => Json(output).into_response(),
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    }
}
