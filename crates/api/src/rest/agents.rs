//! Agent status endpoints and BYO agent-run route.

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use kata_types::agent_run::{
    AgentRunRequest, validate_agent_run_allowed_tools, validate_agent_run_output_schema,
};

use super::{err_json, require_executor};
use crate::executor::{ExecutorError, WorkflowExecutor};
use crate::state::AppState;

/// Agent routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/agents", get(list_agents))
        .route("/agents/run", get(get_agent_run).post(run_agent))
}

async fn list_agents(State(state): State<AppState>) -> impl IntoResponse {
    Json(agent_run_capabilities(&state))
}

async fn get_agent_run(State(state): State<AppState>) -> impl IntoResponse {
    Json(agent_run_capabilities(&state))
}

async fn run_agent(
    State(state): State<AppState>,
    payload: Result<Json<AgentRunRequest>, JsonRejection>,
) -> impl IntoResponse {
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            return err_json(
                StatusCode::BAD_REQUEST,
                format!("invalid JSON request body: {rejection}"),
            );
        }
    };

    if let Some(error) = validate_agent_run_request(&request) {
        return err_json(StatusCode::BAD_REQUEST, error);
    }

    let executor = match require_executor(&state, "agent run execution is unavailable on this node")
    {
        Ok(executor) => executor,
        Err(response) => return response,
    };

    // The agent-run route surfaces its own operator-facing text for these
    // variants (distinct from the canonical `ExecutorError` bodies), so it keeps
    // its arms explicit.
    match Box::pin(executor.run_agent(request)).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(ExecutorError::UnsupportedAgent(agent)) => err_json(
            StatusCode::BAD_REQUEST,
            format!("unsupported agent: {agent}"),
        ),
        Err(ExecutorError::NoWorkers) => err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "no local execution capacity is available",
        ),
        Err(ExecutorError::AdmissionClosed) => err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "installed main is shutting down and no longer admits agent runs",
        ),
        Err(ExecutorError::PolicyDenied(message)) => {
            err_json(StatusCode::PRECONDITION_FAILED, message)
        }
        // The canonical mapping for the rest: an `adapter_undeclared` (or any other
        // CHECK refusal) is the caller's 400, a pool with no certified worker a
        // retriable 503, and only a genuinely internal failure a 500.
        Err(err) => err.into_response(),
    }
}

fn validate_agent_run_request(request: &AgentRunRequest) -> Option<String> {
    if request.prompt.trim().is_empty() {
        return Some("prompt must not be empty".to_string());
    }
    if request.agent.trim().is_empty() {
        return Some("agent must not be empty".to_string());
    }
    if request.timeout_ms == Some(0) {
        return Some("timeout_ms must be a positive integer when provided".to_string());
    }
    if let Err(error) = validate_agent_run_allowed_tools(&request.allowed_tools) {
        return Some(error);
    }
    if let Some(schema) = request.output_schema.as_ref()
        && let Err(error) = validate_agent_run_output_schema(schema)
    {
        return Some(format!("invalid output_schema: {error}"));
    }
    None
}

fn agent_run_capabilities(state: &AppState) -> kata_types::agent_run::AgentRunCapabilities {
    state.workflow_executor.as_deref().map_or_else(
        WorkflowExecutor::unavailable_agent_run_capabilities,
        WorkflowExecutor::agent_run_capabilities,
    )
}
