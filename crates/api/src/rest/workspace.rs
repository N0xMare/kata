//! Workspace awareness endpoint.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use kata_types::workspace_awareness::{
    WORKSPACE_AWARENESS_SCHEMA_VERSION, WorkspaceAwarenessSnapshot, WorkspaceExecutionSummary,
    WorkspaceVcsSummary, WorkspaceWorkerSummary,
};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/workspace", get(get_workspace))
}

async fn get_workspace(State(state): State<AppState>) -> impl IntoResponse {
    match state.workflow_executor.as_deref() {
        Some(executor) => match executor.try_workspace_awareness_snapshot() {
            Ok(snapshot) => Json(snapshot).into_response(),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": error.to_string() })),
            )
                .into_response(),
        },
        None => Json(empty_workspace_snapshot()).into_response(),
    }
}

fn empty_workspace_snapshot() -> WorkspaceAwarenessSnapshot {
    WorkspaceAwarenessSnapshot {
        schema_version: WORKSPACE_AWARENESS_SCHEMA_VERSION,
        generated_at_ms: now_ms(),
        event_head: 0,
        executions: WorkspaceExecutionSummary::default(),
        workers: WorkspaceWorkerSummary::default(),
        vcs: WorkspaceVcsSummary::default(),
        latest_execution: None,
        active_executions: Vec::new(),
    }
}

use kata_types::time::now_ms;
