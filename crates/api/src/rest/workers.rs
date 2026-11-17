//! Worker inventory endpoint.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use kata_types::worker::WorkerInventory;

use crate::state::AppState;

/// Worker routes.
pub fn router() -> Router<AppState> {
    Router::new().route("/workers", get(list_workers))
}

async fn list_workers(State(state): State<AppState>) -> impl IntoResponse {
    let inventory: WorkerInventory = match state.workflow_executor.as_deref() {
        Some(executor) => executor.list_workers(),
        None => Vec::new(),
    };
    Json(inventory)
}
