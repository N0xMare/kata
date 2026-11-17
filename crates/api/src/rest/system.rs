//! System status endpoints.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use kata_workflow::dispatcher::NodeEnvironmentState;
use serde_json::json;

use crate::state::AppState;

/// System routes.
pub fn router() -> Router<AppState> {
    Router::new().route("/system/status", get(system_status))
}

async fn system_status(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "node_id": state.runtime.node_id,
        "process_mode": state.runtime.process_mode,
        "directory_id": state.runtime.directory_id,
        "process_generation": state.runtime.process_generation,
        "attachment_protocol_version": state.runtime.attachment_protocol_version,
        "binary_version": state.runtime.binary_version,
        "loaded_binary_digest": state.runtime.loaded_binary_digest,
        "control_endpoint": state.runtime.control_endpoint,
        "loaded_config_digest": state.runtime.loaded_config_digest,
        "loaded_config_path": state.runtime.loaded_config_path,
        "loaded_service_environment_digest": state.runtime.loaded_service_environment_digest,
        "recovery_state": state.runtime.recovery_state,
        "next_action": state.runtime.next_action,
        "ready": state.runtime.is_ready(),
        // The node's `[node] environment`: bound (its id) or none.
        "node_environment": node_environment_json(
            &state
                .workflow_executor
                .as_ref()
                .map_or(NodeEnvironmentState::None, |executor| {
                    executor.node_environment_state()
                }),
        ),
        "uptime_seconds": state.runtime.uptime_seconds()
    }))
}

/// The `node_environment` object of the system status: `bound` (with its id) or `none`.
fn node_environment_json(state: &NodeEnvironmentState) -> serde_json::Value {
    match state {
        NodeEnvironmentState::Bound(environment) => json!({
            "state": "bound",
            "environment_id": environment.0.to_string(),
        }),
        NodeEnvironmentState::None => json!({ "state": "none" }),
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeEnvironmentState, node_environment_json};

    /// The status surface's wording for each state — moved here from the dispatcher,
    /// which now hands over the neutral fact.
    #[test]
    fn each_node_environment_state_presents_its_own_object() {
        let id = kata_types::execution_contract::EnvironmentId(
            kata_types::primitives::ContentHash::new([0x5A; 32]),
        );
        let bound = node_environment_json(&NodeEnvironmentState::Bound(id));
        assert_eq!(bound["state"], "bound");
        assert_eq!(bound["environment_id"], id.0.to_string());
        assert_eq!(
            node_environment_json(&NodeEnvironmentState::None),
            serde_json::json!({ "state": "none" })
        );
    }
}
