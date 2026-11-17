//! Hermetic REST coverage for the stub / lightweight handlers:
//! `system.rs` (`GET /api/v1/system/status`), and the executor-less
//! `workspace.rs` path (`GET /api/v1/workspace`).
//!
//! These handlers had no coverage of the `system/status` Worker-role
//! branch. All tests build the real `axum` router via `ApiServer::build`
//! and drive it with `tower::ServiceExt::oneshot` — no sockets, no live
//! subsystems.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_types::config::{ApiAuthConfig, ApiConfig};
use tower::ServiceExt;

/// Auth-disabled config so the loopback-dev path is exercised without a
/// bearer token (matches `tests/workspace.rs`).
fn test_config() -> ApiConfig {
    ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: ApiAuthConfig::Disabled {},
    }
}

fn health() -> Arc<SystemHealth> {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    health
}

/// Issue a GET against `uri` on a router built from `state`, returning
/// the status and the parsed JSON body.
async fn get_json(state: AppState, uri: &str) -> (StatusCode, serde_json::Value) {
    let server = ApiServer::build(&test_config(), state).expect("api server builds");
    let router = server.into_router();
    let req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request builds");
    let resp = router.oneshot(req).await.expect("router responds");
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body collects");
    let value: serde_json::Value =
        serde_json::from_slice(&body).expect("handler returns valid JSON");
    (status, value)
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn system_status_reports_process_identity() {
    let state = AppState::new(health()).with_runtime_status("stub-worker-node");
    let (status, value) = get_json(state, "/api/v1/system/status").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["node_id"], "stub-worker-node");
    assert_eq!(value["process_mode"], "unknown");
    assert_eq!(value["ready"], false);
    assert!(
        value["uptime_seconds"].as_u64().is_some(),
        "uptime_seconds must be a number, got: {value}"
    );
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn system_status_reads_live_readiness() {
    let state = AppState::new(health()).with_runtime_status("readiness-test-node");
    state.runtime.set_ready(true);
    let (_, ready) = get_json(state.clone(), "/api/v1/system/status").await;
    assert_eq!(ready["ready"], true);

    state.runtime.set_ready(false);
    let (_, stopping) = get_json(state, "/api/v1/system/status").await;
    assert_eq!(stopping["ready"], false);
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn workspace_stub_returns_empty_snapshot_json_shape() {
    // Executor-less node: the handler returns the empty snapshot. This
    // asserts the raw HTTP/JSON contract (top-level keys) as a
    // complement to the typed deserialization test in `tests/workspace.rs`.
    let (status, value) = get_json(AppState::new(health()), "/api/v1/workspace").await;

    assert_eq!(status, StatusCode::OK);
    assert!(value.get("schema_version").is_some(), "got: {value}");
    assert_eq!(value["event_head"], 0);
    assert!(value.get("executions").is_some(), "got: {value}");
    assert!(value.get("workers").is_some(), "got: {value}");
    assert!(value["latest_execution"].is_null());
}
