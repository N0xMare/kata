//! REST coverage for `GET /api/v1/workers`.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_program::library::WorkflowLibrary;
use kata_transport::transport::WorkerTransport;
use kata_transport::{InProcessTransport, WorkerPoolSupervisor};
use kata_types::config::{ApiAuthConfig, ApiConfig};
use kata_types::worker::WorkerInventory;
use smol_str::SmolStr;
use tower::ServiceExt;

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

fn state_with_supervisor(supervisor: Arc<WorkerPoolSupervisor>) -> AppState {
    let library = Arc::new(WorkflowLibrary::new(vec![]));
    let executor = common::build_executor(supervisor, library);
    AppState::with_executor(health(), executor)
}

async fn get_workers(state: AppState) -> (StatusCode, WorkerInventory) {
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();
    let req = Request::builder()
        .uri("/api/v1/workers")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let inventory: WorkerInventory = serde_json::from_slice(&body).unwrap();
    (status, inventory)
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn workers_endpoint_returns_empty_list_without_executor() {
    let (status, inventory) = get_workers(AppState::new(health())).await;
    assert_eq!(status, StatusCode::OK);
    assert!(inventory.is_empty());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn workers_endpoint_returns_sorted_supervisor_snapshot() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let (z_home, _z_worker) = InProcessTransport::pair(8);
    let (a_home, _a_worker) = InProcessTransport::pair(8);
    let z_home: Arc<dyn WorkerTransport> = Arc::new(z_home);
    let a_home: Arc<dyn WorkerTransport> = Arc::new(a_home);

    supervisor.register_worker_with_containment(
        SmolStr::new("z-worker"),
        z_home,
        vec!["shell".to_string()],
        kata_workflow::test_harness::rig_worker_containment(),
    );
    supervisor.register_worker_with_containment(
        SmolStr::new("a-worker"),
        a_home,
        vec![
            "shell".to_string(),
            "agent:codex".to_string(),
            "agent:codex".to_string(),
        ],
        kata_workflow::test_harness::rig_worker_containment(),
    );
    supervisor
        .get_worker("a-worker")
        .unwrap()
        .active_assignments
        .store(2, Ordering::Relaxed);

    let (status, inventory) = get_workers(state_with_supervisor(supervisor)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        inventory.iter().map(|w| w.id.as_str()).collect::<Vec<_>>(),
        vec!["a-worker", "z-worker"]
    );
    assert_eq!(
        inventory[0].capabilities,
        vec!["agent:codex".to_string(), "shell".to_string()]
    );
    assert_eq!(inventory[0].transport, "in_process");
    assert!(inventory[0].alive);
    assert_eq!(inventory[0].active_assignment_count, 2);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn workers_endpoint_has_no_provisioning_post_route() {
    let server = ApiServer::build(&test_config(), AppState::new(health())).unwrap();
    let router = server.into_router();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/workers")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}
