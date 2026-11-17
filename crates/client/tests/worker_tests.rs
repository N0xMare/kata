//! SDK coverage for the worker inventory surface.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kata_api::executor::WorkflowExecutor;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_client::KataClient;
use kata_core::{InFlightLedger, SubsystemHealth, SubsystemId, SystemHealth};
use kata_program::library::WorkflowLibrary;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_transport::transport::WorkerTransport;
use kata_transport::{InProcessTransport, WorkerPoolSupervisor};
use kata_workflow::dispatcher::Dispatcher;
use smol_str::SmolStr;
use ulid::Ulid;

fn executor_with_supervisor(supervisor: Arc<WorkerPoolSupervisor>) -> Arc<WorkflowExecutor> {
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(500),
        Duration::from_millis(500),
    ));
    let ledger = InFlightLedger::in_memory();
    let dispatcher = Arc::new(Dispatcher::new(Arc::clone(&supervisor), heartbeat, ledger));
    let library = Arc::new(WorkflowLibrary::new(vec![]));
    Arc::new(WorkflowExecutor::new(dispatcher, supervisor, library))
}

fn state_with_executor(executor: Arc<WorkflowExecutor>) -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    AppState::with_executor(health, executor)
}

fn state_with_supervisor(supervisor: Arc<WorkerPoolSupervisor>) -> AppState {
    state_with_executor(executor_with_supervisor(supervisor))
}

async fn boot_client(state: AppState) -> (KataClient, tokio::task::JoinHandle<()>) {
    let cfg = kata_types::config::ApiConfig {
        bind: "127.0.0.1:0".into(),
        auth: kata_types::config::ApiAuthConfig::Disabled {},
    };
    let server = ApiServer::build(&cfg, state).unwrap();
    let router = server.into_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let client = KataClient::new(format!("http://{addr}")).unwrap();
    (client, handle)
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn sdk_list_workers_decodes_inventory() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let (home, _worker) = InProcessTransport::pair(8);
    let home: Arc<dyn WorkerTransport> = Arc::new(home);
    supervisor.register_worker_with_caps(
        SmolStr::new("sdk-worker"),
        home,
        vec!["shell".to_string(), "agent:codex".to_string()],
    );
    supervisor
        .get_worker("sdk-worker")
        .unwrap()
        .active_assignments
        .store(4, Ordering::Relaxed);

    let (client, _handle) = boot_client(state_with_supervisor(supervisor)).await;
    let inventory = client.list_workers().await.expect("list_workers");

    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].id, "sdk-worker");
    assert_eq!(
        inventory[0].capabilities,
        vec!["agent:codex".to_string(), "shell".to_string()]
    );
    assert_eq!(inventory[0].transport, "in_process");
    assert!(inventory[0].alive);
    assert_eq!(inventory[0].active_assignment_count, 4);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn sdk_list_workers_returns_empty_inventory_without_executor() {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let (client, _handle) = boot_client(AppState::new(health)).await;

    let inventory = client.list_workers().await.expect("list_workers");
    assert!(inventory.is_empty());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn sdk_workspace_awareness_decodes_worker_summary() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let (home, _worker) = InProcessTransport::pair(8);
    let home: Arc<dyn WorkerTransport> = Arc::new(home);
    supervisor.register_worker_with_caps(
        SmolStr::new("workspace-sdk-worker"),
        home,
        vec!["shell".to_string()],
    );
    supervisor
        .get_worker("workspace-sdk-worker")
        .unwrap()
        .active_assignments
        .store(2, Ordering::Relaxed);

    let (client, _handle) = boot_client(state_with_supervisor(supervisor)).await;
    let snapshot = client
        .workspace_awareness()
        .await
        .expect("workspace_awareness");

    assert_eq!(snapshot.workers.total, 1);
    assert_eq!(snapshot.workers.live, 1);
    assert_eq!(snapshot.workers.busy, 1);
    assert_eq!(snapshot.executions.total, 0);
    assert_eq!(snapshot.vcs.owned_path_count, 0);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn sdk_execution_workspace_decodes_scoped_snapshot() {
    let executor = executor_with_supervisor(Arc::new(WorkerPoolSupervisor::new()));
    let execution_id = Ulid::new();
    let program = kata_program::execution_program::compile_starlark_execution_program(
        "only = stage(id = \"only\", prompt = \"ok\", agent = \"shell\")\nworkflow(\"workspace-sdk-exec\", root = only)\n",
        "workspace-sdk-exec.star",
        &[],
    ).unwrap();
    executor
        .execution_lifecycle()
        .put_current_program(execution_id, &program)
        .unwrap();

    let (client, _handle) = boot_client(state_with_executor(executor)).await;
    let snapshot = client
        .execution_workspace(execution_id.to_string())
        .await
        .expect("execution_workspace");

    assert_eq!(snapshot.execution_id, execution_id.to_string());
    assert_eq!(snapshot.workflow_name, "workspace-sdk-exec");
    assert!(!snapshot.workspace_provider_attached);
    assert!(snapshot.workspace_provider_backend.is_none());
    assert!(
        snapshot
            .promotion
            .blockers
            .contains(&"no_workspace_provider".to_string())
    );
}

/// The SDK refuses a workspace-awareness snapshot of any schema version but its own.
/// A version-1 body — the shape before the dead working-tree and dynamic-expansion
/// fields left — DECODES into today's type, because serde ignores the extra fields,
/// so without the version check an old server's snapshot would read as a current
/// one. Served raw from a stub route, so the body is not kata's own serializer's.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn sdk_workspace_awareness_refuses_a_version_1_snapshot_by_version() {
    let body = serde_json::json!({
        "schema_version": 1,
        "generated_at_ms": 1,
        "event_head": 0,
        "executions": {"total": 0, "active": 0, "terminal": 0, "pending": 0, "running": 0,
                       "completed": 0, "failed": 0, "cancelled": 0},
        "workers": {"total": 0, "live": 0, "busy": 0},
        "vcs": {"execution_worktree_count": 0, "working_tree_count": 0, "owned_path_count": 0,
                "dynamic_expansion_event_count": 0, "checked_dispatch_guard_count": 0,
                "parked_candidate_count": 0},
        "working_trees": [],
    });
    let decoded: kata_client::types::WorkspaceAwarenessSnapshot =
        serde_json::from_value(body.clone())
            .expect("premise: a version-1 body decodes into the version-2 type");
    assert_eq!(decoded.schema_version, 1);

    let router = axum::Router::new().route(
        "/api/v1/workspace",
        axum::routing::get(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let client = KataClient::new(format!("http://{addr}")).unwrap();

    let error = client
        .workspace_awareness()
        .await
        .expect_err("a version-1 snapshot must be refused");
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "schema_version 1 is not the version {} this SDK reads",
            kata_client::types::WORKSPACE_AWARENESS_SCHEMA_VERSION
        )),
        "{message}"
    );
}

/// The SDK refuses an EXECUTION workspace snapshot of any schema version but its own.
/// The server stamps it with the same [`WORKSPACE_AWARENESS_SCHEMA_VERSION`], and
/// version 2 removed its `observed_working_trees`, so a version-1 body DECODES into
/// today's type exactly as the awareness snapshot's does: the version is the only
/// thing that tells the shapes apart. Served raw from a stub route, so the body is
/// not kata's own serializer's.
///
/// [`WORKSPACE_AWARENESS_SCHEMA_VERSION`]: kata_client::types::WORKSPACE_AWARENESS_SCHEMA_VERSION
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn sdk_execution_workspace_refuses_a_version_1_snapshot_by_version() {
    let execution_id = Ulid::new().to_string();
    let body = serde_json::json!({
        "schema_version": 1,
        "execution_id": execution_id,
        "workflow_name": "workspace-sdk-exec",
        "status": "completed",
        "workspace_provider_attached": false,
        "promotion": {"available": false, "safe_to_promote": false, "status": "unavailable"},
        "parking": {"available": false, "parked": false, "auto_parked": false,
                    "status": "unavailable"},
        "observed_working_trees": [],
    });
    let decoded: kata_client::types::ExecutionWorkspaceSnapshot =
        serde_json::from_value(body.clone())
            .expect("premise: a version-1 body decodes into the version-2 type");
    assert_eq!(decoded.schema_version, 1);

    let router = axum::Router::new().route(
        "/api/v1/executions/{id}/workspace",
        axum::routing::get(move || {
            let body = body.clone();
            async move { axum::Json(body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let client = KataClient::new(format!("http://{addr}")).unwrap();

    let error = client
        .execution_workspace(&execution_id)
        .await
        .expect_err("a version-1 execution workspace snapshot must be refused");
    let message = error.to_string();
    assert!(
        message.contains(&format!(
            "execution workspace snapshot schema_version 1 is not the version {} this SDK reads",
            kata_client::types::WORKSPACE_AWARENESS_SCHEMA_VERSION
        )),
        "{message}"
    );
}
