//! REST coverage for the native memory/context endpoints.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::store::SqliteNativeMemoryStore;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_types::config::{ApiAuthConfig, ApiConfig};
use kata_types::memory::{
    MEMORY_SCHEMA_VERSION, MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus, MemoryProposal,
    MemoryProposalResponse, MemoryProvenance, MemoryScope, MemorySnapshot, MemorySourceKind,
};
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

fn state_with_memory() -> AppState {
    let store = Arc::new(SqliteNativeMemoryStore::open_in_memory().unwrap());
    AppState::new(health()).with_memory_store(store)
}

fn proposal(
    id: Option<&str>,
    expected_revision: Option<u64>,
    title: &str,
    status: MemoryObjectStatus,
) -> MemoryProposal {
    proposal_with_kind(id, expected_revision, title, MemoryObjectKind::Task, status)
}

fn proposal_with_kind(
    id: Option<&str>,
    expected_revision: Option<u64>,
    title: &str,
    kind: MemoryObjectKind,
    status: MemoryObjectStatus,
) -> MemoryProposal {
    MemoryProposal {
        proposal_id: None,
        expected_revision,
        object: MemoryObjectDraft {
            id: id.map(ToOwned::to_owned),
            kind,
            scope: MemoryScope::Global,
            status,
            title: Some(title.to_string()),
            body: serde_json::json!({ "summary": title }),
            tags: vec!["factory".to_string()],
            links: Vec::new(),
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Operator,
                source_id: Some("api-test".to_string()),
                execution_id: None,
                agent_id: None,
                path: None,
            },
        },
        source_file: None,
    }
}

async fn request_json(
    state: AppState,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();
    let body = body.map_or_else(Body::empty, |value| {
        Body::from(serde_json::to_vec(&value).unwrap())
    });
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, value)
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn memory_endpoint_applies_proposal_and_returns_snapshot() {
    let state = state_with_memory();
    let proposal = proposal(
        Some("task-1"),
        None,
        "Define product target",
        MemoryObjectStatus::Active,
    );

    let (status, response) = request_json(
        state.clone(),
        Method::POST,
        "/api/v1/memory",
        Some(serde_json::to_value(&proposal).unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response: MemoryProposalResponse = serde_json::from_value(response).unwrap();
    assert_eq!(response.status, "applied");
    assert_eq!(response.object.unwrap().revision, 1);

    let (status, response) = request_json(
        state,
        Method::GET,
        "/api/v1/memory?kind=task&status=active",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let snapshot: MemorySnapshot = serde_json::from_value(response).unwrap();
    assert_eq!(snapshot.schema_version, MEMORY_SCHEMA_VERSION);
    assert_eq!(snapshot.object_count, 1);
    assert_eq!(snapshot.objects[0].id, "task-1");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn memory_endpoint_surfaces_conflict_without_overwriting() {
    let state = state_with_memory();
    request_json(
        state.clone(),
        Method::POST,
        "/api/v1/memory",
        Some(
            serde_json::to_value(proposal(
                Some("task-1"),
                None,
                "First",
                MemoryObjectStatus::Proposed,
            ))
            .unwrap(),
        ),
    )
    .await;
    request_json(
        state.clone(),
        Method::POST,
        "/api/v1/memory",
        Some(
            serde_json::to_value(proposal(
                Some("task-1"),
                Some(1),
                "Second",
                MemoryObjectStatus::Active,
            ))
            .unwrap(),
        ),
    )
    .await;

    let (status, response) = request_json(
        state.clone(),
        Method::POST,
        "/api/v1/memory",
        Some(
            serde_json::to_value(proposal(
                Some("task-1"),
                Some(1),
                "Stale",
                MemoryObjectStatus::Rejected,
            ))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let response: MemoryProposalResponse = serde_json::from_value(response).unwrap();
    assert_eq!(response.status, "conflict");
    assert_eq!(response.conflict.unwrap().actual_revision, Some(2));

    let (status, object) = request_json(state, Method::GET, "/api/v1/memory/task-1", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(object["revision"], 2);
    assert_eq!(object["status"], "active");
    assert_eq!(object["title"], "Second");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn memory_endpoint_requires_store_and_valid_filters() {
    let (status, response) =
        request_json(AppState::new(health()), Method::GET, "/api/v1/memory", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response["error"], "native memory store unavailable");

    let (status, response) = request_json(
        state_with_memory(),
        Method::GET,
        "/api/v1/memory?kind=nope",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        response["error"]
            .as_str()
            .unwrap()
            .contains("unknown memory kind")
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn memory_endpoint_accepts_controller_query_filters() {
    let state = state_with_memory();
    for proposal in [
        proposal_with_kind(
            Some("task-active"),
            None,
            "Active task",
            MemoryObjectKind::Task,
            MemoryObjectStatus::Active,
        ),
        proposal_with_kind(
            Some("finding-active"),
            None,
            "Active finding",
            MemoryObjectKind::Finding,
            MemoryObjectStatus::Active,
        ),
        proposal_with_kind(
            Some("risk-active"),
            None,
            "Active risk",
            MemoryObjectKind::Risk,
            MemoryObjectStatus::Active,
        ),
        proposal_with_kind(
            Some("task-proposed"),
            None,
            "Proposed task",
            MemoryObjectKind::Task,
            MemoryObjectStatus::Proposed,
        ),
    ] {
        let (status, _) = request_json(
            state.clone(),
            Method::POST,
            "/api/v1/memory",
            Some(serde_json::to_value(proposal).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, response) = request_json(
        state,
        Method::GET,
        "/api/v1/memory?kinds=task,finding&statuses=active&limit=2",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let snapshot: MemorySnapshot = serde_json::from_value(response).unwrap();
    assert_eq!(snapshot.object_count, 2);
    let ids = snapshot
        .objects
        .iter()
        .map(|object| object.id.as_str())
        .collect::<Vec<_>>();
    assert!(ids.contains(&"task-active"));
    assert!(ids.contains(&"finding-active"));
    assert!(
        snapshot
            .objects
            .iter()
            .all(|object| object.status == MemoryObjectStatus::Active)
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn memory_endpoint_rejects_invalid_controller_query_filters() {
    for (uri, expected) in [
        (
            "/api/v1/memory?kind=task&kinds=finding",
            "use either `kind` or `kinds`",
        ),
        ("/api/v1/memory?kinds=task,nope", "unknown memory kind"),
        (
            "/api/v1/memory?status=active&statuses=proposed",
            "use either `status` or `statuses`",
        ),
        (
            "/api/v1/memory?statuses=active,nope",
            "unknown memory status",
        ),
        (
            "/api/v1/memory?limit=0",
            "memory snapshot limit must be greater than zero",
        ),
    ] {
        let (status, response) = request_json(state_with_memory(), Method::GET, uri, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            response["error"].as_str().unwrap().contains(expected),
            "expected {expected:?}, got {response:?}"
        );
    }
}
