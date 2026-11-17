//! SDK coverage for the native memory/context surface.

use std::sync::Arc;

use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_client::{KataClient, MemoryObjectKind, MemoryObjectStatus, MemoryProposal};
use kata_core::store::SqliteNativeMemoryStore;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_types::memory::{MemoryObjectDraft, MemoryProvenance, MemoryScope, MemorySourceKind};

fn state_with_memory() -> AppState {
    let health = Arc::new(SystemHealth::new());
    health.report(SubsystemId::Api, SubsystemHealth::Healthy);
    let store = Arc::new(SqliteNativeMemoryStore::open_in_memory().unwrap());
    AppState::new(health).with_memory_store(store)
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
            tags: Vec::new(),
            links: Vec::new(),
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Sdk,
                source_id: Some("sdk-test".to_string()),
                execution_id: None,
                agent_id: None,
                path: None,
            },
        },
        source_file: None,
    }
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
async fn sdk_memory_surface_applies_snapshots_and_returns_conflicts() {
    let (client, _handle) = boot_client(state_with_memory()).await;

    let created = client
        .propose_memory(&proposal(
            Some("task-1"),
            None,
            "Create",
            MemoryObjectStatus::Proposed,
        ))
        .await
        .expect("create memory");
    assert_eq!(created.status, "applied");
    assert_eq!(created.object.as_ref().unwrap().revision, 1);

    client
        .propose_memory(&proposal(
            Some("task-1"),
            Some(1),
            "Activate",
            MemoryObjectStatus::Active,
        ))
        .await
        .expect("update memory");

    let conflict = client
        .propose_memory(&proposal(
            Some("task-1"),
            Some(1),
            "Stale",
            MemoryObjectStatus::Rejected,
        ))
        .await
        .expect("conflict should decode");
    assert_eq!(conflict.status, "conflict");
    assert_eq!(conflict.conflict.unwrap().actual_revision, Some(2));

    let object = client
        .get_memory_object("task-1")
        .await
        .expect("get memory object");
    assert_eq!(object.revision, 2);
    assert_eq!(object.status, MemoryObjectStatus::Active);

    let snapshot = client
        .memory_snapshot_query(
            &[MemoryObjectKind::Task],
            &[MemoryObjectStatus::Active],
            None,
            None,
        )
        .await
        .expect("memory snapshot");
    assert_eq!(snapshot.object_count, 1);
    assert_eq!(snapshot.objects[0].id, "task-1");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn sdk_memory_query_filters_multiple_kinds_statuses_and_limit() {
    let (client, _handle) = boot_client(state_with_memory()).await;
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
        client
            .propose_memory(&proposal)
            .await
            .expect("create memory object");
    }

    let snapshot = client
        .memory_snapshot_query(
            &[MemoryObjectKind::Task, MemoryObjectKind::Finding],
            &[MemoryObjectStatus::Active],
            None,
            Some(2),
        )
        .await
        .expect("memory snapshot query");
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

    let snapshot = client
        .memory_snapshot_query(
            &[MemoryObjectKind::Finding],
            &[MemoryObjectStatus::Active],
            Some("active findings"),
            Some(2),
        )
        .await
        .expect("memory snapshot query with text filter");
    assert_eq!(snapshot.object_count, 1);
    assert_eq!(snapshot.objects[0].id, "finding-active");
}
