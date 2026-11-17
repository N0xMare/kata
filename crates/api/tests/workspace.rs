//! REST coverage for `GET /api/v1/workspace`.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kata_api::executor::WorkflowExecutor;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::{SubsystemHealth, SubsystemId, SystemHealth};
use kata_program::library::WorkflowLibrary;
use kata_transport::transport::WorkerTransport;
use kata_transport::{InProcessTransport, WorkerPoolSupervisor};
use kata_types::config::{ApiAuthConfig, ApiConfig};
use kata_types::workspace_awareness::{
    ExecutionWorkspaceSnapshot, WORKSPACE_AWARENESS_SCHEMA_VERSION, WorkspaceAwarenessSnapshot,
};
use smol_str::SmolStr;
use tower::ServiceExt;
use ulid::Ulid;

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

fn executor_with_supervisor(supervisor: Arc<WorkerPoolSupervisor>) -> Arc<WorkflowExecutor> {
    common::build_executor(supervisor, Arc::new(WorkflowLibrary::new(vec![])))
}

fn state_with_executor(executor: Arc<WorkflowExecutor>) -> AppState {
    AppState::with_executor(health(), executor)
}

fn state_with_supervisor(supervisor: Arc<WorkerPoolSupervisor>) -> AppState {
    state_with_executor(executor_with_supervisor(supervisor))
}

async fn get_workspace(state: AppState) -> (StatusCode, WorkspaceAwarenessSnapshot) {
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();
    let req = Request::builder()
        .uri("/api/v1/workspace")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let snapshot: WorkspaceAwarenessSnapshot = serde_json::from_slice(&body).unwrap();
    (status, snapshot)
}

async fn get_execution_workspace(
    state: AppState,
    execution_id: &str,
) -> (StatusCode, serde_json::Value) {
    let server = ApiServer::build(&test_config(), state).unwrap();
    let router = server.into_router();
    let req = Request::builder()
        .uri(format!("/api/v1/executions/{execution_id}/workspace"))
        .body(Body::empty())
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
async fn workspace_endpoint_returns_empty_snapshot_without_executor() {
    let (status, snapshot) = get_workspace(AppState::new(health())).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(snapshot.schema_version, WORKSPACE_AWARENESS_SCHEMA_VERSION);
    // The wire version as a LITERAL, independent of the constant the server stamps:
    // a bump changes what every SDK accepts (`refuse_foreign_workspace_schema`), so
    // it is a wire change that edits this pin on purpose, never by accident.
    assert_eq!(
        snapshot.schema_version, 2,
        "the workspace snapshot wire version"
    );
    assert_eq!(snapshot.event_head, 0);
    assert_eq!(snapshot.executions.total, 0);
    assert_eq!(snapshot.workers.total, 0);
    assert_eq!(snapshot.vcs.owned_path_count, 0);
    assert!(snapshot.latest_execution.is_none());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn workspace_endpoint_projects_worker_inventory_summary() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let executor = executor_with_supervisor(Arc::clone(&supervisor));
    let (home, _worker) = InProcessTransport::pair(8);
    let home: Arc<dyn WorkerTransport> = Arc::new(home);
    supervisor.register_worker_with_effect_domain(
        SmolStr::new("workspace-worker"),
        home,
        vec!["shell".to_string(), "agent:codex".to_string()],
        kata_workflow::test_harness::rig_worker_containment(),
        *kata_workflow::test_harness::oci_rig_executor_term().digest(),
        executor
            .dispatcher_for_test()
            .enroll_worker_membrane(
                "api-fixture-inventory",
                kata_types::identity::WorkerMembraneId(Ulid::new()),
            )
            .unwrap(),
    );
    supervisor
        .get_worker("workspace-worker")
        .unwrap()
        .active_assignments
        .store(3, Ordering::Relaxed);

    let (status, snapshot) = get_workspace(state_with_executor(executor)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(snapshot.workers.total, 1);
    assert_eq!(snapshot.workers.live, 1);
    assert_eq!(snapshot.workers.busy, 1);
    assert_eq!(
        snapshot.workers.by_transport.get("in_process").copied(),
        Some(1)
    );
    assert_eq!(snapshot.workers.inventory[0].id, "workspace-worker");
    assert_eq!(snapshot.executions.active, 0);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn execution_workspace_endpoint_returns_service_unavailable_without_executor() {
    let id = Ulid::new().to_string();
    let (status, value) = get_execution_workspace(AppState::new(health()), &id).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        value["error"],
        "workflow execution not available on this node"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn execution_workspace_endpoint_returns_not_found_for_unknown_execution() {
    let state = state_with_supervisor(Arc::new(WorkerPoolSupervisor::new()));
    let id = Ulid::new().to_string();
    let (status, value) = get_execution_workspace(state, &id).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(value["error"].as_str().unwrap().contains(&id));
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn execution_workspace_endpoint_returns_scoped_snapshot() {
    let executor = executor_with_supervisor(Arc::new(WorkerPoolSupervisor::new()));
    let execution_id = Ulid::new();
    let program = kata_program::execution_program::compile_starlark_execution_program(
        "only = stage(id = \"only\", prompt = \"ok\", agent = \"shell\")\nworkflow(\"workspace-route\", root = only)\n",
        "workspace-route.star",
        &[],
    )
    .unwrap();
    executor
        .execution_lifecycle()
        .put_current_program(execution_id, &program)
        .unwrap();

    let (status, value) =
        get_execution_workspace(state_with_executor(executor), &execution_id.to_string()).await;
    assert_eq!(status, StatusCode::OK);
    let snapshot: ExecutionWorkspaceSnapshot = serde_json::from_value(value).unwrap();

    assert_eq!(snapshot.schema_version, WORKSPACE_AWARENESS_SCHEMA_VERSION);
    assert_eq!(snapshot.execution_id, execution_id.to_string());
    assert_eq!(snapshot.workflow_name, "workspace-route");
    assert!(!snapshot.workspace_provider_attached);
    assert!(snapshot.workspace_provider_backend.is_none());
    assert!(snapshot.worktree.is_none());
    assert!(!snapshot.promotion.available);
    assert!(
        snapshot
            .promotion
            .blockers
            .contains(&"no_workspace_provider".to_string())
    );
}

/// `git <args>` at `repo`, stdout trimmed — the store's own answer.
fn git(repo: &std::path::Path, args: &[&str]) -> String {
    let out = kata_test_utils::git::hermetic_git_in(repo)
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A colocated git+jj repository with one committed trunk, an operational store and
/// the jj execution-workspace provider over the repository — what an `oci` main's
/// workspace endpoint reads.
struct WorkspaceRig {
    _dir: tempfile::TempDir,
    repo: std::path::PathBuf,
    trunk: String,
    db: Arc<kata_core::OperationalDb>,
    cas: Arc<kata_core::store::cas::CasStore>,
    face: kata_workflow::execution_lifecycle::ExecutionLifecycleFace,
    provider: Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>,
}

impl WorkspaceRig {
    fn new() -> Self {
        use kata_core::OperationalDb;
        use kata_core::store::cas::CasStore;
        use kata_vcs::{JjBackend, VcsBackend};
        use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        kata_test_utils::git::init_git_repo_at(&repo);
        std::fs::write(repo.join("keep.txt"), "keep\n").unwrap();
        kata_test_utils::git::run_git(&repo, &["add", "-A"]);
        kata_test_utils::git::run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
        let trunk = git(&repo, &["rev-parse", "main"]);

        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let cas = Arc::new(CasStore::open(data.join("cas.db"), data.join("cas")).unwrap());
        let db = Arc::new(
            OperationalDb::open_with_cas(data.join("operational.db"), Arc::clone(&cas)).unwrap(),
        );
        let face = ExecutionLifecycleFace::new(Arc::clone(&db));
        let provider: Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider> = Arc::new(
            <JjBackend as VcsBackend>::open(&repo).expect("the colocated jj backend opens"),
        );
        Self {
            _dir: dir,
            repo,
            trunk,
            db,
            cas,
            face,
            provider,
        }
    }

    /// Admit a fresh execution of a worktree-isolated `write` → `commit` pack.
    fn admit(&self) -> Ulid {
        let program = kata_program::execution_program::compile_starlark_execution_program(
            r#"
write = stage(id = "write", run = "true", agent = "shell")
snap = stage(id = "snap", agent = "workspace_effect", op = "commit", depends_on = ["write"])
workflow("committed-candidate-identity", root = [write, snap], worktree_isolated = True)
"#,
            "committed-candidate-identity.star",
            &[],
        )
        .expect("the pack compiles");
        let execution_id = Ulid::new();
        let target = kata_vcs::test_support::resolve_trunk_target(
            self.provider.as_ref(),
            &kata_effects_contract::ExecutionWorkspaceKey::execution(execution_id),
        )
        .expect("resolve the trunk target");
        self.face
            .put_current_program_with_target(execution_id, &program, target)
            .expect("the execution is admitted");
        execution_id
    }

    /// The live identity `GET /executions/{id}/workspace` reports for `execution_id`.
    async fn endpoint_identity(
        &self,
        execution_id: Ulid,
    ) -> kata_types::execution::ExecutionWorkspaceIdentity {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let dispatcher = Arc::new(
            kata_workflow::dispatcher::Dispatcher::new(
                Arc::clone(&supervisor),
                Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
                    std::time::Duration::from_secs(30),
                    std::time::Duration::from_secs(30),
                )),
                kata_core::InFlightLedger::in_memory(),
            )
            .with_execution_lifecycle(self.face.clone()),
        );
        let executor = Arc::new(
            WorkflowExecutor::new(
                dispatcher,
                supervisor,
                Arc::new(WorkflowLibrary::new(vec![])),
            )
            .with_execution_lifecycle(self.face.clone())
            .with_workspace_provider(Arc::clone(&self.provider)),
        );
        let (status, value) =
            get_execution_workspace(state_with_executor(executor), &execution_id.to_string()).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        let snapshot: ExecutionWorkspaceSnapshot = serde_json::from_value(value).unwrap();
        snapshot
            .worktree
            .expect("the execution's workspace is live")
            .identity
            .expect("the jj provider stamps an identity")
    }
}

/// The workspace identity's `base_ref` is the branch the execution's FROZEN
/// target names, never the trunk the provider resolves now. After admission
/// the repository grows a second branch and still names no trunk, so a live
/// resolution can no longer tell one (refused, while `git branch` lists both);
/// the endpoint still names `main`, beside the recorded base `git rev-parse`
/// gave at admission.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_workspace_identity_names_the_frozen_branch_not_trunk_as_it_resolves_now() {
    use kata_effects_contract::ExecutionWorkspaceKey;
    use kata_types::tree_artifact::WorkTreeInputBounds;

    let rig = WorkspaceRig::new();
    let (repo, trunk, provider) = (&rig.repo, &rig.trunk, &rig.provider);
    let execution_id = rig.admit();
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let handle = kata_vcs::test_support::create_trunk_workspace(provider.as_ref(), &key)
        .expect("the workspace creates");
    kata_core::work_tree::publish_base_tree_head(&rig.db, &rig.cas, execution_id, |put| {
        provider.committed_base_tree(&handle, WorkTreeInputBounds::default(), put)
    })
    .expect("the committed base head publishes");

    git(repo, &["branch", "dev"]);
    assert!(
        kata_vcs::test_support::resolve_trunk_target(
            provider.as_ref(),
            &ExecutionWorkspaceKey::execution(Ulid::new()),
        )
        .is_err(),
        "a live resolution cannot tell trunk any more"
    );

    let identity = rig.endpoint_identity(execution_id).await;
    assert_eq!(
        identity.base_ref.as_deref(),
        Some("main"),
        "the frozen target's branch: {identity:?}"
    );
    assert_eq!(identity.base_commit_sha.as_deref(), Some(trunk.as_str()));
}

/// A committed candidate's workspace identity names the EXECUTION'S base, read
/// through the endpoint the SDK's factory projection consumes.
///
/// `factory_candidate_packet` decides "is the live worktree a candidate, or still
/// just the base?" from `workspace_commit_sha != base_commit_sha` — under `oci` the
/// apply COMMITS each delta into `@`, so the dirty/changed-path arms read clean
/// exactly when work landed. After a `commit` effect, `@` is a fresh empty commit
/// on top of the stage commit, so `@`'s first parent IS the candidate's own commit:
/// an identity whose base is that first parent reported every committed candidate
/// as "just the base".
///
/// The stage's content reaches the workspace through the `oci` verbs themselves
/// (`apply_work_delta`, then `commit_workspace_effect`); every expected value is
/// read through `git` at the colocated repository root. The head row's candidate
/// is not advanced here — the endpoint reads the row's `base_commit`, which no
/// apply or commit moves.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_committed_candidates_identity_names_the_executions_base_not_its_own_commit() {
    use kata_effects_contract::ExecutionWorkspaceKey;
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
    use kata_types::primitives::ObjectId;
    use kata_types::tree_artifact::{TreeEntryMode, TreeNode, TreePath, WorkTreeInputBounds};
    use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};

    let rig = WorkspaceRig::new();
    let (repo, trunk, provider) = (&rig.repo, &rig.trunk, &rig.provider);
    let execution_id = rig.admit();
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let handle = kata_vcs::test_support::create_trunk_workspace(provider.as_ref(), &key)
        .expect("the workspace creates");
    let head =
        kata_core::work_tree::publish_base_tree_head(&rig.db, &rig.cas, execution_id, |put| {
            provider.committed_base_tree(&handle, WorkTreeInputBounds::default(), put)
        })
        .expect("the committed base head publishes");
    assert_eq!(&head.base_commit, trunk, "the execution forks from trunk");

    // The write stage's delta, applied onto the recorded candidate, then the
    // `commit` effect over it.
    let bytes = b"written by the stage\n";
    let object = kata_types::cache::object_id_for_canonical_bytes(bytes);
    let delta = TreeDelta::new(
        ArtifactRef::new(ObjectId::zero(), 0, ArtifactPrivacy::Private),
        vec![TreeChange {
            path: TreePath::new("candidate.txt").unwrap(),
            change: TreeChangeKind::Write {
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object,
                    size_bytes: bytes.len() as u64,
                },
            },
        }],
    )
    .unwrap();
    let applied = provider
        .apply_work_delta(
            &handle,
            &head.candidate_commit_id,
            &delta,
            &|_, _| Ok(bytes.to_vec()),
            "identity-cell-apply",
        )
        .expect("the apply lands");
    let committed = provider
        .commit_workspace_effect(&key, &applied.commit_id, "identity-cell-commit")
        .expect("the commit effect lands");

    // The repository's answer: `exec-<id>` names a commit holding the write,
    // whose parent is trunk.
    let stage_commit = git(repo, &["rev-parse", &format!("exec-{execution_id}")]);
    assert_eq!(stage_commit, committed.commit_sha);
    assert_eq!(
        git(repo, &["show", &format!("{stage_commit}:candidate.txt")]),
        "written by the stage"
    );
    assert_eq!(
        &git(repo, &["rev-parse", &format!("{stage_commit}^")]),
        trunk
    );

    let identity = rig.endpoint_identity(execution_id).await;
    assert_eq!(
        identity.workspace_commit_sha.as_deref(),
        Some(stage_commit.as_str()),
        "the candidate is the stage commit"
    );
    assert_eq!(
        identity.base_commit_sha.as_deref(),
        Some(trunk.as_str()),
        "the base is the commit the execution forked from (its head row's base_commit), \
         not `@`'s first parent — which after a commit IS the candidate"
    );
}

/// A live workspace whose execution has NO recorded jj base reports no base — not
/// the provider's `@`-first-parent guess, and not the head row's empty spelling.
///
/// Two executions over one repository, each with a live jj workspace whose `@`'s
/// first parent is trunk (the provider's own stamp, asserted below — the guess a
/// fallback would report): one admitted with no `/work` head row at all (the
/// `after_base_tree_published_before_head_recorded` window recovery re-drives), one
/// whose root row carries the scratch seed's empty `base_commit` (`''`, the recorded
/// fact "no checkout behind this head").
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_live_workspace_with_no_recorded_jj_base_reports_no_base() {
    use kata_effects_contract::ExecutionWorkspaceKey;

    let rig = WorkspaceRig::new();
    let unrecorded = rig.admit();
    let empty_base = rig.admit();
    for execution_id in [unrecorded, empty_base] {
        let key = ExecutionWorkspaceKey::execution(execution_id);
        kata_vcs::test_support::create_trunk_workspace(&*rig.provider, &key)
            .expect("the workspace creates");
        // The guess a fallback would report is real: the provider's own stamp
        // names trunk as this workspace's base.
        let provider_stamp = rig
            .provider
            .workspace_status(&key)
            .expect("the status reads")
            .and_then(|status| status.identity)
            .and_then(|identity| identity.base_commit_sha);
        assert_eq!(provider_stamp.as_deref(), Some(rig.trunk.as_str()));
    }
    let seed = kata_core::work_tree::declare_empty_tree(&rig.db, &rig.cas, empty_base)
        .expect("the empty seed declares");
    let row = rig
        .db
        .record_work_tree_head(empty_base, "", seed.id().0.0, "")
        .expect("the empty-base head row records");
    assert_eq!(row.base_commit, "");
    assert!(
        rig.db
            .execution_work_tree_head(unrecorded)
            .expect("the head read runs")
            .is_none(),
        "the first execution has no head row"
    );

    for (label, execution_id) in [
        ("no head row", unrecorded),
        ("empty base_commit", empty_base),
    ] {
        let identity = rig.endpoint_identity(execution_id).await;
        assert!(
            identity.workspace_commit_sha.is_some(),
            "{label}: the provider stamped a live identity"
        );
        assert_eq!(
            identity.base_commit_sha, None,
            "{label}: an execution with no recorded jj base states no base"
        );
    }
}
