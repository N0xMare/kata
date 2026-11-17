//! THE OPERATOR LISTING for an `oci` `workspace_effect` gate. A gated effect
//! parks as a `main`-executor `awaiting_approval` attempt, which
//! `live_work_registry` excludes by name — so a listing built on it would make
//! `GET /approvals`, `kata approvals`, and the SDK's `list_approvals` answer
//! `[]` for exactly the gates needing an operator. This cell seeds the parked gate through the
//! real `OperationalDb` door (what `WorkflowRunner::submit_workspace_effect`
//! writes), serves `GET /api/v1/approvals` over the in-process router, and
//! asserts the entry against the RAW attempts row.
//!
//! The same rig drives the operator's DECIDING doors over main-resolved
//! attempts: a second, opposite verdict on a workspace-effect or an expansion
//! gate, and any verdict on an attempt no deciding plane holds as a gate, are a
//! 409 that records nothing.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use kata_api::executor::WorkflowExecutor;
use kata_api::server::ApiServer;
use kata_api::state::AppState;
use kata_core::operational::{
    ExecutionWorkTreeHead, ExpansionSpec, MainAttemptSpec, MainWait, OccurrenceBinding,
    WorkspaceEffectSpec,
};
use kata_core::{InFlightLedger, OperationalDb};
use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_test_utils::disabled_auth_config;
use kata_test_utils::git::{init_git_repo_at, run_git};
use kata_transport::WorkerPoolSupervisor;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_types::execution_contract::OccurrenceRef;
use kata_types::tree_artifact::WorkTreeInputBounds;
use kata_types::workflow::WorkspaceEffectOp;
use kata_vcs::{JjBackend, VcsBackend};
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use ulid::Ulid;

const STAGE: &str = "ship";

/// One `workspace_effect` stage `ship` running `op` — enough program for the
/// claim's occurrence binding to be real. A `forge_export` needs a `commit`
/// ancestor and a required validation criterion, so its program carries both.
fn program(op: WorkspaceEffectOp) -> kata_program::execution_program::ExecutionProgram {
    let pack = match op {
        WorkspaceEffectOp::ForgeExport => {
            r#"
proof = stage(id = "proof", agent = "shell", prompt = "echo ok")
snap = stage(id = "snap", agent = "workspace_effect", op = "commit", depends_on = ["proof"])
ship = stage(
    id = "ship",
    agent = "workspace_effect",
    op = "forge_export",
    depends_on = ["snap"],
)
workflow(
    "approvals-listing-cell",
    root = [proof, snap, ship],
    worktree_isolated = True,
    validation_criteria = [validation_criterion("proof", description = "proof", stage = "proof", required = True)],
)
"#
        }
        _ => {
            r#"
ship = stage(
    id = "ship",
    agent = "workspace_effect",
    op = "park",
)
workflow(
    "approvals-listing-cell",
    root = [ship],
    worktree_isolated = True,
)
"#
        }
    };
    kata_program::execution_program::compile_starlark_execution_program(
        pack,
        "approvals-listing-cell.star",
        &[],
    )
    .expect("the cell's pack compiles")
}

/// The remote a `forge_export` cell's claim records. The fixture repository
/// has NO remote at all, so a listing that showed this name can only have read
/// it off the stored spec.
const CLAIMED_REMOTE: &str = "upstream";

/// Boot the minimal executor over a REAL operational store and park a gated
/// `op` effect on it — the shape the runner produces for `approval = True`.
/// Returns the router, the parked attempt id, and the execution id; the
/// tempdir + db handles stay alive in the returned tuple.
#[allow(clippy::type_complexity)]
fn boot_with_parked_effect(
    op: WorkspaceEffectOp,
) -> (
    axum::Router,
    Ulid,
    Ulid,
    tempfile::TempDir,
    Arc<OperationalDb>,
) {
    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(
        kata_core::store::cas::CasStore::open(dir.path().join("cas.db"), dir.path().join("cas"))
            .unwrap(),
    );
    let db = Arc::new(
        OperationalDb::open_with_cas(dir.path().join("operational.db"), Arc::clone(&cas)).unwrap(),
    );
    let face = ExecutionLifecycleFace::new(Arc::clone(&db));

    // The workspace + recorded head the claim's spec names.
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    std::fs::write(repo.join("a.txt"), "committed\n").unwrap();
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
    let backend = <JjBackend as VcsBackend>::open(&repo).expect("the colocated jj backend opens");

    let execution_id = Ulid::new();
    let program = program(op);
    // Admitted through the production door with the trunk target the provider
    // resolves: the approvals listing reads this invocation back (each gate shows
    // its run's frozen target), so it must be one admission actually wrote.
    face.put_current_program_with_target(
        execution_id,
        &program,
        kata_vcs::test_support::resolve_trunk_target(
            &backend,
            &ExecutionWorkspaceKey::execution(execution_id),
        )
        .expect("the trunk target resolves"),
    )
    .expect("the execution is admitted");
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let workspace = kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect("the workspace creates");
    let head: ExecutionWorkTreeHead =
        kata_core::work_tree::publish_base_tree_head(&db, &Arc::clone(&cas), execution_id, |put| {
            ExecutionWorkspaceProvider::committed_base_tree(
                &backend,
                &workspace,
                WorkTreeInputBounds::default(),
                put,
            )
        })
        .expect("the base head publishes");
    face.mark_running_after_admission(execution_id)
        .expect("the execution runs");

    let stage_id = kata_types::workflow::StageId(smol_str::SmolStr::new(STAGE));
    let lowered =
        kata_program::execution_program::lower_stage_operation(&program, &stage_id).unwrap();
    let forge_export = op == WorkspaceEffectOp::ForgeExport;
    let spec = WorkspaceEffectSpec {
        op,
        label: None,
        target: if forge_export {
            format!("kata/{execution_id}")
        } else {
            backend.parked_ref_name(&key, None)
        },
        candidate_commit: head.candidate_commit_id.clone(),
        delivered_commit: head.candidate_commit_id.clone(),
        candidate_tree_id: ExecutionWorkspaceProvider::workspace_effect_candidate_tree(
            &backend, &key,
        )
        .unwrap()
        .expect("the tree reads"),
        pin: kata_types::execution::CandidateTreePin::Unpinned,
        forge: None,
        forge_remote: forge_export.then(|| CLAIMED_REMOTE.to_owned()),
    };
    let attempt_id = Ulid::new();
    db.claim_workspace_effect_attempt(
        attempt_id,
        &MainAttemptSpec {
            stage_id: STAGE.to_string(),
            occurrence: OccurrenceBinding::new(
                OccurrenceRef::new(
                    kata_types::workflow::ExecutionId(execution_id),
                    program.program_hash,
                    lowered.contract.id(),
                    lowered.path.clone(),
                ),
                None,
                None,
            ),
        },
        &spec,
        Some("approve the effect"),
    )
    .expect("the gated claim parks awaiting_approval");

    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(50),
    ));
    let dispatcher = Arc::new(
        Dispatcher::new(
            Arc::clone(&supervisor),
            heartbeat,
            InFlightLedger::in_memory(),
        )
        .with_execution_lifecycle(face.clone()),
    );
    let executor = Arc::new(
        WorkflowExecutor::new(
            dispatcher,
            supervisor,
            Arc::new(kata_program::library::WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(face)
        .with_workspace_provider(Arc::new(backend)),
    );
    let health = Arc::new(kata_core::SystemHealth::new());
    health.report(
        kata_core::SubsystemId::Api,
        kata_core::SubsystemHealth::Healthy,
    );
    let router = ApiServer::build(
        &disabled_auth_config(),
        AppState::with_executor(health, executor),
    )
    .unwrap()
    .into_router();
    (router, attempt_id, execution_id, dir, db)
}

#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn a_parked_workspace_effect_gate_is_listed_by_get_approvals() {
    let (router, attempt_id, execution_id, dir, _db) =
        boot_with_parked_effect(WorkspaceEffectOp::Park);

    // NON-VACUITY: the parked row really is the shape the defect blinded — a
    // `main`-executor `awaiting_approval` attempt, read off the raw schema.
    let (executor, state): (String, String) =
        rusqlite::Connection::open(dir.path().join("operational.db"))
            .unwrap()
            .query_row(
                "SELECT a.executor, p.state FROM attempts a \
                   JOIN attempt_projection p \
                     ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
                    AND p.attempt_ordinal = a.attempt_ordinal \
                  WHERE a.attempt_id = ?1",
                [attempt_id.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
    assert_eq!(executor, "main");
    assert_eq!(state, "awaiting_approval");

    let (status, json) = common::get_json(&router, "/api/v1/approvals").await;
    assert_eq!(status, StatusCode::OK);
    let list = json.as_array().expect("approvals is a list");
    let entry = list
        .iter()
        .find(|entry| entry["execution_id"].as_str() == Some(&execution_id.to_string()))
        .expect("GET /approvals lists the parked workspace_effect gate");
    assert_eq!(entry["assignment_id"], attempt_id.to_string());
    assert_eq!(entry["stage_name"], STAGE);
    assert_eq!(entry["reason"], "approve the effect");
    assert_eq!(entry["workspace_effect"]["op"], "park");
    assert!(entry["capsule"].is_null());
    // The push destination is shown exactly for a `forge_export` gate.
    let effect = entry["workspace_effect"]
        .as_object()
        .expect("the effect scope");
    assert!(
        !effect.contains_key("forge_remote") && !effect.contains_key("forge_base"),
        "a park gate names no push destination: {effect:?}"
    );
}

/// The parked transition's raw payload, read through a SECOND, read-only
/// handle on `operational.db`.
fn parked_payload(dir: &std::path::Path, attempt_id: Ulid) -> Vec<u8> {
    rusqlite::Connection::open_with_flags(
        dir.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT payload_json FROM transitions \
          WHERE attempt_id = ?1 AND resulting_state = 'awaiting_approval'",
        [attempt_id.to_bytes().as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

/// **The approval gate names where the push goes.** A parked `forge_export`
/// gate's listing shows the remote the claim recorded and the pull request's
/// base — the branch the execution FROZE — beside the op and the candidate.
///
/// Both are derived at read time: the remote off the stored spec (the
/// repository has no remote at all, so `upstream` can come from nowhere
/// else), the base off the stored invocation (the repository's only git
/// branch is renamed after the claim, so the trunk resolved now is refused as
/// ambiguous — asserted — and names no `main`). The
/// parked transition's stored bytes — read through a second read-only handle
/// before and after the listing — carry exactly the four-key scope the claim
/// has always written, so nothing durable changed.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn a_parked_forge_export_gate_names_its_recorded_remote_and_frozen_base() {
    let (router, attempt_id, execution_id, dir, _db) =
        boot_with_parked_effect(WorkspaceEffectOp::ForgeExport);
    run_git(
        &dir.path().join("repo"),
        &["branch", "-m", "main", "renamed"],
    );
    let moved =
        <JjBackend as VcsBackend>::open(&dir.path().join("repo")).expect("reopen the backend");
    // jj still holds its `main` bookmark beside git's `renamed`, so the host's
    // trunk answer is now the ambiguity refusal — it names no `main` to read.
    let answer = kata_vcs::test_support::resolve_trunk_target(
        &moved,
        &ExecutionWorkspaceKey::execution(Ulid::new()),
    );
    assert!(
        matches!(&answer, Err(err) if err.to_string().contains("cannot tell which branch")),
        "the host's trunk answer no longer resolves to main: {answer:?}"
    );
    let stored = parked_payload(dir.path(), attempt_id);
    let scope: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    let keys: Vec<&str> = scope["workspace_effect_gate"]
        .as_object()
        .expect("the stored scope")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        {
            let mut keys = keys.clone();
            keys.sort_unstable();
            keys
        },
        ["candidate_commit", "candidate_tree_id", "op", "target"],
        "the stored scope is the claim's four keys, and no more"
    );

    let (status, json) = common::get_json(&router, "/api/v1/approvals").await;
    assert_eq!(status, StatusCode::OK);
    let entry = json
        .as_array()
        .expect("approvals is a list")
        .iter()
        .find(|entry| entry["execution_id"].as_str() == Some(&execution_id.to_string()))
        .expect("GET /approvals lists the parked forge_export gate");
    let effect = &entry["workspace_effect"];
    assert_eq!(effect["op"], "forge_export", "{entry}");
    assert_eq!(effect["target"], format!("kata/{execution_id}"), "{entry}");
    assert_eq!(effect["forge_remote"], CLAIMED_REMOTE, "{entry}");
    assert_eq!(effect["forge_base"], "main", "{entry}");
    assert_eq!(
        parked_payload(dir.path(), attempt_id),
        stored,
        "the listing writes nothing to the stored park"
    );
}

/// Every transition row and every attempt's projected state, read through a
/// second, read-only handle on `operational.db`: a refused verdict changes
/// neither.
fn raw_decision_plane(dir: &std::path::Path) -> (i64, Vec<(Vec<u8>, String)>) {
    let raw = rusqlite::Connection::open_with_flags(
        dir.join("operational.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let transitions = raw
        .query_row("SELECT COUNT(*) FROM transitions", [], |row| row.get(0))
        .unwrap();
    let mut states = raw
        .prepare(
            "SELECT a.attempt_id, p.state FROM attempts a \
               JOIN attempt_projection p \
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
                AND p.attempt_ordinal = a.attempt_ordinal \
              ORDER BY a.attempt_id",
        )
        .unwrap();
    let states = states
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    (transitions, states)
}

/// A main-resolved attempt the execution holds at `path` that is no gate, its
/// claim binding a fixture operation the admitted program need not name.
fn main_attempt_spec(execution_id: Ulid, path: Vec<u32>) -> MainAttemptSpec {
    let path = kata_types::execution_contract::OperationPath(path);
    MainAttemptSpec {
        stage_id: path.program_operation_stage_id(),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution_id),
                kata_types::primitives::ContentHash::new([0xB7; 32]),
                kata_types::execution_contract::OperationContractId(
                    kata_types::primitives::ContentHash::new([0x5E; 32]),
                ),
                path,
            ),
            None,
            None,
        ),
    }
}

/// `POST /executions/{execution}/{verdict}` on `assignment`.
async fn decide(
    router: &axum::Router,
    execution_id: Ulid,
    assignment: Ulid,
    verdict: &str,
) -> (StatusCode, serde_json::Value) {
    common::post_json(
        router,
        &format!("/api/v1/executions/{execution_id}/{verdict}"),
        serde_json::json!({ "assignment_id": assignment.to_string(), "reason": "operator" }),
    )
    .await
}

/// **A second, opposite verdict on a workspace-effect gate is a 409.** The
/// reject settles the parked gate; the later approve finds it no longer parked
/// and is refused `approval_gate_not_parked` by the deciding door, a CONFLICT on
/// the REST face, and writes no transition and moves no attempt.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn a_second_opposite_verdict_on_a_workspace_effect_gate_is_a_conflict() {
    let (router, attempt_id, execution_id, dir, _db) =
        boot_with_parked_effect(WorkspaceEffectOp::Park);
    let (status, body) = decide(&router, execution_id, attempt_id, "reject").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let decided = raw_decision_plane(dir.path());
    assert!(
        decided
            .1
            .iter()
            .any(|(id, state)| id.as_slice() == attempt_id.to_bytes()
                && state != "awaiting_approval"),
        "the reject settled the gate: {:?}",
        decided.1
    );
    let (status, body) = decide(&router, execution_id, attempt_id, "approve").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        raw_decision_plane(dir.path()),
        decided,
        "the refused approve recorded nothing"
    );
}

/// **A second, opposite verdict on an expansion gate is a 409.** An expansion
/// attempt parked `on_max = "escalate"` is approved; the later reject is refused
/// `approval_already_decided`, a CONFLICT, and records nothing.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn a_second_opposite_verdict_on_an_expansion_gate_is_a_conflict() {
    let (router, _effect, execution_id, dir, db) = boot_with_parked_effect(WorkspaceEffectOp::Park);
    let spec = main_attempt_spec(execution_id, vec![7]);
    let expansion = ExpansionSpec {
        operation: hex::encode(spec.occurrence.operation_contract_id()),
        path: kata_types::execution_contract::OperationPath(vec![7]),
        stage: "worker".to_owned(),
        template: vec![kata_types::execution_contract::OperationPath(vec![8])],
        maximum: 3,
        policy: hex::encode([0x9E; 32]),
    };
    let attempt_id = Ulid::new();
    db.claim_expansion_attempt(attempt_id, &spec, &expansion)
        .expect("the expansion attempt claims");
    db.park_expansion_attempt(
        attempt_id,
        "loop bound spent under escalate",
        &serde_json::json!({
            "expansion": {
                "operation": expansion.operation,
                "path": spec.stage_id,
                "stage": "worker",
                "resolution": {"outcome": "exhausted", "iterations": 1, "on_max": "escalate"},
                "members": [],
                "verdicts": [{"iteration": 0, "verdict": "refine", "feedback": "more"}]
            }
        }),
    )
    .expect("the expansion attempt parks")
    .expect("the attempt was live to park");

    let (status, body) = decide(&router, execution_id, attempt_id, "approve").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let decided = raw_decision_plane(dir.path());
    let (status, body) = decide(&router, execution_id, attempt_id, "reject").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        raw_decision_plane(dir.path()),
        decided,
        "the refused reject recorded nothing"
    );
}

/// **A verdict on an attempt no deciding plane holds as a gate is a 409.** A
/// main-resolved attempt awaiting input is the execution's own, so the request
/// is no unknown assignment; it is no capsule gate, workspace effect or
/// expansion, so both verdicts are refused `approval_gate_not_parked` — a
/// CONFLICT — and record nothing.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn a_verdict_on_an_attempt_no_deciding_plane_holds_is_a_conflict() {
    let (router, _effect, execution_id, dir, db) = boot_with_parked_effect(WorkspaceEffectOp::Park);
    let attempt_id = Ulid::new();
    db.claim_main_attempt(
        attempt_id,
        &main_attempt_spec(execution_id, vec![9]),
        MainWait::Input(None),
    )
    .expect("the main attempt claims");
    let before = raw_decision_plane(dir.path());
    assert!(
        before
            .1
            .iter()
            .any(|(id, state)| id.as_slice() == attempt_id.to_bytes() && state == "awaiting_input"),
        "the execution holds the attempt, awaiting input: {:?}",
        before.1
    );
    for verdict in ["approve", "reject"] {
        let (status, body) = decide(&router, execution_id, attempt_id, verdict).await;
        assert_eq!(status, StatusCode::CONFLICT, "{verdict}: {body}");
    }
    assert_eq!(
        raw_decision_plane(dir.path()),
        before,
        "the refused verdicts recorded nothing"
    );
}
