//! The `oci` `workspace_effect` as a
//! MAIN-RESOLVED durable effect: the claim is the double-spend guard, the jj
//! verbs run at the main between claim and resolve, and the sweep classifies a
//! crashed attempt from repository facts — the remote's for `forge_export` —
//! instead of re-driving blindly.
//!
//! These cells run REAL jj workspaces and the real nucleus — assertions read
//! `git` output, the colocated refs, and the raw schema, never the code under
//! test.

use kata_core::operational::{
    ExecutionWorkTreeHead, MainAttemptSpec, OccurrenceBinding, WorkspaceEffectSpec,
};
use kata_core::{InFlightLedger, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord};
use kata_effects_contract::{
    ExecutionWorkspaceHandle, ExecutionWorkspaceKey, ExecutionWorkspaceProvider, RecordingForge,
};
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_transport::WorkerPoolSupervisor;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{OccurrenceRef, OperationPath};
use kata_types::tree_artifact::WorkTreeInputBounds;
use kata_types::workflow::{WorkspaceEffect, WorkspaceEffectOp};
use kata_vcs::{JjBackend, VcsBackend};
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use std::path::Path;
use std::sync::Arc;
use ulid::Ulid;

const STAGE: &str = "ship";

struct Planes {
    op_path: std::path::PathBuf,
    db: Arc<OperationalDb>,
    cas: Arc<kata_core::store::cas::CasStore>,
}

fn planes(dir: &Path) -> Planes {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let cas = Arc::new(
        kata_core::store::cas::CasStore::open(data_dir.join("cas.db"), data_dir.join("cas"))
            .unwrap(),
    );
    let db = Arc::new(
        OperationalDb::open_with_cas(data_dir.join("operational.db"), Arc::clone(&cas)).unwrap(),
    );
    Planes {
        op_path: data_dir.join("operational.db"),
        db,
        cas,
    }
}

fn as_provider(backend: &Arc<JjBackend>) -> Arc<dyn ExecutionWorkspaceProvider> {
    Arc::clone(backend) as Arc<dyn ExecutionWorkspaceProvider>
}

fn dispatcher(db: &Arc<OperationalDb>) -> Dispatcher {
    Dispatcher::new(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(HeartbeatMonitor::new(
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(50),
        )),
        InFlightLedger::in_memory(),
    )
    .with_execution_lifecycle(ExecutionLifecycleFace::new(Arc::clone(db)))
}

fn program_record(program: &kata_program::execution_program::ExecutionProgram) -> ProgramRecord {
    ProgramRecord {
        program_hash: program.program_hash,
        schema_version: 4,
        program_json: serde_json::to_vec(program).unwrap(),
    }
}

fn invocation() -> InvocationRecord {
    let invocation_json = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1,
        "kind": "workflow",
        "inputs": [1],
    }));
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: kata_types::identity_algebra::AdmissionDigest(
            kata_types::primitives::ContentHash::new(*blake3::hash(&invocation_json).as_bytes()),
        ),
        invocation_json,
    }
}

/// The cell's program — one `workspace_effect` stage (the op the cell names),
/// which `oci` admits only on a `worktree_isolated` run.
fn program_with_effect(op: &str) -> kata_program::execution_program::ExecutionProgram {
    // A `promote`/`forge_export` stage demands a REQUIRED validation criterion
    // bound to a shell proof stage at load; park/commit carry none. A
    // `forge_export` also needs a `commit` among its ancestors.
    const PROOF: &str = "proof = stage(\n\
                         \x20   id = \"proof\",\n\
                         \x20   agent = \"shell\",\n\
                         \x20   prompt = \"echo ok\",\n\
                         )\n";
    const CRITERIA: &str = "\x20   validation_criteria = [validation_criterion(\"proof\", description = \"proof\", stage = \"proof\", required = True)],";
    let (prelude, root, criteria, depends) = match op {
        "promote" => (
            PROOF.to_owned(),
            "[proof, ship]",
            CRITERIA.to_owned(),
            "\x20   depends_on = [\"proof\"],\n",
        ),
        "forge_export" => (
            format!(
                "{PROOF}snap = stage(id = \"snap\", agent = \"workspace_effect\", op = \"commit\", \
                 depends_on = [\"proof\"])\n"
            ),
            "[proof, snap, ship]",
            CRITERIA.to_owned(),
            "\x20   depends_on = [\"snap\"],\n",
        ),
        // `commit → shell(ro) → forge_export`: a read-only stage `look`
        // between the commit and the export.
        "forge_export_after_ro" => (
            format!(
                "{PROOF}snap = stage(id = \"snap\", agent = \"workspace_effect\", op = \"commit\", \
                 depends_on = [\"proof\"])\n\
                 look = stage(id = \"look\", agent = \"shell\", sandbox = \"ro\", \
                 timeout_ms = 30000, prompt = \"cat /work/a.txt\", depends_on = [\"snap\"])\n"
            ),
            "[proof, snap, look, ship]",
            format!(
                "{CRITERIA}\n\x20   sandbox_profiles = {{\"ro\": \
                 sandbox_profile(workspace = \"ro\", net = \"offline\")}},"
            ),
            "\x20   depends_on = [\"look\"],\n",
        ),
        _ => (String::new(), "[ship]", String::new(), ""),
    };
    let op = op.strip_suffix("_after_ro").unwrap_or(op);
    let pack = format!(
        "{prelude}ship = stage(\n\
         \x20   id = \"ship\",\n\
         \x20   agent = \"workspace_effect\",\n\
         \x20   op = \"{op}\",\n\
         {depends}         )\n\
         workflow(\n\
         \x20   \"workspace-effect-cell\",\n\
         \x20   root = {root},\n\
         \x20   worktree_isolated = True,\n\
         {criteria}\n\
         )\n",
    );
    kata_program::execution_program::compile_starlark_execution_program(
        &pack,
        "workspace-effect-cell.star",
        &[],
    )
    .expect("the cell's pack compiles")
}

fn occurrence_ref(
    execution_id: Ulid,
    program: &kata_program::execution_program::ExecutionProgram,
) -> OccurrenceRef {
    let stage_id = kata_types::workflow::StageId(smol_str::SmolStr::new(STAGE));
    let lowered = kata_program::execution_program::lower_stage_operation(program, &stage_id)
        .expect("the ship stage lowers");
    OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program.program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    )
}

/// The fixture: a git repo, the jj execution workspace, the published base
/// head, and the execution submitted.
struct Fixture {
    planes: Planes,
    execution_id: Ulid,
    backend: Arc<JjBackend>,
    head: ExecutionWorkTreeHead,
    dispatcher: Dispatcher,
    program: kata_program::execution_program::ExecutionProgram,
}

fn fixture(dir: &Path, op: &str) -> Fixture {
    fixture_with(dir, op, FixtureInvocation::Opaque)
}

/// The invocation a fixture's execution is submitted under.
#[derive(Clone, Copy)]
enum FixtureInvocation {
    /// The opaque fixture envelope [`invocation`] — no frozen target, so the
    /// promote effect asks the landing ladder no trunk question.
    Opaque,
    /// A real envelope carrying the trunk target resolved and pinned through
    /// the backend, the workspace forked from it — what an isolated admission
    /// stores.
    FrozenTrunk,
}

fn fixture_with(dir: &Path, op: &str, submitted: FixtureInvocation) -> Fixture {
    fixture_on_trunk(dir, op, submitted, "main")
}

/// [`fixture_with`] over a repository whose one branch — its trunk — is
/// named `trunk`.
fn fixture_on_trunk(dir: &Path, op: &str, submitted: FixtureInvocation, trunk: &str) -> Fixture {
    let planes = planes(dir);
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    std::fs::write(repo.join("a.txt"), "committed\n").unwrap();
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
    if trunk != "main" {
        run_git(&repo, &["branch", "-m", "main", trunk]);
    }
    let backend = Arc::new(JjBackend::open(&repo).expect("the colocated jj backend opens"));
    let execution_id = Ulid::new();
    let program = program_with_effect(op);
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let target = kata_vcs::test_support::resolve_trunk_target(backend.as_ref(), &key)
        .expect("resolve the trunk target");
    let record = match submitted {
        FixtureInvocation::Opaque => invocation(),
        FixtureInvocation::FrozenTrunk => {
            let envelope =
                kata_workflow::execution_program_store::ExecutionInvocation::workflow(Vec::new())
                    .with_target(Some(target.clone()));
            let invocation_json = kata_types::idempotency::canonicalize_args(
                &serde_json::to_value(&envelope).unwrap(),
            );
            InvocationRecord {
                schema_version: i64::from(envelope.schema_version),
                kind: InvocationKind::Workflow,
                admission_digest: kata_types::identity_algebra::AdmissionDigest(
                    kata_types::primitives::ContentHash::new(
                        *blake3::hash(&invocation_json).as_bytes(),
                    ),
                ),
                invocation_json,
            }
        }
    };
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &record)
        .unwrap();
    let workspace = ExecutionWorkspaceProvider::create_workspace(backend.as_ref(), &key, &target)
        .expect("the workspace creates");
    let head = kata_core::work_tree::publish_base_tree_head(
        &planes.db,
        &planes.cas,
        execution_id,
        |put| {
            ExecutionWorkspaceProvider::committed_base_tree(
                backend.as_ref(),
                &workspace,
                WorkTreeInputBounds::default(),
                put,
            )
        },
    )
    .expect("the committed base head publishes");
    // The gate decisions refuse a first decision on a non-`running` execution;
    // the cells' executions run.
    kata_workflow::execution_lifecycle::ExecutionLifecycleFace::new(Arc::clone(&planes.db))
        .mark_running_after_admission(execution_id)
        .expect("the execution runs");
    std::fs::write(dir.join("execution_id"), execution_id.to_string()).unwrap();
    let dispatcher = dispatcher(&planes.db);
    Fixture {
        planes,
        execution_id,
        backend,
        head,
        dispatcher,
        program,
    }
}

/// The claim — what `WorkflowRunner::submit_workspace_effect` writes when the
/// stage dispatches.
fn claim_effect(
    fx: &Fixture,
    effect: WorkspaceEffect,
    approval: Option<&str>,
) -> (Ulid, WorkspaceEffectSpec) {
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let status = ExecutionWorkspaceProvider::workspace_status(fx.backend.as_ref(), &key)
        .unwrap()
        .expect("the workspace is live");
    // The recorded candidate IS the head row's — the status read is only for
    // the promote target's base ref.
    let candidate_commit = fx.head.candidate_commit_id.clone();
    let candidate_tree_id =
        ExecutionWorkspaceProvider::workspace_effect_candidate_tree(fx.backend.as_ref(), &key)
            .unwrap()
            .expect("the tree reads");
    let target = match effect.op {
        WorkspaceEffectOp::Commit => format!("exec-{}", fx.execution_id),
        // The ref the spec records is execution-scoped — the label rides the
        // spec as metadata only (the writer and the classifier
        // name `parked/<exec-id>` regardless).
        WorkspaceEffectOp::Park => fx.backend.parked_ref_name(&key, None),
        WorkspaceEffectOp::Promote => status
            .identity
            .as_ref()
            .and_then(|identity| identity.base_ref.clone())
            .unwrap_or_else(|| "<trunk>".to_owned()),
        WorkspaceEffectOp::ForgeExport => {
            format!("kata/{}", fx.execution_id)
        }
    };
    let delivered_commit = delivered_commit(fx, effect.op, &candidate_commit, &fx.head);
    let spec = WorkspaceEffectSpec {
        op: effect.op,
        label: effect.label.clone(),
        target,
        candidate_commit,
        delivered_commit,
        candidate_tree_id,
        pin: kata_types::execution::CandidateTreePin::Unpinned,
        forge: effect.forge.clone(),
        forge_remote: claimed_remote(fx, effect.op),
    };
    let attempt_id = Ulid::new();
    let _claim = fx
        .planes
        .db
        .claim_workspace_effect_attempt(
            attempt_id,
            &MainAttemptSpec {
                stage_id: STAGE.to_string(),
                occurrence: OccurrenceBinding::new(
                    occurrence_ref(fx.execution_id, &fx.program),
                    None,
                    None,
                ),
            },
            &spec,
            approval,
        )
        .expect("the claim lands");
    (attempt_id, spec)
}

/// The push remote a `forge_export` claim records — asked of the dispatcher's
/// one claim rule (`Dispatcher::forge_export_claim_remote`), the call
/// `WorkflowRunner::submit_workspace_effect` makes before it claims; `None`
/// for every other op.
fn claimed_remote(fx: &Fixture, op: WorkspaceEffectOp) -> Option<String> {
    (op == WorkspaceEffectOp::ForgeExport).then(|| {
        fx.dispatcher
            .forge_export_claim_remote(fx.execution_id, &as_provider(&fx.backend))
            .expect("the export's remote resolves at claim")
    })
}

/// The commit the claim records as delivered — asked of the provider's one
/// claim rule (`workspace_effect_delivered_commit`) with the operands
/// `WorkflowRunner::submit_workspace_effect` passes: the op, the candidate and
/// the head row's `committed_commit_id`. That the runner passes exactly these
/// is pinned live (`checked_command_live`).
fn delivered_commit(
    fx: &Fixture,
    op: WorkspaceEffectOp,
    candidate_commit: &str,
    head: &ExecutionWorkTreeHead,
) -> String {
    ExecutionWorkspaceProvider::workspace_effect_delivered_commit(
        fx.backend.as_ref(),
        op,
        candidate_commit,
        &head.committed_commit_id,
    )
    .expect("the delivered commit resolves")
}

/// `git show <commit>:<path>` — read from the repo, never kata's bookkeeping.
fn git_show(repo: &Path, commit: &str, path: &str) -> Option<String> {
    let out = hermetic_git_in(repo)
        .args(["show", &format!("{commit}:{path}")])
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `git rev-parse <ref>` — the bare remote's own fact, read off the remote.
fn git_rev(repo: &Path, reference: &str) -> Option<String> {
    let out = hermetic_git_in(repo)
        .args(["rev-parse", reference])
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn attempt_state(fx: &Fixture, attempt_id: Ulid) -> String {
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    conn.query_row(
        "SELECT state FROM attempt_projection p
           JOIN attempts a ON a.execution_id = p.execution_id
            AND a.stage_id = p.stage_id AND a.attempt_ordinal = p.attempt_ordinal
          WHERE a.attempt_id = ?1",
        rusqlite::params![attempt_id.to_bytes().as_slice()],
        |row| row.get::<_, String>(0),
    )
    .unwrap()
}

fn write_in_workspace(fx: &Fixture, rel: &str, bytes: &str) {
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let handle = ExecutionWorkspaceProvider::lookup_workspace(fx.backend.as_ref(), &key)
        .unwrap()
        .unwrap();
    std::fs::write(handle.path.join(rel), bytes).unwrap();
}

// -- the happy-path cells ------------------------------------------------------

/// A `commit` claim performs at the main: the `exec-<id>` ref names the
/// finalized candidate — its tree the candidate's, which is NOT the base's — the
/// head row's candidate advances to the fresh empty `@` in the resolving
/// transaction, and a second drive is a no-op. Every tree id is read off git.
#[test]
fn a_commit_effect_lands_once_and_advances_the_head() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "commit");
    // A candidate whose tree differs from the base: a stage's write, snapshotted
    // into the workspace and recorded as the head row's candidate. The disk
    // stays clean against it (the dirty case is its own refusal cell below).
    let candidate = write_after_commit(&fx, "shipped.txt", "the stage wrote this\n");
    let mut commit_spec = follow_on_spec(&fx, WorkspaceEffectOp::Commit, None);
    commit_spec.target = format!("exec-{}", fx.execution_id);
    assert_eq!(commit_spec.candidate_commit, candidate);
    let (attempt_id, spec) = claim_effect_at(&fx, commit_spec, STAGE, vec![7]);
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the commit drives");
    let repo = dir.path().join("repo");
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    let last: String = conn
        .query_row(
            "SELECT payload_json FROM transitions WHERE attempt_id = ?1
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    let landed_ref = git_rev(&repo, &format!("exec-{}", fx.execution_id));
    assert!(
        landed_ref.is_some(),
        "exec-<id> exists — read from git (attempt {} last transition: {last})",
        attempt_state(&fx, attempt_id),
    );
    // The landed commit is the finalized rewrite of the recorded candidate —
    // its TREE is the candidate's tree, its parent is the commit the candidate
    // stood on.
    let landed = landed_ref.unwrap();
    let tree_of = |commit: &str| git_rev(&repo, &format!("{commit}^{{tree}}")).unwrap();
    let candidate_tree = tree_of(&spec.candidate_commit);
    assert_ne!(
        candidate_tree,
        tree_of("main"),
        "the fixture's candidate tree differs from the base's"
    );
    assert_eq!(
        tree_of(&landed),
        candidate_tree,
        "the landed commit's tree is the candidate's"
    );
    let base = git_rev(&repo, &format!("{}^", spec.candidate_commit)).unwrap();
    let landed_parent = {
        let out = hermetic_git_in(&repo)
            .args(["rev-list", "--parents", "-1", &landed])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        landed_parent, base,
        "the landed commit sits on the commit the candidate stood on"
    );
    assert_eq!(
        attempt_state(&fx, attempt_id),
        "completed",
        "the effect attempt resolved"
    );
    let moved = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_ne!(
        moved.candidate_commit_id, spec.candidate_commit,
        "the head row advanced to the fresh empty @"
    );
    // The new @ is an empty commit atop the landed one — the candidate tree is
    // the committed tree.
    assert_eq!(
        tree_of(&moved.candidate_commit_id),
        candidate_tree,
        "the new @ keeps the candidate's tree"
    );
    // A second drive: nothing re-performs.
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .unwrap();
    let again = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(again.candidate_commit_id, moved.candidate_commit_id);
}

/// A `park` claim performs at the main: the `parked/<exec>` ref names the
/// candidate AND the workspace is gone — the teardown is the verb's own.
#[test]
fn a_park_effect_publishes_the_ref_and_removes_the_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let ref_name = fx.backend.parked_ref_name(&key, None);
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the park drives");
    let repo = dir.path().join("repo");
    assert_eq!(
        git_rev(&repo, &ref_name),
        Some(spec.candidate_commit.clone()),
        "the parked ref names the recorded candidate — read from git"
    );
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(fx.backend.as_ref(), &key)
            .unwrap()
            .is_none(),
        "the workspace is torn down"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    // The sweep sees no pending work on a second pass.
    assert!(
        fx.planes
            .db
            .pending_workspace_effects(fx.execution_id)
            .unwrap()
            .is_empty()
    );
}

/// A `promote` claim lands the candidate on trunk and tears the workspace
/// down — read off git, not kata's records.
#[test]
fn a_promote_effect_lands_on_trunk_and_removes_the_workspace() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "promote");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let repo = dir.path().join("repo");
    let trunk_before = git_rev(&repo, "main").unwrap();
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the promote drives");
    let trunk_after = git_rev(&repo, "main").unwrap();
    assert_ne!(trunk_before, trunk_after, "trunk moved");
    let on_trunk = |commit: &str| {
        hermetic_git_in(&repo)
            .args(["merge-base", "--is-ancestor", commit, "main"])
            .status()
            .unwrap()
            .success()
    };
    assert!(
        on_trunk(&spec.candidate_commit),
        "the recorded candidate is on trunk"
    );
    assert!(on_trunk(&trunk_before), "trunk fast-forwarded");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(fx.backend.as_ref(), &key)
            .unwrap()
            .is_none()
    );
}

/// `target_trunk_renamed` on the `oci` `promote` effect: the execution froze
/// trunk `main`, and the node's `vcs.trunk` now names `release` (a branch
/// created after admission). The promote refuses by name before anything
/// moves — both branches read back from git unchanged — and the workspace is
/// left standing.
#[test]
fn a_promote_onto_a_trunk_renamed_since_admission_is_refused_and_moves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let (attempt_id, _spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let repo = dir.path().join("repo");
    run_git(&repo, &["branch", "release"]);
    let main_before = git_rev(&repo, "main").unwrap();
    let release_before = git_rev(&repo, "release").unwrap();
    let renamed: Arc<dyn ExecutionWorkspaceProvider> = Arc::new(
        JjBackend::open(&repo)
            .expect("reopen the backend")
            .with_configured_trunk(Some("release".to_owned())),
    );
    // The renamed trunk enters jj's view the way it does for any later run: a
    // resolution's scoped git import.
    kata_vcs::test_support::resolve_trunk_target(
        renamed.as_ref(),
        &ExecutionWorkspaceKey::execution(Ulid::new()),
    )
    .expect("another run resolves the renamed trunk");

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&renamed), None)
        .expect("the drive settles the refusal");

    assert_eq!(attempt_state(&fx, attempt_id), "failed");
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    let payload: String = conn
        .query_row(
            "SELECT payload_json FROM transitions WHERE attempt_id = ?1
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap();
    assert!(
        payload.contains(kata_types::target::TARGET_TRUNK_RENAMED),
        "the typed refusal reached the transition: {payload}"
    );
    assert_eq!(
        git_rev(&repo, "main").unwrap(),
        main_before,
        "main did not move"
    );
    assert_eq!(
        git_rev(&repo, "release").unwrap(),
        release_before,
        "the renamed trunk did not move"
    );
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(
            fx.backend.as_ref(),
            &ExecutionWorkspaceKey::execution(fx.execution_id)
        )
        .unwrap()
        .is_some(),
        "the workspace stands for a re-run"
    );
}

/// A `forge_export` claim writes `kata/<exec>` and pushes it to the configured
/// remote, then the forge opens the PR — the bare remote's own refs are the
/// evidence.
#[test]
fn a_forge_export_pushes_kata_branch_and_opens_the_pr() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    // A LOCAL bare origin — the push target, no network.
    let origin = forge_remote(dir.path(), &dir.path().join("repo"), "origin");
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/7",
    ));
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::ForgeExport,
            label: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
            forge: Some(kata_types::workflow::ForgeExportSpec {
                title: None,
                body: None,
            }),
        },
        None,
    );
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export drives");
    let branch = format!("kata/{}", fx.execution_id);
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/{branch}")),
        Some(spec.candidate_commit.clone()),
        "the remote holds the pushed kata/<exec> branch — read from the bare repo"
    );
    assert_eq!(forge.call_count(), 1, "one PR opened");
    let call = &forge.calls()[0];
    assert_eq!(call.head, branch);
    assert_eq!(call.base, "main");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
}

// -- the divergence cells -------------------------------------------------------

/// A workspace whose `@` moved under the claim fails `oci_candidate_diverged`
/// and publishes nothing.
#[test]
fn a_moved_candidate_fails_the_effect_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, mut spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    // Move the workspace's @: a foreign commit — the verb under test is the
    // FENCE, not the mover.
    let agent = kata_types::AgentId(fx.execution_id);
    write_in_workspace(&fx, "foreign.txt", "foreign\n");
    kata_vcs::VcsBackend::commit(fx.backend.as_ref(), &agent, "foreign write").unwrap();
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the drive settles the refusal");
    assert_eq!(attempt_state(&fx, attempt_id), "failed");
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    let payload: String = conn
        .query_row(
            "SELECT payload_json FROM transitions WHERE attempt_id = ?1
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap();
    assert!(
        payload.contains("oci_candidate_diverged"),
        "the typed refusal reached the transition: {payload}"
    );
    spec.candidate_commit.clear();
}

/// Dirty disk under the candidate is `oci_candidate_disk_diverged` — a foreign
/// edit refuses rather than publishes.
#[test]
fn a_dirty_workspace_fails_the_effect_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "commit");
    let (attempt_id, _spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Commit,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    write_in_workspace(&fx, "foreign.txt", "foreign\n");
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the drive settles the refusal");
    assert_eq!(attempt_state(&fx, attempt_id), "failed");
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    let payload: String = conn
        .query_row(
            "SELECT payload_json FROM transitions WHERE attempt_id = ?1
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap();
    assert!(
        payload.contains("oci_candidate_disk_diverged"),
        "the typed refusal reached the transition: {payload}"
    );
    assert!(
        git_rev(
            &dir.path().join("repo"),
            &format!("exec-{}", fx.execution_id)
        )
        .is_none(),
        "nothing published"
    );
}

// -- the approval-gate cells ---------------------------------------------------

/// An `approval_required` claim parks `awaiting_approval` carrying the
/// `{op, target, candidate, tree}` scope; the operator's approve performs the
/// effect exactly once.
#[test]
fn a_gated_effect_performs_only_after_the_decision() {
    use kata_core::operational::{
        WorkspaceEffectApprovalDecision, WorkspaceEffectGateScope, WorkspaceEffectVerdict,
    };
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        Some("approve the park"),
    );
    assert_eq!(
        attempt_state(&fx, attempt_id),
        "awaiting_approval",
        "the gated claim parks"
    );
    // Nothing ran: no parked ref, workspace live.
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let ref_name = fx.backend.parked_ref_name(&key, None);
    assert!(git_rev(&dir.path().join("repo"), &ref_name).is_none());
    let gates = fx
        .planes
        .db
        .parked_workspace_effect_gates(fx.execution_id)
        .unwrap();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].scope.op, "park");
    assert_eq!(gates[0].scope.target, ref_name);
    assert_eq!(gates[0].scope.candidate_commit, spec.candidate_commit);
    // A decision naming a DIFFERENT candidate is `approval_gate_not_parked` —
    // the scope re-bind fences it.
    let wrong_scope = WorkspaceEffectGateScope {
        op: "park".to_owned(),
        target: ref_name.clone(),
        candidate_commit: "0".repeat(40),
        candidate_tree_id: "0".repeat(64),
    };
    let err = fx
        .planes
        .db
        .decide_workspace_effect_approval(
            attempt_id,
            &WorkspaceEffectApprovalDecision {
                principal: &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                verdict: WorkspaceEffectVerdict::Approve,
            },
            &wrong_scope,
        )
        .expect_err("a scope naming a different candidate refuses");
    assert!(
        err.to_string().contains("approval_gate_not_parked"),
        "{err}"
    );
    // Approve with the parked scope — the decision un-parks, the sweep performs.
    let scope = WorkspaceEffectGateScope {
        op: "park".to_owned(),
        target: ref_name.clone(),
        candidate_commit: spec.candidate_commit.clone(),
        candidate_tree_id: spec.candidate_tree_id.clone(),
    };
    fx.planes
        .db
        .decide_workspace_effect_approval(
            attempt_id,
            &WorkspaceEffectApprovalDecision {
                principal: &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                verdict: WorkspaceEffectVerdict::Approve,
            },
            &scope,
        )
        .expect("the decision lands");
    assert_eq!(attempt_state(&fx, attempt_id), "pending");
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .unwrap();
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(
        git_rev(&dir.path().join("repo"), &ref_name),
        Some(spec.candidate_commit.clone())
    );
}

/// A rejected gate resolves `failed` — proven not performed — and a second
/// verdict is `approval_already_decided`.
#[test]
fn a_rejected_effect_gate_performs_nothing_and_the_decision_is_write_once() {
    use kata_core::operational::{
        WorkspaceEffectApprovalDecision, WorkspaceEffectGateScope, WorkspaceEffectVerdict,
    };
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        Some("approve the park"),
    );
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let ref_name = fx.backend.parked_ref_name(&key, None);
    let scope = WorkspaceEffectGateScope {
        op: "park".to_owned(),
        target: ref_name.clone(),
        candidate_commit: spec.candidate_commit.clone(),
        candidate_tree_id: spec.candidate_tree_id.clone(),
    };
    fx.planes
        .db
        .decide_workspace_effect_approval(
            attempt_id,
            &WorkspaceEffectApprovalDecision {
                principal: &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                verdict: WorkspaceEffectVerdict::Reject { reason: "no" },
            },
            &scope,
        )
        .expect("the reject lands");
    assert_eq!(attempt_state(&fx, attempt_id), "failed");
    assert!(git_rev(&dir.path().join("repo"), &ref_name).is_none());
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(fx.backend.as_ref(), &key)
            .unwrap()
            .is_some(),
        "a rejected park leaves the workspace live — nothing was performed"
    );
    // The decision is write-once: an approve after the reject is refused.
    let err = fx
        .planes
        .db
        .decide_workspace_effect_approval(
            attempt_id,
            &WorkspaceEffectApprovalDecision {
                principal: &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                verdict: WorkspaceEffectVerdict::Approve,
            },
            &scope,
        )
        .expect_err("a second verdict is refused");
    assert!(
        err.to_string().contains("approval_already_decided"),
        "{err}"
    );
    // The sweep drains nothing — the rejected attempt is terminal.
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .unwrap();
    assert!(git_rev(&dir.path().join("repo"), &ref_name).is_none());
}

// -- the armed-crash cells ------------------------------------------------------

/// The armed child's whole drive: reopen the planes + backend from the
/// fixture dir, then run the sweep, aborting at whichever boundary
/// `KATA_FAULT_INJECT` or `KATA_WORKSPACE_EFFECT_CRASH_ARM` names.
const CHILD_MARKER: &str = "KATA_WORKSPACE_EFFECT_CHILD";
const CHILD_DIR: &str = "KATA_WORKSPACE_EFFECT_CHILD_DIR";
/// The child's forge: a `gh` program at this path (the stateful fake
/// [`stateful_gh`] writes) instead of an in-process [`RecordingForge`], so a
/// pull request the child opens outlives it.
const CHILD_GH: &str = "KATA_WORKSPACE_EFFECT_CHILD_GH";

fn workspace_effect_child_entry() {
    if std::env::var(CHILD_MARKER).is_err() {
        return;
    }
    let dir = std::path::PathBuf::from(std::env::var(CHILD_DIR).expect("CHILD_DIR"));
    let execution_id: Ulid = std::fs::read_to_string(dir.join("execution_id"))
        .unwrap()
        .parse()
        .unwrap();
    let planes = planes(&dir);
    let backend: Arc<dyn ExecutionWorkspaceProvider> =
        Arc::new(JjBackend::open(&dir.join("repo")).expect("the child opens the jj backend"));
    let dispatcher = dispatcher(&planes.db);
    let forge = match std::env::var_os(CHILD_GH) {
        Some(gh) => Arc::new(kata_vcs::GhCliForge::with_program(gh, dir.join("repo")))
            as Arc<dyn kata_effects_contract::Forge>,
        None => Arc::new(RecordingForge::succeeding_with_url(
            "https://forge.test/pull/9",
        )) as Arc<dyn kata_effects_contract::Forge>,
    };
    dispatcher
        .drive_pending_workspace_effects(execution_id, Some(&backend), Some(&forge))
        .expect("the child's drive");
    panic!("the armed fault point was never reached — the cell proves nothing");
}

/// Spawn the child armed at `boundary`, assert it died there, return the
/// parent's unarmed recovery answer.
fn crash_then_recover(boundary: &str, dir: &Path, test: &str) -> (Fixture, String) {
    crash_then_recover_armed(
        &[("KATA_FAULT_INJECT", format!("operational.{boundary}"))],
        dir,
        test,
    )
}

/// `crash_then_recover` carrying extra arm env — the jj verbs' own
/// `KATA_WORKSPACE_EFFECT_CRASH_ARM` boundaries live inside kata-vcs, outside
/// the `operational.*` registry, so a cell at one of THOSE windows arms it
/// here while the child's own marker/dir vars stay identical.
fn crash_then_recover_armed(
    extra_env: &[(&str, String)],
    dir: &Path,
    test: &str,
) -> (Fixture, String) {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg(test)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let output = command.output().expect("spawn the crash child");
    let boundary = extra_env
        .first()
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "{test}: the armed child must abort at {boundary}, not exit cleanly — {stderr}"
    );
    // Only the armed point's own line proves WHERE the child died — any abort
    // signals, and `boundary` already carries the `operational.` prefix.
    assert!(
        stderr.contains(&format!("crash point reached: {boundary} "))
            || stderr.contains(&format!("crash arm reached: {boundary};")),
        "{test}: the child must die AT {boundary} — stderr:\n{stderr}"
    );
    (reopen(dir), String::new())
}

/// The fixture a dead child left at `dir`, every plane re-opened from disk.
fn reopen(dir: &Path) -> Fixture {
    let planes = planes(dir);
    let backend: Arc<JjBackend> = Arc::new(JjBackend::open(&dir.join("repo")).unwrap());
    let execution_id: Ulid = std::fs::read_to_string(dir.join("execution_id"))
        .unwrap()
        .parse()
        .unwrap();
    let head = planes
        .db
        .execution_work_tree_head(execution_id)
        .unwrap()
        .unwrap();
    let dispatcher = dispatcher(&planes.db);
    let program = program_with_effect("park");
    Fixture {
        planes,
        execution_id,
        backend,
        head,
        dispatcher,
        program,
    }
}

/// Armed crash AFTER the effect claim committed, BEFORE the verb ran: the
/// pending attempt is the sweep's input, and the recovery drive performs it
/// exactly once — the parked ref names the candidate and nothing is
/// duplicated.
#[test]
fn crash_after_workspace_effect_claimed_before_jj_publish() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_workspace_effect_claimed_before_jj_publish",
        dir.path(),
        "crash_after_workspace_effect_claimed_before_jj_publish",
    );
    // The child's armed drive died before the verb — the recovery drive runs
    // the parked perform once.
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let ref_name = fx.backend.parked_ref_name(&key, None);
    assert_eq!(
        git_rev(&dir.path().join("repo"), &ref_name),
        Some(spec.candidate_commit.clone()),
        "the recovered park landed exactly once"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert!(
        fx.planes
            .db
            .pending_workspace_effects(fx.execution_id)
            .unwrap()
            .is_empty()
    );
}

/// Armed crash AFTER the park verb returned (ref published, workspace torn
/// down) but BEFORE the resolve committed: recovery classifies the parked ref
/// and resolves — never a second publish. A still-live workspace is the
/// in-verb window's
/// (`crash_after_park_ref_write_before_teardown_recovers_and_tears_the_workspace_down`).
#[test]
fn crash_after_workspace_effect_jj_publish_before_resolution() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_workspace_effect_jj_publish_before_resolution",
        dir.path(),
        "crash_after_workspace_effect_jj_publish_before_resolution",
    );
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let ref_name = fx.backend.parked_ref_name(&key, None);
    // The child's verb ran to its end, teardown included; its resolve did not.
    assert_eq!(
        git_rev(&dir.path().join("repo"), &ref_name),
        Some(spec.candidate_commit.clone()),
        "the child's park published its ref before the abort"
    );
    assert_eq!(
        attempt_state(&fx, attempt_id),
        "pending",
        "the resolve never committed"
    );
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(fx.backend.as_ref(), &key)
            .unwrap()
            .is_none(),
        "the workspace the child's verb tore down stays gone"
    );
}

/// Armed crash AFTER the push landed but BEFORE its receipt
/// (`after_forge_push_before_pr`): the push intent is open (a second read-only
/// handle). The recovery's observer reads kata's commit on the remote —
/// PERFORMED, recorded on the intent ("a crash after the push records
/// `Pushed`") — opens the PR once, and resolves: no second push, no second
/// PR. Between the crash and the recovery the host gains a second remote and
/// points `branch.main.remote` at it: the observer still reads the remote the
/// intent recorded, so the second remote is never pushed to.
#[test]
fn crash_after_forge_push_before_pr() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = forge_remote(dir.path(), &dir.path().join("repo"), "origin");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::ForgeExport,
            label: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
            forge: Some(kata_types::workflow::ForgeExportSpec {
                title: None,
                body: None,
            }),
        },
        None,
    );
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_push_before_pr",
        dir.path(),
        "crash_after_forge_push_before_pr",
    );
    let branch = format!("kata/{}", fx.execution_id);
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/{branch}")),
        Some(spec.candidate_commit.clone()),
        "the child's push landed on the remote before the abort"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "pending");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [open_intent(0, "push")]
    );
    let moved = tracked_upstream(dir.path(), &dir.path().join("repo"), "main");
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/42",
    ));
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the recovery drive observes the pushed branch");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "observer"),
            intent(1, "pull_request", "performed", "receipt"),
        ]
    );
    assert_eq!(forge.call_count(), 1, "one PR, opened by the recovery leg");
    assert_eq!(
        forge.calls()[0].base,
        "main",
        "the recovery leg asks for the frozen trunk"
    );
    assert_eq!(
        remote_refs(&moved),
        "",
        "the remote the config names after the crash was never pushed to"
    );
}

// -- regression cells ---------------------------------------------------------

/// The real backend with one interposition, every other call delegated.
struct Interposed {
    inner: Arc<JjBackend>,
    at: Interposition,
}

/// Where [`Interposed`] departs from the real backend.
enum Interposition {
    /// The `commit` verb answers `OutcomeUnknown` — the answer jj's shell-outs
    /// give when the spawn result is indeterminate and the mutation may have
    /// landed.
    OutcomeUnknownCommit,
    /// This runs inside the push call — after the push's intent is recorded,
    /// before `git push` — then the real push.
    BeforePush(Box<dyn Fn() + Send + Sync>),
}

impl ExecutionWorkspaceProvider for Interposed {
    fn backend(&self) -> kata_effects_contract::ExecutionWorkspaceBackend {
        ExecutionWorkspaceProvider::backend(self.inner.as_ref())
    }

    fn resolve_target(
        &self,
        execution_id: Ulid,
        spec: &kata_types::target::TargetSpec,
        forge: Option<&dyn kata_effects_contract::Forge>,
    ) -> KataResult<kata_types::target::ExecutionTarget> {
        ExecutionWorkspaceProvider::resolve_target(self.inner.as_ref(), execution_id, spec, forge)
    }

    fn release_target_pins(&self, execution_id: Ulid) -> KataResult<()> {
        ExecutionWorkspaceProvider::release_target_pins(self.inner.as_ref(), execution_id)
    }

    fn sweep_target_pins(
        &self,
        claim: &dyn Fn(Ulid) -> kata_effects_contract::TargetPinClaim,
    ) -> KataResult<kata_effects_contract::TargetPinSweep> {
        ExecutionWorkspaceProvider::sweep_target_pins(self.inner.as_ref(), claim)
    }

    fn create_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        target: &kata_types::target::ExecutionTarget,
    ) -> KataResult<ExecutionWorkspaceHandle> {
        ExecutionWorkspaceProvider::create_workspace(self.inner.as_ref(), key, target)
    }

    fn workspace_status(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<kata_effects_contract::ExecutionWorkspaceStatus>> {
        ExecutionWorkspaceProvider::workspace_status(self.inner.as_ref(), key)
    }

    fn remove_workspace(&self, key: &ExecutionWorkspaceKey) -> KataResult<()> {
        ExecutionWorkspaceProvider::remove_workspace(self.inner.as_ref(), key)
    }

    fn promote_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        pin: &kata_types::execution::CandidateTreePin,
        landing_branch: Option<&str>,
    ) -> KataResult<kata_effects_contract::PromotedWorkspace> {
        ExecutionWorkspaceProvider::promote_workspace(self.inner.as_ref(), key, pin, landing_branch)
    }

    fn park_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        label: Option<&str>,
    ) -> KataResult<kata_effects_contract::ParkedWorkspace> {
        ExecutionWorkspaceProvider::park_workspace(self.inner.as_ref(), key, label)
    }

    fn parked_ref_name(&self, key: &ExecutionWorkspaceKey, label: Option<&str>) -> String {
        ExecutionWorkspaceProvider::parked_ref_name(self.inner.as_ref(), key, label)
    }

    fn lookup_parked_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        ref_name: &str,
    ) -> KataResult<Option<kata_effects_contract::ParkedWorkspace>> {
        ExecutionWorkspaceProvider::lookup_parked_workspace(self.inner.as_ref(), key, ref_name)
    }

    fn lookup_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<ExecutionWorkspaceHandle>> {
        ExecutionWorkspaceProvider::lookup_workspace(self.inner.as_ref(), key)
    }

    fn repair_stale_checkout(&self, handle: &ExecutionWorkspaceHandle) -> KataResult<()> {
        ExecutionWorkspaceProvider::repair_stale_checkout(self.inner.as_ref(), handle)
    }

    fn classify_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        handle: Option<&ExecutionWorkspaceHandle>,
        op: WorkspaceEffectOp,
        recorded_candidate: &str,
        delivered_commit: &str,
        landing_branch: Option<&str>,
    ) -> KataResult<kata_effects_contract::WorkspaceEffectClass> {
        self.inner.classify_workspace_effect(
            key,
            handle,
            op,
            recorded_candidate,
            delivered_commit,
            landing_branch,
        )
    }

    fn commit_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
        effect_tag: &str,
    ) -> KataResult<kata_effects_contract::CommittedEffect> {
        if matches!(self.at, Interposition::OutcomeUnknownCommit) {
            return Err(KataError::OutcomeUnknown(
                "workspace_effect commit: the publish's outcome is indeterminate".to_owned(),
            ));
        }
        ExecutionWorkspaceProvider::commit_workspace_effect(
            self.inner.as_ref(),
            key,
            expected_wc_commit,
            effect_tag,
        )
    }
    fn promotion_snapshots_dirty(&self) -> bool {
        ExecutionWorkspaceProvider::promotion_snapshots_dirty(self.inner.as_ref())
    }

    fn refuse_unsupported_repository_features(
        &self,
        handle: &kata_effects_contract::ExecutionWorkspaceHandle,
    ) -> KataResult<()> {
        ExecutionWorkspaceProvider::refuse_unsupported_repository_features(
            self.inner.as_ref(),
            handle,
        )
    }

    fn committed_base_tree(
        &self,
        handle: &kata_effects_contract::ExecutionWorkspaceHandle,
        bounds: kata_types::tree_artifact::WorkTreeInputBounds,
        put_member: &mut dyn FnMut(&[u8]) -> KataResult<kata_types::primitives::ObjectId>,
    ) -> KataResult<kata_types::tree_artifact::CommittedBaseTree> {
        ExecutionWorkspaceProvider::committed_base_tree(
            self.inner.as_ref(),
            handle,
            bounds,
            put_member,
        )
    }

    fn committed_base_git_history(
        &self,
        handle: &kata_effects_contract::ExecutionWorkspaceHandle,
        target: &kata_types::target::ExecutionTarget,
        history_depth: Option<u32>,
        history_bytes_ceiling: u64,
        put_member: &mut dyn FnMut(&[u8]) -> KataResult<kata_types::primitives::ObjectId>,
    ) -> KataResult<kata_types::tree_artifact::CommittedBaseGitView> {
        ExecutionWorkspaceProvider::committed_base_git_history(
            self.inner.as_ref(),
            handle,
            target,
            history_depth,
            history_bytes_ceiling,
            put_member,
        )
    }

    fn reap_terminal_workspaces(
        &self,
        policy: kata_effects_contract::TerminalWorkspaceReapPolicy,
        classify: &dyn Fn(Ulid) -> kata_effects_contract::ExecutionLiveness,
    ) -> KataResult<usize> {
        ExecutionWorkspaceProvider::reap_terminal_workspaces(self.inner.as_ref(), policy, classify)
    }

    fn lookup_promoted_workspace(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
        base_ref: &str,
        candidate_commit_sha: &str,
    ) -> KataResult<Option<kata_effects_contract::PromotedWorkspace>> {
        ExecutionWorkspaceProvider::lookup_promoted_workspace(
            self.inner.as_ref(),
            key,
            base_ref,
            candidate_commit_sha,
        )
    }

    fn apply_work_delta(
        &self,
        handle: &kata_effects_contract::ExecutionWorkspaceHandle,
        expected_wc_commit: &str,
        delta: &kata_types::tree_delta::TreeDelta,
        members: &dyn Fn(kata_types::primitives::ObjectId, u64) -> KataResult<Vec<u8>>,
        effect_tag: &str,
    ) -> KataResult<kata_effects_contract::AppliedCandidate> {
        ExecutionWorkspaceProvider::apply_work_delta(
            self.inner.as_ref(),
            handle,
            expected_wc_commit,
            delta,
            members,
            effect_tag,
        )
    }

    fn classify_work_apply(
        &self,
        handle: &kata_effects_contract::ExecutionWorkspaceHandle,
        recorded_head_commit: &str,
        effect_tag: &str,
        delta: &kata_types::tree_delta::TreeDelta,
        since_ms: i64,
    ) -> KataResult<kata_effects_contract::WorkApplyState> {
        ExecutionWorkspaceProvider::classify_work_apply(
            self.inner.as_ref(),
            handle,
            recorded_head_commit,
            effect_tag,
            delta,
            since_ms,
        )
    }

    fn park_workspace_effect(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
    ) -> KataResult<kata_effects_contract::ParkedWorkspace> {
        ExecutionWorkspaceProvider::park_workspace_effect(
            self.inner.as_ref(),
            key,
            expected_wc_commit,
            delivered_commit,
            effect_tag,
        )
    }

    fn promote_workspace_effect(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
        pin: &kata_types::execution::CandidateTreePin,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
        landing_branch: Option<&str>,
    ) -> KataResult<kata_effects_contract::PromotedWorkspace> {
        ExecutionWorkspaceProvider::promote_workspace_effect(
            self.inner.as_ref(),
            key,
            pin,
            expected_wc_commit,
            delivered_commit,
            effect_tag,
            landing_branch,
        )
    }

    fn workspace_effect_delivered_commit(
        &self,
        op: WorkspaceEffectOp,
        candidate_commit: &str,
        committed_commit: &str,
    ) -> KataResult<String> {
        ExecutionWorkspaceProvider::workspace_effect_delivered_commit(
            self.inner.as_ref(),
            op,
            candidate_commit,
            committed_commit,
        )
    }

    fn require_clean_recorded_candidate(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
        expected_wc_commit: &str,
    ) -> KataResult<kata_effects_contract::ExecutionWorkspaceStatus> {
        ExecutionWorkspaceProvider::require_clean_recorded_candidate(
            self.inner.as_ref(),
            key,
            expected_wc_commit,
        )
    }

    fn ensure_workspace_ref(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
        ref_name: &str,
        commit_sha: &str,
        effect_tag: &str,
    ) -> KataResult<()> {
        ExecutionWorkspaceProvider::ensure_workspace_ref(
            self.inner.as_ref(),
            key,
            ref_name,
            commit_sha,
            effect_tag,
        )
    }

    fn teardown_workspace_effect(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
        effect_tag: &str,
    ) -> KataResult<()> {
        ExecutionWorkspaceProvider::teardown_workspace_effect(self.inner.as_ref(), key, effect_tag)
    }

    fn write_workspace_effect_forge_ref(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
        branch: &str,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
    ) -> KataResult<()> {
        ExecutionWorkspaceProvider::write_workspace_effect_forge_ref(
            self.inner.as_ref(),
            key,
            branch,
            expected_wc_commit,
            delivered_commit,
            effect_tag,
        )
    }

    fn push_workspace_effect_ref_expecting(
        &self,
        remote: &str,
        branch: &str,
        commit: &str,
        expected_remote: Option<&str>,
    ) -> KataResult<()> {
        if let Interposition::BeforePush(before) = &self.at {
            before();
        }
        ExecutionWorkspaceProvider::push_workspace_effect_ref_expecting(
            self.inner.as_ref(),
            remote,
            branch,
            commit,
            expected_remote,
        )
    }

    fn park_workspace_recorded(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
        label: Option<&str>,
        expected_wc_commit: &str,
    ) -> KataResult<kata_effects_contract::ParkedWorkspace> {
        ExecutionWorkspaceProvider::park_workspace_recorded(
            self.inner.as_ref(),
            key,
            label,
            expected_wc_commit,
        )
    }

    fn recorded_workspace_status(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
    ) -> KataResult<Option<kata_effects_contract::RecordedWorkspaceStatus>> {
        ExecutionWorkspaceProvider::recorded_workspace_status(self.inner.as_ref(), key)
    }

    fn recorded_commit_diff(
        &self,
        base_commit: &str,
        head_commit: &str,
    ) -> KataResult<Vec<kata_effects_contract::RecordedPathChange>> {
        ExecutionWorkspaceProvider::recorded_commit_diff(
            self.inner.as_ref(),
            base_commit,
            head_commit,
        )
    }

    fn recorded_commit_text_diff(
        &self,
        base_commit: &str,
        head_commit: &str,
        max_bytes: usize,
    ) -> KataResult<kata_effects_contract::RecordedTextDiff> {
        ExecutionWorkspaceProvider::recorded_commit_text_diff(
            self.inner.as_ref(),
            base_commit,
            head_commit,
            max_bytes,
        )
    }

    fn workspace_effect_candidate_commit(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
    ) -> KataResult<Option<String>> {
        ExecutionWorkspaceProvider::workspace_effect_candidate_commit(self.inner.as_ref(), key)
    }

    fn commit_tree_id(&self, commit_sha: &str) -> KataResult<String> {
        ExecutionWorkspaceProvider::commit_tree_id(self.inner.as_ref(), commit_sha)
    }

    fn workspace_effect_candidate_tree(
        &self,
        key: &kata_effects_contract::ExecutionWorkspaceKey,
    ) -> KataResult<Option<String>> {
        ExecutionWorkspaceProvider::workspace_effect_candidate_tree(self.inner.as_ref(), key)
    }

    fn forge_export_remote(&self, branch: &str) -> KataResult<String> {
        ExecutionWorkspaceProvider::forge_export_remote(self.inner.as_ref(), branch)
    }

    fn forge_export_repository(&self, remote: &str) -> KataResult<String> {
        ExecutionWorkspaceProvider::forge_export_repository(self.inner.as_ref(), remote)
    }

    fn forge_remote_head(
        &self,
        remote: &str,
        branch: &str,
        timeout: std::time::Duration,
    ) -> KataResult<Option<String>> {
        ExecutionWorkspaceProvider::forge_remote_head(self.inner.as_ref(), remote, branch, timeout)
    }
}

/// An `OutcomeUnknown` (or any non-`Validation`) verb error leaves the
/// attempt `pending` for the sweep's repository-facts classify; only a typed
/// refusal settles `failed`. The attempt survives to be driven again.
#[test]
fn an_outcome_unknown_perform_stays_pending_for_the_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "commit");
    let (attempt_id, _spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Commit,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let flaky: Arc<dyn ExecutionWorkspaceProvider> = Arc::new(Interposed {
        inner: Arc::clone(&fx.backend),
        at: Interposition::OutcomeUnknownCommit,
    });
    let error = fx
        .dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&flaky), None)
        .expect_err("an outcome-unknown perform propagates, never records failed");
    assert!(
        matches!(error, KataError::OutcomeUnknown(_)),
        "the ambiguous outcome propagates: {error}"
    );
    assert_eq!(
        attempt_state(&fx, attempt_id),
        "pending",
        "the ambiguous perform does NOT settle the attempt — the sweep's classify owns it"
    );
    assert!(
        git_rev(
            dir.path().join("repo").as_path(),
            &format!("exec-{}", fx.execution_id)
        )
        .is_none(),
        "the refusing drive wrote no exec-<id> ref"
    );
    // The sweep's classify then performs the effect for real.
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the sweep performs the still-pending attempt");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
}

/// Armed crash AFTER the `commit` verb returned (its jj publish, checkout and
/// `exec-<id>` write all landed) but BEFORE the resolve: the landed shape is
/// `@` = `next_wc` whose SINGLE parent is the rewritten candidate
/// (`rewrite_commit` mints a new id — the recorded candidate is a PREDECESSOR
/// edge, never a parent). Recovery must classify `Committed` off that edge —
/// not `Diverged` — with `exec-<id>` at the rewrite, the commit the verb
/// actually published, recording it as the head row's `committed_commit_id` so
/// a later `promote` delivers it rather than the empty `@` above it. The
/// verb's in-verb `after_jj_publish_before_return` arm sits after the same
/// ref write with nothing between it and the return, so this cell covers that
/// window too.
#[test]
fn crash_after_workspace_effect_commit_returned_before_resolution() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "commit");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Commit,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_workspace_effect_jj_publish_before_resolution",
        dir.path(),
        "crash_after_workspace_effect_commit_returned_before_resolution",
    );
    let repo = dir.path().join("repo");
    let exec_ref = format!("exec-{}", fx.execution_id);
    // The child's verb landed — publish, checkout, ref write — but its
    // resolve never committed.
    assert!(
        git_rev(&repo, &exec_ref).is_some(),
        "the child's exec-<id> write landed before the abort"
    );
    assert_eq!(
        attempt_state(&fx, attempt_id),
        "pending",
        "the resolve never committed"
    );
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive classifies the landed commit");
    let landed = git_rev(&repo, &exec_ref).expect("exec-<id> stands after the recovery");
    assert_ne!(
        landed, spec.candidate_commit,
        "exec-<id> names the REWRITE — the commit the verb published — not the recorded candidate"
    );
    let landed_parent = {
        let out = hermetic_git_in(&repo)
            .args(["rev-list", "--parents", "-1", &landed])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        landed_parent,
        git_rev(&repo, "main").unwrap(),
        "the landed commit sits on the candidate's base"
    );
    assert_eq!(
        git_show(&repo, &landed, "a.txt").as_deref(),
        Some("committed\n"),
        "the rewrite kept the candidate's tree"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    // And the head row advanced to the fresh empty `@`.
    let head = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_ne!(
        head.candidate_commit_id, spec.candidate_commit,
        "the head advanced to the post-commit @"
    );
    // The sweep's `Committed` leg wrote the committed commit into the head
    // row, read through a second, read-only handle: an empty column here
    // would make the next `promote` deliver the empty `@` again.
    let (raw_candidate, raw_committed): (String, String) = rusqlite::Connection::open_with_flags(
        &fx.planes.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT candidate_commit_id, committed_commit_id FROM execution_work_tree_heads \
             WHERE execution_id = ?1 AND branch = ''",
        [fx.execution_id.to_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .expect("the root head row");
    assert_eq!(
        raw_committed, landed,
        "the recovered resolve recorded the commit it classified as committed_commit_id"
    );
    assert_eq!(raw_candidate, head.candidate_commit_id);
    // And a `promote` claimed after the recovery lands that commit on trunk.
    let trunk_before = git_rev(&repo, "main").unwrap();
    let (promote_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::Promote, None, "promote", vec![7]);
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the promote drives");
    assert_eq!(attempt_state(&fx, promote_attempt), "completed");
    assert_eq!(
        git_rev(&repo, "main"),
        Some(landed),
        "trunk's tip IS the recovered committed commit — not the empty @ above it"
    );
    assert_eq!(git_log_one(&repo, "%P", "main"), trunk_before);
}

/// Armed crash on `promote` after the verb returned (the land published, the
/// workspace torn down) and before the resolve: the attempt is still
/// `pending`. Under no frozen target the recovery classifies `Promoted` off
/// the trunk the repository resolves and resolves — no second land, no
/// Diverged. The window before the verb's own teardown is
/// `crash_after_promote_lands_before_teardown_recovers_and_tears_the_workspace_down`'s.
#[test]
fn crash_after_workspace_effect_promote_returned_before_resolution() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "promote");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_workspace_effect_jj_publish_before_resolution",
        dir.path(),
        "crash_after_workspace_effect_promote_returned_before_resolution",
    );
    let repo = dir.path().join("repo");
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.candidate_commit.as_str()),
        "the child's land is on trunk already"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "pending");
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive classifies the landed promote");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    let head = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        head.candidate_commit_id, spec.candidate_commit,
        "the resolve left the head row at the recorded candidate"
    );
}

/// A labelled `park` writes `parked/<exec-id>` and ONLY that: the label
/// is spec metadata, never the ref name — so recovery reads the same ref the
/// verb wrote and two executions cannot collide on one label.
#[test]
fn a_labelled_park_writes_the_execution_scoped_ref() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: Some("review".to_owned()),
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    assert_eq!(
        spec.target,
        fx.backend.parked_ref_name(&key, None),
        "the recorded scope names the execution-scoped ref, not the label"
    );
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the labelled park drives");
    let repo = dir.path().join("repo");
    assert_eq!(
        git_rev(&repo, &format!("parked/{}", fx.execution_id)),
        Some(spec.candidate_commit.clone()),
        "the execution-scoped ref names the candidate — read from git"
    );
    assert_eq!(
        git_rev(&repo, "parked/review"),
        None,
        "no label-named ref exists — the label is metadata only"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
}

/// Armed crash on a LABELLED park after the verb (its teardown included)
/// returned and before the resolve: the ref is `parked/<exec-id>` (never the
/// label), and recovery reads the same ref and resolves, no `Diverged` on a
/// label-shaped lookup. The window before the verb's teardown is
/// `crash_after_park_ref_write_before_teardown_recovers_and_tears_the_workspace_down`'s.
#[test]
fn crash_after_labelled_park_returned_before_resolution() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: Some("review".to_owned()),
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_workspace_effect_jj_publish_before_resolution",
        dir.path(),
        "crash_after_labelled_park_returned_before_resolution",
    );
    let repo = dir.path().join("repo");
    let ref_name = format!("parked/{}", fx.execution_id);
    assert_eq!(
        git_rev(&repo, &ref_name),
        Some(spec.candidate_commit.clone()),
        "the child's labelled park published the execution-scoped ref"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "pending");
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive classifies the landed park");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(fx.backend.as_ref(), &key)
            .unwrap()
            .is_none(),
        "the workspace the child's verb tore down stays gone"
    );
}

/// The execution's terminal INTENT latches while the attempt is still
/// `pending` (the state between `begin_terminalization` and the outcome's
/// publication). A sweep that enumerates a `terminalizing` execution's
/// pending effects performs a dead execution's mutation — a remote push or a
/// ref that no outcome will ever name. The lifecycle filter +
/// drivability re-check refuse before any publish: no ref, and the attempt
/// stays `pending` for the publication commit's drain to settle.
#[test]
fn a_pending_effect_terminalized_before_perform_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, _spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    // The terminal intent latches — the execution is `terminalizing`, the
    // outcome not yet published. This is exactly the window the sweep must
    // not perform through.
    fx.planes
        .db
        .begin_terminalization(
            fx.execution_id,
            kata_core::operational::LifecycleState::Cancelled,
            br#"{"kind":"cancelled","detail":"the operator cancelled the execution under a pending effect"}"#,
        )
        .expect("the terminal intent latches");
    assert!(
        fx.planes
            .db
            .pending_workspace_effects(fx.execution_id)
            .unwrap()
            .is_empty(),
        "a terminalizing execution's effects do not enumerate"
    );
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the sweep is a no-op under terminal intent");
    assert_eq!(
        git_rev(
            dir.path().join("repo").as_path(),
            &format!("parked/{}", fx.execution_id)
        ),
        None,
        "no parked ref — the terminalizing fence holds before any publish"
    );
    // The publication commit then drains the attempt — `cancelled`, not
    // performed.
    fx.planes
        .db
        .finish_terminalization(fx.execution_id)
        .expect("the outcome publishes and drains the pending effect");
    assert_eq!(
        attempt_state(&fx, attempt_id),
        "cancelled",
        "the drain settles the pending effect in the publication commit"
    );
}

/// Concurrent drivers — the gate-decision path and the runner's pass loop can reach
/// the same pending attempt concurrently. The perform lock + the drivability
/// re-check make exactly one perform land: two drivers racing one attempt
/// leave exactly the verbs' op count, not twice it.
#[test]
fn concurrent_drives_perform_the_effect_once() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "commit");
    let (attempt_id, _spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Commit,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let ops_before = fx.backend.op_log_len().unwrap();
    let second = dispatcher(&fx.planes.db);
    let provider = as_provider(&fx.backend);
    let (first_result, second_result) = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            fx.dispatcher
                .drive_pending_workspace_effects(fx.execution_id, Some(&provider), None)
        });
        let b = scope.spawn(|| {
            second.drive_pending_workspace_effects(fx.execution_id, Some(&provider), None)
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    first_result.expect("driver one");
    second_result.expect("driver two");
    assert_eq!(
        attempt_state(&fx, attempt_id),
        "completed",
        "exactly one perform resolved the attempt"
    );
    // The commit verb's two publishing ops (the rewrite+repoint and the
    // exec-<id> ref write) land exactly once — a second perform would add two
    // more or die on the moved candidate.
    assert_eq!(
        fx.backend.op_log_len().unwrap(),
        ops_before + 2,
        "one perform's worth of ops, not two"
    );
}

/// **The push is leased on what the read before its intent found, never on a
/// local remote-tracking ref.** The read finds the branch absent, so the push
/// is `--force-with-lease=<ref>:` (absence). Plant a STALE tracking ref naming
/// a foreign commit: under the bare lease, which reads that tracking ref, the
/// push would refuse (expected = the foreign commit, actual = absent); under
/// the read's lease it lands — the remote's own emptiness is what the read saw.
#[test]
fn a_push_is_leased_on_the_read_and_not_on_a_stale_tracking_ref() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = forge_remote(dir.path(), &repo, "origin");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::ForgeExport,
            label: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
            forge: Some(kata_types::workflow::ForgeExportSpec {
                title: None,
                body: None,
            }),
        },
        None,
    );
    // The stale tracking ref — `refs/remotes/origin/kata/<exec>` exists
    // locally naming a commit that is NOT the candidate, while the remote's
    // branch is absent. A bare `--force-with-lease` would refuse on it.
    let foreign = git_rev(&repo, "main").expect("the base commit exists");
    assert_ne!(foreign, spec.candidate_commit);
    run_git(
        &repo,
        &[
            "update-ref",
            &format!("refs/remotes/origin/kata/{}", fx.execution_id),
            &foreign,
        ],
    );
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
        None,
        "the remote branch is absent — the read before the intent finds no branch"
    );
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/88",
    ));
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export pushes under the absent lease");
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
        Some(spec.candidate_commit.clone()),
        "the branch landed on the remote despite the stale tracking ref"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
}

// -- mutation cells -----------------------------------------------------------
// The sweep's own classify is not the only door: `perform_workspace_effect`
// re-classifies inside the perform lock, and `effect_output` is the recorded
// document `stages.<x>` reads. These cells read the transition payload and
// the colocated refs raw, never the dispatcher's own answer.

/// A claimed `workspace_effect` at a SECOND occurrence — the sweep counts
/// pending rows, so a two-attempt fixture needs two occurrences.
fn claim_effect_at(
    fx: &Fixture,
    spec: WorkspaceEffectSpec,
    stage: &str,
    op_path: Vec<u32>,
) -> (Ulid, WorkspaceEffectSpec) {
    claim_gated_effect_at(fx, spec, stage, op_path, None)
}

/// [`claim_effect_at`] under `approval` — `Some` parks the claim
/// `awaiting_approval`, as a stage with `approval = True` does.
fn claim_gated_effect_at(
    fx: &Fixture,
    spec: WorkspaceEffectSpec,
    stage: &str,
    op_path: Vec<u32>,
    approval: Option<&str>,
) -> (Ulid, WorkspaceEffectSpec) {
    let ref_occurrence = occurrence_ref(fx.execution_id, &fx.program);
    let attempt_id = Ulid::new();
    fx.planes
        .db
        .claim_workspace_effect_attempt(
            attempt_id,
            &MainAttemptSpec {
                stage_id: stage.to_string(),
                occurrence: OccurrenceBinding::new(
                    OccurrenceRef::new(
                        kata_types::workflow::ExecutionId(fx.execution_id),
                        fx.program.program_hash,
                        ref_occurrence.operation,
                        OperationPath(op_path),
                    ),
                    None,
                    None,
                ),
            },
            &spec,
            approval,
        )
        .expect("the second claim lands");
    (attempt_id, spec)
}

/// The resolving transition's `output`, read raw off `transitions.payload_json`.
fn resolved_output(fx: &Fixture, attempt_id: Ulid) -> serde_json::Value {
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    let payload: Vec<u8> = conn
        .query_row(
            "SELECT payload_json FROM transitions WHERE attempt_id = ?1
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the resolving transition's payload");
    serde_json::from_slice::<serde_json::Value>(&payload).expect("the payload decodes")["output"]
        .clone()
}

/// **The recorded output is the `effect_applied` envelope, not a default.** The
/// attempt's Complete resolution carries `{"content": <envelope>,
/// "stop_reason": "effect_applied", "stage", "execution": {"backend":
/// "workspace_effect"}}` — the document a downstream `stages.<x>` read sees.
/// A defaulted output is a silent change of the contract the frontend reads.
#[test]
fn a_completed_effect_records_the_effect_applied_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "commit");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Commit,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the commit drives");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    let output = resolved_output(&fx, attempt_id);
    assert_eq!(
        output["stop_reason"].as_str(),
        Some("effect_applied"),
        "the envelope's stop_reason: {output}"
    );
    assert_eq!(
        output["stage"].as_str(),
        Some(STAGE),
        "the envelope's stage: {output}"
    );
    let content: serde_json::Value = serde_json::from_str(
        output["content"]
            .as_str()
            .expect("the envelope carries a content string"),
    )
    .expect("content is the serialized operation envelope");
    assert_eq!(content["operation"].as_str(), Some("commit"), "{content}");
    let ref_name = format!("exec-{}", fx.execution_id);
    assert_eq!(content["ref_name"].as_str(), Some(ref_name.as_str()));
    // `commit_sha` is the finalize's LANDED commit — the sha the ref itself
    // names, read off git rather than the claim's recorded candidate.
    let _ = spec;
    assert_eq!(
        content["commit_sha"].as_str(),
        git_rev(&dir.path().join("repo"), &ref_name).as_deref(),
        "the envelope names the commit the ref names: {content}"
    );
}

/// **`perform_workspace_effect`'s own promote classify is the mid-land idempotent
/// leg** — trunk already names the candidate (the publish landed; the resolve or
/// the teardown did not), so the inner classify answers `Promoted` and records
/// its envelope (`ref_moved`, the key the verb and the sweep write too) WITHOUT
/// re-running the verb. A perform that falls through to the verb either
/// double-publishes or refuses the missing workspace — either way the attempt
/// does not resolve `completed` on the landed commit.
#[test]
fn a_perform_seeing_the_promote_landed_records_the_classify_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "promote");
    let (first, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    // The publish half landed and the resolve recorded — but a crash between
    // them leaves exactly this shape: trunk names the candidate, the workspace
    // is gone, and a pending promote attempt is still owed an outcome.
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the first promote lands");
    assert_eq!(attempt_state(&fx, first), "completed");
    let repo = dir.path().join("repo");
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.candidate_commit.as_str()),
        "trunk names the candidate"
    );

    // A second claim re-performing the same effect is the re-drive shape the
    // inner classify exists for: the sweep's own classify answers Promoted
    // before perform is reached, so `perform_workspace_effect` is the only
    // door that exercises the arm — call it as the runner's pass loop does.
    let (second, spec) = claim_effect_at(&fx, spec.clone(), "ship2", vec![7]);
    assert_eq!(attempt_state(&fx, second), "pending");
    fx.dispatcher
        .perform_workspace_effect(
            fx.execution_id,
            second,
            "ship2",
            &spec,
            &as_provider(&fx.backend),
            None,
        )
        .expect("the Promoted classify resolves the re-drive");
    assert_eq!(attempt_state(&fx, second), "completed");
    let output = resolved_output(&fx, second);
    let content: serde_json::Value =
        serde_json::from_str(output["content"].as_str().expect("the content string"))
            .expect("the envelope decodes");
    assert_eq!(
        content["ref_moved"].as_str(),
        Some("main"),
        "the Promoted arm records the trunk ref under ref_moved: {content}"
    );
    assert_eq!(
        content["commit_sha"].as_str(),
        Some(spec.candidate_commit.as_str()),
        "{content}"
    );
}

/// **The inner `Diverged` arm records the refusal instead of re-running the
/// verb** — `parked/<exec-id>` at a commit that is neither the delivered
/// commit nor the landing's own rebase of it (here trunk's head, which the
/// ladder never parks) is an outside write. Falling through to the verb would
/// land the candidate over it; the refusal moves nothing and tears nothing
/// down. The landing's own rebase is answered as its refusal instead
/// (`crash_after_a_revalidation_park_before_teardown_the_perform_leg_records_the_refusal`).
#[test]
fn a_perform_seeing_an_outside_parked_ref_fails_diverged_and_moves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "promote");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let repo = dir.path().join("repo");
    let trunk = git_rev(&repo, "main").expect("trunk");
    assert_ne!(trunk, spec.candidate_commit);
    // An outside write, through the provider's own jj leg: the
    // execution-scoped parked ref names trunk's head, not the recorded
    // candidate and not a rebase of it.
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let parked_ref = fx.backend.parked_ref_name(&key, None);
    ExecutionWorkspaceProvider::ensure_workspace_ref(
        fx.backend.as_ref(),
        &key,
        &parked_ref,
        &trunk,
        "test-parked-residue",
    )
    .expect("the parked ref writes");
    fx.dispatcher
        .perform_workspace_effect(
            fx.execution_id,
            attempt_id,
            STAGE,
            &spec,
            &as_provider(&fx.backend),
            None,
        )
        .expect("the classify leg settles the diverged perform");
    assert_eq!(attempt_state(&fx, attempt_id), "failed");
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    let payload: String = conn
        .query_row(
            "SELECT payload_json FROM transitions WHERE attempt_id = ?1
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap();
    assert!(
        payload.contains("an outside write"),
        "the recorded reason names the outside parked ref: {payload}"
    );
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(trunk.as_str()),
        "trunk never moved — the diverged perform published nothing"
    );
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(fx.backend.as_ref(), &key)
            .unwrap()
            .is_some(),
        "the refusal tore nothing down"
    );
}

/// **The drive counts what it drove.** Two pending attempts at distinct
/// occurrences, one pass: `drive_pending_workspace_effects` answers `2`, and
/// both attempts are `completed` — a counter folded with `*=` reports 0 while
/// the work reports done.
#[test]
fn a_drive_over_two_pending_effects_reports_two() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let effect = WorkspaceEffect {
        op: WorkspaceEffectOp::Park,
        label: None,
        forge: None,
        candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
    };
    let (first, spec) = claim_effect(&fx, effect.clone(), None);
    let (second, _) = claim_effect_at(&fx, spec, "ship2", vec![7]);
    assert_eq!(attempt_state(&fx, first), "pending");
    assert_eq!(attempt_state(&fx, second), "pending");
    let progressed = fx
        .dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the drive");
    assert_eq!(
        progressed, 2,
        "the drive's own count: two pending effects progressed"
    );
    assert_eq!(attempt_state(&fx, first), "completed");
    assert_eq!(attempt_state(&fx, second), "completed");
}

/// **The dispatcher's decision door decides the parked gate by attempt id** —
/// `decide_workspace_effect_gate` looks the gate up in the execution's parked
/// list; a lookup answering on a DIFFERENT attempt id reads nothing and the
/// door refuses `approval_gate_not_parked` instead of deciding.
#[test]
fn the_decision_door_approves_the_parked_effect_gate() {
    use kata_core::operational::WorkspaceEffectVerdict;
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        Some("approve the park"),
    );
    assert_eq!(attempt_state(&fx, attempt_id), "awaiting_approval");
    fx.dispatcher
        .decide_workspace_effect_gate(
            attempt_id,
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
            WorkspaceEffectVerdict::Approve,
            &as_provider(&fx.backend),
            None,
        )
        .expect("the approve decides and performs");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let ref_name = fx.backend.parked_ref_name(&key, None);
    assert_eq!(
        git_rev(&dir.path().join("repo"), &ref_name),
        Some(spec.candidate_commit.clone()),
        "the approved effect performed — the parked ref names the candidate"
    );
}

/// **The operator's parked-gate list sees a workspace_effect gate.** A gated
/// effect parks as a `main`-executor `awaiting_approval` attempt, and
/// `live_work_registry` excludes main attempts by name, so enumerating it would
/// make `pending_approvals` / `GET /approvals` / `kata approvals` answer the
/// empty list for exactly the gates an operator must find. The enumeration asks the operational plane for every
/// `awaiting_approval` attempt of a live execution and routes main-executor
/// rows through the workspace-effect view.
#[test]
fn a_gated_workspace_effect_is_listed_for_the_operator() {
    use kata_core::operational::WorkspaceEffectVerdict;
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        Some("approve the park"),
    );
    assert_eq!(attempt_state(&fx, attempt_id), "awaiting_approval");

    // The raw row is a MAIN-executor attempt — the row the live registry sheds.
    let executor: String = rusqlite::Connection::open(&fx.planes.op_path)
        .unwrap()
        .query_row(
            "SELECT executor FROM attempts WHERE attempt_id = ?1",
            [attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        executor, "main",
        "the fixture parks the gate as a main attempt"
    );

    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let ref_name = fx.backend.parked_ref_name(&key, None);
    let gates = fx
        .dispatcher
        .parked_approval_gates()
        .expect("the operator's gate list answers");
    let gate = gates
        .iter()
        .find(|gate| gate.assignment_id == attempt_id)
        .expect(
            "the parked workspace_effect gate is listed — it is invisible \
                 to the registry but the operator's list is not the registry",
        );
    assert_eq!(gate.execution_id, fx.execution_id);
    assert_eq!(gate.stage_name.as_str(), STAGE);
    let scope = gate
        .workspace_effect
        .as_ref()
        .expect("the gate carries the effect's scope");
    assert_eq!(scope.op, "park");
    assert_eq!(scope.target, ref_name);
    assert_eq!(scope.candidate_commit, spec.candidate_commit);

    // Decided, it leaves the list — parked gates are not sticky.
    fx.dispatcher
        .decide_workspace_effect_gate(
            attempt_id,
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
            WorkspaceEffectVerdict::Approve,
            &as_provider(&fx.backend),
            None,
        )
        .expect("the approve decides and performs");
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    let after = fx
        .dispatcher
        .parked_approval_gates()
        .expect("the list answers after the decision");
    assert!(
        after.iter().all(|gate| gate.assignment_id != attempt_id),
        "a decided gate leaves the operator's list"
    );
}

// -- the committed commit is what promote and forge_export deliver ----------------

/// A follow-on effect claimed AFTER an earlier effect resolved — what
/// `WorkflowRunner::submit_workspace_effect` records: the head row is read
/// fresh (the `commit` resolve advanced it), so the fence is the head row's
/// current candidate, never the fixture's admission-time head.
fn claim_follow_on(
    fx: &Fixture,
    op: WorkspaceEffectOp,
    forge: Option<kata_types::workflow::ForgeExportSpec>,
    stage: &str,
    op_path: Vec<u32>,
) -> (Ulid, WorkspaceEffectSpec) {
    claim_effect_at(fx, follow_on_spec(fx, op, forge), stage, op_path)
}

/// The spec [`claim_follow_on`] claims: the head row read fresh.
fn follow_on_spec(
    fx: &Fixture,
    op: WorkspaceEffectOp,
    forge: Option<kata_types::workflow::ForgeExportSpec>,
) -> WorkspaceEffectSpec {
    let head = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .expect("the head row");
    let candidate_tree_id =
        ExecutionWorkspaceProvider::commit_tree_id(fx.backend.as_ref(), &head.candidate_commit_id)
            .unwrap();
    let target = match op {
        WorkspaceEffectOp::ForgeExport => format!("kata/{}", fx.execution_id),
        _ => "main".to_owned(),
    };
    let delivered_commit = delivered_commit(fx, op, &head.candidate_commit_id, &head);
    WorkspaceEffectSpec {
        op,
        label: None,
        target,
        candidate_commit: head.candidate_commit_id,
        delivered_commit,
        candidate_tree_id,
        pin: kata_types::execution::CandidateTreePin::Unpinned,
        forge,
        forge_remote: claimed_remote(fx, op),
    }
}

/// `git log -1 --format=<format> <reference>` — a commit fact read off git.
fn git_log_one(repo: &Path, format: &str, reference: &str) -> String {
    let out = hermetic_git_in(repo)
        .args(["log", "-1", &format!("--format={format}"), reference])
        .output()
        .unwrap();
    assert!(out.status.success(), "git log -1 {reference} runs");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Drive a `commit` effect to completion and return the commit it recorded —
/// the envelope's `commit_sha`, cross-checked against the `exec-<id>` ref git
/// itself names.
fn commit_and_read_sha(fx: &Fixture, repo: &Path) -> String {
    let (commit_attempt, _) = claim_effect(
        fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Commit,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the commit drives");
    assert_eq!(attempt_state(fx, commit_attempt), "completed");
    let output = resolved_output(fx, commit_attempt);
    let content: serde_json::Value =
        serde_json::from_str(output["content"].as_str().expect("content")).expect("envelope");
    let commit_sha = content["commit_sha"]
        .as_str()
        .expect("the commit envelope names commit_sha")
        .to_owned();
    assert_eq!(
        git_rev(repo, &format!("exec-{}", fx.execution_id)).as_deref(),
        Some(commit_sha.as_str()),
        "the envelope's commit_sha is the commit git's exec-<id> names"
    );
    commit_sha
}

/// **`commit → promote` lands the COMMITTED commit**, not the empty `@` the
/// commit left on top of it: trunk's tip is the commit effect's `commit_sha`,
/// carries the effect's description, and sits directly on the trunk the
/// candidate forked from. Every fact is read off git.
#[test]
fn a_commit_then_promote_lands_the_committed_commit() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "promote");
    let repo = dir.path().join("repo");
    let trunk_before = git_rev(&repo, "main").unwrap();
    let commit_sha = commit_and_read_sha(&fx, &repo);

    let (promote_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::Promote, None, "promote", vec![7]);
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the promote drives");
    assert_eq!(attempt_state(&fx, promote_attempt), "completed");

    assert_eq!(
        git_rev(&repo, "main"),
        Some(commit_sha.clone()),
        "trunk's tip IS the committed commit — not an empty child of it"
    );
    assert_eq!(
        git_log_one(&repo, "%s", "main"),
        format!(
            "kata workspace_effect commit for execution {}",
            fx.execution_id
        ),
        "trunk's tip carries the commit effect's description"
    );
    assert_eq!(
        git_log_one(&repo, "%P", "main"),
        trunk_before,
        "the committed commit sits directly on the trunk it forked from"
    );
}

/// **`commit → park` parks the COMMITTED commit**, not the empty `@` the commit
/// left on top of it, exactly as `promote` lands it: `parked/<exec>` IS the
/// commit effect's `commit_sha`, carries the effect's description, and the
/// workspace is gone. Every fact is read off git.
///
/// **Would red if:** the park published the candidate when it is the commit's
/// empty child (watched at the base: `parked/<exec>` named an undescribed
/// commit whose parent was `exec-<exec>`).
#[test]
fn a_commit_then_park_parks_the_committed_commit() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let repo = dir.path().join("repo");
    let commit_sha = commit_and_read_sha(&fx, &repo);

    let (park_attempt, _) = claim_follow_on(&fx, WorkspaceEffectOp::Park, None, "park", vec![7]);
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the park drives");
    assert_eq!(attempt_state(&fx, park_attempt), "completed");

    let parked_ref = format!("parked/{}", fx.execution_id);
    assert_eq!(
        git_rev(&repo, &parked_ref),
        Some(commit_sha.clone()),
        "the parked ref IS the committed commit — not an empty child of it"
    );
    assert_eq!(
        git_log_one(&repo, "%s", &parked_ref),
        format!(
            "kata workspace_effect commit for execution {}",
            fx.execution_id
        ),
        "the parked commit carries the commit effect's description"
    );
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(fx.backend.as_ref(), &key)
            .unwrap()
            .is_none(),
        "the workspace is torn down"
    );
    let output = resolved_output(&fx, park_attempt);
    let content: serde_json::Value =
        serde_json::from_str(output["content"].as_str().expect("content")).expect("envelope");
    assert_eq!(
        content["commit_sha"], commit_sha,
        "the park's envelope names the commit git parked"
    );
}

/// **`commit → promote → forge_export` pushes the COMMITTED commit** to the
/// remote's `kata/<exec>` — the same commit trunk landed, read off the bare
/// remote's own refs.
#[test]
fn a_commit_then_promote_then_export_pushes_the_committed_commit() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = forge_remote(dir.path(), &repo, "origin");
    let commit_sha = commit_and_read_sha(&fx, &repo);

    let (promote_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::Promote, None, "promote", vec![7]);
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the promote drives");
    assert_eq!(attempt_state(&fx, promote_attempt), "completed");

    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let (export_attempt, _) = claim_follow_on(
        &fx,
        WorkspaceEffectOp::ForgeExport,
        Some(kata_types::workflow::ForgeExportSpec {
            title: None,
            body: None,
        }),
        "export",
        vec![8],
    );
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export drives");
    assert_eq!(attempt_state(&fx, export_attempt), "completed");

    assert_eq!(
        git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
        Some(commit_sha.clone()),
        "the remote's kata/<exec> IS the committed commit — read off the bare remote"
    );
    assert_eq!(
        git_rev(&repo, "main"),
        Some(commit_sha),
        "the exported branch and the landed trunk are the same commit"
    );
    assert_eq!(forge.call_count(), 1, "one PR opened");
}

/// **The push's observer judges the remote against the DELIVERED commit.**
/// After `commit → promote`, a `forge_export` crashes after its push and
/// before its receipt: the remote's `kata/<exec>` holds the committed commit,
/// and the recovery's observer must read that as THIS intent's push
/// (PERFORMED), open one PR and resolve — not read the committed commit as a
/// foreign head because the recorded candidate is the empty `@` above it.
#[test]
fn crash_after_forge_push_before_pr_of_a_committed_commit() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = forge_remote(dir.path(), &repo, "origin");
    let commit_sha = commit_and_read_sha(&fx, &repo);
    let (promote_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::Promote, None, "promote", vec![7]);
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the promote drives");
    assert_eq!(attempt_state(&fx, promote_attempt), "completed");
    let (export_attempt, _) = claim_follow_on(
        &fx,
        WorkspaceEffectOp::ForgeExport,
        Some(kata_types::workflow::ForgeExportSpec {
            title: None,
            body: None,
        }),
        "export",
        vec![8],
    );
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_push_before_pr",
        dir.path(),
        "crash_after_forge_push_before_pr_of_a_committed_commit",
    );
    let branch = format!("refs/heads/kata/{}", fx.execution_id);
    assert_eq!(
        git_rev(&origin, &branch),
        Some(commit_sha.clone()),
        "the child pushed the committed commit before the abort"
    );
    assert_eq!(attempt_state(&fx, export_attempt), "pending");
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/43",
    ));
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the recovery drive observes the pushed branch");
    assert_eq!(attempt_state(&fx, export_attempt), "completed");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, export_attempt),
        [
            intent(0, "push", "performed", "observer"),
            intent(1, "pull_request", "performed", "receipt"),
        ]
    );
    assert_eq!(forge.call_count(), 1, "one PR, opened by the recovery leg");
    assert_eq!(
        forge.calls()[0].base,
        "main",
        "the recovery leg asks for the frozen trunk"
    );
    assert_eq!(
        git_rev(&origin, &branch),
        Some(commit_sha),
        "the remote still holds the committed commit — nothing re-pushed over it"
    );
}

// -- what a forge_export after a commit pushes (T5) -----------------------------

/// A bare `origin` for `repo` at `<dir>/origin.git` — the remote whose own
/// refs the export cells read back ([`forge_remote`]).
fn bare_origin(dir: &Path, repo: &Path) -> std::path::PathBuf {
    forge_remote(dir, repo, "origin")
}

/// The forge repository the git remote `name` of the rig names: `origin`
/// names `forge.test/o/r`, any other `forge.test/o/<name>` — what the stateful
/// fake `gh` keys its pull requests by.
fn forge_repository(name: &str) -> String {
    if name == "origin" {
        "forge.test/o/r".to_owned()
    } else {
        format!("forge.test/o/{name}")
    }
}

/// A bare remote `name` for `repo` at `<dir>/<name>.git`, configured as the
/// forge repository [`forge_repository`] names
/// (`kata_test_utils::git::add_forge_remote`).
fn forge_remote(dir: &Path, repo: &Path, name: &str) -> std::path::PathBuf {
    let bare = dir.join(format!("{name}.git"));
    run_git(dir, &["init", "--bare", "-q", bare.to_str().unwrap()]);
    kata_test_utils::git::add_forge_remote(repo, name, &bare, &forge_repository(name));
    bare
}

/// Every ref the bare remote holds, `<sha> <ref>` per line — read off the
/// remote with git.
fn remote_refs(origin: &Path) -> String {
    let out = hermetic_git_in(origin)
        .args(["for-each-ref", "--format=%(objectname) %(refname)"])
        .output()
        .unwrap();
    assert!(out.status.success(), "git for-each-ref runs on the remote");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// What a WRITABLE stage between `commit` and `forge_export` leaves: a new
/// file snapshotted into the workspace, and the head row's candidate moved
/// onto the workspace's resulting `@` — the row an apply compare-and-swaps,
/// written raw. Returns the new candidate.
fn write_after_commit(fx: &Fixture, rel: &str, bytes: &str) -> String {
    write_in_workspace(fx, rel, bytes);
    let agent = kata_types::AgentId(fx.execution_id);
    kata_vcs::VcsBackend::commit(fx.backend.as_ref(), &agent, "a writable stage's edit").unwrap();
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let candidate =
        ExecutionWorkspaceProvider::workspace_effect_candidate_commit(fx.backend.as_ref(), &key)
            .unwrap()
            .expect("the workspace names its @");
    record_head_candidate(fx, &candidate);
    candidate
}

/// Move the head row's candidate onto `candidate` — the row an apply
/// compare-and-swaps, written raw.
fn record_head_candidate(fx: &Fixture, candidate: &str) {
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    let moved = conn
        .execute(
            "UPDATE execution_work_tree_heads SET candidate_commit_id = ?1 \
             WHERE execution_id = ?2",
            rusqlite::params![candidate, fx.execution_id.to_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(moved, 1, "the head row's candidate moved");
}

/// The latest transition's payload for `attempt_id`, raw off the store.
fn latest_payload(fx: &Fixture, attempt_id: Ulid) -> String {
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    conn.query_row(
        "SELECT payload_json FROM transitions WHERE attempt_id = ?1 ORDER BY seq DESC LIMIT 1",
        rusqlite::params![attempt_id.to_bytes().as_slice()],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    .unwrap()
}

/// **`commit → forge_export` pushes the COMMITTED commit and leaves trunk
/// alone.** No `promote` runs: the remote's `kata/<exec>` is the commit
/// effect's `commit_sha` (read off the bare remote), the pull request is asked
/// against the frozen trunk, and the local trunk is the commit it was before.
/// A read-only stage between `commit` and the export moves no candidate, so
/// this is also that path's shape.
#[test]
fn a_commit_then_export_pushes_the_committed_commit_and_leaves_trunk() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = bare_origin(dir.path(), &repo);
    let trunk_before = git_rev(&repo, "main").unwrap();
    let commit_sha = commit_and_read_sha(&fx, &repo);

    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let (export_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export drives");
    assert_eq!(attempt_state(&fx, export_attempt), "completed");
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
        Some(commit_sha),
        "the remote's kata/<exec> IS the committed commit"
    );
    assert_eq!(
        git_rev(&repo, "main"),
        Some(trunk_before),
        "no promote ran: trunk is unchanged"
    );
    assert_eq!(forge.call_count(), 1, "one PR opened");
    assert_eq!(forge.calls()[0].base, "main", "into the frozen trunk");
}

/// **`commit → shell(rw) → forge_export` is refused by name, and nothing is
/// pushed** — on the live perform leg. The writable stage moved the candidate
/// after the commit, so the delivered commit is that candidate, not the
/// committed one; pushing it would publish edits no `commit` recorded. The
/// bare remote holds no ref and the forge was asked nothing.
#[test]
fn an_export_of_a_candidate_written_after_the_commit_is_refused_on_the_perform_leg() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = bare_origin(dir.path(), &repo);
    let commit_sha = commit_and_read_sha(&fx, &repo);
    let candidate = write_after_commit(&fx, "after.txt", "written after the commit\n");
    assert_ne!(candidate, commit_sha);

    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let (export_attempt, spec) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    assert_eq!(
        spec.delivered_commit, candidate,
        "the claim delivers the changed candidate"
    );
    fx.dispatcher
        .perform_workspace_effect(
            fx.execution_id,
            export_attempt,
            "export",
            &spec,
            &as_provider(&fx.backend),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the perform settles the refusal");
    assert_eq!(attempt_state(&fx, export_attempt), "failed");
    let payload = latest_payload(&fx, export_attempt);
    assert!(
        payload.contains("forge_export_uncommitted_candidate"),
        "the typed refusal reached the transition: {payload}"
    );
    assert_eq!(remote_refs(&origin), "", "nothing was pushed");
    assert_eq!(forge.call_count(), 0, "no pull request was asked for");
}

/// The same refusal on the SWEEP leg — the drive a crashed or re-presented
/// claim takes — before the remote is read or anything is pushed.
#[test]
fn an_export_of_a_candidate_written_after_the_commit_is_refused_on_the_sweep_leg() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = bare_origin(dir.path(), &repo);
    commit_and_read_sha(&fx, &repo);
    write_after_commit(&fx, "after.txt", "written after the commit\n");

    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let (export_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the sweep settles the refusal");
    assert_eq!(attempt_state(&fx, export_attempt), "failed");
    let payload = latest_payload(&fx, export_attempt);
    assert!(
        payload.contains("forge_export_uncommitted_candidate"),
        "the typed refusal reached the transition: {payload}"
    );
    assert_eq!(remote_refs(&origin), "", "nothing was pushed");
    assert_eq!(forge.call_count(), 0, "no pull request was asked for");
}

// -- the export's base and remote come from the run, not the pack (T2/T3) -------

/// A fake `gh` at `<dir>/bin/gh` that logs every argv to `<dir>/gh.log` as one
/// `|`-joined line (a newline inside an argument, as the pull request body's
/// marker line brings, logged as a space), answers `pr list` with no pull
/// request, `pr create` with a URL and `repo view <HOST/OWNER/REPO>` with that
/// repository — the forge the cells read back, outside kata.
fn fake_gh(dir: &Path, repo: &Path) -> Arc<dyn kata_effects_contract::Forge> {
    use std::os::unix::fs::PermissionsExt as _;
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let gh = bin.join("gh");
    std::fs::write(
        &gh,
        format!(
            "#!/bin/sh\nprintf '%s|' \"$@\" | tr '\\n' ' ' >> {d}/gh.log; printf '\\n' >> {d}/gh.log\n\
             case \"$1 $2\" in\n\
               'pr list') printf '[]\\n' ;;\n\
               'pr create') printf 'https://forge.test/o/r/pull/11\\n' ;;\n\
               'repo view') printf '{{\"nameWithOwner\":\"%s\"}}\\n' \"${{3#*/}}\" ;;\n\
             esac\n",
            d = dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    Arc::new(kata_vcs::GhCliForge::with_program(gh, repo))
}

fn gh_log(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("gh.log")).unwrap_or_default()
}

/// **A `master`-trunk repository's export opens its pull request into
/// `master`.** The run froze trunk `master` as its landable branch, so the
/// fake `gh`'s logged `pr create` argv carries `--base master` — no pack text
/// and no default names the base — and the bare remote holds the committed
/// commit at `kata/<exec>`.
#[test]
fn a_master_trunk_export_opens_its_pull_request_into_master() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_on_trunk(
        dir.path(),
        "forge_export",
        FixtureInvocation::FrozenTrunk,
        "master",
    );
    let repo = dir.path().join("repo");
    let origin = bare_origin(dir.path(), &repo);
    let commit_sha = commit_and_read_sha(&fx, &repo);
    let forge = fake_gh(dir.path(), &repo);
    let (export_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&forge),
        )
        .expect("the export drives");
    assert_eq!(attempt_state(&fx, export_attempt), "completed");
    let branch = format!("kata/{}", fx.execution_id);
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/{branch}")),
        Some(commit_sha)
    );
    let log = gh_log(dir.path());
    let create = log
        .lines()
        .find(|line| line.starts_with("pr|create|"))
        .unwrap_or_else(|| panic!("one `pr create` ran: {log}"));
    assert!(
        create.contains(&format!("|--base|master|--head|{branch}|")),
        "the pull request goes into the frozen trunk `master`: {create}"
    );
}

/// The push remote is INHERITED: with two remotes, `branch.main.remote` names
/// the one trunk tracks, and the export pushes there and nowhere else — read
/// off both bare remotes.
#[test]
fn an_export_pushes_to_the_remote_its_landable_branch_tracks() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = bare_origin(dir.path(), &repo);
    let upstream = forge_remote(dir.path(), &repo, "upstream");
    run_git(&repo, &["config", "branch.main.remote", "upstream"]);
    let commit_sha = commit_and_read_sha(&fx, &repo);
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let (export_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export drives");
    assert_eq!(attempt_state(&fx, export_attempt), "completed");
    assert_eq!(
        git_rev(&upstream, &format!("refs/heads/kata/{}", fx.execution_id)),
        Some(commit_sha),
        "pushed to the remote trunk tracks"
    );
    assert_eq!(remote_refs(&origin), "", "and to no other remote");
}

/// The push remote is git's PUSH remote for the landable branch, the one `git
/// push` on it would use: `branch.main.pushRemote`, else `remote.pushDefault`,
/// else `branch.main.remote`. A fork's shape — `upstream` tracked for fetch,
/// pushes to `origin` — pushes `kata/<exec>` to `origin` and leaves `upstream`
/// empty, read off both bare remotes; one shape per config key, the last with
/// no `branch.main.remote` at all beside two remotes.
#[test]
fn an_export_pushes_to_the_push_remote_git_names_for_its_landable_branch() {
    let shapes: [(&str, &[(&str, &str)]); 3] = [
        (
            "remote.pushDefault over branch.main.remote",
            &[
                ("branch.main.remote", "upstream"),
                ("remote.pushDefault", "origin"),
            ],
        ),
        (
            "branch.main.pushRemote over remote.pushDefault",
            &[
                ("branch.main.remote", "upstream"),
                ("remote.pushDefault", "upstream"),
                ("branch.main.pushRemote", "origin"),
            ],
        ),
        (
            "remote.pushDefault with no branch.main.remote",
            &[("remote.pushDefault", "origin")],
        ),
    ];
    for (shape, config) in shapes {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
        let repo = dir.path().join("repo");
        let origin = bare_origin(dir.path(), &repo);
        let upstream = forge_remote(dir.path(), &repo, "upstream");
        for (key, value) in config {
            run_git(&repo, &["config", key, value]);
        }
        let commit_sha = commit_and_read_sha(&fx, &repo);
        let forge = Arc::new(RecordingForge::succeeding_with_url(
            "https://forge.test/pull/9",
        ));
        let (export_attempt, _) =
            claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
        fx.dispatcher
            .drive_pending_workspace_effects(
                fx.execution_id,
                Some(&as_provider(&fx.backend)),
                Some(&(forge as Arc<dyn kata_effects_contract::Forge>)),
            )
            .expect("the export drives");
        assert_eq!(attempt_state(&fx, export_attempt), "completed", "{shape}");
        assert_eq!(
            git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
            Some(commit_sha),
            "{shape}: pushed to the remote `git push` on main pushes to"
        );
        assert_eq!(
            remote_refs(&upstream),
            "",
            "{shape}: and to no other remote"
        );
    }
}

/// `forge_remote_unresolved`, one cell per refused shape: no remote at all;
/// two remotes and no push remote named; `branch.main.remote` naming no
/// configured remote; `remote.pushDefault` naming none; and
/// `branch.main.pushRemote` a URL. Each refuses at the CLAIM's remote
/// resolution — the call `WorkflowRunner::submit_workspace_effect` makes
/// before it claims — so nothing is claimed: the repository holds no
/// `kata/<exec>`, every bare remote holds no ref, and the execution holds no
/// attempt row.
#[test]
fn an_export_with_no_single_inherited_remote_is_refused_and_pushes_nothing() {
    for shape in [
        "no remote",
        "two remotes",
        "unknown upstream",
        "unknown push default",
        "url push remote",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
        let repo = dir.path().join("repo");
        let mut remotes = Vec::new();
        if shape != "no remote" {
            remotes.push(bare_origin(dir.path(), &repo));
        }
        if shape == "two remotes" {
            let second = forge_remote(dir.path(), &repo, "second");
            remotes.push(second);
        }
        if shape == "unknown upstream" {
            run_git(&repo, &["config", "branch.main.remote", "gone"]);
        }
        if shape == "unknown push default" {
            // The push default wins over a tracked remote that does resolve.
            run_git(&repo, &["config", "branch.main.remote", "origin"]);
            run_git(&repo, &["config", "remote.pushDefault", "gone"]);
        }
        if shape == "url push remote" {
            run_git(&repo, &["config", "branch.main.remote", "origin"]);
            run_git(
                &repo,
                &[
                    "config",
                    "branch.main.pushRemote",
                    "https://forge.test/o/r.git",
                ],
            );
        }
        commit_and_read_sha(&fx, &repo);
        let attempts_before = attempt_count(&fx);
        let refusal = fx
            .dispatcher
            .forge_export_claim_remote(fx.execution_id, &as_provider(&fx.backend))
            .expect_err("no single remote is inherited");
        assert!(
            refusal.to_string().contains("forge_remote_unresolved"),
            "{shape}: the typed refusal: {refusal}"
        );
        assert_eq!(
            attempt_count(&fx),
            attempts_before,
            "{shape}: nothing claimed"
        );
        assert_eq!(
            git_rev(&repo, &format!("refs/heads/kata/{}", fx.execution_id)),
            None,
            "{shape}: no branch was written"
        );
        for remote in &remotes {
            assert_eq!(remote_refs(remote), "", "{shape}: nothing was pushed");
        }
    }
}

/// An export under an invocation that froze NO landable branch is refused
/// `target_not_landable` at the claim's remote resolution — admission refuses
/// such a program first, and the export never falls back to a default base.
#[test]
fn an_export_under_no_frozen_landable_branch_is_refused_and_pushes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::Opaque);
    let repo = dir.path().join("repo");
    let origin = bare_origin(dir.path(), &repo);
    commit_and_read_sha(&fx, &repo);
    let attempts_before = attempt_count(&fx);
    let refusal = fx
        .dispatcher
        .forge_export_claim_remote(fx.execution_id, &as_provider(&fx.backend))
        .expect_err("no landable branch is frozen");
    assert!(
        refusal.to_string().contains("target_not_landable"),
        "{refusal}"
    );
    assert_eq!(attempt_count(&fx), attempts_before, "nothing claimed");
    assert_eq!(remote_refs(&origin), "", "nothing was pushed");
}

/// Every attempt row of the fixture's execution, counted raw off the store.
fn attempt_count(fx: &Fixture) -> i64 {
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1",
        rusqlite::params![fx.execution_id.to_bytes().as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

/// A second bare remote `upstream` for `repo`, tracked by `branch.<trunk>`.
fn tracked_upstream(dir: &Path, repo: &Path, trunk: &str) -> std::path::PathBuf {
    let upstream = forge_remote(dir, repo, "upstream");
    run_git(
        repo,
        &["config", &format!("branch.{trunk}.remote"), "upstream"],
    );
    upstream
}

/// **The LIVE PERFORM leg opens a `master` trunk's pull request into `master`
/// through the remote `master` tracks.** The claim is performed directly —
/// `perform_workspace_effect`, the leg a fresh claim takes, never the sweep —
/// and the fake `gh`'s logged `pr create` argv carries `--base
/// master`; the branch lands on `upstream` (read off that bare remote) and
/// `origin` holds nothing.
#[test]
fn the_perform_leg_exports_a_master_trunk_into_master_through_its_tracked_remote() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_on_trunk(
        dir.path(),
        "forge_export",
        FixtureInvocation::FrozenTrunk,
        "master",
    );
    let repo = dir.path().join("repo");
    let origin = bare_origin(dir.path(), &repo);
    let upstream = tracked_upstream(dir.path(), &repo, "master");
    let commit_sha = commit_and_read_sha(&fx, &repo);
    let forge = fake_gh(dir.path(), &repo);
    let (export_attempt, spec) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    fx.dispatcher
        .perform_workspace_effect(
            fx.execution_id,
            export_attempt,
            "export",
            &spec,
            &as_provider(&fx.backend),
            Some(&forge),
        )
        .expect("the perform resolves");
    assert_eq!(
        attempt_state(&fx, export_attempt),
        "completed",
        "{}",
        latest_payload(&fx, export_attempt)
    );
    let branch = format!("kata/{}", fx.execution_id);
    assert_eq!(
        git_rev(&upstream, &format!("refs/heads/{branch}")),
        Some(commit_sha),
        "pushed to the remote `master` tracks"
    );
    assert_eq!(remote_refs(&origin), "", "and to no other remote");
    let log = gh_log(dir.path());
    let create = log
        .lines()
        .find(|line| line.starts_with("pr|create|"))
        .unwrap_or_else(|| panic!("one `pr create` ran: {log}"));
    assert!(
        create.contains(&format!("|--base|master|--head|{branch}|")),
        "the perform leg asks for the frozen trunk `master`: {create}"
    );
}

/// **Every leg pushes to the remote the CLAIM recorded.** The claim resolves
/// `upstream` (trunk tracks it); the host then re-points
/// `branch.main.remote` at `origin` before the export performs. The live
/// perform leg and the sweep (a second execution's claim, driven by the
/// sweep) each push to `upstream` only — read off both bare
/// remotes — and never to the remote the config names by then.
#[test]
fn an_export_pushes_to_the_claimed_remote_after_the_host_config_moves() {
    for leg in ["perform", "sweep"] {
        let dir = tempfile::tempdir().unwrap();
        let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
        let repo = dir.path().join("repo");
        let origin = bare_origin(dir.path(), &repo);
        let upstream = tracked_upstream(dir.path(), &repo, "main");
        let commit_sha = commit_and_read_sha(&fx, &repo);
        let forge = Arc::new(RecordingForge::succeeding_with_url(
            "https://forge.test/pull/9",
        ));
        let (export_attempt, spec) =
            claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
        assert_eq!(spec.forge_remote.as_deref(), Some("upstream"), "{leg}");
        run_git(&repo, &["config", "branch.main.remote", "origin"]);
        let forge_dyn = forge.clone() as Arc<dyn kata_effects_contract::Forge>;
        if leg == "perform" {
            fx.dispatcher
                .perform_workspace_effect(
                    fx.execution_id,
                    export_attempt,
                    "export",
                    &spec,
                    &as_provider(&fx.backend),
                    Some(&forge_dyn),
                )
                .expect("the perform resolves");
        } else {
            fx.dispatcher
                .drive_pending_workspace_effects(
                    fx.execution_id,
                    Some(&as_provider(&fx.backend)),
                    Some(&forge_dyn),
                )
                .expect("the sweep resolves");
        }
        assert_eq!(attempt_state(&fx, export_attempt), "completed", "{leg}");
        assert_eq!(
            git_rev(&upstream, &format!("refs/heads/kata/{}", fx.execution_id)),
            Some(commit_sha),
            "{leg}: pushed to the claimed remote"
        );
        assert_eq!(
            remote_refs(&origin),
            "",
            "{leg}: never to the remote the config names now"
        );
        assert_eq!(forge.call_count(), 1, "{leg}: one PR");
    }
}

/// **`commit → shell(rw) → promote → forge_export` exports what the promote
/// LANDED.** The writable stage moved the candidate after the commit, the
/// promote landed that candidate on trunk, and the export of the same commit
/// is not an edit no boundary recorded: the promote recorded it. The bare
/// remote's `kata/<exec>` is trunk's new tip, read off git.
#[test]
fn an_export_of_the_commit_a_promote_landed_after_a_writable_stage_pushes_it() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = bare_origin(dir.path(), &repo);
    let commit_sha = commit_and_read_sha(&fx, &repo);
    let candidate = write_after_commit(&fx, "after.txt", "written after the commit\n");
    assert_ne!(candidate, commit_sha);

    let (promote_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::Promote, None, "promote", vec![7]);
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the promote drives");
    assert_eq!(attempt_state(&fx, promote_attempt), "completed");
    let landed = git_rev(&repo, "main").expect("trunk names a commit");
    assert_eq!(
        landed, candidate,
        "the promote landed the written candidate"
    );

    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let (export_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export drives");
    assert_eq!(
        attempt_state(&fx, export_attempt),
        "completed",
        "{}",
        latest_payload(&fx, export_attempt)
    );
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
        Some(landed),
        "the remote's kata/<exec> IS the commit the promote landed"
    );
    assert_eq!(forge.call_count(), 1, "one PR opened");
}

// -- a read-only stage between `commit` and `forge_export` (T5) ---------------

/// The fixture environment a capsule declaration names.
const RO_ENVIRONMENT_ID: [u8; 32] = [0x03; 32];

fn declare_ro_environment(planes: &Planes) {
    if planes.db.environment(RO_ENVIRONMENT_ID).unwrap().is_some() {
        return;
    }
    let manifest = planes
        .cas
        .put_durable(b"workspace-effect-fixture-environment-manifest")
        .unwrap();
    planes
        .db
        .declare_environment(
            &kata_core::operational::EnvironmentDeclaration::for_staged_root(
                RO_ENVIRONMENT_ID,
                &manifest,
                [0x5C; 32],
                "workspace-effect-fixture",
                [0x04; 32],
                "01JZZZZZZZZZZZZZZZZZZZZZE1",
            )
            .unwrap(),
        )
        .unwrap();
}

/// The `/work` tree artifact the head row maps, as a reference.
fn head_work_ref(fx: &Fixture) -> kata_types::execution_contract::ArtifactRef {
    let head = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .expect("the head row");
    let row = fx
        .planes
        .db
        .artifact(head.work_tree_artifact_id)
        .unwrap()
        .expect("the head's artifact row exists");
    kata_types::execution_contract::ArtifactRef::new(
        kata_types::primitives::ObjectId::new(row.object_id),
        row.size_bytes,
        row.privacy,
    )
}

/// The read-only stage `look`'s completion, the way the reactor takes it: its
/// capsule attempt is claimed and dispatched, the scope judge reads the EMPTY
/// delta a stage that writes nothing reports, and the completion is adopted
/// and accepted carrying it. Returns whether the judge settled the attempt.
fn complete_read_only_stage(fx: &Fixture) -> bool {
    use kata_types::execution_contract as ec;
    declare_ro_environment(&fx.planes);
    let stage_id = kata_types::workflow::StageId(smol_str::SmolStr::new("look"));
    let lowered = kata_program::execution_program::lower_stage_operation(&fx.program, &stage_id)
        .expect("the look stage lowers");
    let occurrence = OccurrenceRef::new(
        kata_types::workflow::ExecutionId(fx.execution_id),
        fx.program.program_hash,
        lowered.contract.id(),
        lowered.path.clone(),
    );
    let work = head_work_ref(fx);
    let capsule = ec::Capsule::new(
        occurrence.id(),
        ec::PreparedActionId(kata_types::primitives::ContentHash::new([0x02; 32])),
        ec::EnvironmentId(kata_types::primitives::ContentHash::new(RO_ENVIRONMENT_ID)),
        ec::PlatformId(kata_types::primitives::ContentHash::new([0x04; 32])),
        vec![ec::GuestMapping {
            artifact: work.id(),
            guest_path: ec::GuestPath::new("/work").unwrap(),
            access: ec::GuestAccess::ReadWrite,
        }],
        ec::CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "cat /work/a.txt".into()],
        },
        ec::CapsuleNetwork::Offline,
        None,
        ec::CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 1 << 20,
            result_entries: 16,
            work_delta_bytes: ec::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: ec::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap();
    let bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = fx.planes.cas.put_durable(&bytes).unwrap();
    fx.planes
        .db
        .declare_capsule(
            &kata_core::operational::CapsuleDeclaration::for_durable_object(
                &capsule, &bytes, &durable,
            )
            .unwrap(),
        )
        .unwrap();
    let attempt_id = Ulid::new();
    let claimed = fx
        .planes
        .db
        .claim_attempt(
            fx.execution_id,
            attempt_id,
            &kata_core::operational::AttemptClaimSpec {
                stage_id: "look".to_string(),
                assignment_json: b"{\"capsule\":{}}".to_vec(),
                initial_state: "pending".to_string(),
                run_ordinal: 0,
                worker_id: None,
                occurrence: OccurrenceBinding::new(
                    occurrence.clone(),
                    Some(capsule.action()),
                    Some(capsule.id()),
                )
                .with_work_tree(work.id().0.0),
            },
        )
        .unwrap();
    fx.planes
        .db
        .dispatch_claimed_attempt(
            attempt_id,
            "w-1",
            Ulid::new(),
            &kata_core::operational::CommandSpec {
                command_json: br#"{"kind":"capsule"}"#.to_vec(),
            },
        )
        .unwrap();
    fx.planes
        .db
        .record_main_side_transition(
            attempt_id,
            &kata_core::operational::MainSideTransition {
                worker_id: Some("w-1"),
                ..kata_core::operational::MainSideTransition::bare("running")
            },
        )
        .unwrap();
    // The EMPTY delta a stage that writes nothing reports against its `/work`.
    let empty = kata_types::tree_delta::TreeDelta::new(work.clone(), Vec::new()).unwrap();
    let delta_bytes = empty.delta_bytes().unwrap();
    let delta_durable = fx.planes.cas.put_durable(&delta_bytes).unwrap();
    fx.planes
        .db
        .declare_artifact(
            &kata_core::operational::ArtifactDeclaration::for_durable_delta(
                &empty,
                ec::ArtifactPrivacy::Private,
                kata_core::operational::CasRootOwner::Execution(fx.execution_id),
                &delta_durable,
            )
            .unwrap(),
        )
        .unwrap();
    let delta_ref = ec::ArtifactRef::new(
        delta_durable.object_id(),
        delta_durable.size(),
        ec::ArtifactPrivacy::Private,
    );
    let recovered = fx.planes.db.recovered_attempt(attempt_id).unwrap().unwrap();
    let settled = fx
        .dispatcher
        .judge_work_delta_scope(&recovered, occurrence.id(), Some(&delta_ref), None)
        .expect("the judge runs");
    if settled {
        return true;
    }
    let attempt = fx.planes.db.attempt(attempt_id).unwrap().unwrap();
    let capture = |bytes: &[u8]| {
        let receipt = fx.planes.cas.put_durable(bytes).unwrap();
        ec::ArtifactRef::new(
            receipt.object_id(),
            receipt.size(),
            ec::ArtifactPrivacy::Private,
        )
    };
    let member = fx.planes.cas.put_durable(b"result\n").unwrap();
    let manifest =
        kata_types::tree_artifact::TreeManifest::new(vec![kata_types::tree_artifact::TreeEntry {
            path: kata_types::tree_artifact::TreePath::new("r").unwrap(),
            node: kata_types::tree_artifact::TreeNode::File {
                mode: kata_types::tree_artifact::TreeEntryMode::Regular,
                object: member.object_id(),
                size_bytes: member.size(),
            },
        }])
        .unwrap();
    let result = capture(&manifest.manifest_bytes().unwrap());
    let stdout = capture(b"committed\n");
    let stderr = capture(b"");
    fx.planes
        .db
        .adopt_and_accept_capsule_completion(
            &kata_core::operational::CapsuleResultAdoption {
                execution_id: fx.execution_id,
                occurrence_id: occurrence.id(),
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(delta_ref),
                capture_exceeded: false,
                agent: None,
                egress_refusals: vec![],
            },
            |adopted| kata_core::operational::WorkerCompletionInput {
                execution_id: fx.execution_id,
                attempt_id,
                attempt_ordinal: claimed.attempt_ordinal,
                lease_epoch: attempt.lease_epoch,
                worker_id: "w-1".to_string(),
                output: kata_core::operational::capsule_result_output(
                    adopted,
                    &result,
                    Some(0),
                    &stdout,
                    &stderr,
                    false,
                    None,
                ),
            },
        )
        .unwrap();
    false
}

/// **`commit → shell(ro) → forge_export` pushes the COMMITTED commit.** The
/// read-only stage `look` runs its completion path between the commit and the
/// export — claimed, judged in scope on the empty delta it reports, adopted,
/// accepted, and its apply driven — and the head row's candidate (read raw off
/// the store) is the one the commit left. The export is not refused
/// `forge_export_uncommitted_candidate`: the bare remote's `kata/<exec>` is the
/// commit envelope's `commit_sha`, read off git.
#[test]
fn a_read_only_stage_between_commit_and_export_leaves_the_committed_commit_to_push() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(
        dir.path(),
        "forge_export_after_ro",
        FixtureInvocation::FrozenTrunk,
    );
    let repo = dir.path().join("repo");
    let origin = bare_origin(dir.path(), &repo);
    let commit_sha = commit_and_read_sha(&fx, &repo);
    let candidate_of = |fx: &Fixture| -> String {
        let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
        conn.query_row(
            "SELECT candidate_commit_id FROM execution_work_tree_heads \
             WHERE execution_id = ?1 AND branch = ''",
            rusqlite::params![fx.execution_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
    };
    let candidate_after_commit = candidate_of(&fx);

    assert!(
        !complete_read_only_stage(&fx),
        "the read-only stage's empty delta is in scope"
    );
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            Some(fx.backend.as_ref()),
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the apply drive runs");
    assert!(
        fx.planes
            .db
            .pending_work_applies(fx.execution_id)
            .unwrap()
            .is_empty(),
        "the read-only stage owes no apply"
    );
    assert_eq!(
        candidate_of(&fx),
        candidate_after_commit,
        "the read-only stage moved no candidate"
    );

    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let (export_attempt, spec) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    assert_eq!(
        spec.delivered_commit, commit_sha,
        "the claim delivers the commit"
    );
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export drives");
    assert_eq!(
        attempt_state(&fx, export_attempt),
        "completed",
        "{}",
        latest_payload(&fx, export_attempt)
    );
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
        Some(commit_sha),
        "the remote's kata/<exec> IS the committed commit"
    );
    assert_eq!(forge.call_count(), 1, "one PR opened");
}

// -- a data directory whose export rows name a pack remote/base (T2/T3) -------

/// The last operational stamp whose `forge_export` attempt specs and frozen
/// program directives could name a pack-written `remote`/`base` — a fact about
/// directories already on disk, so it is spelled, never derived.
const LAST_STAMP_WITH_PACK_REMOTE_AND_BASE: i64 = 40;

/// **A directory stamped where export specs named `remote`/`base` is refused
/// at OPEN, before any reader decodes one.** A claimed export's recorded spec
/// is rewritten (raw SQL) to the shape that stamp wrote — `forge: {remote,
/// base}` — and the file is stamped back to that version. Reopening refuses it
/// `SchemaMigrationRequired` with the new-data-directory recourse; a build that
/// opened it would fail the execution's sweep, gate listing and
/// terminalization on the spec decode instead.
#[test]
fn a_directory_whose_export_specs_name_a_remote_and_base_is_refused_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    bare_origin(dir.path(), &repo);
    commit_and_read_sha(&fx, &repo);
    let (export_attempt, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    let op_path = fx.planes.op_path.clone();
    {
        let conn = rusqlite::Connection::open(&op_path).unwrap();
        let blob: Vec<u8> = conn
            .query_row(
                "SELECT assignment_json FROM attempts WHERE attempt_id = ?1",
                rusqlite::params![export_attempt.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let mut frame: serde_json::Value = serde_json::from_slice(&blob).unwrap();
        let spec = &mut frame["main"]["spec"];
        spec["forge"] = serde_json::json!({"remote": "origin", "base": "main"});
        spec.as_object_mut().unwrap().remove("forge_remote");
        conn.execute(
            "UPDATE attempts SET assignment_json = ?1 WHERE attempt_id = ?2",
            rusqlite::params![
                serde_json::to_vec(&frame).unwrap(),
                export_attempt.to_bytes().as_slice()
            ],
        )
        .unwrap();
    }
    fx.planes
        .db
        .debug_stamp_user_version(LAST_STAMP_WITH_PACK_REMOTE_AND_BASE)
        .unwrap();
    drop(fx);
    let error = OperationalDb::open(&op_path)
        .expect_err("a directory whose export specs name a remote and base is refused");
    assert!(
        matches!(error, KataError::SchemaMigrationRequired(_)),
        "refused at open, never read: {error:?}"
    );
    assert!(
        error
            .to_string()
            .contains("use a new empty data directory and preserve this directory offline"),
        "{error}"
    );
}

// -- the promote reconcile judges the FROZEN trunk -----------------------------

/// Move the host's trunk ANSWER off the trunk the execution froze: a remote
/// whose `HEAD` names `master` (what `git clone` writes, and what
/// `git remote set-head` rewrites when the forge's default branch changes),
/// with `master` a local branch at `at`. `main` is untouched. Asserted through
/// the resolver another run would use, so the cell cannot pass on a move that
/// did not happen.
fn move_host_trunk_to_master(dir: &Path, repo: &Path, at: &str) {
    run_git(repo, &["branch", "master", at]);
    let origin = bare_origin(dir, repo);
    run_git(repo, &["push", "-q", "origin", "main", "master"]);
    run_git(repo, &["fetch", "-q", "origin"]);
    run_git(repo, &["remote", "set-head", "origin", "master"]);
    assert!(origin.is_dir());
    let moved = JjBackend::open(repo).expect("reopen the backend");
    let answer = kata_vcs::test_support::resolve_trunk_target(
        &moved,
        &ExecutionWorkspaceKey::execution(Ulid::new()),
    )
    .expect("another run resolves the host's trunk now");
    assert_eq!(
        answer.branch.as_deref(),
        Some("master"),
        "the host's trunk answer moved to master"
    );
}

/// The attempt's projected state, read through a SECOND, read-only handle.
fn attempt_state_read_only(op_path: &Path, attempt_id: Ulid) -> String {
    let conn =
        rusqlite::Connection::open_with_flags(op_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    conn.query_row(
        "SELECT state FROM attempt_projection p
           JOIN attempts a ON a.execution_id = p.execution_id
            AND a.stage_id = p.stage_id AND a.attempt_ordinal = p.attempt_ordinal
          WHERE a.attempt_id = ?1",
        rusqlite::params![attempt_id.to_bytes().as_slice()],
        |row| row.get::<_, String>(0),
    )
    .unwrap()
}

/// The resolving envelope's content, read through a read-only handle.
fn resolved_content_read_only(op_path: &Path, attempt_id: Ulid) -> serde_json::Value {
    let conn =
        rusqlite::Connection::open_with_flags(op_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let payload: Vec<u8> = conn
        .query_row(
            "SELECT payload_json FROM transitions WHERE attempt_id = ?1
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the resolving transition's payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    serde_json::from_str(
        payload["output"]["content"]
            .as_str()
            .unwrap_or_else(|| panic!("the resolution carries no output: {payload}")),
    )
    .expect("the envelope decodes")
}

/// **The fourth T2 site, on the sweep leg.** The execution froze trunk `main`;
/// the armed child lands the promote on `main`, tears the workspace down and
/// dies before the resolve. Between the crash and the recovery the host's
/// trunk answer moves to `master` (its remote's `HEAD`). The recovery classify
/// judges the FROZEN `main` — which holds the delivered commit — so the attempt
/// resolves `completed` naming `main`. Judged against the live answer it would
/// find `master` without the commit and a torn-down workspace, and record a
/// landed promote `failed` as a foreign teardown.
///
/// From outside the classifier: `main` and `master` read back from git (`main`
/// is the delivered commit, `master` never moved), and the attempt's state and
/// envelope through a second read-only handle on `operational.db`.
#[test]
fn crash_after_promote_lands_then_the_host_trunk_moves_recovers_on_the_frozen_trunk() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let repo = dir.path().join("repo");
    let seed = git_rev(&repo, "main").expect("the seed trunk");
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_workspace_effect_jj_publish_before_resolution",
        dir.path(),
        "crash_after_promote_lands_then_the_host_trunk_moves_recovers_on_the_frozen_trunk",
    );
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.delivered_commit.as_str()),
        "the child landed the promote on the frozen main"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    move_host_trunk_to_master(dir.path(), &repo, &seed);

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");

    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed",
        "the landed promote is recorded landed"
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(content["ref_moved"].as_str(), Some("main"), "{content}");
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.delivered_commit.as_str()),
        "main still names the delivered commit"
    );
    assert_eq!(
        git_rev(&repo, "master").as_deref(),
        Some(seed.as_str()),
        "nothing landed on master"
    );
}

/// **The fourth T2 site, on the perform leg.** The perform's reconcile-first
/// classify asks the same question the sweep does, with the same frozen
/// branch: a promote that already landed on the frozen `main` is answered
/// `Promoted` off `main` after the host's trunk answer moved to `master` —
/// never re-driven toward `master`, never refused. Read back as the sweep
/// cell reads it.
#[test]
fn a_perform_after_the_host_trunk_moves_classifies_the_landed_promote_on_the_frozen_trunk() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let (first, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let repo = dir.path().join("repo");
    let seed = git_rev(&repo, "main").expect("the seed trunk");
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the first promote lands");
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, first),
        "completed"
    );
    move_host_trunk_to_master(dir.path(), &repo, &seed);

    let (second, spec) = claim_effect_at(&fx, spec.clone(), "ship2", vec![7]);
    let moved: Arc<dyn ExecutionWorkspaceProvider> =
        Arc::new(JjBackend::open(&repo).expect("reopen the backend"));
    fx.dispatcher
        .perform_workspace_effect(fx.execution_id, second, "ship2", &spec, &moved, None)
        .expect("the perform settles");

    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, second),
        "completed",
        "the landed promote is answered off the frozen trunk"
    );
    let content = resolved_content_read_only(&fx.planes.op_path, second);
    assert_eq!(content["ref_moved"].as_str(), Some("main"), "{content}");
    assert_eq!(
        git_rev(&repo, "master").as_deref(),
        Some(seed.as_str()),
        "nothing landed on master"
    );
}

// -- the in-verb crash windows --------------------------------------------------
// `KATA_WORKSPACE_EFFECT_CRASH_ARM` names windows INSIDE one kata-vcs verb call
// (`workspace_effect_crash_point`), where no dispatcher line can sit; the
// `operational.*` boundary above fires only after the verb returned, its
// teardown included.

/// Spawn the child armed at the in-verb `arm`, assert it died there, and return
/// the parent's unarmed fixture.
fn crash_inside_the_verb_then_recover(arm: &str, dir: &Path, test: &str) -> Fixture {
    crash_then_recover_armed(
        &[("KATA_WORKSPACE_EFFECT_CRASH_ARM", arm.to_owned())],
        dir,
        test,
    )
    .0
}

/// The execution workspace's directory, spelled from the repository layout
/// (`<repo>/agents/<exec-id>`), not asked of the provider.
fn execution_workspace_dir(repo: &Path, execution_id: Ulid) -> std::path::PathBuf {
    repo.join("agents").join(execution_id.to_string())
}

/// The repository's jj workspace names as the `jj` CLI lists them — a reader
/// that shares no code with kata's provider. `--ignore-working-copy` keeps the
/// read from snapshotting, and so writing, the root working copy; an empty
/// `JJ_CONFIG` keeps the host's jj config out of it.
fn jj_cli_workspace_names(dir: &Path, repo: &Path) -> Vec<String> {
    let config = dir.join("jj-cli-config.toml");
    std::fs::write(&config, "").unwrap();
    let out = std::process::Command::new("jj")
        .args([
            "--ignore-working-copy",
            "--no-pager",
            "--color",
            "never",
            "-R",
        ])
        .arg(repo)
        .args(["workspace", "list", "-T", "name ++ \"\\n\""])
        .env("JJ_CONFIG", &config)
        .output()
        .expect("the jj CLI runs (the dev shell provides it)");
    assert!(
        out.status.success(),
        "jj workspace list: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// What a `park`'s or `promote`'s teardown leaves after the recovery: no workspace
/// directory on disk, only jj's `default` workspace in the CLI's list, and no
/// workspace through the provider.
fn assert_the_execution_workspace_is_gone(fx: &Fixture, dir: &Path) {
    let repo = dir.join("repo");
    assert!(
        !execution_workspace_dir(&repo, fx.execution_id).exists(),
        "the workspace directory is removed"
    );
    assert_eq!(
        jj_cli_workspace_names(dir, &repo),
        vec!["default".to_owned()],
        "jj lists no execution workspace"
    );
    assert!(
        ExecutionWorkspaceProvider::lookup_workspace(
            fx.backend.as_ref(),
            &ExecutionWorkspaceKey::execution(fx.execution_id)
        )
        .unwrap()
        .is_none(),
        "the provider finds no workspace"
    );
}

/// The promote's in-verb window after the land: the child lands the delivered
/// commit on the frozen `main` and dies BEFORE its `remove_workspace` — the
/// workspace directory and jj's record of it still stand (both read before the
/// recovery). The recovery drive is the SWEEP leg (`drive_one_workspace_effect`):
/// it classifies `Promoted` off the frozen trunk and owes the teardown the dead
/// child never ran, exactly as its `Parked` arm does — the attempt resolves
/// `completed` (a second read-only handle) AND the workspace is gone (the
/// filesystem, the `jj` CLI, the provider).
#[test]
fn crash_after_promote_lands_before_teardown_recovers_and_tears_the_workspace_down() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let fx = crash_inside_the_verb_then_recover(
        "after_jj_publish_before_teardown",
        dir.path(),
        "crash_after_promote_lands_before_teardown_recovers_and_tears_the_workspace_down",
    );
    let repo = dir.path().join("repo");
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.delivered_commit.as_str()),
        "the child landed the promote on the frozen main"
    );
    assert!(
        execution_workspace_dir(&repo, fx.execution_id).is_dir(),
        "the child died before its teardown: the workspace directory stands"
    );
    assert!(
        jj_cli_workspace_names(dir.path(), &repo).contains(&format!("agent-{}", fx.execution_id)),
        "jj still lists the execution workspace"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");

    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed",
        "the landed promote is recorded landed"
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(content["ref_moved"].as_str(), Some("main"), "{content}");
    assert_the_execution_workspace_is_gone(&fx, dir.path());
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.delivered_commit.as_str()),
        "the recovery landed nothing further"
    );
}

/// The same in-verb window, recovered through the PERFORM leg's
/// reconcile-first classify (`perform_workspace_effect`, the door the runner's
/// fresh claim and the approval decision take): `Promoted` off the frozen
/// trunk owes the same teardown, so the attempt resolves `completed` and the
/// workspace is gone — read as the sweep cell reads it.
#[test]
fn crash_after_promote_lands_before_teardown_the_perform_leg_tears_the_workspace_down() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let fx = crash_inside_the_verb_then_recover(
        "after_jj_publish_before_teardown",
        dir.path(),
        "crash_after_promote_lands_before_teardown_the_perform_leg_tears_the_workspace_down",
    );
    let repo = dir.path().join("repo");
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.delivered_commit.as_str()),
        "the child landed the promote on the frozen main"
    );
    assert!(
        execution_workspace_dir(&repo, fx.execution_id).is_dir(),
        "the child died before its teardown: the workspace directory stands"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );

    fx.dispatcher
        .perform_workspace_effect(
            fx.execution_id,
            attempt_id,
            STAGE,
            &spec,
            &as_provider(&fx.backend),
            None,
        )
        .expect("the perform settles");

    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed",
        "the landed promote is answered off the frozen trunk"
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(content["ref_moved"].as_str(), Some("main"), "{content}");
    assert_the_execution_workspace_is_gone(&fx, dir.path());
}

/// **Before the push's intent** (`after_forge_read_before_push_intent`): the
/// child wrote the local `kata/<exec>` and read the remote's head, and died
/// before the intent committed. No intent row (a second read-only handle) and
/// nothing on the remote (git): the export was never issued, so the recovery
/// performs it from the start — one push landed (the remote's own
/// `post-receive` log), one pull request — and the workspace still stands,
/// because no `forge_export` leg owns its removal.
///
/// **Would red if:** the intent committed after the push (the remote would
/// hold the branch at the crash, issued with no intent).
#[test]
fn crash_after_forge_read_before_push_intent_records_no_intent_and_pushes_once() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = counted_origin(dir.path(), &repo);
    let (attempt_id, spec) = claim_export(&fx);
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_read_before_push_intent",
        dir.path(),
        "crash_after_forge_read_before_push_intent_records_no_intent_and_pushes_once",
    );
    let branch = format!("kata/{}", fx.execution_id);
    assert_eq!(
        git_rev(&repo, &format!("refs/heads/{branch}")),
        Some(spec.delivered_commit.clone()),
        "the child wrote the local branch"
    );
    assert_eq!(remote_refs(&origin), "", "the child died before the push");
    assert!(
        intents_read_only(&fx.planes.op_path, attempt_id).is_empty(),
        "no intent was recorded"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/77",
    ));
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the recovery drive performs the export");
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    assert_eq!(
        remote_refs(&origin),
        format!("{} refs/heads/{branch}\n", spec.delivered_commit),
        "the remote holds exactly the exported branch"
    );
    assert_eq!(pushes(dir.path()).len(), 1, "one push landed");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "performed", "receipt"),
        ]
    );
    assert_eq!(forge.call_count(), 1, "one PR, opened by the recovery leg");
    assert!(
        execution_workspace_dir(&repo, fx.execution_id).is_dir(),
        "forge_export never tears the workspace down"
    );
}

/// `park`'s in-verb window: the child writes `parked/<exec-id>` and dies BEFORE
/// its `remove_workspace`, so the workspace stands (read before the recovery).
/// The SWEEP's `Parked` arm owes the teardown: the attempt resolves `completed`
/// and the workspace is gone. The `operational.*` park cells cannot reach this
/// state — their child dies after the verb's own teardown already ran.
#[test]
fn crash_after_park_ref_write_before_teardown_recovers_and_tears_the_workspace_down() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let fx = crash_inside_the_verb_then_recover(
        "after_jj_publish_before_teardown",
        dir.path(),
        "crash_after_park_ref_write_before_teardown_recovers_and_tears_the_workspace_down",
    );
    let repo = dir.path().join("repo");
    let ref_name = format!("parked/{}", fx.execution_id);
    assert_eq!(
        git_rev(&repo, &ref_name),
        Some(spec.candidate_commit.clone()),
        "the child wrote the parked ref"
    );
    assert!(
        execution_workspace_dir(&repo, fx.execution_id).is_dir(),
        "the child died before its teardown: the workspace directory stands"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");

    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    assert_the_execution_workspace_is_gone(&fx, dir.path());
    assert_eq!(
        git_rev(&repo, &ref_name),
        Some(spec.candidate_commit.clone()),
        "the parked ref still names the candidate"
    );
}

/// The park window recovered through the PERFORM leg's reconcile-first read
/// (the parked ref already at the candidate): it owes the same teardown as the
/// sweep's `Parked` arm, and writes the ref no second time.
///
/// **Would red if:** the perform skipped its reconcile-first arm and parked
/// again (two writes of `parked/<exec>` in jj's operation log).
#[test]
fn crash_after_park_ref_write_before_teardown_the_perform_leg_tears_the_workspace_down() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let fx = crash_inside_the_verb_then_recover(
        "after_jj_publish_before_teardown",
        dir.path(),
        "crash_after_park_ref_write_before_teardown_the_perform_leg_tears_the_workspace_down",
    );
    let repo = dir.path().join("repo");
    // Without the ref the perform would run a fresh park, never reaching the
    // reconcile-first arm this cell names.
    assert_eq!(
        git_rev(&repo, &format!("parked/{}", fx.execution_id)),
        Some(spec.candidate_commit.clone()),
        "the child wrote the parked ref"
    );
    assert!(
        execution_workspace_dir(&repo, fx.execution_id).is_dir(),
        "the child died before its teardown: the workspace directory stands"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    fx.dispatcher
        .perform_workspace_effect(
            fx.execution_id,
            attempt_id,
            STAGE,
            &spec,
            &as_provider(&fx.backend),
            None,
        )
        .expect("the perform settles");
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    assert_the_execution_workspace_is_gone(&fx, dir.path());
    assert_eq!(
        jj_cli_parked_ref_writes(dir.path(), &repo, fx.execution_id),
        1,
        "the perform resolved off the child's write and never parked again"
    );
}

/// How many jj operations wrote `parked/<execution_id>`, counted off the `jj`
/// CLI's operation log — a reader that shares no code with kata's provider.
/// `--ignore-working-copy` keeps the read from snapshotting, and so writing, the
/// root working copy; an empty `JJ_CONFIG` keeps the host's jj config out of it.
fn jj_cli_parked_ref_writes(dir: &Path, repo: &Path, execution_id: Ulid) -> usize {
    let config = dir.join("jj-cli-config.toml");
    std::fs::write(&config, "").unwrap();
    let out = std::process::Command::new("jj")
        .args([
            "--ignore-working-copy",
            "--no-pager",
            "--color",
            "never",
            "-R",
        ])
        .arg(repo)
        .args(["op", "log", "--no-graph", "-T", "description ++ \"\\n\""])
        .env("JJ_CONFIG", &config)
        .output()
        .expect("the jj CLI runs (the dev shell provides it)");
    assert!(
        out.status.success(),
        "jj op log: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let wrote = format!("kata set bookmark parked/{execution_id}");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|line| *line == wrote)
        .count()
}

/// The park window of [`crash_after_park_ref_write_before_teardown_recovers_and_tears_the_workspace_down`]
/// AFTER a `commit`: the park delivers the COMMITTED commit, not its candidate
/// (the commit's empty child), so the ref the child wrote names a commit the
/// recorded candidate is not. Commit and park run in the parent and the child,
/// the ref is read off git before the recovery, and the SWEEP
/// (`classify_park_effect`) answers it `Parked`: the attempt resolves
/// `completed` and the workspace is gone.
///
/// **Would red if:** the classify compared the ref with the recorded candidate
/// (the ref is then a foreign move and the park is recorded `failed`).
#[test]
fn crash_after_a_commit_then_park_writes_its_ref_the_sweep_recovers_it_parked() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let repo = dir.path().join("repo");
    let commit_sha = commit_and_read_sha(&fx, &repo);
    let (attempt_id, spec) = claim_follow_on(&fx, WorkspaceEffectOp::Park, None, "park", vec![7]);
    assert_ne!(
        spec.candidate_commit, commit_sha,
        "the candidate is the commit's empty child, not the committed commit"
    );
    drop(fx);
    let fx = crash_inside_the_verb_then_recover(
        "after_jj_publish_before_teardown",
        dir.path(),
        "crash_after_a_commit_then_park_writes_its_ref_the_sweep_recovers_it_parked",
    );
    let ref_name = format!("parked/{}", fx.execution_id);
    assert_eq!(
        git_rev(&repo, &ref_name),
        Some(commit_sha.clone()),
        "the child wrote the parked ref at the committed commit"
    );
    assert!(
        execution_workspace_dir(&repo, fx.execution_id).is_dir(),
        "the child died before its teardown: the workspace directory stands"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");

    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(
        content["commit_sha"].as_str(),
        Some(commit_sha.as_str()),
        "{content}"
    );
    assert_the_execution_workspace_is_gone(&fx, dir.path());
    assert_eq!(
        git_rev(&repo, &ref_name),
        Some(commit_sha),
        "the parked ref still names the committed commit"
    );
    assert_eq!(
        jj_cli_parked_ref_writes(dir.path(), &repo, fx.execution_id),
        1,
        "the sweep resolved off the child's write and never wrote the ref again"
    );
}

/// [`crash_after_a_commit_then_park_writes_its_ref_the_sweep_recovers_it_parked`]'s
/// window recovered through the PERFORM leg's reconcile-first read: the parked
/// ref already at the delivered commit is this park's own performance, so it
/// resolves `completed` off that ref and owes the teardown.
///
/// **Would red if:** the reconcile-first read compared the ref with the
/// candidate: the perform then runs the park a second time, which writes
/// `parked/<exec>` again — two writes in jj's operation log, not one.
#[test]
fn crash_after_a_commit_then_park_writes_its_ref_the_perform_leg_recovers_it_parked() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "park");
    let repo = dir.path().join("repo");
    let commit_sha = commit_and_read_sha(&fx, &repo);
    let (attempt_id, spec) = claim_follow_on(&fx, WorkspaceEffectOp::Park, None, "park", vec![7]);
    assert_ne!(
        spec.candidate_commit, commit_sha,
        "the candidate is the commit's empty child, not the committed commit"
    );
    drop(fx);
    let fx = crash_inside_the_verb_then_recover(
        "after_jj_publish_before_teardown",
        dir.path(),
        "crash_after_a_commit_then_park_writes_its_ref_the_perform_leg_recovers_it_parked",
    );
    let ref_name = format!("parked/{}", fx.execution_id);
    // Without the ref the perform would run a fresh park, never reaching the
    // reconcile-first arm this cell names.
    assert_eq!(
        git_rev(&repo, &ref_name),
        Some(commit_sha.clone()),
        "the child wrote the parked ref at the committed commit"
    );
    assert!(
        execution_workspace_dir(&repo, fx.execution_id).is_dir(),
        "the child died before its teardown: the workspace directory stands"
    );
    assert_eq!(
        jj_cli_parked_ref_writes(dir.path(), &repo, fx.execution_id),
        1,
        "the child's park wrote the ref once"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    fx.dispatcher
        .perform_workspace_effect(
            fx.execution_id,
            attempt_id,
            "park",
            &spec,
            &as_provider(&fx.backend),
            None,
        )
        .expect("the perform settles");
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(
        content["commit_sha"].as_str(),
        Some(commit_sha.as_str()),
        "{content}"
    );
    assert_the_execution_workspace_is_gone(&fx, dir.path());
    assert_eq!(
        git_rev(&repo, &ref_name),
        Some(commit_sha),
        "the parked ref still names the committed commit"
    );
    assert_eq!(
        jj_cli_parked_ref_writes(dir.path(), &repo, fx.execution_id),
        1,
        "the recovery resolved off the child's write and never wrote the ref again"
    );
}

// -- the commit verb's pre-publish windows -------------------------------------

/// One `jj log` over `revset`, one `template` line per commit, through the jj
/// CLI with no working-copy snapshot and an empty config — the repository's
/// VISIBLE commits, the set an unpublished operation never reaches.
fn jj_cli_log(dir: &Path, repo: &Path, revset: &str, template: &str) -> Vec<String> {
    let config = dir.join("jj-cli-config.toml");
    std::fs::write(&config, "").unwrap();
    let out = std::process::Command::new("jj")
        .args([
            "--ignore-working-copy",
            "--no-pager",
            "--color",
            "never",
            "-R",
        ])
        .arg(repo)
        .args(["log", "--no-graph", "-r", revset, "-T"])
        .arg(format!("{template} ++ \"\\n\""))
        .env("JJ_CONFIG", &config)
        .output()
        .expect("the jj CLI runs (the dev shell provides it)");
    assert!(
        out.status.success(),
        "jj log -r {revset}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The root head row's `(candidate_commit_id, committed_commit_id)`, read
/// through a SECOND, read-only handle.
fn head_row_read_only(op_path: &Path, execution_id: Ulid) -> (String, String) {
    let conn =
        rusqlite::Connection::open_with_flags(op_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    conn.query_row(
        "SELECT candidate_commit_id, committed_commit_id FROM execution_work_tree_heads \
         WHERE execution_id = ?1 AND branch = ''",
        [execution_id.to_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .expect("the root head row")
}

/// The child crashes inside the `commit` verb at `arm`, before its operation is
/// published. Before the recovery: the attempt is `pending`, `exec-<exec-id>`
/// is absent (git), no visible commit carries the effect's description and the
/// workspace's `@` is still the recorded candidate (the jj CLI). The sweep
/// classifies `NotPerformed` and commits ONCE: exactly one visible commit
/// carries the description, it is `exec-<exec-id>` by git and the parent of
/// the workspace's empty `@`, the head row names that `@` and that commit (a
/// second read-only handle), and the workspace stands — `commit` never tears
/// it down.
fn crash_inside_the_commit_before_its_publish(arm: &str, test: &str) {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), "commit");
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Commit,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let repo = dir.path().join("repo");
    let seed = git_rev(&repo, "main").expect("the seed trunk");
    drop(fx);
    let fx = crash_inside_the_verb_then_recover(arm, dir.path(), test);
    let exec_ref = format!("exec-{}", fx.execution_id);
    let described = format!(
        "description(substring:\"kata workspace_effect commit for execution {}\")",
        fx.execution_id
    );
    let wc = format!("\"agent-{}\"@", fx.execution_id);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    assert_eq!(git_rev(&repo, &exec_ref), None, "no exec ref was written");
    assert_eq!(
        jj_cli_log(dir.path(), &repo, &described, "commit_id"),
        Vec::<String>::new(),
        "the dead child published no commit"
    );
    assert_eq!(
        jj_cli_log(dir.path(), &repo, &wc, "commit_id"),
        vec![spec.candidate_commit.clone()],
        "the workspace's @ is still the recorded candidate"
    );

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");

    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    let committed = jj_cli_log(dir.path(), &repo, &described, "commit_id");
    let [committed] = committed.as_slice() else {
        panic!("exactly one visible commit carries the effect's description: {committed:?}");
    };
    assert_eq!(git_rev(&repo, &exec_ref).as_ref(), Some(committed));
    assert_eq!(git_log_one(&repo, "%P", committed), seed);
    assert_eq!(
        jj_cli_log(dir.path(), &repo, &format!("{wc}-"), "commit_id"),
        vec![committed.clone()],
        "the workspace's @ sits on the commit"
    );
    let new_wc = jj_cli_log(dir.path(), &repo, &wc, "commit_id ++ \" \" ++ empty");
    let [new_wc] = new_wc.as_slice() else {
        panic!("one workspace @: {new_wc:?}");
    };
    let (new_wc, empty) = new_wc.split_once(' ').unwrap();
    assert_eq!(empty, "true", "the @ the commit leaves is empty");
    assert_eq!(
        head_row_read_only(&fx.planes.op_path, fx.execution_id),
        (new_wc.to_owned(), committed.clone()),
        "the head row names the new @ and the commit"
    );
    assert!(
        jj_cli_workspace_names(dir.path(), &repo).contains(&format!("agent-{}", fx.execution_id)),
        "`commit` never tears the workspace down"
    );
}

/// `commit`'s window before its operation is written.
#[test]
fn crash_inside_the_commit_before_its_publish_commits_once_on_recovery() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_commit_before_its_publish(
        "before_jj_publish",
        "crash_inside_the_commit_before_its_publish_commits_once_on_recovery",
    );
}

/// `commit`'s window between `tx.write` and `publish`: the operation is in the
/// op store but no op head names it, so it is invisible and recovery commits
/// once.
#[test]
fn crash_inside_the_commit_between_write_and_publish_commits_once_on_recovery() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_commit_before_its_publish(
        "between_write_and_publish",
        "crash_inside_the_commit_between_write_and_publish_commits_once_on_recovery",
    );
}

// -- the landing-park windows --------------------------------------------------
// A `promote` whose landing PARKS writes `parked/<exec-id>` inside the merge
// queue and only then removes the workspace (`promote_workspace_effect`'s two
// parked arms, armed at `after_landing_park_before_teardown`). The live verb's
// answer to a landing park is the attempt `failed` with the landing's refusal
// and the workspace removed; a recovery of a crash between the two owes the
// same answer.

/// Which refusal the landing gives.
#[derive(Clone, Copy)]
enum LandingPark {
    /// The rebase onto the advanced trunk conflicts: the delivered commit itself
    /// is parked (`LandingOutcome::Parked`).
    Conflict,
    /// The rebase is clean but the base advanced: the REBASED commit is parked
    /// for revalidation (`LandingOutcome::ParkedForRevalidation`).
    Revalidation,
}

/// Which recovery leg answers the crashed attempt.
#[derive(Clone, Copy)]
enum RecoveryLeg {
    /// `drive_pending_workspace_effects` — the sweep.
    Sweep,
    /// `perform_workspace_effect` — the runner's and the approval decision's door.
    Perform,
}

/// Land a SECOND execution's change on trunk through the landing ladder, so the
/// fixture's execution, forked from the seed, finds its base advanced. The
/// other execution's workspace is removed again, so after a teardown the jj
/// CLI lists only `default`. Returns trunk's new head, read off git.
fn advance_trunk_by_another_execution(fx: &Fixture, repo: &Path, rel: &str, bytes: &str) -> String {
    let key = ExecutionWorkspaceKey::execution(Ulid::new());
    let handle = kata_vcs::test_support::create_trunk_workspace(fx.backend.as_ref(), &key)
        .expect("the other execution's workspace creates");
    std::fs::write(handle.path.join(rel), bytes).unwrap();
    let commit = VcsBackend::commit(
        fx.backend.as_ref(),
        &kata_types::AgentId(key.execution_id),
        "another execution's change",
    )
    .unwrap();
    let outcome = fx
        .backend
        .land_committed_candidate(&key, &commit, None)
        .expect("the other execution's change lands");
    assert!(outcome.is_landed(), "the other change fast-forwards trunk");
    ExecutionWorkspaceProvider::remove_workspace(fx.backend.as_ref(), &key).unwrap();
    assert_eq!(
        git_rev(repo, "main").as_deref(),
        Some(commit.as_str()),
        "trunk advanced to the other execution's change, by git"
    );
    commit
}

/// A frozen-trunk `promote` claimed so that its landing parks: the candidate
/// changes `a.txt` (conflict) or adds `b.txt` (revalidation), then another
/// execution lands a change to `a.txt` (conflict) or adds `other.txt`
/// (revalidation). Returns the fixture, the pending attempt, its spec and
/// trunk's head.
fn a_promote_whose_landing_parks(
    dir: &Path,
    park: LandingPark,
) -> (Fixture, Ulid, WorkspaceEffectSpec, String) {
    let fx = fixture_with(dir, "promote", FixtureInvocation::FrozenTrunk);
    let repo = dir.join("repo");
    let (candidate_file, trunk_file) = match park {
        LandingPark::Conflict => ("a.txt", "a.txt"),
        LandingPark::Revalidation => ("b.txt", "other.txt"),
    };
    write_after_commit(&fx, candidate_file, "the candidate's side\n");
    let trunk = advance_trunk_by_another_execution(&fx, &repo, trunk_file, "trunk's side\n");
    let (attempt_id, spec) = claim_follow_on(&fx, WorkspaceEffectOp::Promote, None, STAGE, vec![7]);
    (fx, attempt_id, spec, trunk)
}

/// The refusal a conflict-parked landing records, spelled here from the
/// verb's published message rather than asked of it.
fn conflict_park_refusal(execution_id: Ulid) -> String {
    format!(
        "promote parked candidate for execution {execution_id}: rebase onto main conflicts in \
         [\"a.txt\"]; candidate work preserved at parked/{execution_id} (revalidate + re-land)"
    )
}

/// The refusal a revalidation-parked landing records, over shas read off git.
fn revalidation_park_refusal(
    execution_id: Ulid,
    delivered: &str,
    base: &str,
    rebased: &str,
) -> String {
    format!(
        "promote candidate for execution {execution_id} PARKED needs-revalidation: base \
         advanced ({delivered} -> {base}), so the rebased tree {rebased} was not the tree \
         validation approved and must be revalidated before it can be trusted; rebased \
         candidate preserved at parked/{execution_id} (revalidate the rebased tree + re-land)"
    )
}

/// The `reason` the attempt's latest transition recorded, read through a
/// SECOND, read-only handle.
fn failure_reason_read_only(op_path: &Path, attempt_id: Ulid) -> String {
    let conn =
        rusqlite::Connection::open_with_flags(op_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let payload: Vec<u8> = conn
        .query_row(
            "SELECT payload_json FROM transitions WHERE attempt_id = ?1
              ORDER BY seq DESC LIMIT 1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the resolving transition's payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    payload["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("the resolution records no reason: {payload}"))
        .to_owned()
}

/// What the landing left, read before any recovery: `parked/<exec-id>` (by
/// git) names the delivered commit (conflict) or a rebase of it onto trunk's
/// head carrying both sides (revalidation), trunk did not move, the workspace
/// stands (the filesystem and the jj CLI) and the attempt is `pending`.
/// Returns the parked commit.
fn assert_the_landing_parked(
    fx: &Fixture,
    dir: &Path,
    attempt_id: Ulid,
    spec: &WorkspaceEffectSpec,
    trunk: &str,
    park: LandingPark,
) -> String {
    let repo = dir.join("repo");
    let parked = git_rev(&repo, &format!("parked/{}", fx.execution_id))
        .expect("the landing wrote parked/<exec-id>");
    match park {
        LandingPark::Conflict => assert_eq!(
            parked, spec.delivered_commit,
            "a conflict park preserves the delivered commit itself"
        ),
        LandingPark::Revalidation => {
            assert_ne!(parked, spec.delivered_commit, "the rebase is a new commit");
            assert_eq!(
                git_log_one(&repo, "%P", &parked),
                trunk,
                "the rebased commit's one parent is trunk's head"
            );
            assert_eq!(
                git_show(&repo, &parked, "b.txt").as_deref(),
                Some("the candidate's side\n")
            );
            assert_eq!(
                git_show(&repo, &parked, "other.txt").as_deref(),
                Some("trunk's side\n")
            );
        }
    }
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(trunk),
        "the landing left trunk where it was"
    );
    assert!(
        execution_workspace_dir(&repo, fx.execution_id).is_dir(),
        "the workspace directory stands"
    );
    assert!(
        jj_cli_workspace_names(dir, &repo).contains(&format!("agent-{}", fx.execution_id)),
        "jj still lists the execution workspace"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    parked
}

/// The live verb's answer to a landing park, as it is read after the drive:
/// the attempt `failed` with `reason` (a second read-only handle), the
/// workspace gone (the filesystem, the jj CLI, the provider), the parked ref
/// unchanged and trunk unmoved (git).
fn assert_the_landing_park_was_answered(
    fx: &Fixture,
    dir: &Path,
    attempt_id: Ulid,
    reason: &str,
    parked: &str,
    trunk: &str,
) {
    let repo = dir.join("repo");
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed",
        "a parked landing is the promote's refusal"
    );
    assert_eq!(
        failure_reason_read_only(&fx.planes.op_path, attempt_id),
        reason
    );
    assert_the_execution_workspace_is_gone(fx, dir);
    assert_eq!(
        git_rev(&repo, &format!("parked/{}", fx.execution_id)).as_deref(),
        Some(parked),
        "the parked ref still names what the landing preserved"
    );
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(trunk),
        "nothing landed"
    );
}

/// The refusal the live verb records for `park`, over the parked commit.
fn landing_park_refusal(
    fx: &Fixture,
    spec: &WorkspaceEffectSpec,
    trunk: &str,
    parked: &str,
    park: LandingPark,
) -> String {
    match park {
        LandingPark::Conflict => conflict_park_refusal(fx.execution_id),
        LandingPark::Revalidation => {
            revalidation_park_refusal(fx.execution_id, &spec.delivered_commit, trunk, parked)
        }
    }
}

/// The live verb, no crash: a promote whose landing parks resolves `failed`
/// with the landing's refusal and removes its workspace.
fn a_landing_park_is_refused_and_torn_down(park: LandingPark) {
    let dir = tempfile::tempdir().unwrap();
    let (fx, attempt_id, spec, trunk) = a_promote_whose_landing_parks(dir.path(), park);
    fx.dispatcher
        .perform_workspace_effect(
            fx.execution_id,
            attempt_id,
            STAGE,
            &spec,
            &as_provider(&fx.backend),
            None,
        )
        .expect("the perform settles");
    let parked = git_rev(
        &dir.path().join("repo"),
        &format!("parked/{}", fx.execution_id),
    )
    .expect("the landing wrote parked/<exec-id>");
    let reason = landing_park_refusal(&fx, &spec, &trunk, &parked, park);
    assert_the_landing_park_was_answered(&fx, dir.path(), attempt_id, &reason, &parked, &trunk);
}

/// The child crashes inside the promote verb after the landing parked and
/// before its teardown; `leg` recovers it. The recovery records the refusal
/// the live verb records ([`a_landing_park_is_refused_and_torn_down`]) and
/// removes the workspace.
fn crash_inside_a_landing_park(park: LandingPark, leg: RecoveryLeg, test: &str) {
    let dir = tempfile::tempdir().unwrap();
    let (fx, attempt_id, spec, trunk) = a_promote_whose_landing_parks(dir.path(), park);
    drop(fx);
    let fx =
        crash_inside_the_verb_then_recover("after_landing_park_before_teardown", dir.path(), test);
    let parked = assert_the_landing_parked(&fx, dir.path(), attempt_id, &spec, &trunk, park);
    match leg {
        RecoveryLeg::Sweep => {
            fx.dispatcher
                .drive_pending_workspace_effects(
                    fx.execution_id,
                    Some(&as_provider(&fx.backend)),
                    None,
                )
                .expect("the recovery drive");
        }
        RecoveryLeg::Perform => fx
            .dispatcher
            .perform_workspace_effect(
                fx.execution_id,
                attempt_id,
                STAGE,
                &spec,
                &as_provider(&fx.backend),
                None,
            )
            .expect("the perform settles"),
    }
    let reason = landing_park_refusal(&fx, &spec, &trunk, &parked, park);
    assert_the_landing_park_was_answered(&fx, dir.path(), attempt_id, &reason, &parked, &trunk);
}

/// **The live conflict park.** The landing's rebase conflicts in `a.txt`:
/// `failed` with the verb's conflict refusal, the delivered commit preserved at
/// `parked/<exec-id>`, the workspace removed.
#[test]
fn a_promote_whose_landing_conflicts_records_the_refusal_and_removes_the_workspace() {
    a_landing_park_is_refused_and_torn_down(LandingPark::Conflict);
}

/// **The live revalidation park.** The base advanced and the rebase is clean:
/// `failed` with the verb's revalidation refusal naming the rebased commit, the
/// rebase preserved at `parked/<exec-id>`, the workspace removed.
#[test]
fn a_promote_whose_base_advanced_records_the_revalidation_refusal_and_removes_the_workspace() {
    a_landing_park_is_refused_and_torn_down(LandingPark::Revalidation);
}

/// A conflict park crashed before its teardown, recovered by the SWEEP. The
/// state is the live workspace with `@` the candidate and `parked/<exec-id>`
/// at the delivered commit; the sweep classifies `NotPerformed` and re-drives
/// the verb, which, over the same trunk, parks the same commit, removes the
/// workspace and records the same refusal.
#[test]
fn crash_after_a_conflict_park_before_teardown_recovers_the_refusal_and_the_teardown() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_a_landing_park(
        LandingPark::Conflict,
        RecoveryLeg::Sweep,
        "crash_after_a_conflict_park_before_teardown_recovers_the_refusal_and_the_teardown",
    );
}

/// The conflict-park window recovered through the PERFORM leg.
#[test]
fn crash_after_a_conflict_park_before_teardown_the_perform_leg_records_the_refusal() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_a_landing_park(
        LandingPark::Conflict,
        RecoveryLeg::Perform,
        "crash_after_a_conflict_park_before_teardown_the_perform_leg_records_the_refusal",
    );
}

/// A revalidation park crashed before its teardown, recovered by the SWEEP:
/// `parked/<exec-id>` names the landing's own rebase of the delivered commit,
/// so the sweep records the revalidation refusal the verb would have returned
/// and finishes the teardown.
#[test]
fn crash_after_a_revalidation_park_before_teardown_recovers_the_refusal_and_the_teardown() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_a_landing_park(
        LandingPark::Revalidation,
        RecoveryLeg::Sweep,
        "crash_after_a_revalidation_park_before_teardown_recovers_the_refusal_and_the_teardown",
    );
}

/// The revalidation-park window recovered through the PERFORM leg's
/// reconcile-first classify.
#[test]
fn crash_after_a_revalidation_park_before_teardown_the_perform_leg_records_the_refusal() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_a_landing_park(
        LandingPark::Revalidation,
        RecoveryLeg::Perform,
        "crash_after_a_revalidation_park_before_teardown_the_perform_leg_records_the_refusal",
    );
}

/// A revalidation park whose verb RETURNED (its teardown done) and whose
/// resolve never committed (`after_workspace_effect_jj_publish_before_resolution`):
/// the workspace is already gone, and the sweep still reads the landing's own
/// rebase at `parked/<exec-id>` and records the live verb's refusal.
#[test]
fn crash_after_a_revalidation_park_returned_before_resolution_records_the_refusal() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (fx, attempt_id, spec, trunk) =
        a_promote_whose_landing_parks(dir.path(), LandingPark::Revalidation);
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_workspace_effect_jj_publish_before_resolution",
        dir.path(),
        "crash_after_a_revalidation_park_returned_before_resolution_records_the_refusal",
    );
    let repo = dir.path().join("repo");
    let parked = git_rev(&repo, &format!("parked/{}", fx.execution_id))
        .expect("the landing wrote parked/<exec-id>");
    assert!(
        !execution_workspace_dir(&repo, fx.execution_id).exists(),
        "the verb's own teardown ran before the abort"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");
    let reason =
        revalidation_park_refusal(fx.execution_id, &spec.delivered_commit, &trunk, &parked);
    assert_the_landing_park_was_answered(&fx, dir.path(), attempt_id, &reason, &parked, &trunk);
}

/// How the host's trunk answer leaves the branch the execution froze, between
/// the crash and the recovery.
#[derive(Clone, Copy)]
enum HostTrunkChange {
    /// The remote's `HEAD` moves to `master`, a branch at the seed
    /// ([`move_host_trunk_to_master`]).
    Moved,
    /// The node's `vcs.trunk` names `release`, a branch at the seed.
    Renamed,
}

/// **A landing park judged on the FROZEN branch.** The execution froze `main`;
/// its promote's landing parks the rebase onto `main`'s advanced head for
/// revalidation and the child dies at `after_landing_park_before_teardown`.
/// Then the host's trunk answer leaves `main` (`change`) for a branch at the
/// seed, which holds neither the park's base nor its rebase. The sweep judges
/// `own_revalidation_park` on the frozen `main` (the classify resolves trunk
/// from `landing_branch`), so it answers `LandingParked`: the attempt `failed`
/// with the live verb's refusal and the workspace removed. Judged on the host's
/// answer, the park would be an outside write (`Diverged`, nothing removed).
/// Read out of git, the filesystem and the jj CLI, and a second read-only
/// handle on `operational.db`.
fn a_landing_park_recovers_on_the_frozen_branch(change: HostTrunkChange, test: &str) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let (fx, attempt_id, spec, trunk) =
        a_promote_whose_landing_parks(dir.path(), LandingPark::Revalidation);
    let seed = git_log_one(&repo, "%P", &trunk);
    drop(fx);
    let fx =
        crash_inside_the_verb_then_recover("after_landing_park_before_teardown", dir.path(), test);
    let parked = assert_the_landing_parked(
        &fx,
        dir.path(),
        attempt_id,
        &spec,
        &trunk,
        LandingPark::Revalidation,
    );
    let host: Arc<dyn ExecutionWorkspaceProvider> = match change {
        HostTrunkChange::Moved => {
            move_host_trunk_to_master(dir.path(), &repo, &seed);
            Arc::new(JjBackend::open(&repo).expect("reopen the backend"))
        }
        HostTrunkChange::Renamed => {
            run_git(&repo, &["branch", "release", &seed]);
            let renamed: Arc<dyn ExecutionWorkspaceProvider> = Arc::new(
                JjBackend::open(&repo)
                    .expect("reopen the backend")
                    .with_configured_trunk(Some("release".to_owned())),
            );
            let answer = kata_vcs::test_support::resolve_trunk_target(
                renamed.as_ref(),
                &ExecutionWorkspaceKey::execution(Ulid::new()),
            )
            .expect("another run resolves the renamed trunk");
            assert_eq!(answer.branch.as_deref(), Some("release"));
            renamed
        }
    };
    let host_branch = match change {
        HostTrunkChange::Moved => "master",
        HostTrunkChange::Renamed => "release",
    };

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&host), None)
        .expect("the recovery drive");

    let reason =
        revalidation_park_refusal(fx.execution_id, &spec.delivered_commit, &trunk, &parked);
    assert_the_landing_park_was_answered(&fx, dir.path(), attempt_id, &reason, &parked, &trunk);
    assert_eq!(
        git_rev(&repo, host_branch).as_deref(),
        Some(seed.as_str()),
        "nothing landed on the host's new trunk"
    );
}

/// [`a_landing_park_recovers_on_the_frozen_branch`] after the host's trunk
/// answer MOVED to `master`.
#[test]
fn crash_after_a_revalidation_park_then_the_host_trunk_moves_recovers_on_the_frozen_branch() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    a_landing_park_recovers_on_the_frozen_branch(
        HostTrunkChange::Moved,
        "crash_after_a_revalidation_park_then_the_host_trunk_moves_recovers_on_the_frozen_branch",
    );
}

/// [`a_landing_park_recovers_on_the_frozen_branch`] after the node's trunk was
/// RENAMED to `release`.
#[test]
fn crash_after_a_revalidation_park_then_the_trunk_is_renamed_recovers_on_the_frozen_branch() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    a_landing_park_recovers_on_the_frozen_branch(
        HostTrunkChange::Renamed,
        "crash_after_a_revalidation_park_then_the_trunk_is_renamed_recovers_on_the_frozen_branch",
    );
}

// -- a crash INSIDE the teardown -------------------------------------------------
// Every teardown (`JjBackend::remove_workspace_tagged`) is three steps that no
// one transaction spans: the jj transaction that removes the workspace's
// working-copy commit from the view, the workspace store's `forget`, then the
// directory's removal. A crash between them leaves `<repo>/agents/<exec-id>`
// on disk — `.jj` included — with no working-copy commit in the view: a
// teardown partly done, which the recovery finishes, never a live workspace it
// could repair or classify the `@` of.

/// The window inside the teardown the child dies in.
#[derive(Clone, Copy)]
enum TeardownWindow {
    /// The working-copy commit is gone from the view; the store still names
    /// the workspace and the directory stands.
    AfterWcRemoval,
    /// The store forgot the workspace too; the directory stands.
    AfterForget,
}

impl TeardownWindow {
    fn arm(self) -> &'static str {
        match self {
            Self::AfterWcRemoval => "after_wc_removal_before_forget",
            Self::AfterForget => "after_forget_before_remove_dir",
        }
    }
}

/// The effect whose teardown the child dies inside.
#[derive(Clone, Copy)]
enum TornDown {
    /// A frozen-`main` promote that landed the delivered commit.
    LandedPromote,
    /// A park that wrote `parked/<exec-id>` at the candidate.
    Park,
    /// A frozen-`main` promote whose landing parked the rebase for
    /// revalidation.
    RevalidationPark,
}

/// Whether jj's workspace STORE still names `agent-<exec-id>`, read as raw
/// bytes off the store's index file (`.jj/repo/workspace_store/index`, a
/// protobuf whose entries carry each name as a plain string) — the file kata's
/// `forget` rewrites, read with no jj code at all. (The jj CLI cannot answer
/// it: `jj workspace root --name` asks the view first, and the view loses the
/// name one step before the store does.)
fn store_index_names_the_workspace(repo: &Path, execution_id: Ulid) -> bool {
    let index = repo.join(".jj/repo/workspace_store/index");
    let bytes = std::fs::read(&index)
        .unwrap_or_else(|err| panic!("the workspace store index {}: {err}", index.display()));
    let name = format!("agent-{execution_id}");
    bytes
        .windows(name.len())
        .any(|window| window == name.as_bytes())
}

/// What the child left inside the teardown, read before any recovery: the
/// directory stands with `.jj` (the filesystem), the jj CLI lists no
/// `agent-<exec-id>` (the view lost its working-copy commit), the store names
/// it until the `forget` ran, and the attempt is `pending` (a second read-only
/// handle).
fn assert_the_teardown_is_partly_done(
    fx: &Fixture,
    dir: &Path,
    attempt_id: Ulid,
    window: TeardownWindow,
) {
    let repo = dir.join("repo");
    assert!(
        execution_workspace_dir(&repo, fx.execution_id)
            .join(".jj")
            .is_dir(),
        "the child died before the directory's removal: `.jj` stands"
    );
    assert!(
        !jj_cli_workspace_names(dir, &repo).contains(&format!("agent-{}", fx.execution_id)),
        "the view lost the workspace's working-copy commit"
    );
    assert_eq!(
        store_index_names_the_workspace(&repo, fx.execution_id),
        matches!(window, TeardownWindow::AfterWcRemoval),
        "the store names the workspace exactly until the `forget` ran"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
}

/// The child dies at `window` inside `effect`'s teardown; `leg` recovers it.
/// Before the recovery the effect's own mark is read off git — trunk at the
/// delivered commit, or `parked/<exec-id>` at the candidate or the landing's
/// rebase — and the teardown reads partly done. After it the attempt carries
/// the live verb's answer (a second read-only handle), the workspace is gone
/// (the filesystem, the jj CLI's list, the store, the provider) and git reads
/// the same mark: nothing landed or parked twice.
fn crash_inside_the_teardown(
    effect: TornDown,
    window: TeardownWindow,
    leg: RecoveryLeg,
    test: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let (fx, attempt_id, spec, trunk) = match effect {
        TornDown::LandedPromote => {
            let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
            let (attempt_id, spec) = claim_effect(
                &fx,
                WorkspaceEffect {
                    op: WorkspaceEffectOp::Promote,
                    label: None,
                    forge: None,
                    candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
                },
                None,
            );
            (fx, attempt_id, spec, None)
        }
        TornDown::Park => {
            let fx = fixture(dir.path(), "park");
            let (attempt_id, spec) = claim_effect(
                &fx,
                WorkspaceEffect {
                    op: WorkspaceEffectOp::Park,
                    label: None,
                    forge: None,
                    candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
                },
                None,
            );
            (fx, attempt_id, spec, None)
        }
        TornDown::RevalidationPark => {
            let (fx, attempt_id, spec, trunk) =
                a_promote_whose_landing_parks(dir.path(), LandingPark::Revalidation);
            (fx, attempt_id, spec, Some(trunk))
        }
    };
    drop(fx);
    let fx = crash_inside_the_verb_then_recover(window.arm(), dir.path(), test);
    let parked_ref = format!("parked/{}", fx.execution_id);
    // The effect's own mark, before the recovery.
    let mark = match effect {
        TornDown::LandedPromote => {
            assert_eq!(
                git_rev(&repo, "main").as_deref(),
                Some(spec.delivered_commit.as_str()),
                "the child landed the promote on the frozen main"
            );
            spec.delivered_commit.clone()
        }
        TornDown::Park => {
            assert_eq!(
                git_rev(&repo, &parked_ref).as_deref(),
                Some(spec.candidate_commit.as_str()),
                "the child wrote the parked ref at the candidate"
            );
            spec.candidate_commit.clone()
        }
        TornDown::RevalidationPark => assert_the_landing_parked_rebase(
            &fx,
            &repo,
            &spec,
            trunk.as_deref().expect("the advanced trunk"),
        ),
    };
    assert_the_teardown_is_partly_done(&fx, dir.path(), attempt_id, window);

    match leg {
        RecoveryLeg::Sweep => {
            fx.dispatcher
                .drive_pending_workspace_effects(
                    fx.execution_id,
                    Some(&as_provider(&fx.backend)),
                    None,
                )
                .expect("the recovery drive");
        }
        RecoveryLeg::Perform => fx
            .dispatcher
            .perform_workspace_effect(
                fx.execution_id,
                attempt_id,
                STAGE,
                &spec,
                &as_provider(&fx.backend),
                None,
            )
            .expect("the perform settles"),
    }

    match effect {
        TornDown::LandedPromote => {
            assert_eq!(
                attempt_state_read_only(&fx.planes.op_path, attempt_id),
                "completed",
                "the landed promote is recorded landed"
            );
            let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
            assert_eq!(content["ref_moved"].as_str(), Some("main"), "{content}");
            assert_eq!(
                git_rev(&repo, "main").as_deref(),
                Some(mark.as_str()),
                "the recovery landed nothing further"
            );
        }
        TornDown::Park => {
            assert_eq!(
                attempt_state_read_only(&fx.planes.op_path, attempt_id),
                "completed",
                "the published park is recorded parked"
            );
            let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
            assert_eq!(
                content["ref_name"].as_str(),
                Some(parked_ref.as_str()),
                "{content}"
            );
            assert_eq!(
                git_rev(&repo, &parked_ref).as_deref(),
                Some(mark.as_str()),
                "the parked ref still names the candidate"
            );
        }
        TornDown::RevalidationPark => {
            let trunk = trunk.expect("the advanced trunk");
            assert_eq!(
                attempt_state_read_only(&fx.planes.op_path, attempt_id),
                "failed",
                "a parked landing is the promote's refusal"
            );
            assert_eq!(
                failure_reason_read_only(&fx.planes.op_path, attempt_id),
                revalidation_park_refusal(fx.execution_id, &spec.delivered_commit, &trunk, &mark)
            );
            assert_eq!(
                git_rev(&repo, &parked_ref).as_deref(),
                Some(mark.as_str()),
                "the parked ref still names the landing's rebase"
            );
            assert_eq!(
                git_rev(&repo, "main").as_deref(),
                Some(trunk.as_str()),
                "nothing landed"
            );
        }
    }
    assert_the_execution_workspace_is_gone(&fx, dir.path());
    assert!(
        !store_index_names_the_workspace(&repo, fx.execution_id),
        "the store no longer names the workspace"
    );
}

/// The revalidation park's rebase, read off git before the recovery: one
/// parent, trunk's advanced head, carrying both sides; trunk unmoved. Returns
/// the parked commit.
fn assert_the_landing_parked_rebase(
    fx: &Fixture,
    repo: &Path,
    spec: &WorkspaceEffectSpec,
    trunk: &str,
) -> String {
    let parked = git_rev(repo, &format!("parked/{}", fx.execution_id))
        .expect("the landing wrote parked/<exec-id>");
    assert_ne!(parked, spec.delivered_commit, "the rebase is a new commit");
    assert_eq!(
        git_log_one(repo, "%P", &parked),
        trunk,
        "the rebased commit's one parent is trunk's head"
    );
    assert_eq!(
        git_show(repo, &parked, "b.txt").as_deref(),
        Some("the candidate's side\n")
    );
    assert_eq!(
        git_rev(repo, "main").as_deref(),
        Some(trunk),
        "the landing left trunk where it was"
    );
    parked
}

/// A landed promote's teardown died after the working-copy commit left the
/// view: the SWEEP finishes the `forget` and the removal and records the
/// promote landed.
#[test]
fn crash_inside_a_landed_promotes_teardown_after_the_wc_removal_recovers_and_finishes_it() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_teardown(
        TornDown::LandedPromote,
        TeardownWindow::AfterWcRemoval,
        RecoveryLeg::Sweep,
        "crash_inside_a_landed_promotes_teardown_after_the_wc_removal_recovers_and_finishes_it",
    );
}

/// The same promote, dead after the `forget`: the sweep finishes the removal.
#[test]
fn crash_inside_a_landed_promotes_teardown_after_the_forget_recovers_and_finishes_it() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_teardown(
        TornDown::LandedPromote,
        TeardownWindow::AfterForget,
        RecoveryLeg::Sweep,
        "crash_inside_a_landed_promotes_teardown_after_the_forget_recovers_and_finishes_it",
    );
}

/// The promote's teardown dead after the working-copy removal, recovered
/// through the PERFORM leg's reconcile-first classify.
#[test]
fn crash_inside_a_landed_promotes_teardown_the_perform_leg_finishes_it() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_teardown(
        TornDown::LandedPromote,
        TeardownWindow::AfterWcRemoval,
        RecoveryLeg::Perform,
        "crash_inside_a_landed_promotes_teardown_the_perform_leg_finishes_it",
    );
}

/// A park's teardown dead after the working-copy removal: the sweep's `Parked`
/// arm finishes it and records the park.
#[test]
fn crash_inside_a_parks_teardown_after_the_wc_removal_recovers_and_finishes_it() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_teardown(
        TornDown::Park,
        TeardownWindow::AfterWcRemoval,
        RecoveryLeg::Sweep,
        "crash_inside_a_parks_teardown_after_the_wc_removal_recovers_and_finishes_it",
    );
}

/// A park's teardown dead after the `forget`, recovered through the perform
/// leg's reconcile-first read of the parked ref.
#[test]
fn crash_inside_a_parks_teardown_after_the_forget_the_perform_leg_finishes_it() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_teardown(
        TornDown::Park,
        TeardownWindow::AfterForget,
        RecoveryLeg::Perform,
        "crash_inside_a_parks_teardown_after_the_forget_the_perform_leg_finishes_it",
    );
}

/// A revalidation park's teardown dead after the working-copy removal: the
/// sweep reads the landing's own rebase (`LandingParked`), finishes the
/// teardown and records the live verb's refusal.
#[test]
fn crash_inside_a_revalidation_parks_teardown_recovers_the_refusal_and_finishes_it() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_teardown(
        TornDown::RevalidationPark,
        TeardownWindow::AfterWcRemoval,
        RecoveryLeg::Sweep,
        "crash_inside_a_revalidation_parks_teardown_recovers_the_refusal_and_finishes_it",
    );
}

/// What a crash INSIDE the directory's removal can leave, which no arm can
/// stop at (`remove_dir_all` walks the tree in directory order).
#[derive(Clone, Copy)]
enum PartialRemoval {
    /// `.jj/repo` — the pointer to the shared repository — is gone, so the
    /// directory no longer loads as a jj workspace at all.
    RepoPointerGone,
    /// `.jj` is gone and a checked-out file still stands.
    MetadataGone,
}

/// A landed promote's teardown dies after the `forget`, then part of the
/// directory goes the way an interrupted `remove_dir_all` leaves it. The sweep
/// records the promote landed and removes what is left of the directory.
fn crash_inside_the_directory_removal(removal: PartialRemoval, test: &str) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let fx =
        crash_inside_the_verb_then_recover(TeardownWindow::AfterForget.arm(), dir.path(), test);
    let workspace = execution_workspace_dir(&repo, fx.execution_id);
    match removal {
        PartialRemoval::RepoPointerGone => {
            std::fs::remove_file(workspace.join(".jj").join("repo")).unwrap();
        }
        PartialRemoval::MetadataGone => {
            std::fs::remove_dir_all(workspace.join(".jj")).unwrap();
        }
    }
    assert!(
        workspace.join("a.txt").is_file(),
        "a checked-out file of the partly removed directory stands"
    );
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.delivered_commit.as_str()),
        "the child landed the promote on the frozen main"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");

    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed",
        "the landed promote is recorded landed"
    );
    assert!(
        !workspace.exists(),
        "the recovery removed what the interrupted removal left"
    );
    assert_the_execution_workspace_is_gone(&fx, dir.path());
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.delivered_commit.as_str()),
        "the recovery landed nothing further"
    );
}

/// The interrupted removal took `.jj/repo`: the directory no longer loads as a
/// workspace, and the sweep still finishes it.
#[test]
fn crash_inside_the_directory_removal_that_broke_the_metadata_recovers_and_finishes_it() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_directory_removal(
        PartialRemoval::RepoPointerGone,
        "crash_inside_the_directory_removal_that_broke_the_metadata_recovers_and_finishes_it",
    );
}

/// The interrupted removal took all of `.jj` and left a checked-out file: the
/// sweep removes the rest.
#[test]
fn crash_inside_the_directory_removal_that_took_the_metadata_recovers_and_finishes_it() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    crash_inside_the_directory_removal(
        PartialRemoval::MetadataGone,
        "crash_inside_the_directory_removal_that_took_the_metadata_recovers_and_finishes_it",
    );
}

// -- a sweep that cannot classify records it on the attempt ----------------------
// The sweep's classify phase — the workspace lookup, then the op's classify
// (the repository's refs and view) or, for a `forge_export`, the remote read —
// runs in the pre-fold slot. An error there means the facts that answer whether
// the effect ran could not be read: it is recorded on the attempt under
// `workspace_effect_unclassified`, never passed off as the verb's refusal and
// never a failure of the whole run before the fold. The stale-checkout repair
// runs only after the classify, so a working copy that cannot be repaired never
// hides a ref that answers the effect.

/// Rename the frozen `main` to `release` in git and let a later run's workspace
/// creation import every git ref, so jj's view holds no `main`. Returns the
/// backend that names `release` as the configured trunk.
fn rename_the_frozen_trunk(repo: &Path) -> Arc<dyn ExecutionWorkspaceProvider> {
    run_git(repo, &["branch", "-m", "main", "release"]);
    let renamed: Arc<dyn ExecutionWorkspaceProvider> = Arc::new(
        JjBackend::open(repo)
            .expect("reopen the backend")
            .with_configured_trunk(Some("release".to_owned())),
    );
    let later = ExecutionWorkspaceKey::execution(Ulid::new());
    kata_vcs::test_support::create_trunk_workspace(renamed.as_ref(), &later)
        .expect("a later run forks the renamed trunk");
    ExecutionWorkspaceProvider::remove_workspace(renamed.as_ref(), &later).unwrap();
    renamed
}

/// The attempt is `failed` under `workspace_effect_unclassified`, naming the
/// classify phase's error `cause` (a second read-only handle).
fn assert_recorded_unclassified(fx: &Fixture, attempt_id: Ulid, cause: &str) {
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.starts_with("workspace_effect_unclassified: ") && reason.contains(cause),
        "{reason}"
    );
}

/// **The renamed trunk on the sweep leg, before the promote ran.** The
/// execution froze `main`; before its pending promote is driven, `main` is
/// renamed to `release` and imported, so the classify cannot read the frozen
/// branch (`landing base bookmark main is absent or conflicted`). The sweep
/// records that as `workspace_effect_unclassified` (a second read-only handle)
/// and returns; nothing lands (git: no `main`, `release` at the seed) and the
/// workspace stands — never an error out of the sweep.
#[test]
fn a_sweep_whose_classify_refuses_records_the_effect_unclassified() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let (attempt_id, _spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let seed = git_rev(&repo, "main").expect("the seed trunk");
    let renamed = rename_the_frozen_trunk(&repo);

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&renamed), None)
        .expect("the sweep records the failure rather than failing");

    assert_recorded_unclassified(
        &fx,
        attempt_id,
        "landing base bookmark main is absent or conflicted",
    );
    assert_eq!(git_rev(&repo, "refs/heads/main"), None, "nothing landed");
    assert_eq!(
        git_rev(&repo, "release").as_deref(),
        Some(seed.as_str()),
        "the renamed trunk did not move"
    );
    assert!(
        execution_workspace_dir(&repo, fx.execution_id)
            .join(".jj")
            .is_dir(),
        "nothing was torn down"
    );
}

/// **The renamed trunk on the sweep leg, after the promote LANDED.** The child
/// lands the promote on the frozen `main` and dies before its resolve
/// (`after_workspace_effect_jj_publish_before_resolution`); `main` is then
/// renamed to `release` and imported. The classify cannot read the frozen
/// branch, so it cannot tell that the promote landed: the attempt is recorded
/// `workspace_effect_unclassified` naming that read, never the bare text a
/// verb's refusal carries (a second read-only handle), while git reads the
/// delivered commit on `release` — the facts the record does not claim to know.
#[test]
fn a_landed_promote_whose_trunk_was_renamed_is_recorded_unclassified() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let fx = fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk);
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Promote,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_workspace_effect_jj_publish_before_resolution",
        dir.path(),
        "a_landed_promote_whose_trunk_was_renamed_is_recorded_unclassified",
    );
    assert_eq!(
        git_rev(&repo, "main").as_deref(),
        Some(spec.delivered_commit.as_str()),
        "the child landed the promote on the frozen main"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    let renamed = rename_the_frozen_trunk(&repo);

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&renamed), None)
        .expect("the sweep records the failure rather than failing");

    assert_recorded_unclassified(
        &fx,
        attempt_id,
        "landing base bookmark main is absent or conflicted",
    );
    assert_eq!(
        git_rev(&repo, "release").as_deref(),
        Some(spec.delivered_commit.as_str()),
        "the renamed trunk holds the landed commit"
    );
    assert_eq!(git_rev(&repo, "refs/heads/main"), None);
}

/// A `park` or `promote` published, its workspace still standing (the child
/// died at `after_jj_publish_before_teardown`), and then its working-copy
/// state (`.jj/working_copy`) is lost while the view still names it, so no
/// read of its `@` and no stale-checkout repair can load it. The sweep answers
/// the effect from its ref — `parked/<exec-id>` at the candidate, or the
/// frozen `main` holding the delivered commit — and never needs the working
/// copy: the attempt is `completed` (a second read-only handle), git reads the
/// same mark, and the workspace is gone (the filesystem, the jj CLI, the
/// store, the provider).
fn a_published_effect_whose_working_copy_cannot_be_loaded(op: WorkspaceEffectOp, test: &str) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let fx = match op {
        WorkspaceEffectOp::Promote => {
            fixture_with(dir.path(), "promote", FixtureInvocation::FrozenTrunk)
        }
        _ => fixture(dir.path(), "park"),
    };
    let (attempt_id, spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    drop(fx);
    let fx =
        crash_inside_the_verb_then_recover("after_jj_publish_before_teardown", dir.path(), test);
    let (mark_ref, mark) = match op {
        WorkspaceEffectOp::Promote => ("main".to_owned(), spec.delivered_commit.clone()),
        _ => (
            format!("parked/{}", fx.execution_id),
            spec.candidate_commit.clone(),
        ),
    };
    assert_eq!(
        git_rev(&repo, &mark_ref).as_deref(),
        Some(mark.as_str()),
        "the child published the effect"
    );
    let workspace = execution_workspace_dir(&repo, fx.execution_id);
    std::fs::remove_dir_all(workspace.join(".jj").join("working_copy")).unwrap();
    assert!(
        jj_cli_workspace_names(dir.path(), &repo).contains(&format!("agent-{}", fx.execution_id)),
        "the view still names the workspace"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the recovery drive");

    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed",
        "the published effect is answered off its ref"
    );
    assert_eq!(
        git_rev(&repo, &mark_ref).as_deref(),
        Some(mark.as_str()),
        "nothing was published twice"
    );
    assert_the_execution_workspace_is_gone(&fx, dir.path());
    assert!(
        !store_index_names_the_workspace(&repo, fx.execution_id),
        "the store no longer names the workspace"
    );
}

/// **A landed promote whose working copy cannot be loaded.**
#[test]
fn a_landed_promote_whose_working_copy_cannot_be_loaded_is_recorded_landed() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    a_published_effect_whose_working_copy_cannot_be_loaded(
        WorkspaceEffectOp::Promote,
        "a_landed_promote_whose_working_copy_cannot_be_loaded_is_recorded_landed",
    );
}

/// **A published park whose working copy cannot be loaded.**
#[test]
fn a_published_park_whose_working_copy_cannot_be_loaded_is_recorded_parked() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    a_published_effect_whose_working_copy_cannot_be_loaded(
        WorkspaceEffectOp::Park,
        "a_published_park_whose_working_copy_cannot_be_loaded_is_recorded_parked",
    );
}

/// **A workspace the sweep cannot load, with no ref to answer from.** A
/// pending park never ran: no `parked/<exec-id>`, and its workspace lost its
/// working-copy state (`.jj/working_copy`) while the view still names it, so
/// the classify's read of the live `@` cannot load it. The sweep records the
/// attempt `workspace_effect_unclassified` naming the load error (a second
/// read-only handle) and returns; nothing is parked (git) and nothing is torn
/// down (the directory stands).
#[test]
fn a_sweep_that_cannot_load_the_workspace_records_the_effect_unclassified() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let fx = fixture(dir.path(), "park");
    let (attempt_id, _spec) = claim_effect(
        &fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::Park,
            label: None,
            forge: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
        },
        None,
    );
    let workspace = execution_workspace_dir(&repo, fx.execution_id);
    std::fs::remove_dir_all(workspace.join(".jj").join("working_copy")).unwrap();
    assert!(
        jj_cli_workspace_names(dir.path(), &repo).contains(&format!("agent-{}", fx.execution_id)),
        "the view still names the workspace"
    );

    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the sweep records the failure rather than failing");

    assert_recorded_unclassified(&fx, attempt_id, "failed to load the execution workspace");
    assert_eq!(
        git_rev(&repo, &format!("parked/{}", fx.execution_id)),
        None,
        "nothing was parked"
    );
    assert!(workspace.join(".jj").is_dir(), "nothing was torn down");
}

// -- every forge_export leg refuses before it writes ----------------------------
// The export refuses before it writes `kata/<exec>`: a live workspace whose
// disk is dirty (`oci_candidate_disk_diverged`) or whose `@` moved off the
// recorded candidate (`oci_candidate_diverged`), a delivered commit whose tree
// is conflicted (`forge_export_conflicted_commit`), and one whose author or
// committer is an identity kata will not publish. An approved gate and a
// restart after the claim reach the same driver through the sweep, with no
// intent recorded, and must refuse the same set before they write anything.

/// Which leg drives the export.
#[derive(Clone, Copy)]
enum ExportLeg {
    /// The claim parked for approval; the operator's decision door approves
    /// and drives it (`Dispatcher::decide_workspace_effect_gate`).
    ApprovedGate,
    /// The pending claim with nothing performed — the state a main killed at
    /// `after_workspace_effect_claimed_before_jj_publish` leaves — driven by
    /// the restart's sweep (`drive_pending_workspace_effects`). The cell
    /// builds that state by claiming directly rather than by a crash: for a
    /// `forge_export` the boundary sits only in the runner's live claim arm,
    /// which these dispatcher cells do not drive.
    AfterTheClaim,
}

/// `git ls-remote <origin>` — every ref the bare remote advertises, read by
/// git off the remote.
fn ls_remote(dir: &Path, origin: &Path) -> String {
    let out = hermetic_git_in(dir)
        .arg("ls-remote")
        .arg(origin)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git ls-remote runs: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A `commit` effect over a candidate whose tree carries a conflict at
/// `a.txt`: the commit verb never asks, so it finalizes the conflicted tree.
/// Returns the committed commit — the head row's `committed_commit_id` (a
/// second read-only handle), `exec-<exec-id>` by git, and conflicted by the jj
/// CLI.
fn commit_a_conflicted_candidate(fx: &Fixture, dir: &Path) -> String {
    let repo = dir.join("repo");
    let key = ExecutionWorkspaceKey::execution(fx.execution_id);
    let conflicted = kata_vcs::test_support::conflict_the_workspace_candidate(
        fx.backend.as_ref(),
        &key,
        "a.txt",
    )
    .expect("the conflicted candidate is written");
    record_head_candidate(fx, &conflicted);
    let (commit_attempt, _) = claim_follow_on(fx, WorkspaceEffectOp::Commit, None, "snap", vec![6]);
    fx.dispatcher
        .drive_pending_workspace_effects(fx.execution_id, Some(&as_provider(&fx.backend)), None)
        .expect("the commit drives");
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, commit_attempt),
        "completed"
    );
    let (_, committed) = head_row_read_only(&fx.planes.op_path, fx.execution_id);
    assert_eq!(
        git_rev(&repo, &format!("exec-{}", fx.execution_id)).as_deref(),
        Some(committed.as_str())
    );
    assert_eq!(
        jj_cli_log(dir, &repo, &committed, "conflict"),
        vec!["true".to_owned()],
        "the committed commit's tree is conflicted"
    );
    committed
}

/// Drive the export claimed over the current head row through `leg`, against
/// a forge that records every call. Returns the attempt and the forge.
fn drive_the_export(fx: &Fixture, leg: ExportLeg) -> (Ulid, Arc<RecordingForge>) {
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let as_forge = forge.clone() as Arc<dyn kata_effects_contract::Forge>;
    let spec = follow_on_spec(fx, WorkspaceEffectOp::ForgeExport, None);
    let attempt_id = match leg {
        ExportLeg::ApprovedGate => {
            let (attempt_id, _) =
                claim_gated_effect_at(fx, spec, "export", vec![8], Some("approve the export"));
            assert_eq!(
                attempt_state_read_only(&fx.planes.op_path, attempt_id),
                "awaiting_approval",
                "the gated export parks"
            );
            fx.dispatcher
                .decide_workspace_effect_gate(
                    attempt_id,
                    &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                    kata_core::operational::WorkspaceEffectVerdict::Approve,
                    &as_provider(&fx.backend),
                    Some(&as_forge),
                )
                .expect("the approval decides and drives the export");
            attempt_id
        }
        ExportLeg::AfterTheClaim => {
            let (attempt_id, _) = claim_effect_at(fx, spec, "export", vec![8]);
            fx.dispatcher
                .drive_pending_workspace_effects(
                    fx.execution_id,
                    Some(&as_provider(&fx.backend)),
                    Some(&as_forge),
                )
                .expect("the restart's sweep drives the export");
            attempt_id
        }
    };
    (attempt_id, forge)
}

/// The export refused before any ref write: the attempt `failed` with a reason
/// carrying `refusal` (a second read-only handle), no `kata/<exec>` in the
/// repository (git), nothing on the bare remote (`git ls-remote`), and no pull
/// request asked for.
fn assert_the_export_was_refused(
    fx: &Fixture,
    dir: &Path,
    origin: &Path,
    attempt_id: Ulid,
    forge: &RecordingForge,
    refusal: &str,
) {
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed",
        "the export is refused"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(reason.contains(refusal), "{reason}");
    assert_eq!(
        git_rev(
            &dir.join("repo"),
            &format!("refs/heads/kata/{}", fx.execution_id)
        ),
        None,
        "no export branch was written"
    );
    assert_eq!(ls_remote(dir, origin), "", "nothing reached the remote");
    assert_eq!(forge.call_count(), 0, "no pull request was asked for");
}

/// A conflicted committed candidate exported through `leg` is refused
/// `forge_export_conflicted_commit` by the local branch write every drive that
/// issues the push asks first (`write_workspace_effect_forge_ref`), as on the
/// live claim.
fn a_conflicted_export_is_refused(leg: ExportLeg) {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = bare_origin(dir.path(), &dir.path().join("repo"));
    commit_a_conflicted_candidate(&fx, dir.path());
    let (attempt_id, forge) = drive_the_export(&fx, leg);
    assert_the_export_was_refused(
        &fx,
        dir.path(),
        &origin,
        attempt_id,
        &forge,
        "forge_export_conflicted_commit",
    );
}

/// **An approved gate over a conflicted commit.**
#[test]
fn an_approved_export_gate_over_a_conflicted_commit_is_refused_and_pushes_nothing() {
    a_conflicted_export_is_refused(ExportLeg::ApprovedGate);
}

/// **A restart after the export's claim, over a conflicted commit.**
#[test]
fn an_export_recovered_after_its_claim_over_a_conflicted_commit_is_refused_and_pushes_nothing() {
    a_conflicted_export_is_refused(ExportLeg::AfterTheClaim);
}

/// **An identity kata will not publish, on the sweep leg.** The repository
/// declares the agent sandbox identity, which kata refuses to commit as, and
/// a candidate is committed under it through the engine trait (no `commit`
/// effect ran, so the export delivers that candidate). The restart's sweep
/// refuses it — `forge_export: refusing to publish commit` — before any ref
/// write.
#[test]
fn an_export_recovered_after_its_claim_of_an_unpublishable_identity_is_refused() {
    use kata_types::commit_identity::{SANDBOX_AGENT_EMAIL, SANDBOX_AGENT_NAME};
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = bare_origin(dir.path(), &repo);
    run_git(&repo, &["config", "user.name", SANDBOX_AGENT_NAME]);
    run_git(&repo, &["config", "user.email", SANDBOX_AGENT_EMAIL]);
    let candidate = write_after_commit(&fx, "agent.txt", "work\n");
    assert_ne!(
        git_log_one(&repo, "%ae", &candidate),
        "test@example.invalid",
        "the candidate does not carry the fixture's operator identity"
    );
    let (attempt_id, forge) = drive_the_export(&fx, ExportLeg::AfterTheClaim);
    assert_the_export_was_refused(
        &fx,
        dir.path(),
        &origin,
        attempt_id,
        &forge,
        "forge_export: refusing to publish commit",
    );
}

/// After `commit`, the export claimed, then the workspace changes under it
/// before the restart's sweep drives the export.
#[derive(Clone, Copy)]
enum ExportFence {
    /// A file is written into the workspace: its disk is dirty.
    DirtyDisk,
    /// A file is written and committed: `@` moved, the disk clean.
    MovedCandidate,
}

/// A fence member on the sweep leg: refused by name before any ref write.
fn a_fenced_export_is_refused(fence: ExportFence, refusal: &str) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = bare_origin(dir.path(), &repo);
    commit_and_read_sha(&fx, &repo);
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let (attempt_id, _) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    write_in_workspace(&fx, "foreign.txt", "written after the claim\n");
    if matches!(fence, ExportFence::MovedCandidate) {
        kata_vcs::VcsBackend::commit(
            fx.backend.as_ref(),
            &kata_types::AgentId(fx.execution_id),
            "a foreign write",
        )
        .unwrap();
    }
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the restart's sweep drives the export");
    assert_the_export_was_refused(&fx, dir.path(), &origin, attempt_id, &forge, refusal);
}

/// **A dirty workspace, on the sweep leg.**
#[test]
fn an_export_recovered_after_its_claim_over_a_dirty_workspace_is_refused() {
    a_fenced_export_is_refused(ExportFence::DirtyDisk, "oci_candidate_disk_diverged");
}

/// **A moved candidate, on the sweep leg.**
#[test]
fn an_export_recovered_after_its_claim_over_a_moved_candidate_is_refused() {
    a_fenced_export_is_refused(ExportFence::MovedCandidate, "oci_candidate_diverged");
}

// -- forge intents: every wire effect under an intent, every unknown outcome
// judged by its observer (ADR 0003 "Effects", E1; M0's ForgeIntent.tla) -------
//
// Oracles outside kata: the `forge_intents` rows through a second read-only
// handle, the bare remote's refs by git and its own `post-receive` log of the
// pushes that landed, and the fake forge's own state file and argv log.

/// One `forge_intents` row as a second read-only handle reads it:
/// `(effect_index, effect, verdict, verdict_by)`.
type RawIntent = (i64, String, Option<String>, Option<String>);

/// An intent row with its verdict.
fn intent(index: i64, effect: &str, verdict: &str, by: &str) -> RawIntent {
    (
        index,
        effect.to_owned(),
        Some(verdict.to_owned()),
        Some(by.to_owned()),
    )
}

/// An intent row with no verdict.
fn open_intent(index: i64, effect: &str) -> RawIntent {
    (index, effect.to_owned(), None, None)
}

fn intents_read_only(op_path: &Path, attempt_id: Ulid) -> Vec<RawIntent> {
    let conn =
        rusqlite::Connection::open_with_flags(op_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = conn
        .prepare(
            "SELECT effect_index, effect, verdict, verdict_by FROM forge_intents \
             WHERE attempt_id = ?1 ORDER BY effect_index",
        )
        .unwrap();
    statement
        .query_map(rusqlite::params![attempt_id.to_bytes().as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// The `lease` of each of the attempt's intents, in effect order, read raw.
fn leases_read_only(op_path: &Path, attempt_id: Ulid) -> Vec<Option<String>> {
    let conn =
        rusqlite::Connection::open_with_flags(op_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = conn
        .prepare("SELECT lease FROM forge_intents WHERE attempt_id = ?1 ORDER BY effect_index")
        .unwrap();
    statement
        .query_map(rusqlite::params![attempt_id.to_bytes().as_slice()], |row| {
            row.get(0)
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// The attempt's intent at `index`, read raw: `(unanswered_reads,
/// last_read_error, command_error)`.
fn unanswered_read_only(
    op_path: &Path,
    attempt_id: Ulid,
    index: i64,
) -> (i64, Option<String>, Option<String>) {
    let conn =
        rusqlite::Connection::open_with_flags(op_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    conn.query_row(
        "SELECT unanswered_reads, last_read_error, command_error FROM forge_intents \
         WHERE attempt_id = ?1 AND effect_index = ?2",
        rusqlite::params![attempt_id.to_bytes().as_slice(), index],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .unwrap()
}

/// The verdict detail of the attempt's intent at `index`, read raw.
fn verdict_detail_read_only(op_path: &Path, attempt_id: Ulid, index: i64) -> serde_json::Value {
    let conn =
        rusqlite::Connection::open_with_flags(op_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT verdict_json FROM forge_intents WHERE attempt_id = ?1 AND effect_index = ?2",
            rusqlite::params![attempt_id.to_bytes().as_slice(), index],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// `kata run forge-reconcile`'s door: the execution's pending exports driven
/// now, an open intent's observer asked at once.
fn reconcile_with(
    fx: &Fixture,
    forge: &Arc<dyn kata_effects_contract::Forge>,
) -> KataResult<Vec<kata_workflow::dispatcher::ForgeReconcile>> {
    fx.dispatcher.reconcile_forge_exports(
        fx.execution_id,
        Some(&as_provider(&fx.backend)),
        Some(forge),
    )
}

/// [`bare_origin`] whose `post-receive` hook appends every ref update it
/// accepted to `<dir>/pushes.log` — the remote's own count of the pushes that
/// landed (a client's `core.hooksPath` does not reach a local remote's hooks,
/// measured on git 2.56).
fn counted_origin(dir: &Path, repo: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let origin = bare_origin(dir, repo);
    let hook = origin.join("hooks").join("post-receive");
    std::fs::write(
        &hook,
        format!("#!/bin/sh\ncat >> '{}'\n", dir.join("pushes.log").display()),
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    origin
}

/// The ref updates the remote's hook logged.
fn pushes(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("pushes.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Claim a `forge_export` of the fixture's candidate with the default title
/// and body.
fn claim_export(fx: &Fixture) -> (Ulid, WorkspaceEffectSpec) {
    claim_effect(
        fx,
        WorkspaceEffect {
            op: WorkspaceEffectOp::ForgeExport,
            label: None,
            candidate_tree: kata_types::execution::CandidateTreePin::Unpinned,
            forge: Some(kata_types::workflow::ForgeExportSpec {
                title: None,
                body: None,
            }),
        },
        None,
    )
}

/// Drive the execution's pending effects once against `forge`.
fn drive_with(fx: &Fixture, forge: &Arc<dyn kata_effects_contract::Forge>) {
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&as_provider(&fx.backend)),
            Some(forge),
        )
        .expect("the drive records the export's outcome");
}

/// A fake `gh` at `<dir>/bin/gh-stateful` that KEEPS its pull requests, in
/// `<dir>/gh-prs.json`, each in a repository (`repo`, `forge.test/o/r` when a
/// seeded one names none): `pr create` appends one (open, numbered, with the
/// repository, head, base, title and body it was given) and prints its URL;
/// `pr list` answers the repository's pull requests on the head in the state
/// asked (`all` included) with the `--json` fields asked. The repository is
/// `--repo`'s, else gh's own default as measured on gh 2.103.3: the remote
/// `upstream`'s URL, else `origin`'s, read from the git config of the
/// directory it runs in. It serves the host `forge.test` only: a repository
/// on any other host fails every verb the way gh 2.103.3 fails an SSH alias
/// it cannot reach (`error connecting to <host>`, exit 1), and `repo view
/// <HOST/OWNER/REPO> --json nameWithOwner` answers `OWNER/REPO` for one on
/// it. A `--json` field a pull request does not hold fails the verb, as gh
/// fails an unknown field; only `isCrossRepository` reads `false` when a
/// seeded pull request leaves it out. Every argv is appended to
/// `<dir>/gh-argv.log` as one JSON array per line. The forge the cells read
/// back, outside kata.
///
/// A [`GhFault`] armed by [`arm_gh_fault`] makes one verb fail the way a real
/// forge can.
fn stateful_gh(dir: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let gh = bin.join("gh-stateful");
    let script = r#"#!/usr/bin/env -S python3 -I
import json, os, signal, subprocess, sys
STATE = "@STATE@"
FAULTS = "@FAULTS@"
argv = sys.argv[1:]
with open("@LOG@", "a") as log:
    log.write(json.dumps(argv) + "\n")
prs = json.load(open(STATE)) if os.path.exists(STATE) else []
def flag(name, default=None):
    return argv[argv.index(name) + 1] if name in argv else default
def armed(fault):
    return os.path.exists(os.path.join(FAULTS, fault))
def default_repo():
    for remote in ("upstream", "origin"):
        url = subprocess.run(["git", "config", "--get", "remote.%s.url" % remote],
                             capture_output=True, text=True).stdout.strip()
        if url:
            return url.split("://", 1)[-1].removesuffix(".git").lower()
    sys.exit("no git remotes found")
repo = argv[2] if argv[:2] == ["repo", "view"] else flag("--repo") or default_repo()
host = repo.split("/", 1)[0]
if host != "forge.test":
    sys.exit("error connecting to %s" % host)
def in_repo(pr):
    return pr.get("repo", "forge.test/o/r") == repo
def field(pr, name):
    if name == "isCrossRepository":
        return pr.get(name, False)
    name = {"baseRefName": "base"}.get(name, name)
    if name not in pr:
        sys.exit("Unknown JSON field: %r" % name)
    return pr[name]
if argv[:2] == ["repo", "view"]:
    if flag("--json") != "nameWithOwner":
        sys.exit("the fake gh answers `repo view` only for --json nameWithOwner")
    print(json.dumps({"nameWithOwner": repo.split("/", 1)[1]}))
elif argv[:2] == ["pr", "list"]:
    head, state = flag("--head"), flag("--state", "open")
    if armed("list-fails") or (state == "all" and armed("list-all-fails")):
        sys.exit("the forge did not answer the listing")
    if state == "open" and armed("list-open-kills-caller"):
        os.kill(os.getppid(), signal.SIGKILL)
        sys.exit("the main died before the listing was answered")
    fields = flag("--json", "number,url").split(",")
    print(json.dumps([{k: field(pr, k) for k in fields} for pr in prs
                      if in_repo(pr) and pr["head"] == head
                      and state in ("all", pr["state"])]))
elif argv[:2] == ["pr", "create"]:
    if armed("create-refused"):
        sys.exit("the forge refused the create")
    number = len(prs) + 1
    prs.append({"number": number, "url": "https://%s/pull/%d" % (repo, number), "repo": repo,
                "head": flag("--head"), "base": flag("--base"), "title": flag("--title"),
                "body": flag("--body"), "state": "open"})
    json.dump(prs, open(STATE, "w"))
    print(prs[-1]["url"])
    if armed("create-errs-after-opening"):
        sys.exit("the forge errored after it opened the pull request")
else:
    sys.exit("the fake gh has no verb %r" % argv)
"#
    .replace("@STATE@", &dir.join("gh-prs.json").display().to_string())
    .replace("@FAULTS@", &dir.join("gh-faults").display().to_string())
    .replace("@LOG@", &dir.join("gh-argv.log").display().to_string());
    std::fs::write(&gh, script).unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    gh
}

/// A way the stateful fake `gh` fails.
#[derive(Clone, Copy)]
enum GhFault {
    /// `pr create` exits non-zero having opened nothing.
    CreateRefused,
    /// `pr create` opens the pull request, prints its URL, then exits non-zero.
    CreateErrsAfterOpening,
    /// `pr list --state all` — the marker observer's read — exits non-zero;
    /// the open-only listing still answers.
    ListAllFails,
    /// Every `pr list` exits non-zero, open-only and any-state alike: the
    /// forge does not answer a read.
    ListFails,
    /// `pr list --state open` — the lookup before the pull request's intent —
    /// SIGKILLs the process that asked: the main dies inside the lookup.
    ListOpenKillsCaller,
}

/// Arm `fault` on the stateful fake `gh` at `<dir>`.
fn arm_gh_fault(dir: &Path, fault: GhFault) {
    let name = match fault {
        GhFault::CreateRefused => "create-refused",
        GhFault::CreateErrsAfterOpening => "create-errs-after-opening",
        GhFault::ListAllFails => "list-all-fails",
        GhFault::ListFails => "list-fails",
        GhFault::ListOpenKillsCaller => "list-open-kills-caller",
    };
    let faults = dir.join("gh-faults");
    std::fs::create_dir_all(&faults).unwrap();
    std::fs::write(faults.join(name), "").unwrap();
}

/// Disarm `fault` on the stateful fake `gh` at `<dir>`: the forge answers again.
fn disarm_gh_fault(dir: &Path, fault: GhFault) {
    let name = match fault {
        GhFault::CreateRefused => "create-refused",
        GhFault::CreateErrsAfterOpening => "create-errs-after-opening",
        GhFault::ListAllFails => "list-all-fails",
        GhFault::ListFails => "list-fails",
        GhFault::ListOpenKillsCaller => "list-open-kills-caller",
    };
    std::fs::remove_file(dir.join("gh-faults").join(name)).unwrap();
}

/// How many `gh pr list --state all` — the marker observer's read — the fake
/// forge was asked for, off its argv log.
fn forge_marker_reads(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("gh-argv.log"))
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            let argv: Vec<String> = serde_json::from_str(line).unwrap();
            argv.get(..2) == Some(&["pr".to_owned(), "list".to_owned()][..])
                && argv.windows(2).any(|pair| pair == ["--state", "all"])
        })
        .count()
}

fn stateful_forge(dir: &Path) -> Arc<dyn kata_effects_contract::Forge> {
    Arc::new(kata_vcs::GhCliForge::with_program(
        stateful_gh(dir),
        dir.join("repo"),
    ))
}

/// The fake forge's pull requests, read off its state file.
fn forge_pull_requests(dir: &Path) -> Vec<serde_json::Value> {
    std::fs::read(dir.join("gh-prs.json"))
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .unwrap_or_default()
}

/// How many `gh pr create` the fake forge was asked for, off its argv log.
fn forge_creates(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("gh-argv.log"))
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            let argv: Vec<String> = serde_json::from_str(line).unwrap();
            argv.get(..2) == Some(&["pr".to_owned(), "create".to_owned()][..])
        })
        .count()
}

/// Rewrite every pull request on the fake forge through `edit` — what a
/// human does on the forge between the crash and the recovery.
fn edit_forge_pull_requests(dir: &Path, edit: impl Fn(&mut serde_json::Value)) {
    let mut prs = forge_pull_requests(dir);
    prs.iter_mut().for_each(edit);
    std::fs::write(dir.join("gh-prs.json"), serde_json::to_vec(&prs).unwrap()).unwrap();
}

/// The marker a pull request opened under the attempt's intent at
/// `effect_index` carries — the intent's coordinates — spelled here rather than
/// asked of kata.
fn marker_of(attempt_id: Ulid, effect_index: i64) -> String {
    format!("<!-- kata-forge-intent: {attempt_id}/{effect_index} -->")
}

/// A commit someone else pushes to `origin`'s `branch`, from a scratch clone
/// that shares nothing with the fixture's repository. Returns its sha.
fn foreign_push(dir: &Path, origin: &Path, branch: &str) -> String {
    let scratch = dir.join("someone-else");
    std::fs::create_dir_all(&scratch).unwrap();
    init_git_repo_at(&scratch);
    std::fs::write(scratch.join("theirs.txt"), "someone else's work\n").unwrap();
    run_git(&scratch, &["add", "-A"]);
    run_git(&scratch, &["commit", "-q", "-m", "someone else's commit"]);
    run_git(
        &scratch,
        &[
            "push",
            "-q",
            origin.to_str().unwrap(),
            &format!("HEAD:refs/heads/{branch}"),
        ],
    );
    git_rev(&scratch, "HEAD").unwrap()
}

/// **The live export: a push and a pull request, each under its intent, the
/// pull request's body carrying the marker.** The intents read back raw — a
/// push leased on the branch's absence and the pull request, both settled by
/// their receipts — and the body the forge was asked for ends with the
/// pull-request intent's own id, spelled here.
///
/// **Would red if:** an effect were issued with no intent, or the body carried
/// no marker for the observer to find.
#[test]
fn a_forge_export_issues_each_wire_effect_under_its_intent_and_marks_the_body() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/7",
    ));
    let (attempt_id, spec) = claim_export(&fx);
    drive_with(
        &fx,
        &(forge.clone() as Arc<dyn kata_effects_contract::Forge>),
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
        Some(spec.delivered_commit)
    );
    assert_eq!(pushes(dir.path()).len(), 1);
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "performed", "receipt"),
        ]
    );
    assert_eq!(
        leases_read_only(&fx.planes.op_path, attempt_id),
        [None, None],
        "the push was leased on the branch's absence"
    );
    let body = &forge.calls()[0].body;
    assert!(
        body.starts_with(&format!("Exported by kata execution {}", fx.execution_id))
            && body.ends_with(&marker_of(attempt_id, 1)),
        "the body is the authored body, then the pull request intent's marker: {body:?}"
    );
}

/// **After the push's intent, before the push**
/// (`after_forge_push_intent_before_push`). The child recorded the open push
/// intent, leased on the branch's absence, and died with nothing on the remote.
/// The recovery's observer reads the ref still at the lease — NOT PERFORMED,
/// recorded on the intent — and the export pushes again under a fresh intent:
/// one push landed (the remote's log), one pull request.
///
/// **Would red if:** an intent with no verdict were read as performed (the
/// pull request would open over an empty remote).
#[test]
fn crash_after_forge_push_intent_before_push_is_observed_not_performed_and_pushes_once() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, spec) = claim_export(&fx);
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_push_intent_before_push",
        dir.path(),
        "crash_after_forge_push_intent_before_push_is_observed_not_performed_and_pushes_once",
    );
    assert_eq!(remote_refs(&origin), "", "the child died before the push");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [open_intent(0, "push")]
    );
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/8",
    ));
    drive_with(
        &fx,
        &(forge.clone() as Arc<dyn kata_effects_contract::Forge>),
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(
        remote_refs(&origin),
        format!(
            "{} refs/heads/kata/{}\n",
            spec.delivered_commit, fx.execution_id
        )
    );
    assert_eq!(pushes(dir.path()).len(), 1, "one push landed");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "not_performed", "observer"),
            intent(1, "push", "performed", "receipt"),
            intent(2, "pull_request", "performed", "receipt"),
        ]
    );
    assert_eq!(forge.call_count(), 1);
}

/// **A remote that does not answer the push's observer settles nothing; asked
/// again once it answers, the export completes, one push landed.** The child
/// died after the push's intent; the remote is then moved away. The sweep's
/// observer read goes unanswered: the attempt stays `pending`, the intent open
/// with one unanswered read counted (raw), nothing pushed (git) and nothing
/// asked of the forge. A second sweep at once does not ask again — the count
/// stays one, the spacing between asks. The remote is moved back and `kata run
/// forge-reconcile` asks at once: the ref still holds the lease (absence) —
/// NOT PERFORMED — so the export pushes under a fresh intent and opens its pull
/// request: one push in the remote's own log.
///
/// **Would red if:** an unanswered read settled the intent UNCLASSIFIED at once
/// (M0 `unread_is_unclassified`, the code before owner decision #15), or the
/// sweep asked again before the spacing passed.
#[test]
fn an_export_cut_from_its_remote_stays_open_and_completes_once_the_remote_answers() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, spec) = claim_export(&fx);
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_push_intent_before_push",
        dir.path(),
        "an_export_cut_from_its_remote_stays_open_and_completes_once_the_remote_answers",
    );
    let away = dir.path().join("origin.git.away");
    std::fs::rename(&origin, &away).unwrap();
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    let forge_dyn = forge.clone() as Arc<dyn kata_effects_contract::Forge>;
    drive_with(&fx, &forge_dyn);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [open_intent(0, "push")]
    );
    let (count, last_error, command_error) =
        unanswered_read_only(&fx.planes.op_path, attempt_id, 0);
    assert_eq!(count, 1, "one unanswered read counted");
    assert!(
        last_error
            .as_deref()
            .is_some_and(|error| error.contains("git ls-remote")),
        "{last_error:?}"
    );
    assert_eq!(command_error, None, "no command answered: a crash left it");
    drive_with(&fx, &forge_dyn);
    assert_eq!(
        unanswered_read_only(&fx.planes.op_path, attempt_id, 0).0,
        1,
        "the sweep does not ask again before the spacing passes"
    );
    assert_eq!(remote_refs(&away), "", "nothing was pushed");
    assert_eq!(forge.call_count(), 0, "no pull request was asked for");

    std::fs::rename(&away, &origin).unwrap();
    let reconciled = reconcile_with(&fx, &forge_dyn).expect("the reconcile drives the export");
    assert_eq!(reconciled.len(), 1);
    assert_eq!(reconciled[0].state, "completed");
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "not_performed", "observer"),
            intent(1, "push", "performed", "receipt"),
            intent(2, "pull_request", "performed", "receipt"),
        ]
    );
    assert_eq!(
        remote_refs(&origin),
        format!(
            "{} refs/heads/kata/{}\n",
            spec.delivered_commit, fx.execution_id
        )
    );
    assert_eq!(pushes(dir.path()).len(), 1, "one push landed");
    assert_eq!(forge.call_count(), 1);
}

/// Move the attempt's open intents' last unanswered read `ago_ms` into the
/// past through a writable handle — the wall clock passing, without the wait.
fn backdate_last_unanswered(fx: &Fixture, attempt_id: Ulid, ago_ms: i64) {
    let now_ms = i64::try_from(kata_types::time::now_ms()).unwrap();
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    let moved = conn
        .execute(
            "UPDATE forge_intents SET last_unanswered_at_ms = ?2 \
             WHERE attempt_id = ?1 AND verdict_json IS NULL AND unanswered_reads > 0",
            rusqlite::params![attempt_id.to_bytes().as_slice(), now_ms - ago_ms],
        )
        .unwrap();
    assert_eq!(moved, 1, "one open intent carries an unanswered read");
}

/// **The sweep asks again once the spacing has passed, and only then.** The
/// child died after the push's intent; the remote is moved away. The sweep's
/// read goes unanswered (count 1, raw) and a second sweep at once does not ask
/// (still 1). With the last unanswered read moved 61 s into the past through a
/// writable handle, the next sweep — no reconcile — asks again: count 2. The
/// remote is moved back, the read backdated again, and the next sweep asks:
/// the ref holds the lease, NOT PERFORMED, so the export pushes under a fresh
/// intent and completes, one push in the remote's own log.
///
/// **Would red if:** the scheduled ask were never due again (an export with
/// one unanswered read would wait for an operator's reconcile — M0
/// `unbounded_reask` in effect), or the spacing were read in the wrong unit.
#[test]
fn the_sweep_asks_again_once_the_spacing_has_passed() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, spec) = claim_export(&fx);
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_push_intent_before_push",
        dir.path(),
        "the_sweep_asks_again_once_the_spacing_has_passed",
    );
    let away = dir.path().join("origin.git.away");
    std::fs::rename(&origin, &away).unwrap();
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/14",
    ));
    let forge_dyn = forge.clone() as Arc<dyn kata_effects_contract::Forge>;
    drive_with(&fx, &forge_dyn);
    assert_eq!(unanswered_read_only(&fx.planes.op_path, attempt_id, 0).0, 1);
    drive_with(&fx, &forge_dyn);
    assert_eq!(
        unanswered_read_only(&fx.planes.op_path, attempt_id, 0).0,
        1,
        "not asked again before the spacing"
    );

    backdate_last_unanswered(&fx, attempt_id, 61_000);
    drive_with(&fx, &forge_dyn);
    assert_eq!(
        unanswered_read_only(&fx.planes.op_path, attempt_id, 0).0,
        2,
        "the sweep asked again once the spacing had passed"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );

    std::fs::rename(&away, &origin).unwrap();
    backdate_last_unanswered(&fx, attempt_id, 61_000);
    drive_with(&fx, &forge_dyn);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "not_performed", "observer"),
            intent(1, "push", "performed", "receipt"),
            intent(2, "pull_request", "performed", "receipt"),
        ]
    );
    assert_eq!(
        remote_refs(&origin),
        format!(
            "{} refs/heads/kata/{}\n",
            spec.delivered_commit, fx.execution_id
        )
    );
    assert_eq!(pushes(dir.path()).len(), 1, "one push landed");
    assert_eq!(forge.call_count(), 1);
}

/// **The bound: the tenth unanswered read settles the intent UNCLASSIFIED,
/// and nothing asks past it.** As above, the remote stays away: the sweep's
/// read and nine `kata run forge-reconcile` asks go unanswered. Through the
/// ninth the attempt stays `pending`; the tenth records the export failed
/// `workspace_effect_unclassified`, the intent `unclassified` by its observer
/// with `unanswered_reads` 10 (raw, the column and the verdict's detail). With
/// the remote back, a reconcile is refused — nothing is pending — and no sweep
/// pushes: the remote holds no export branch (git).
///
/// **Would red if:** an unanswered read never settled the intent (M0
/// `unbounded_reask`: the export would wait on a dead remote forever), or
/// settled it before the bound.
#[test]
fn an_observer_left_unanswered_ten_times_settles_unclassified() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, _spec) = claim_export(&fx);
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_push_intent_before_push",
        dir.path(),
        "an_observer_left_unanswered_ten_times_settles_unclassified",
    );
    let away = dir.path().join("origin.git.away");
    std::fs::rename(&origin, &away).unwrap();
    let forge: Arc<dyn kata_effects_contract::Forge> = Arc::new(
        RecordingForge::succeeding_with_url("https://forge.test/pull/12"),
    );
    drive_with(&fx, &forge);
    for asked in 2..=9 {
        reconcile_with(&fx, &forge).expect("the reconcile asks");
        assert_eq!(
            unanswered_read_only(&fx.planes.op_path, attempt_id, 0).0,
            asked
        );
        assert_eq!(
            attempt_state_read_only(&fx.planes.op_path, attempt_id),
            "pending",
            "{asked} unanswered reads settle nothing"
        );
    }
    let reconciled = reconcile_with(&fx, &forge).expect("the tenth ask");
    assert_eq!(reconciled[0].state, "failed");
    assert_recorded_unclassified(&fx, attempt_id, "did not answer 10 reads");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [intent(0, "push", "unclassified", "observer")]
    );
    assert_eq!(
        unanswered_read_only(&fx.planes.op_path, attempt_id, 0).0,
        10
    );
    assert_eq!(
        verdict_detail_read_only(&fx.planes.op_path, attempt_id, 0)["unanswered_reads"],
        10
    );
    std::fs::rename(&away, &origin).unwrap();
    let refused = reconcile_with(&fx, &forge).expect_err("nothing is pending");
    assert!(
        refused
            .to_string()
            .contains("forge_reconcile_nothing_pending"),
        "{refused}"
    );
    drive_with(&fx, &forge);
    assert_eq!(remote_refs(&origin), "", "nothing was ever pushed");
    assert!(pushes(dir.path()).is_empty());
}

/// **An intent already at the bound is settled without another ask.** A crash
/// between the tenth unanswered read and its settlement leaves the intent open
/// with ten counted — written here through a writable handle, as that crash
/// leaves it. With the remote answering, and still holding the lease, the
/// next drive settles the intent UNCLASSIFIED without reading it: had it
/// asked, it would read NOT PERFORMED and push, and the remote holds no export
/// branch (git) and logs no push.
///
/// **Would red if:** a drive asked an intent whose count had reached the bound
/// (M0 `NoAskPastTheBound`).
#[test]
fn an_intent_at_the_bound_is_settled_without_another_ask() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, _spec) = claim_export(&fx);
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_push_intent_before_push",
        dir.path(),
        "an_intent_at_the_bound_is_settled_without_another_ask",
    );
    {
        let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
        conn.execute(
            "UPDATE forge_intents SET unanswered_reads = 10, last_unanswered_at_ms = 1, \
             last_read_error = 'the remote did not answer' WHERE attempt_id = ?1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
        )
        .unwrap();
    }
    let forge: Arc<dyn kata_effects_contract::Forge> = Arc::new(
        RecordingForge::succeeding_with_url("https://forge.test/pull/13"),
    );
    drive_with(&fx, &forge);
    assert_recorded_unclassified(&fx, attempt_id, "did not answer 10 reads");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [intent(0, "push", "unclassified", "observer")]
    );
    assert_eq!(remote_refs(&origin), "", "the observer was not asked");
    assert!(pushes(dir.path()).is_empty());
}

/// **Reachable at the read, gone at the push, on the live leg; back before the
/// next ask.** The remote's `pre-receive` hook moves the remote away and
/// declines, so the push fails: its error is recorded on the intent first
/// (raw `command_error`), and the observer it asks at once cannot read the
/// remote, so the intent stays open, one unanswered read counted, the attempt
/// `pending`. The remote is moved back with its hook removed — a push would
/// land now — and `kata run forge-reconcile` asks: the ref holds the lease, NOT
/// PERFORMED, and since the push's own command failed the export fails with
/// that error, proven not performed. Nothing was pushed again: the remote holds
/// no export branch (git) and logs no push.
///
/// **Would red if:** an unanswered read after a failed push settled the export
/// UNCLASSIFIED at once, or a later NOT PERFORMED forgot the command's error
/// and pushed again.
#[test]
fn a_push_whose_remote_vanishes_stays_open_then_fails_not_performed_with_its_error() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let away = dir.path().join("origin.git.away");
    let hook = origin.join("hooks").join("pre-receive");
    std::fs::write(
        &hook,
        format!(
            "#!/bin/sh\nmv '{}' '{}'\nexit 1\n",
            origin.display(),
            away.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (attempt_id, _spec) = claim_export(&fx);
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/10",
    ));
    let forge_dyn = forge.clone() as Arc<dyn kata_effects_contract::Forge>;
    drive_with(&fx, &forge_dyn);
    assert!(
        !origin.exists() && away.is_dir(),
        "the hook moved the remote"
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [open_intent(0, "push")]
    );
    let (count, _, command_error) = unanswered_read_only(&fx.planes.op_path, attempt_id, 0);
    assert_eq!(count, 1);
    assert!(
        command_error
            .as_deref()
            .is_some_and(|error| error.contains("`git push`")),
        "{command_error:?}"
    );

    std::fs::rename(&away, &origin).unwrap();
    std::fs::remove_file(origin.join("hooks").join("pre-receive")).unwrap();
    reconcile_with(&fx, &forge_dyn).expect("the reconcile asks");
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.contains("`git push`")
            && reason.contains("so it was not performed and nothing is pushed again"),
        "{reason}"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [intent(0, "push", "not_performed", "observer")]
    );
    assert_eq!(remote_refs(&origin), "", "nothing was pushed again");
    assert!(pushes(dir.path()).is_empty());
    assert_eq!(forge.call_count(), 0);
}

/// **A remote that does not answer the read before the intent.** The claimed
/// remote is gone (its bare repository removed), so the pre-intent read fails:
/// no intent row (raw), the export recorded failed `forge_export_remote_unread`
/// PROVEN NOT PERFORMED, and the forge asked nothing.
///
/// **Would red if:** the push were not leased on a read before its intent (an
/// intent row would be recorded over a remote nothing read).
#[test]
fn an_export_whose_remote_does_not_answer_the_read_records_no_intent_and_is_not_performed() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = bare_origin(dir.path(), &repo);
    commit_and_read_sha(&fx, &repo);
    let (attempt_id, _spec) =
        claim_follow_on(&fx, WorkspaceEffectOp::ForgeExport, None, "export", vec![8]);
    std::fs::remove_dir_all(&origin).unwrap();
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/9",
    ));
    drive_with(
        &fx,
        &(forge.clone() as Arc<dyn kata_effects_contract::Forge>),
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.starts_with("forge_export_remote_unread: ")
            && reason.contains("git ls-remote")
            && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    assert!(intents_read_only(&fx.planes.op_path, attempt_id).is_empty());
    assert_eq!(forge.call_count(), 0, "no pull request was asked for");
}

/// **A foreign head where the push's lease stood.** The child died after the
/// push's intent (leased on absence); someone else then pushes their own
/// commit to `kata/<exec>`. The observer reads a head that is neither kata's
/// nor the lease: `workspace_effect_unclassified`, the intent `unclassified`,
/// and the foreign commit is never pushed over (git; the remote's log holds
/// only the foreign push).
///
/// **Would red if:** the observer read any head but kata's commit as NOT
/// PERFORMED (M0's `naive_push_observer`).
#[test]
fn a_foreign_head_after_the_push_intent_is_recorded_unclassified_and_never_clobbered() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, _spec) = claim_export(&fx);
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_push_intent_before_push",
        dir.path(),
        "a_foreign_head_after_the_push_intent_is_recorded_unclassified_and_never_clobbered",
    );
    let branch = format!("kata/{}", fx.execution_id);
    let theirs = foreign_push(dir.path(), &origin, &branch);
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/11",
    ));
    drive_with(
        &fx,
        &(forge.clone() as Arc<dyn kata_effects_contract::Forge>),
    );
    assert_recorded_unclassified(&fx, attempt_id, "neither the pushed");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [intent(0, "push", "unclassified", "observer")]
    );
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/{branch}")),
        Some(theirs),
        "the foreign commit stands"
    );
    assert_eq!(pushes(dir.path()).len(), 1, "only the foreign push landed");
    assert_eq!(forge.call_count(), 0);
}

/// **A foreign head at the read is refused; a head this execution pushed is
/// leased.** Someone else's commit on `kata/<exec>` before the export: the
/// read refuses it `forge_export_diverged` with no intent and the remote
/// unchanged. A second export, whose remote branch holds the commit an earlier
/// export of the same execution recorded as performed, leases on that commit
/// and lands over it (git; the intent's lease, raw).
///
/// **Would red if:** the read leased on any head (the foreign commit would be
/// pushed over), or refused kata's own earlier push.
#[test]
fn a_foreign_head_at_the_read_is_refused_and_one_this_execution_pushed_is_leased() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let branch = format!("kata/{}", fx.execution_id);
    let theirs = foreign_push(dir.path(), &origin, &branch);
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/12",
    ));
    let (refused, spec) = claim_export(&fx);
    drive_with(
        &fx,
        &(forge.clone() as Arc<dyn kata_effects_contract::Forge>),
    );
    assert_eq!(attempt_state(&fx, refused), "failed");
    let reason = failure_reason_read_only(&fx.planes.op_path, refused);
    assert!(
        reason.starts_with("forge_export_diverged: ") && reason.contains(&theirs),
        "{reason}"
    );
    assert!(intents_read_only(&fx.planes.op_path, refused).is_empty());
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/{branch}")),
        Some(theirs.clone())
    );

    // An earlier export of this execution recorded `theirs` as its performed
    // push (planted through the plane's own writers on a second claim).
    let (earlier, _) = claim_effect_at(&fx, spec.clone(), "earlier", vec![5]);
    let planted = fx
        .planes
        .db
        .record_forge_intent(&kata_core::operational::NewForgeIntent {
            attempt_id: earlier,
            remote: "origin",
            branch: &branch,
            commit: &theirs,
            effect: kata_core::operational::ForgeIntentEffect::Push { lease: None },
        })
        .unwrap()
        .unwrap();
    fx.planes
        .db
        .settle_forge_intent(
            planted.id,
            &kata_core::operational::ForgeIntentOutcome {
                verdict: kata_core::operational::ForgeIntentVerdict::Performed,
                source: kata_core::operational::ForgeVerdictSource::Receipt,
                detail: serde_json::json!({"planted": true}),
            },
        )
        .unwrap();
    let (leased, _) = claim_effect_at(&fx, spec.clone(), "export", vec![6]);
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/13",
    ));
    fx.dispatcher
        .perform_workspace_effect(
            fx.execution_id,
            leased,
            "export",
            &spec,
            &as_provider(&fx.backend),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export drives");
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, leased),
        "completed"
    );
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/{branch}")),
        Some(spec.delivered_commit.clone()),
        "the export landed over this execution's own earlier push"
    );
    assert_eq!(
        leases_read_only(&fx.planes.op_path, leased)[0],
        Some(theirs),
        "leased on the head the read found"
    );
}

/// **The ABA residual, branch deletion included, pinned as stated.** The
/// child's push landed (`after_forge_push_before_pr`); the branch is then
/// deleted on the remote, and kata had found it absent. Back on the lease, the
/// observer reads NOT PERFORMED, and the push is issued again under a fresh
/// intent: the remote's log shows two pushes. ADR 0003 and M0 (finding F9)
/// state this residual; this cell keeps the statement exact.
///
/// **Would red if:** the observer stopped reading a ref back on the lease as
/// NOT PERFORMED (the residual would no longer be what the docs state).
#[test]
fn a_branch_deleted_after_the_push_reads_not_performed_and_is_pushed_again() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, spec) = claim_export(&fx);
    drop(fx);
    let (fx, _) = crash_then_recover(
        "after_forge_push_before_pr",
        dir.path(),
        "a_branch_deleted_after_the_push_reads_not_performed_and_is_pushed_again",
    );
    let branch = format!("refs/heads/kata/{}", fx.execution_id);
    assert_eq!(
        git_rev(&origin, &branch),
        Some(spec.delivered_commit.clone())
    );
    run_git(&origin, &["update-ref", "-d", &branch]);
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/14",
    ));
    drive_with(
        &fx,
        &(forge.clone() as Arc<dyn kata_effects_contract::Forge>),
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(git_rev(&origin, &branch), Some(spec.delivered_commit));
    assert_eq!(pushes(dir.path()).len(), 2, "the push was issued twice");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "not_performed", "observer"),
            intent(1, "push", "performed", "receipt"),
            intent(2, "pull_request", "performed", "receipt"),
        ]
    );
}

/// Run the child's drive against the stateful fake forge at `<dir>` with
/// [`GhFault::ListOpenKillsCaller`] armed, assert the forge killed it inside
/// the open-pull-request lookup — SIGKILL, that lookup the forge's last argv —
/// then disarm the fault and answer the fixture the dead child left.
fn die_in_the_open_lookup(dir: &Path, test: &str) -> Fixture {
    use std::os::unix::process::ExitStatusExt as _;
    arm_gh_fault(dir, GhFault::ListOpenKillsCaller);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture"])
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir)
        .env(CHILD_GH, stateful_gh(dir))
        .output()
        .expect("spawn the child");
    assert_eq!(
        output.status.signal(),
        Some(9),
        "{test}: the forge must SIGKILL the child in its lookup — stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let log = std::fs::read_to_string(dir.join("gh-argv.log")).unwrap();
    let last: Vec<String> = serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert!(
        last.get(..2) == Some(&["pr".to_owned(), "list".to_owned()][..])
            && last.windows(2).any(|pair| pair == ["--state", "open"]),
        "the child died in the open-pull-request lookup, its last forge call: {last:?}"
    );
    disarm_gh_fault(dir, GhFault::ListOpenKillsCaller);
    reopen(dir)
}

/// **A main killed inside the open-pull-request lookup, after its push's
/// receipt, pushes once (DIFF-2).** The child's push lands and returns; the
/// fake forge kills the child inside `gh pr list --state open`. The push's
/// receipt committed before that lookup (second read-only handle). Another
/// party then deletes the branch, back on the absence kata leased on. The
/// recovery reads the push PERFORMED from its row and goes on to the pull
/// request: one push in the remote's own `post-receive` log, never a NOT
/// PERFORMED verdict, one `gh pr create`.
///
/// **Would red if:** the receipt were held in memory across the lookup (the
/// push intent open at the death, the observer then reading the deleted
/// branch NOT PERFORMED and pushing again).
#[test]
fn a_main_killed_in_the_open_lookup_after_the_push_receipt_pushes_once() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, spec) = claim_export(&fx);
    drop(fx);
    let fx = die_in_the_open_lookup(
        dir.path(),
        "a_main_killed_in_the_open_lookup_after_the_push_receipt_pushes_once",
    );
    let branch = format!("refs/heads/kata/{}", fx.execution_id);
    assert_eq!(
        git_rev(&origin, &branch),
        Some(spec.delivered_commit.clone())
    );
    let at_the_death = intents_read_only(&fx.planes.op_path, attempt_id);
    run_git(&origin, &["update-ref", "-d", &branch]);
    drive_with(&fx, &stateful_forge(dir.path()));
    assert_eq!(pushes(dir.path()).len(), 1, "the push was issued once");
    assert_eq!(
        at_the_death,
        [intent(0, "push", "performed", "receipt")],
        "the receipt committed before the lookup"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(forge_creates(dir.path()), 1);
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "performed", "receipt"),
        ]
    );
}

/// **A main killed inside the open-pull-request lookup, after its push
/// observer's answered read, pushes once (DIFF-2, D3-F1).** The first child
/// dies after its push landed and before the receipt
/// (`after_forge_push_before_pr`). The second child's observer reads kata's
/// commit on the remote, PERFORMED, and the fake forge kills it inside `gh pr
/// list --state open`: that verdict committed before the lookup (second
/// read-only handle). Another party then deletes the branch, back on the
/// lease. The recovery asks no observer again: one push in the remote's own
/// log, never a NOT PERFORMED verdict, one `gh pr create`.
///
/// **Would red if:** the observer's PERFORMED were held in memory across the
/// lookup (asked again, it would read the deleted branch NOT PERFORMED and push
/// again — the probe's second push).
#[test]
fn a_main_killed_in_the_open_lookup_after_the_push_observer_answered_pushes_once() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let test = "a_main_killed_in_the_open_lookup_after_the_push_observer_answered_pushes_once";
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, spec) = claim_export(&fx);
    drop(fx);
    let (fx, _) = crash_then_recover("after_forge_push_before_pr", dir.path(), test);
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [open_intent(0, "push")]
    );
    drop(fx);
    let fx = die_in_the_open_lookup(dir.path(), test);
    let branch = format!("refs/heads/kata/{}", fx.execution_id);
    assert_eq!(
        git_rev(&origin, &branch),
        Some(spec.delivered_commit.clone())
    );
    let at_the_death = intents_read_only(&fx.planes.op_path, attempt_id);
    run_git(&origin, &["update-ref", "-d", &branch]);
    drive_with(&fx, &stateful_forge(dir.path()));
    assert_eq!(pushes(dir.path()).len(), 1, "the push was issued once");
    assert_eq!(
        at_the_death,
        [intent(0, "push", "performed", "observer")],
        "the observer's answer committed before the lookup"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(forge_creates(dir.path()), 1);
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "observer"),
            intent(1, "pull_request", "performed", "receipt"),
        ]
    );
}

/// The armed child's drive, against the stateful fake forge at `<dir>`.
fn crash_with_the_stateful_forge(boundary: &str, dir: &Path, test: &str) -> Fixture {
    crash_then_recover_armed(
        &[
            ("KATA_FAULT_INJECT", format!("operational.{boundary}")),
            (CHILD_GH, stateful_gh(dir).display().to_string()),
        ],
        dir,
        test,
    )
    .0
}

/// **After the pull request's intent, before the create**
/// (`after_forge_pr_intent_before_create`). The push's receipt committed
/// before the pull request's open intent, and the forge was asked for no pull
/// request (no `gh pr create` in its log). The
/// recovery's marker observer finds no pull request — NOT PERFORMED, recorded —
/// and the export opens one under a fresh intent: one `gh pr create` (the fake
/// forge's log), whose body carries THAT intent's marker (its state file).
///
/// **Would red if:** an empty marker listing were not read as NOT PERFORMED
/// (the export would fail rather than open its pull request).
#[test]
fn crash_after_forge_pr_intent_before_create_opens_one_pull_request() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, _spec) = claim_export(&fx);
    drop(fx);
    let fx = crash_with_the_stateful_forge(
        "after_forge_pr_intent_before_create",
        dir.path(),
        "crash_after_forge_pr_intent_before_create_opens_one_pull_request",
    );
    assert_eq!(forge_creates(dir.path()), 0);
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            open_intent(1, "pull_request"),
        ]
    );
    drive_with(&fx, &stateful_forge(dir.path()));
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(forge_creates(dir.path()), 1, "one pull request opened");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "not_performed", "observer"),
            intent(2, "pull_request", "performed", "receipt"),
        ]
    );
    let prs = forge_pull_requests(dir.path());
    assert!(
        prs[0]["body"]
            .as_str()
            .unwrap()
            .ends_with(&marker_of(attempt_id, 2)),
        "{prs:?}"
    );
    assert_eq!(pushes(dir.path()).len(), 1, "the push was not repeated");
}

/// **A pull request closed before recovery is adopted, with one create.** The
/// child's create landed (`after_forge_pr_create_before_receipt`) and someone
/// closes the pull request before the recovery. The marker observer lists the
/// head's pull requests in every state, finds the closed one carrying the
/// intent's marker, and adopts it: the export completes naming it, and the
/// forge's log holds one `gh pr create` — where a lookup of OPEN pull requests
/// alone (the baseline's `find_open_pr`) opens a second.
///
/// **Would red if:** the observer read only open pull requests.
#[test]
fn a_pull_request_closed_before_recovery_is_adopted_with_one_create() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, _spec) = claim_export(&fx);
    drop(fx);
    let fx = crash_with_the_stateful_forge(
        "after_forge_pr_create_before_receipt",
        dir.path(),
        "a_pull_request_closed_before_recovery_is_adopted_with_one_create",
    );
    assert_eq!(forge_creates(dir.path()), 1, "the child's create landed");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            open_intent(1, "pull_request"),
        ]
    );
    edit_forge_pull_requests(dir.path(), |pr| pr["state"] = "closed".into());
    drive_with(&fx, &stateful_forge(dir.path()));
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(
        forge_creates(dir.path()),
        1,
        "the closed pull request was adopted"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "performed", "observer"),
        ]
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(
        content["pr_url"].as_str(),
        Some("https://forge.test/o/r/pull/1"),
        "{content}"
    );
}

/// **The deleted-marker residual, pinned as stated.** As above, but someone
/// deletes the marker from the pull request's body and closes it. The observer
/// finds no pull request carrying the marker — NOT PERFORMED — and, with no
/// OPEN pull request on the head for the lookup before the fresh intent to
/// adopt, a second is opened under that intent: two `gh pr create` in the
/// forge's log, the stated residual. (An open one without its marker is
/// adopted by that lookup: `an_open_pull_request_on_the_head_is_adopted_under_no_intent`.)
///
/// **Would red if:** the observer adopted any pull request on the head rather
/// than the one carrying the intent's marker.
#[test]
fn a_closed_pull_request_whose_marker_was_deleted_is_opened_again() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, _spec) = claim_export(&fx);
    drop(fx);
    let fx = crash_with_the_stateful_forge(
        "after_forge_pr_create_before_receipt",
        dir.path(),
        "a_closed_pull_request_whose_marker_was_deleted_is_opened_again",
    );
    edit_forge_pull_requests(dir.path(), |pr| {
        pr["body"] = "edited by a human".into();
        pr["state"] = "closed".into();
    });
    drive_with(&fx, &stateful_forge(dir.path()));
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(
        forge_creates(dir.path()),
        2,
        "a second pull request was opened"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "not_performed", "observer"),
            intent(2, "pull_request", "performed", "receipt"),
        ]
    );
}

/// Install `script` as `origin`'s `pre-receive` hook.
fn pre_receive(origin: &Path, script: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let hook = origin.join("hooks").join("pre-receive");
    std::fs::write(&hook, script).unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// **A push the remote declines, at the lease, on the live leg.** The remote's
/// `pre-receive` hook logs the attempt and declines it, the branch still
/// absent. The push's observer reads the lease — NOT PERFORMED, recorded on
/// the intent — and the export fails with the push's own error, proven not
/// performed: the hook ran once (its log), nothing is on the remote (git), and
/// no pull request was asked for.
///
/// **Would red if:** a NOT PERFORMED verdict after a push that returned an
/// error issued the push again on the live leg (a remote that keeps declining
/// would be pushed to without end).
#[test]
fn a_declined_push_at_the_lease_fails_not_performed_and_is_not_repeated() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let declines = dir.path().join("declines.log");
    pre_receive(
        &origin,
        &format!(
            "#!/bin/sh\necho declined >> '{}'\nexit 1\n",
            declines.display()
        ),
    );
    let (attempt_id, _spec) = claim_export(&fx);
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/15",
    ));
    drive_with(
        &fx,
        &(forge.clone() as Arc<dyn kata_effects_contract::Forge>),
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.starts_with("forge_export: the push of ")
            && reason.contains("still holds the lease (no branch)")
            && reason.contains("it was not performed and nothing is pushed again"),
        "{reason}"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [intent(0, "push", "not_performed", "observer")]
    );
    assert_eq!(
        std::fs::read_to_string(&declines).unwrap().lines().count(),
        1,
        "the push reached the remote once"
    );
    assert_eq!(remote_refs(&origin), "");
    assert!(pushes(dir.path()).is_empty());
    assert_eq!(forge.call_count(), 0);
}

/// **The moved-lease residual, pinned as stated.** Between the read and the
/// push, the branch moves: the remote's `pre-receive` hook writes someone
/// else's commit to `kata/<exec>` outside the push's quarantine, so the push,
/// leased on absence, is refused. The observer reads a head that is neither
/// kata's commit nor the lease: `workspace_effect_unclassified`, the intent
/// `unclassified` (raw) — never NOT PERFORMED, though the push did not land —
/// and the foreign commit stands (git). ADR 0002 decision 4, the driver's
/// module doc, the ledger and the operator guide state this residual; this
/// cell keeps the statement exact.
///
/// **Would red if:** the observer read a head that is neither the commit nor
/// the lease as NOT PERFORMED (a foreign write after kata's push landed would
/// be pushed over).
#[test]
fn a_branch_moved_between_the_read_and_the_push_is_recorded_unclassified() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let foreign = dir.path().join("foreign.sha");
    pre_receive(
        &origin,
        &format!(
            "#!/bin/sh\n\
             unset GIT_QUARANTINE_PATH GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES\n\
             while read old new ref; do\n  \
               tree=$(git --git-dir='{o}' mktree </dev/null)\n  \
               commit=$(GIT_AUTHOR_NAME=someone GIT_AUTHOR_EMAIL=someone@example.invalid \
                 GIT_COMMITTER_NAME=someone GIT_COMMITTER_EMAIL=someone@example.invalid \
                 git --git-dir='{o}' commit-tree \"$tree\" -m 'someone else moved it')\n  \
               git --git-dir='{o}' update-ref \"$ref\" \"$commit\"\n  \
               echo \"$commit\" > '{f}'\n\
             done\n\
             exit 0\n",
            o = origin.display(),
            f = foreign.display()
        ),
    );
    let (attempt_id, spec) = claim_export(&fx);
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/16",
    ));
    drive_with(
        &fx,
        &(forge.clone() as Arc<dyn kata_effects_contract::Forge>),
    );
    let theirs = std::fs::read_to_string(&foreign).unwrap().trim().to_owned();
    assert_recorded_unclassified(&fx, attempt_id, "neither the pushed");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [intent(0, "push", "unclassified", "observer")]
    );
    let branch = format!("refs/heads/kata/{}", fx.execution_id);
    assert_eq!(git_rev(&origin, &branch), Some(theirs), "the move stands");
    assert_ne!(git_rev(&origin, &branch), Some(spec.delivered_commit));
    assert_eq!(forge.call_count(), 0);
}

/// **The push sends the commit its intent recorded, not what the local branch
/// names when `git push` runs.** After the push's intent is recorded (asserted
/// raw, open, from inside the window) and before the push, a write from
/// outside kata moves the colocated root's `refs/heads/kata/<exec>` to another
/// commit — what an operator's `git branch -f` or a jj operation that
/// re-exports bookmarks does. The push still sends the delivered commit: the
/// remote's ref (git) and its own `post-receive` log hold it, the receipt
/// names it (raw), and the pull request opens on the branch that holds it.
/// The outside write stands locally — the local branch only carries the push,
/// the intent names what is pushed, so kata neither pushes nor refuses on it.
///
/// **Would red if:** the push named the local branch as its source (the
/// outside commit would land under the lease and be receipted as the
/// delivered one).
#[test]
fn a_local_branch_moved_after_the_push_intent_does_not_change_what_is_pushed() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = counted_origin(dir.path(), &repo);
    let (attempt_id, spec) = claim_export(&fx);
    let branch = format!("refs/heads/kata/{}", fx.execution_id);
    let outside = git_rev(&repo, "main").expect("the base commit exists");
    assert_ne!(outside, spec.delivered_commit);
    let moved = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let provider: Arc<dyn ExecutionWorkspaceProvider> = Arc::new(Interposed {
        inner: Arc::clone(&fx.backend),
        at: Interposition::BeforePush(Box::new({
            let (repo, branch, outside) = (repo.clone(), branch.clone(), outside.clone());
            let (op_path, moved) = (fx.planes.op_path.clone(), Arc::clone(&moved));
            move || {
                assert_eq!(
                    intents_read_only(&op_path, attempt_id),
                    [open_intent(0, "push")],
                    "the push's intent is recorded, with no verdict, before the move"
                );
                run_git(&repo, &["update-ref", &branch, &outside]);
                moved.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        })),
    });
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/17",
    ));
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&provider),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export drives");
    assert!(
        moved.load(std::sync::atomic::Ordering::SeqCst),
        "the move ran"
    );
    assert_eq!(
        git_rev(&repo, &branch),
        Some(outside.clone()),
        "the outside write stands on the local branch"
    );
    assert_eq!(
        git_rev(&origin, &branch),
        Some(spec.delivered_commit.clone()),
        "the remote holds the intent's commit, not the local branch's"
    );
    let landed = pushes(dir.path());
    assert_eq!(landed.len(), 1, "one push landed: {landed:?}");
    assert!(
        landed[0].split_whitespace().nth(1) == Some(spec.delivered_commit.as_str()),
        "the remote's own log names the delivered commit: {landed:?}"
    );
    assert_eq!(
        verdict_detail_read_only(&fx.planes.op_path, attempt_id, 0)["pushed"],
        serde_json::json!(spec.delivered_commit),
        "the receipt names the commit pushed"
    );
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(forge.call_count(), 1, "one pull request opened");
}

/// What a `forge_export` left behind, each read outside kata: the bare
/// remote's `kata/<exec>` (git), the commits its own `post-receive` hook
/// logged, the push receipt's `pushed` (raw `verdict_json`), the attempt's
/// state (second read-only handle) and the pull requests opened.
#[derive(Debug, PartialEq)]
struct PushSeen {
    remote_ref: Option<String>,
    logged: Vec<String>,
    receipt: serde_json::Value,
    state: String,
    pull_requests: usize,
}

/// A `forge_export` driven once over a write from outside kata.
struct OutsideWritePush {
    /// Keeps the fixture's repositories alive for the caller's reads.
    _dir: tempfile::TempDir,
    repo: std::path::PathBuf,
    origin: std::path::PathBuf,
    /// `refs/heads/kata/<exec>`.
    branch: String,
    delivered: String,
    outside: String,
    seen: PushSeen,
}

impl OutsideWritePush {
    /// What a push of exactly the delivered commit leaves.
    fn delivered_seen(&self) -> PushSeen {
        PushSeen {
            remote_ref: Some(self.delivered.clone()),
            logged: vec![self.delivered.clone()],
            receipt: serde_json::json!(self.delivered),
            state: "completed".to_owned(),
            pull_requests: 1,
        }
    }
}

/// Drive a `forge_export` whose push call first runs `write(repo, delivered,
/// outside)` — a write from outside kata to the colocated root, after the
/// push's intent is recorded (asserted raw, open, from inside the window) and
/// before `git push` runs; `outside` is another commit, the base.
fn push_after_outside_write(
    write: impl Fn(&Path, &str, &str) + Send + Sync + 'static,
) -> OutsideWritePush {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = counted_origin(dir.path(), &repo);
    let (attempt_id, spec) = claim_export(&fx);
    let branch = format!("refs/heads/kata/{}", fx.execution_id);
    let outside = git_rev(&repo, "main").expect("the base commit exists");
    assert_ne!(outside, spec.delivered_commit);
    let provider: Arc<dyn ExecutionWorkspaceProvider> = Arc::new(Interposed {
        inner: Arc::clone(&fx.backend),
        at: Interposition::BeforePush(Box::new({
            let (repo, delivered, outside) =
                (repo.clone(), spec.delivered_commit.clone(), outside.clone());
            let op_path = fx.planes.op_path.clone();
            move || {
                assert_eq!(
                    intents_read_only(&op_path, attempt_id),
                    [open_intent(0, "push")],
                    "the push's intent is recorded, with no verdict, before the write"
                );
                write(&repo, &delivered, &outside);
            }
        })),
    });
    let forge = Arc::new(RecordingForge::succeeding_with_url(
        "https://forge.test/pull/18",
    ));
    fx.dispatcher
        .drive_pending_workspace_effects(
            fx.execution_id,
            Some(&provider),
            Some(&(forge.clone() as Arc<dyn kata_effects_contract::Forge>)),
        )
        .expect("the export drives");
    let seen = PushSeen {
        remote_ref: git_rev(&origin, &branch),
        logged: pushes(dir.path())
            .iter()
            .map(|line| line.split_whitespace().nth(1).unwrap_or("").to_owned())
            .collect(),
        receipt: verdict_detail_read_only(&fx.planes.op_path, attempt_id, 0)["pushed"].clone(),
        state: attempt_state_read_only(&fx.planes.op_path, attempt_id),
        pull_requests: forge.call_count(),
    };
    drop(fx);
    OutsideWritePush {
        _dir: dir,
        repo,
        origin,
        branch,
        delivered: spec.delivered_commit,
        outside,
        seen,
    }
}

/// **No local ref spelled as the commit's object id changes what is pushed.**
/// git resolves a name `<id>` through six rules, first match wins: `<id>`
/// itself (a file at the top of `.git`), `refs/<id>`, `refs/tags/<id>`,
/// `refs/heads/<id>`, `refs/remotes/<id>` and `refs/remotes/<id>/HEAD`; and
/// `git push` matches a bare refspec source against the local refs before it
/// reads it as an object id. For each rule — `<id>` the delivered commit's
/// full hex id, on its own fixture — a write from outside kata, inside the
/// push call after the intent is recorded, creates that ref at another
/// commit. The push still sends the delivered commit: the remote's ref (git)
/// and its own `post-receive` log hold it, the receipt names it (raw), and
/// the export completes with one pull request despite git's
/// ambiguous-refname warning on the push's stderr. Every outcome is collected
/// before the assertion, so a red names each rule that shadowed.
///
/// **Would red if:** the refspec's source were the bare `<id>`, which `git
/// push` reads as the name of a `refs/heads/<id>`, `refs/tags/<id>`,
/// `refs/remotes/<id>` or `refs/remotes/<id>/HEAD` (measured: each such ref's
/// commit lands and is receipted as the delivered one; the top-level `<id>`
/// and `refs/<id>` rows stay green there), or if the push's outcome were read
/// off its stderr rather than its exit status.
#[test]
fn a_local_ref_named_as_the_commit_id_does_not_change_what_is_pushed() {
    let mut wrong = Vec::new();
    for rule in [
        "",
        "refs/",
        "refs/tags/",
        "refs/heads/",
        "refs/remotes/",
        "refs/remotes/{}/HEAD",
    ] {
        let shadow_of = move |id: &str| {
            if rule.contains("{}") {
                rule.replace("{}", id)
            } else {
                format!("{rule}{id}")
            }
        };
        let push = push_after_outside_write(move |repo, delivered, outside| {
            run_git(repo, &["update-ref", &shadow_of(delivered), outside]);
        });
        let shadow = shadow_of(&push.delivered);
        // `git rev-parse <id>` answers the object id itself, so the top-level
        // ref is read off its file.
        let stands = if rule.is_empty() {
            std::fs::read_to_string(push.repo.join(".git").join(&shadow))
                .ok()
                .map(|held| held.trim().to_owned())
        } else {
            git_rev(&push.repo, &shadow)
        };
        assert_eq!(
            stands,
            Some(push.outside.clone()),
            "{shadow}: the shadowing ref was written and stands"
        );
        if push.seen != push.delivered_seen() {
            wrong.push(format!(
                "{shadow}: {:?}, delivered {}, shadow at {}",
                push.seen, push.delivered, push.outside
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "a ref named as the commit id changed what was pushed:\n{}",
        wrong.join("\n")
    );
}

/// **A local replace ref or graft does not change what is pushed.** A write
/// from outside kata, inside the push call after the intent is recorded, on
/// its own fixture per row: `refs/replace/<id>` — `<id>` the delivered commit
/// — at an annotated tag of another commit, and at that other commit itself
/// (`git replace`); and a `.git/info/grafts` line giving the delivered
/// commit, and on another fixture its parent (an unpushed ancestor), one more
/// parent: a new commit outside the delivered history. git reads an object through its replace ref
/// unless replacement is off, so with it on the source `<id>^{commit}` peels
/// the tag to the other commit, and a pack could carry the replacement's
/// content under `<id>`; and it walks a graft's parents when it packs, so the
/// grafted-in parent commit would leave too. The push still sends the
/// delivered commit: the remote's ref (git) and its own `post-receive` log
/// hold it, the receipt names it (raw), the export completes with one pull
/// request, and the remote, empty before the export, holds exactly the
/// objects the delivered commit reaches — read with git, on the remote, and
/// in the local repository with replacement off and no graft file. The
/// replace ref and the graft file stand. Every outcome is collected before
/// the assertion.
///
/// **Would red if:** the push ran with replace refs honored (the tag row's
/// other commit would land and be receipted as the delivered one), or read
/// the repository's graft file (both graft rows' outside commit would land on
/// the remote).
#[test]
fn a_local_replace_ref_or_graft_does_not_change_what_is_pushed() {
    /// Every object `args` lists in `repo`, read with replacement off and no
    /// graft file, sorted.
    fn objects(repo: &Path, args: &[&str]) -> Vec<String> {
        let out = hermetic_git_in(repo)
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_GRAFT_FILE", "/dev/null")
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} runs in {}",
            repo.display()
        );
        let mut ids: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|line| line.split_whitespace().next().unwrap_or("").to_owned())
            .collect();
        ids.sort();
        ids
    }
    /// A `.git/info/grafts` line giving `grafted` one more parent: a new
    /// commit, `refs/outside/grafted`, outside the delivered history.
    fn graft(repo: &Path, grafted: &str, outside: &str) {
        let extra = hermetic_git_in(repo)
            .args([
                "commit-tree",
                "-m",
                "outside the delivered history",
                &format!("{outside}^{{tree}}"),
            ])
            .output()
            .unwrap();
        assert!(extra.status.success(), "the outside commit is written");
        let extra = String::from_utf8_lossy(&extra.stdout).trim().to_owned();
        run_git(repo, &["update-ref", "refs/outside/grafted", &extra]);
        let parents = hermetic_git_in(repo)
            .args(["rev-parse", &format!("{grafted}^@")])
            .output()
            .unwrap();
        let parents = String::from_utf8_lossy(&parents.stdout).replace('\n', " ");
        std::fs::create_dir_all(repo.join(".git/info")).unwrap();
        std::fs::write(
            repo.join(".git/info/grafts"),
            format!("{grafted} {} {extra}\n", parents.trim()),
        )
        .unwrap();
    }
    let mut wrong = Vec::new();
    for row in [
        "replace by an annotated tag",
        "replace by a commit",
        "graft on the delivered commit",
        "graft on its unpushed parent",
    ] {
        let push = push_after_outside_write(move |repo, delivered, outside| match row {
            "replace by a commit" => run_git(
                repo,
                &["update-ref", &format!("refs/replace/{delivered}"), outside],
            ),
            "replace by an annotated tag" => {
                run_git(repo, &["tag", "-a", "-m", "outside", "outside", outside]);
                let tag = git_rev(repo, "refs/tags/outside").expect("the tag was written");
                run_git(
                    repo,
                    &["update-ref", &format!("refs/replace/{delivered}"), &tag],
                );
            }
            "graft on the delivered commit" => graft(repo, delivered, outside),
            _ => graft(
                repo,
                &git_rev(repo, &format!("{delivered}~1")).expect("the delivered commit's parent"),
                outside,
            ),
        });
        if row.starts_with("replace") {
            assert!(
                git_rev(&push.repo, &format!("refs/replace/{}", push.delivered)).is_some(),
                "{row}: the replace ref was written and stands"
            );
        } else {
            let extra = git_rev(&push.repo, "refs/outside/grafted").expect("the outside commit");
            let grafts = std::fs::read_to_string(push.repo.join(".git/info/grafts"))
                .expect("the graft file stands");
            assert!(grafts.contains(&extra), "{row}: {grafts}");
            // The graft does reach outside the delivered history: git reading
            // the graft file lists the outside commit, which the delivered
            // commit's own history (no graft file) does not hold.
            let grafted = hermetic_git_in(&push.repo)
                .args(["rev-list", &push.delivered])
                .output()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&grafted.stdout).contains(&extra),
                "{row}: the graft gives the delivered history the outside commit"
            );
            assert!(
                !objects(&push.repo, &["rev-list", "--objects", &push.delivered]).contains(&extra),
                "{row}: the outside commit is not in the delivered history"
            );
        }
        let reached = objects(&push.repo, &["rev-list", "--objects", &push.delivered]);
        let remote = objects(
            &push.origin,
            &[
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname)",
            ],
        );
        if push.seen != push.delivered_seen() || remote != reached {
            let extra: Vec<&String> = remote.iter().filter(|id| !reached.contains(id)).collect();
            let missing: Vec<&String> = reached.iter().filter(|id| !remote.contains(id)).collect();
            wrong.push(format!(
                "{row}: {:?}, remote objects the delivered commit does not reach {extra:?}, \
                 objects it reaches the remote lacks {missing:?}, delivered {}",
                push.seen, push.delivered
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "a replace ref or graft changed what was pushed:\n{}",
        wrong.join("\n")
    );
}

/// **The push writes its one branch, and only it, whatever the push
/// configuration says.** A write from outside kata, inside the push call after
/// the intent is recorded, sets the colocated root's config, one row per
/// fixture: `push.followTags=true` with an annotated tag written at the
/// delivered commit and another at its parent; and
/// `push.recurseSubmodules=only`, under which `git push` pushes submodules and
/// not the repository itself, and still exits 0. Each export completes with
/// the delivered commit pushed — the remote's ref (git), its `post-receive`
/// log, the receipt (raw) — and the remote, empty before the export, holds
/// exactly `kata/<exec>` at the delivered commit and nothing else (git).
/// Every outcome is collected before the assertion.
///
/// **Would red if:** the push followed the configuration's `followTags` (both
/// annotated tags reach the history pushed, so both would land), or its
/// `recurseSubmodules` (`only` writes nothing, receipted as the delivered
/// commit pushed).
#[test]
fn the_push_writes_its_one_branch_whatever_the_push_configuration_says() {
    let mut wrong = Vec::new();
    for row in ["push.followTags", "push.recurseSubmodules"] {
        let push = push_after_outside_write(move |repo, delivered, _outside| {
            if row == "push.followTags" {
                run_git(repo, &["config", "push.followTags", "true"]);
                run_git(
                    repo,
                    &["tag", "-a", "-m", "delivered", "delivered", delivered],
                );
                run_git(
                    repo,
                    &[
                        "tag",
                        "-a",
                        "-m",
                        "parent",
                        "parent",
                        &format!("{delivered}~1"),
                    ],
                );
            } else {
                run_git(repo, &["config", "push.recurseSubmodules", "only"]);
            }
        });
        if row == "push.followTags" {
            assert!(
                git_rev(&push.repo, "refs/tags/delivered").is_some()
                    && git_rev(&push.repo, "refs/tags/parent").is_some(),
                "both tags stand locally"
            );
        }
        let remote = remote_refs(&push.origin);
        if push.seen != push.delivered_seen()
            || remote != format!("{} {}\n", push.delivered, push.branch)
        {
            wrong.push(format!(
                "{row}: {:?}, remote refs {remote:?}, delivered {}",
                push.seen, push.delivered
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "the push configuration changed what was written:\n{}",
        wrong.join("\n")
    );
}

/// **A create that errs after it opened the pull request is adopted.** The
/// fake forge opens the pull request, prints its URL and exits non-zero. The
/// marker observer finds it — PERFORMED, recorded by the observer — and the
/// export completes naming it, with one `gh pr create` in the forge's log.
///
/// **Would red if:** a create that returned an error were failed without
/// asking its observer (the opened pull request would be disowned).
#[test]
fn a_create_that_errs_after_opening_its_pull_request_is_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let forge = stateful_forge(dir.path());
    arm_gh_fault(dir.path(), GhFault::CreateErrsAfterOpening);
    let (attempt_id, _spec) = claim_export(&fx);
    drive_with(&fx, &forge);
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(forge_creates(dir.path()), 1);
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "performed", "observer"),
        ]
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(
        content["pr_url"].as_str(),
        Some("https://forge.test/o/r/pull/1"),
        "{content}"
    );
}

/// **A create the forge refuses, opening nothing, on the live leg.** The
/// marker observer finds no pull request — NOT PERFORMED, recorded — and the
/// export fails with the create's own error: one `gh pr create` in the
/// forge's log, no pull request on it, and the pushed branch standing (git).
///
/// **Would red if:** a NOT PERFORMED verdict after a create that returned an
/// error issued the create again on the live leg (a forge that keeps refusing
/// would be asked without end).
#[test]
fn a_refused_create_fails_not_performed_and_is_not_repeated() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let forge = stateful_forge(dir.path());
    arm_gh_fault(dir.path(), GhFault::CreateRefused);
    let (attempt_id, spec) = claim_export(&fx);
    drive_with(&fx, &forge);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.contains("the forge refused the create")
            && reason.contains("so no pull request was opened; the pushed branch stands"),
        "{reason}"
    );
    assert_eq!(forge_creates(dir.path()), 1, "one create was asked for");
    assert!(forge_pull_requests(dir.path()).is_empty());
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "not_performed", "observer"),
        ]
    );
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
        Some(spec.delivered_commit)
    );
}

/// **A create that errs over a forge that cannot be listed stays open, and
/// fails not performed once the forge answers.** The create is refused and
/// the marker observer's `gh pr list --state all` fails too: the attempt stays
/// `pending`, the pull-request intent open with the create's error and one
/// unanswered read (raw). A second sweep at once does not list again (the
/// forge's own argv log holds one marker listing). The listing is restored and
/// `kata run forge-reconcile` asks: no pull request carries the marker — NOT
/// PERFORMED — so the export fails with the create's error, one create in the
/// forge's log and no pull request on it.
///
/// **Would red if:** a listing that did not answer settled the intent at once
/// (as UNCLASSIFIED, the code before owner decision #15, or as NOT PERFORMED),
/// or the sweep listed again before the spacing passed.
#[test]
fn a_create_that_errs_over_an_unlistable_forge_stays_open_then_fails_not_performed() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let forge = stateful_forge(dir.path());
    arm_gh_fault(dir.path(), GhFault::CreateRefused);
    arm_gh_fault(dir.path(), GhFault::ListAllFails);
    let (attempt_id, _spec) = claim_export(&fx);
    drive_with(&fx, &forge);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "pending"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            open_intent(1, "pull_request"),
        ]
    );
    let (count, last_error, command_error) =
        unanswered_read_only(&fx.planes.op_path, attempt_id, 1);
    assert_eq!(count, 1);
    assert!(
        last_error
            .as_deref()
            .is_some_and(|error| error.contains("the forge did not answer the listing")),
        "{last_error:?}"
    );
    assert!(
        command_error
            .as_deref()
            .is_some_and(|error| error.contains("the forge refused the create")),
        "{command_error:?}"
    );
    assert_eq!(forge_marker_reads(dir.path()), 1);
    drive_with(&fx, &forge);
    assert_eq!(
        forge_marker_reads(dir.path()),
        1,
        "the sweep does not list again before the spacing passes"
    );

    disarm_gh_fault(dir.path(), GhFault::ListAllFails);
    reconcile_with(&fx, &forge).expect("the reconcile asks");
    assert_eq!(forge_marker_reads(dir.path()), 2);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.contains("the forge refused the create")
            && reason.contains("so no pull request was opened; the pushed branch stands"),
        "{reason}"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "not_performed", "observer"),
        ]
    );
    assert_eq!(forge_creates(dir.path()), 1, "the create was not repeated");
    assert!(forge_pull_requests(dir.path()).is_empty());
}

/// **A marker listing past its bound is an answer: UNCLASSIFIED at once.** The
/// child died after the pull request's intent, before the create; the fake
/// forge then holds 100 closed pull requests on the head, none marked — the
/// listing's bound. The observer cannot rule a marked one out, and asking again
/// does not change that, so the export is recorded failed
/// `workspace_effect_unclassified` on the first ask with no unanswered read
/// counted (raw), and no create in the forge's log.
///
/// **Would red if:** a listing at its bound were read as NOT PERFORMED (a
/// second pull request) or as an unanswered read (asked ten times over).
#[test]
fn a_marker_listing_past_its_bound_settles_unclassified_at_once() {
    workspace_effect_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let (attempt_id, _spec) = claim_export(&fx);
    drop(fx);
    let fx = crash_with_the_stateful_forge(
        "after_forge_pr_intent_before_create",
        dir.path(),
        "a_marker_listing_past_its_bound_settles_unclassified_at_once",
    );
    let head = format!("kata/{}", fx.execution_id);
    let flood: Vec<serde_json::Value> = (1..=100)
        .map(|number| {
            serde_json::json!({
                "number": number,
                "url": format!("https://forge.test/o/r/pull/{number}"),
                "head": head,
                "base": "main",
                "title": "someone else's",
                "body": "no marker",
                "state": "closed",
            })
        })
        .collect();
    std::fs::write(
        dir.path().join("gh-prs.json"),
        serde_json::to_vec(&flood).unwrap(),
    )
    .unwrap();
    drive_with(&fx, &stateful_forge(dir.path()));
    assert_recorded_unclassified(&fx, attempt_id, "its bound");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "unclassified", "observer"),
        ]
    );
    assert_eq!(unanswered_read_only(&fx.planes.op_path, attempt_id, 1).0, 0);
    assert_eq!(forge_creates(dir.path()), 0);
}

/// **An open pull request from the head into another base is not the
/// export's.** The fake forge holds an open pull request from `kata/<exec>`
/// into `release`; the export's base is `main`. The lookup adopts nothing, so
/// the export opens its own under an intent: two pull requests on the forge
/// (its state file), the export naming the new one into `main`.
///
/// **Would red if:** the lookup adopted any open pull request on the head
/// (vcs-effects-evidence-7): the export would report the pull request into
/// `release` as its own.
#[test]
fn an_open_pull_request_into_another_base_is_not_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let forge = stateful_forge(dir.path());
    let (attempt_id, _spec) = claim_export(&fx);
    std::fs::write(
        dir.path().join("gh-prs.json"),
        serde_json::to_vec(&serde_json::json!([{
            "number": 1,
            "url": "https://forge.test/o/r/pull/1",
            "head": format!("kata/{}", fx.execution_id),
            "base": "release",
            "title": "into another base",
            "body": "no marker",
            "state": "open",
        }]))
        .unwrap(),
    )
    .unwrap();
    drive_with(&fx, &forge);
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(forge_creates(dir.path()), 1);
    let prs = forge_pull_requests(dir.path());
    assert_eq!(prs.len(), 2, "{prs:?}");
    assert_eq!(prs[1]["base"], "main");
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(
        content["pr_url"].as_str(),
        Some("https://forge.test/o/r/pull/2"),
        "{content}"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "performed", "receipt"),
        ]
    );
}

/// **A forge that does not answer the open-pull-request lookup records no
/// intent.** Every `gh pr list` fails. The lookup runs before the pull
/// request's intent, so the export fails `forge_export_forge_unread`, PROVEN
/// NOT PERFORMED (second read-only handle): no pull-request intent row (raw,
/// the push's receipt written beside the failure), no `gh pr create` in the
/// forge's log, and the pushed branch standing (git).
///
/// **Would red if:** the lookup ran after the pull request's intent (the
/// marker observer, failing too, would record the intent `unclassified`
/// though nothing was sent).
#[test]
fn a_forge_that_does_not_answer_the_lookup_records_no_intent_and_is_not_performed() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let origin = counted_origin(dir.path(), &dir.path().join("repo"));
    let forge = stateful_forge(dir.path());
    arm_gh_fault(dir.path(), GhFault::ListFails);
    let (attempt_id, spec) = claim_export(&fx);
    drive_with(&fx, &forge);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.starts_with("forge_export_forge_unread: ")
            && reason.contains("the forge did not answer the listing")
            && reason.contains("PROVEN NOT PERFORMED"),
        "{reason}"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [intent(0, "push", "performed", "receipt")]
    );
    assert_eq!(forge_creates(dir.path()), 0, "no create was asked for");
    assert_eq!(
        git_rev(&origin, &format!("refs/heads/kata/{}", fx.execution_id)),
        Some(spec.delivered_commit)
    );
}

/// **An open pull request already on the head is adopted under no intent.**
/// The fake forge holds an open pull request on `kata/<exec>` that carries no
/// marker. The lookup before the pull request's intent finds it, and the
/// export completes naming it (`pr_url`, second read-only handle) with no
/// pull-request intent row (raw) and no `gh pr create` in the forge's log:
/// adopting sends nothing, so nothing is intended.
///
/// **Would red if:** the lookup ran under a pull-request intent (an intent
/// row for an effect never sent), or a second pull request were opened.
#[test]
fn an_open_pull_request_on_the_head_is_adopted_under_no_intent() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let forge = stateful_forge(dir.path());
    let (attempt_id, _spec) = claim_export(&fx);
    std::fs::write(
        dir.path().join("gh-prs.json"),
        serde_json::to_vec(&serde_json::json!([{
            "number": 7,
            "url": "https://forge.test/o/r/pull/7",
            "head": format!("kata/{}", fx.execution_id),
            "base": "main",
            "title": "opened by hand",
            "body": "no marker",
            "state": "open",
        }]))
        .unwrap(),
    )
    .unwrap();
    drive_with(&fx, &forge);
    assert_eq!(attempt_state(&fx, attempt_id), "completed");
    assert_eq!(forge_creates(dir.path()), 0, "nothing was opened");
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [intent(0, "push", "performed", "receipt")]
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(
        content["pr_url"].as_str(),
        Some("https://forge.test/o/r/pull/7"),
        "{content}"
    );
}

/// **The pull request opens, and is observed, in the repository the push
/// remote names — never gh's default.** The claim records `origin`
/// (`forge.test/o/r`); an `upstream` remote (`forge.test/o/upstream`), which
/// gh's own default ranks ahead of `origin`, is added after it. The create
/// opens its pull request and then errs, so the marker observer decides it.
/// Read outside kata: the confirmation before the push (`gh repo view`) names
/// `forge.test/o/r`, every `gh pr` argv in the fake forge's log carries
/// `--repo forge.test/o/r`, the forge holds one pull request, in `o/r`, on
/// `kata/<exec>`, and the export completes naming it (second read-only
/// handle) with its pull request's intent PERFORMED by the observer.
///
/// **Would red if:** any `gh` call ran without `--repo` bound to the recorded
/// remote's repository (R3-02): the create would open in `o/upstream`, where
/// the branch was never pushed, and the observer would read there.
#[test]
fn the_pull_request_opens_and_is_observed_in_the_push_remotes_repository() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    counted_origin(dir.path(), &repo);
    let forge = stateful_forge(dir.path());
    let (attempt_id, _spec) = claim_export(&fx);
    forge_remote(dir.path(), &repo, "upstream");
    arm_gh_fault(dir.path(), GhFault::CreateErrsAfterOpening);
    drive_with(&fx, &forge);
    let prs = forge_pull_requests(dir.path());
    assert_eq!(prs.len(), 1, "{prs:?}");
    assert_eq!(prs[0]["repo"].as_str(), Some("forge.test/o/r"), "{prs:?}");
    let argvs: Vec<Vec<String>> = std::fs::read_to_string(dir.path().join("gh-argv.log"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        argvs[0],
        ["repo", "view", "forge.test/o/r", "--json", "nameWithOwner"],
        "the confirmation before the push names the push remote's repository"
    );
    assert_eq!(
        argvs.len(),
        4,
        "confirmation, lookup, create, observer: {argvs:?}"
    );
    for argv in &argvs[1..] {
        assert!(
            argv.windows(2)
                .any(|pair| pair == ["--repo", "forge.test/o/r"]),
            "every gh call names the push remote's repository: {argv:?}"
        );
    }
    assert_eq!(
        prs[0]["head"].as_str(),
        Some(format!("kata/{}", fx.execution_id).as_str())
    );
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "performed", "observer"),
        ]
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(content["pr_url"], prs[0]["url"], "{content}");
}

/// **An export whose push remote names no forge repository is refused before
/// anything is written or pushed.** `origin` is a bare directory by its path,
/// a URL with no host, so no repository can be named for `gh --repo`. The
/// export fails `forge_export_repository_unresolved` (second read-only
/// handle) with no intent row, nothing on the remote (its own refs) and no
/// `gh` call (the fake forge's log).
///
/// **Would red if:** the repository were resolved only at the pull request
/// (the branch would be pushed for a pull request that cannot open), or gh's
/// default repository stood in for it (R3-02).
#[test]
fn an_export_whose_push_remote_names_no_forge_repository_is_refused_before_the_push() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = dir.path().join("origin.git");
    run_git(
        dir.path(),
        &["init", "--bare", "-q", origin.to_str().unwrap()],
    );
    run_git(
        &repo,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    let forge = stateful_forge(dir.path());
    let (attempt_id, _spec) = claim_export(&fx);
    drive_with(&fx, &forge);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.contains("forge_export_repository_unresolved") && reason.contains("origin"),
        "{reason}"
    );
    assert!(intents_read_only(&fx.planes.op_path, attempt_id).is_empty());
    assert_eq!(remote_refs(&origin), "", "nothing was pushed");
    assert!(
        !dir.path().join("gh-argv.log").exists(),
        "no gh call was made"
    );
}

/// **A refused push remote's password is never recorded.** `origin`'s URL
/// carries the password `SECRET` and a path deeper than `OWNER/REPO`, so the
/// export fails `forge_export_repository_unresolved`; the failure reason, read
/// through a second read-only handle, names the remote and the URL's host and
/// path, and holds neither the password nor the user name.
///
/// **Would red if:** the refusal rendered the configured URL whole (L3 re-fix
/// blocker): the attempt's durable failure reason, which the API and CLI show,
/// would carry the credential.
#[test]
fn a_refused_push_remotes_password_is_never_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    run_git(
        &repo,
        &[
            "remote",
            "add",
            "origin",
            "https://user:SECRET@forge.test/group/sub/r.git",
        ],
    );
    let forge = stateful_forge(dir.path());
    let (attempt_id, _spec) = claim_export(&fx);
    drive_with(&fx, &forge);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.starts_with("forge_export_repository_unresolved:")
            && reason.contains("forge.test/group/sub/r.git"),
        "{reason}"
    );
    assert!(
        !reason.contains("SECRET") && !reason.contains("user"),
        "the recorded reason shows the URL's userinfo: {reason}"
    );
}

/// **An export whose repository `gh` cannot address is refused before the
/// push.** `origin` is an SSH host alias, `git@github-work:o/r.git`, which an
/// `insteadOf` sends to the rig's bare remote, so git can push to it; its
/// repository reads `github-work/o/r`, a host the fake forge cannot reach, as
/// gh 2.103.3 cannot (`error connecting to github-work`). The export fails
/// `forge_export_repository_unaddressed` (second read-only handle) with no
/// intent row, nothing on the remote (its own refs), and one `gh` call, the
/// read-only `repo view` (the fake forge's log).
///
/// **Would red if:** the pre-push check stopped at the URL's reading (L3
/// re-fix, R3-02's alias case): the branch would be pushed, and only the
/// lookup after it would find the forge unreachable.
#[test]
fn an_export_whose_repository_gh_cannot_address_is_refused_before_the_push() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    let repo = dir.path().join("repo");
    let origin = dir.path().join("origin.git");
    run_git(
        dir.path(),
        &["init", "--bare", "-q", origin.to_str().unwrap()],
    );
    let alias = "git@github-work:o/r.git";
    run_git(&repo, &["remote", "add", "origin", alias]);
    run_git(
        &repo,
        &[
            "config",
            &format!("url.{}.insteadOf", origin.display()),
            alias,
        ],
    );
    let forge = stateful_forge(dir.path());
    let (attempt_id, _spec) = claim_export(&fx);
    drive_with(&fx, &forge);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    let reason = failure_reason_read_only(&fx.planes.op_path, attempt_id);
    assert!(
        reason.starts_with("forge_export_repository_unaddressed:")
            && reason.contains("github-work/o/r"),
        "{reason}"
    );
    assert!(intents_read_only(&fx.planes.op_path, attempt_id).is_empty());
    assert_eq!(remote_refs(&origin), "", "nothing was pushed");
    let argvs: Vec<Vec<String>> = std::fs::read_to_string(dir.path().join("gh-argv.log"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        argvs,
        [["repo", "view", "github-work/o/r", "--json", "nameWithOwner"]],
        "the one gh call is the read-only confirmation"
    );
}

/// **A fork's pull request on the export's head name is not adopted.** The
/// fake forge holds an open pull request into `main` from a branch named
/// `kata/<exec>` in another repository (`isCrossRepository`), which `gh pr list
/// --head` lists by name. The lookup does not adopt it: the export opens its
/// own under an intent (one `gh pr create` in the forge's log, a second pull
/// request in its state) and records that one (`pr_url`, second read-only
/// handle).
///
/// **Would red if:** the lookup adopted any open pull request on the head
/// name into the base (R3-01): the export would complete naming the fork's
/// pull request, with no pull request of its own.
#[test]
fn a_fork_pull_request_on_the_head_name_is_not_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let forge = stateful_forge(dir.path());
    let (attempt_id, _spec) = claim_export(&fx);
    let head = format!("kata/{}", fx.execution_id);
    std::fs::write(
        dir.path().join("gh-prs.json"),
        serde_json::to_vec(&serde_json::json!([{
            "number": 7,
            "url": "https://forge.test/o/r/pull/7",
            "head": head,
            "base": "main",
            "title": "a fork's branch of the same name",
            "body": "no marker",
            "state": "open",
            "isCrossRepository": true,
        }]))
        .unwrap(),
    )
    .unwrap();
    drive_with(&fx, &forge);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "completed"
    );
    assert_eq!(forge_creates(dir.path()), 1, "the export opened its own");
    let prs = forge_pull_requests(dir.path());
    assert_eq!(prs.len(), 2, "{prs:?}");
    assert_eq!(prs[1]["head"].as_str(), Some(head.as_str()));
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "performed", "receipt"),
        ]
    );
    let content = resolved_content_read_only(&fx.planes.op_path, attempt_id);
    assert_eq!(content["pr_url"], prs[1]["url"], "{content}");
}

/// **The observer adopts only the intent's own marker.** A closed pull request
/// on the head carries the marker of the same attempt's intent 10, whose
/// coordinates begin with intent 1's; the create under intent 1 is refused.
/// The observer finds no pull request carrying intent 1's marker, terminator
/// included — NOT PERFORMED — and the export fails, adopting nothing.
///
/// **Would red if:** the observer matched the marker as a prefix (intent 1
/// would adopt intent 10's pull request).
#[test]
fn a_pull_request_marked_for_another_intent_is_not_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture_with(dir.path(), "forge_export", FixtureInvocation::FrozenTrunk);
    counted_origin(dir.path(), &dir.path().join("repo"));
    let forge = stateful_forge(dir.path());
    let (attempt_id, _spec) = claim_export(&fx);
    std::fs::write(
        dir.path().join("gh-prs.json"),
        serde_json::to_vec(&serde_json::json!([{
            "number": 1,
            "url": "https://forge.test/o/r/pull/1",
            "head": format!("kata/{}", fx.execution_id),
            "base": "main",
            "title": "another intent's pull request",
            "body": format!("Exported\n\n{}", marker_of(attempt_id, 10)),
            "state": "closed",
        }]))
        .unwrap(),
    )
    .unwrap();
    arm_gh_fault(dir.path(), GhFault::CreateRefused);
    drive_with(&fx, &forge);
    assert_eq!(
        attempt_state_read_only(&fx.planes.op_path, attempt_id),
        "failed"
    );
    assert_eq!(
        intents_read_only(&fx.planes.op_path, attempt_id),
        [
            intent(0, "push", "performed", "receipt"),
            intent(1, "pull_request", "not_performed", "observer"),
        ]
    );
}
