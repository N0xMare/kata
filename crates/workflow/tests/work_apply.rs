//! The `/work` apply driven end to end: a recorded capsule
//! delta lands on the execution workspace's candidate through
//! `Dispatcher::drive_pending_work_applies`, the head row advances in the
//! resolving transaction, recovery classifies a published-but-unresolved apply,
//! and an empty delta never touches jj.
//!
//! These cells run REAL jj workspaces (a git-colocated repo in a tempdir) and
//! the real nucleus — the assertions read `git` output and the raw schema,
//! never the code under test.

use kata_core::InFlightLedger;
use kata_core::operational::{
    AttemptClaimSpec, CapsuleDeclaration, CapsuleResultAdoption, ExecutionWorkTreeHead,
    MainAttemptSpec, OccurrenceBinding, WorkApplyClaimOutcome, WorkerCompletionInput,
};
use kata_core::store::cas::CasStore;
use kata_core::{InvocationKind, InvocationRecord, OperationalDb, ProgramRecord};
use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_transport::WorkerPoolSupervisor;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_types::execution_contract::work_apply_stage_id;
use kata_types::execution_contract::{
    ArtifactId, ArtifactPrivacy, ArtifactRef, Capsule, CapsuleBudgets, CapsuleNetwork,
    CapsuleProcess, EnvironmentId, GuestAccess, GuestMapping, GuestPath, OccurrenceId,
    OccurrenceRef, OperationContractId, OperationPath, PlatformId, PreparedActionId,
    work_apply_operation_contract,
};
use kata_types::primitives::ContentHash;
use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxDirective};
use kata_types::tree_artifact::{
    TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath, WorkTreeInputBounds,
};
use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};
use kata_vcs::{JjBackend, VcsBackend};
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use ulid::Ulid;

const STAGE: &str = "digest";
const MEMBER: &[u8] = b"the worker wrote this\n";

struct Planes {
    _dir: tempfile::TempDir,
    op_path: std::path::PathBuf,
    db: Arc<OperationalDb>,
    cas: Arc<CasStore>,
}

fn planes(dir: &Path) -> Planes {
    let data_dir = dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    // `open`/`open_with_cas` adopt an existing nucleus — a crash-cell child
    // reopens the parent's planes verbatim.
    let cas = Arc::new(CasStore::open(data_dir.join("cas.db"), data_dir.join("cas")).unwrap());
    let db = Arc::new(
        OperationalDb::open_with_cas(data_dir.join("operational.db"), Arc::clone(&cas)).unwrap(),
    );
    Planes {
        _dir: tempfile::tempdir().unwrap(),
        op_path: data_dir.join("operational.db"),
        db,
        cas,
    }
}

fn dispatcher(db: &Arc<OperationalDb>) -> Dispatcher {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(50),
    ));
    let ledger = InFlightLedger::in_memory();
    Dispatcher::new(Arc::clone(&supervisor), heartbeat, Arc::clone(&ledger))
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
        admission_digest: kata_types::identity_algebra::AdmissionDigest(ContentHash::new(
            *blake3::hash(&invocation_json).as_bytes(),
        )),
        invocation_json,
    }
}

/// A program with one stage `digest` that authors `produces_files = ["r"]`
/// under a WRITABLE workspace — the produces_files-scope cells need a posture
/// whose declared closure is the live question; a `ro` stage refuses the same
/// delta earlier, by posture, which is `program_with_ro_scope`'s cell.
fn program_with_scope() -> kata_program::execution_program::ExecutionProgram {
    program_with_workspace(
        "rw",
        "produces_files = [\"r\", \".gitattributes\", \"owned\"],",
    )
}

/// The same shape as [`program_with_scope`] but `workspace = "ro"` and NO
/// `produces_files` — the pair is a contradiction CHECK refuses by name
/// (`produces_files_under_read_only_workspace`), so the runtime
/// cell exercises the posture alone: a stage that may write nothing and
/// reports any delta is refused before a closure question can arise.
fn program_with_ro_scope() -> kata_program::execution_program::ExecutionProgram {
    program_with_workspace("ro", "")
}

fn program_with_workspace(
    workspace: &str,
    closure_line: &str,
) -> kata_program::execution_program::ExecutionProgram {
    let pack = format!(
        "probe = stage(\n\
         \x20   id = \"digest\",\n\
         \x20   agent = \"shell\",\n\
         \x20   sandbox = \"iso\",\n\
         \x20   timeout_ms = 30000,\n\
         \x20   {closure_line}\n\
         \x20   prompt = \"echo done > /work/r\",\n\
         )\n\
         workflow(\n\
         \x20   \"work-apply-cell\",\n\
         \x20   root = [probe],\n\
         \x20   sandbox_profiles = {{\n\
         \x20       \"iso\": sandbox_profile(workspace = \"{workspace}\", net = \"offline\"),\n\
         \x20   }},\n\
         )\n"
    );
    kata_program::execution_program::compile_starlark_execution_program(
        &pack,
        "work-apply-cell.star",
        &[],
    )
    .expect("the cell's pack compiles")
}

fn occurrence_ref(
    execution_id: Ulid,
    program: &kata_program::execution_program::ExecutionProgram,
) -> (OccurrenceRef, kata_types::workflow::StageId) {
    let stage_id = kata_types::workflow::StageId(smol_str::SmolStr::new(STAGE));
    let lowered = kata_program::execution_program::lower_stage_operation(program, &stage_id)
        .expect("the digest stage lowers");
    (
        OccurrenceRef::new(
            kata_types::workflow::ExecutionId(execution_id),
            program.program_hash,
            lowered.contract.id(),
            lowered.path.clone(),
        ),
        stage_id,
    )
}

fn capsule(occurrence: OccurrenceId, work: ArtifactId) -> Capsule {
    capsule_running(
        occurrence,
        work,
        CapsuleProcess::Command {
            argv: vec!["sh".into(), "-c".into(), "echo done > /work/r".into()],
        },
    )
}

/// The `Agent` process the charge cells authorize: a `nanocode_openai` turn on a
/// declared model.
fn agent_process() -> CapsuleProcess {
    CapsuleProcess::Agent(kata_types::execution_contract::AgentTurnSpec {
        adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
        model: Some("gpt-declared".into()),
        reasoning_effort: None,
        output_schema: None,
        prompt: ArtifactId(ContentHash::new([0x51; 32])),
        credential: None,
        env: BTreeMap::new(),
    })
}

fn capsule_running(occurrence: OccurrenceId, work: ArtifactId, process: CapsuleProcess) -> Capsule {
    Capsule::new(
        occurrence,
        PreparedActionId(ContentHash::new([0x02; 32])),
        EnvironmentId(ContentHash::new([0x03; 32])),
        PlatformId(ContentHash::new([0x04; 32])),
        vec![GuestMapping {
            artifact: work,
            guest_path: GuestPath::new("/work").unwrap(),
            access: GuestAccess::ReadWrite,
        }],
        process,
        CapsuleNetwork::Offline,
        None,
        CapsuleBudgets {
            wall_time_ms: 30_000,
            output_bytes: 1 << 20,
            memory_bytes: 512 * 1024 * 1024,
            process_count: 64,
            result_bytes: 1 << 20,
            result_entries: 16,
            work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
            work_delta_entries: kata_types::execution_contract::CAPSULE_WORK_DELTA_ENTRIES,
        },
        None,
    )
    .unwrap()
}

const ENVIRONMENT_ID: [u8; 32] = [0x03; 32];

fn declare_environment(planes: &Planes) {
    if planes.db.environment(ENVIRONMENT_ID).unwrap().is_some() {
        return;
    }
    let manifest = planes
        .cas
        .put_durable(b"work-apply-fixture-environment-manifest")
        .unwrap();
    planes
        .db
        .declare_environment(
            &kata_core::operational::EnvironmentDeclaration::for_staged_root(
                ENVIRONMENT_ID,
                &manifest,
                [0x5C; 32],
                "work-apply-fixture",
                [0x04; 32],
                "01JZZZZZZZZZZZZZZZZZZZZZE1",
            )
            .unwrap(),
        )
        .unwrap();
}

/// A delta against `base` writing `r` = MEMBER, published and declared.
fn write_delta(
    planes: &Planes,
    execution_id: Ulid,
    base: &ArtifactRef,
) -> (ArtifactRef, TreeDelta) {
    write_delta_at(planes, execution_id, base, "r", MEMBER)
}

/// A delta against `base` writing `path` = `bytes`, published and declared.
fn write_delta_at(
    planes: &Planes,
    execution_id: Ulid,
    base: &ArtifactRef,
    path: &str,
    bytes: &[u8],
) -> (ArtifactRef, TreeDelta) {
    let member = planes.cas.put_durable(bytes).unwrap();
    let delta = TreeDelta::new(
        base.clone(),
        vec![TreeChange {
            path: TreePath::new(path).unwrap(),
            change: TreeChangeKind::Write {
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: member.object_id(),
                    size_bytes: member.size(),
                },
            },
        }],
    )
    .unwrap();
    let bytes = delta.delta_bytes().unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    let declaration = kata_core::operational::ArtifactDeclaration::for_durable_delta(
        &delta,
        ArtifactPrivacy::Private,
        kata_core::operational::CasRootOwner::Execution(execution_id),
        &durable,
    )
    .unwrap();
    planes.db.declare_artifact(&declaration).unwrap();
    (declaration_reference(&durable), delta)
}

fn declaration_reference(durable: &kata_core::store::cas::DurableObject) -> ArtifactRef {
    ArtifactRef::new(
        durable.object_id(),
        durable.size(),
        ArtifactPrivacy::Private,
    )
}

/// Claim the capsule attempt and leave it `running` — the scope judge's cell
/// settles it (or passes it through) before adoption, exactly as the reactor
/// does.
fn claim_capsule_attempt(
    planes: &Planes,
    execution_id: Ulid,
    occurrence: &OccurrenceRef,
    work: &ArtifactRef,
) -> (Ulid, i64, i64) {
    claim_capsule_attempt_at(planes, execution_id, STAGE, occurrence, work)
}

/// [`claim_capsule_attempt`] under an arbitrary durable `stage` spelling —
/// the expansion's `#op/<path>` coordinate is a stage the program's own list
/// never carries.
fn claim_capsule_attempt_at(
    planes: &Planes,
    execution_id: Ulid,
    stage: &str,
    occurrence: &OccurrenceRef,
    work: &ArtifactRef,
) -> (Ulid, i64, i64) {
    claim_capsule_attempt_running(
        planes,
        execution_id,
        stage,
        occurrence,
        capsule(occurrence.id(), work.id()),
        work,
    )
}

/// [`claim_capsule_attempt_at`] authorizing `capsule` — the charge cells' agent turn.
fn claim_capsule_attempt_running(
    planes: &Planes,
    execution_id: Ulid,
    stage: &str,
    occurrence: &OccurrenceRef,
    capsule: Capsule,
    work: &ArtifactRef,
) -> (Ulid, i64, i64) {
    let bytes = serde_json::to_vec(&capsule).unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    planes
        .db
        .declare_capsule(
            &CapsuleDeclaration::for_durable_object(&capsule, &bytes, &durable).unwrap(),
        )
        .unwrap();
    let attempt_id = Ulid::new();
    let claimed = planes
        .db
        .claim_attempt(
            execution_id,
            attempt_id,
            &AttemptClaimSpec {
                stage_id: stage.to_string(),
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
    // Dispatch first — the settlement guards read `attempt_projection`, which
    // only the dispatch commit creates (the capsule route's real shape), so a
    // bare `running` transition would settle nothing in the scope cells.
    planes
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
    planes
        .db
        .record_main_side_transition(
            attempt_id,
            &kata_core::operational::MainSideTransition {
                worker_id: Some("w-1"),
                ..kata_core::operational::MainSideTransition::bare("running")
            },
        )
        .unwrap();
    let lease_epoch = planes.db.attempt(attempt_id).unwrap().unwrap().lease_epoch;
    (attempt_id, claimed.attempt_ordinal, lease_epoch)
}

/// Accept one capsule completion carrying `delta` as its `/work` delta.
fn accept_capsule_with_delta(
    planes: &Planes,
    execution_id: Ulid,
    occurrence: &OccurrenceRef,
    work: &ArtifactRef,
    delta_ref: &ArtifactRef,
) {
    accept_capsule_with_delta_at(planes, execution_id, STAGE, occurrence, work, delta_ref);
}

/// [`accept_capsule_with_delta`] under an arbitrary durable `stage` spelling.
fn accept_capsule_with_delta_at(
    planes: &Planes,
    execution_id: Ulid,
    stage: &str,
    occurrence: &OccurrenceRef,
    work: &ArtifactRef,
    delta_ref: &ArtifactRef,
) {
    let (attempt_id, attempt_ordinal, lease_epoch) =
        claim_capsule_attempt_at(planes, execution_id, stage, occurrence, work);
    let member = planes.cas.put_durable(b"result\n").unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("r").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .unwrap();
    let receipt = planes
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    let result = ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    );
    let capture = |bytes: &[u8]| {
        let receipt = planes.cas.put_durable(bytes).unwrap();
        ArtifactRef::new(
            receipt.object_id(),
            receipt.size(),
            ArtifactPrivacy::Private,
        )
    };
    let stdout = capture(b"{}\n");
    let stderr = capture(b"");
    planes
        .db
        .adopt_and_accept_capsule_completion(
            &CapsuleResultAdoption {
                execution_id,
                occurrence_id: occurrence.id(),
                result: result.clone(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
                work_delta: Some(delta_ref.clone()),
                capture_exceeded: false,
                agent: None,
                egress_refusals: vec![],
            },
            |adopted| WorkerCompletionInput {
                execution_id,
                attempt_id,
                attempt_ordinal,
                lease_epoch,
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
}

/// The base tree these scope cells map `/work` onto: the committed base's
/// published manifest — or any declared tree; the judge never reads it.
fn empty_work(planes: &Planes, execution_id: Ulid) -> ArtifactRef {
    declared_work(
        planes,
        execution_id,
        &TreeManifest::new(Vec::new()).unwrap(),
    )
}

/// `manifest` as the execution's declared `/work` tree.
fn declared_work(planes: &Planes, execution_id: Ulid, manifest: &TreeManifest) -> ArtifactRef {
    let bytes = manifest.manifest_bytes().unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    let declaration = kata_core::operational::ArtifactDeclaration::for_durable_tree(
        manifest,
        ArtifactPrivacy::Public,
        kata_core::operational::CasRootOwner::Execution(execution_id),
        &durable,
    )
    .unwrap();
    planes.db.declare_artifact(&declaration).unwrap();
    ArtifactRef::new(durable.object_id(), durable.size(), ArtifactPrivacy::Public)
}

/// The last transition a recorded refusal wrote — the reason the attempt was
/// settled with, verbatim from the plane.
fn last_transition_payload(op_path: &Path, attempt_id: Ulid) -> String {
    let conn = rusqlite::Connection::open(op_path).unwrap();
    conn.query_row(
        "SELECT payload_json FROM transitions WHERE attempt_id = ?1 ORDER BY seq DESC LIMIT 1",
        rusqlite::params![attempt_id.to_bytes().as_slice()],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    .unwrap()
}

/// The fixture: a git repo, the jj execution workspace, the published base
/// head, and one accepted capsule completion whose delta writes `r`.
struct Fixture {
    planes: Planes,
    execution_id: Ulid,
    program: kata_program::execution_program::ExecutionProgram,
    backend: JjBackend,
    workspace: kata_effects_contract::ExecutionWorkspaceHandle,
    head: ExecutionWorkTreeHead,
    delta: TreeDelta,
    dispatcher: Dispatcher,
}

fn fixture(dir: &Path) -> Fixture {
    let planes = planes(dir);
    declare_environment(&planes);
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    std::fs::write(repo.join("a.txt"), "committed\n").unwrap();
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
    let backend = JjBackend::open(&repo).expect("the colocated jj backend opens");
    let execution_id = Ulid::new();
    let program = program_with_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let workspace = kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect("the workspace creates");
    let head = kata_core::work_tree::publish_base_tree_head(
        &planes.db,
        &planes.cas,
        execution_id,
        |put| {
            ExecutionWorkspaceProvider::committed_base_tree(
                &backend,
                &workspace,
                WorkTreeInputBounds::default(),
                put,
            )
        },
    )
    .expect("the committed base head publishes");
    let (occurrence, _stage) = occurrence_ref(execution_id, &program);
    let base_ref = head_artifact_ref(&planes, &head);
    let (delta_ref, delta) = write_delta(&planes, execution_id, &base_ref);
    let _ = &delta_ref;
    accept_capsule_with_delta(&planes, execution_id, &occurrence, &base_ref, &delta_ref);
    // The crash cells' armed child rebuilds the whole drive from the dir.
    std::fs::write(dir.join("execution_id"), execution_id.to_string()).unwrap();
    let _ = &delta_ref;
    let dispatcher = dispatcher(&planes.db);
    Fixture {
        planes,
        execution_id,
        program,
        backend,
        workspace,
        head,
        delta,
        dispatcher,
    }
}

/// The head row's `/work` artifact as an [`ArtifactRef`] — the delta's `base`
/// names the artifact, and the CAS-resolved row carries object and size.
fn head_artifact_ref(planes: &Planes, head: &ExecutionWorkTreeHead) -> ArtifactRef {
    let row = planes
        .db
        .artifact(head.work_tree_artifact_id)
        .unwrap()
        .expect("the head's artifact row exists");
    ArtifactRef::new(
        kata_types::primitives::ObjectId::new(row.object_id),
        row.size_bytes,
        row.privacy,
    )
}

/// `git show <commit>:<path>` read back from the repo the workspace lives in —
/// the assertion never asks kata what kata wrote.
fn git_show(repo: &Path, commit: &str, path: &str) -> Option<String> {
    let out = hermetic_git_in(repo)
        .args(["show", &format!("{commit}:{path}")])
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn a_pending_apply_lands_on_the_candidate_and_advances_the_head() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    // The successor gate holds while the apply is owed.
    assert!(
        fx.planes
            .db
            .pending_work_apply_for_stage(fx.execution_id, STAGE)
            .unwrap(),
        "a completed stage's delta keeps its successors gated until the apply lands"
    );
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            Some(&fx.backend),
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the apply drives");
    assert!(
        !fx.planes
            .db
            .pending_work_apply_for_stage(fx.execution_id, STAGE)
            .unwrap(),
        "the accepted apply releases the stage's successors"
    );
    let moved = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(moved.head_seq, fx.head.head_seq + 1);
    assert_ne!(moved.candidate_commit_id, fx.head.candidate_commit_id);
    // The applied tree is the delta's effect on the candidate — read from GIT,
    // not from kata's bookkeeping.
    assert_eq!(
        git_show(
            dir.path().join("repo").as_path(),
            &moved.candidate_commit_id,
            "r"
        )
        .as_deref(),
        Some(std::str::from_utf8(MEMBER).unwrap()),
        "the applied commit's `r` is the delta's member"
    );
    assert_eq!(
        git_show(
            dir.path().join("repo").as_path(),
            &moved.candidate_commit_id,
            "a.txt"
        )
        .as_deref(),
        Some("committed\n"),
        "the applied commit keeps the base's files"
    );
    // A second drive is the idempotent arm: the head does not move again.
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            Some(&fx.backend),
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the re-drive is a no-op");
    let again = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(again.head_seq, moved.head_seq);
    assert_eq!(again.candidate_commit_id, moved.candidate_commit_id);
}

/// A NON-ISOLATED rig: the scratch-seeded root head — no candidate, no jj
/// checkout anywhere behind it — and one accepted capsule completion whose
/// delta writes `r`.
struct CasFixture {
    planes: Planes,
    execution_id: Ulid,
    program: kata_program::execution_program::ExecutionProgram,
    head: ExecutionWorkTreeHead,
    delta: TreeDelta,
    dispatcher: Dispatcher,
}

fn cas_fixture(dir: &Path) -> CasFixture {
    let planes = planes(dir);
    declare_environment(&planes);
    let execution_id = Ulid::new();
    let program = program_with_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(scratch.join("a.txt"), "committed\n").unwrap();
    let head = kata_core::work_tree::publish_scratch_tree_head(
        &planes.db,
        &planes.cas,
        execution_id,
        &scratch,
    )
    .expect("the scratch seed publishes");
    let (occurrence, _stage) = occurrence_ref(execution_id, &program);
    let base_ref = head_artifact_ref(&planes, &head);
    let (delta_ref, delta) = write_delta(&planes, execution_id, &base_ref);
    accept_capsule_with_delta(&planes, execution_id, &occurrence, &base_ref, &delta_ref);
    let dispatcher = dispatcher(&planes.db);
    CasFixture {
        planes,
        execution_id,
        program,
        head,
        delta,
        dispatcher,
    }
}

/// Decode a `kind='tree'` artifact's manifest — read from the CAS, not from
/// the plane's own projection.
fn manifest_of(planes: &Planes, artifact_id: [u8; 32]) -> TreeManifest {
    let row = planes
        .db
        .artifact(artifact_id)
        .unwrap()
        .expect("the artifact row exists");
    let bytes = planes
        .cas
        .get_verified(
            &kata_types::primitives::ObjectId::new(row.object_id),
            row.size_bytes,
            TreeManifest::MAXIMUM_ENCODED_BYTES,
        )
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The `r` member's bytes under `manifest`, read out of the CAS itself.
fn r_content(planes: &Planes, manifest: &TreeManifest) -> Vec<u8> {
    let entry = manifest
        .entries()
        .iter()
        .find(|entry| entry.path.as_str() == "r")
        .expect("the applied manifest carries r");
    let TreeNode::File {
        object, size_bytes, ..
    } = &entry.node
    else {
        panic!("r is a file entry");
    };
    planes
        .cas
        .get_verified(
            object,
            *size_bytes,
            kata_types::tree_artifact::MAX_MEMBER_BYTES,
        )
        .unwrap()
}

/// THE CAS-ONLY LEG — a non-isolated execution's head has
/// no candidate and no checkout exists, so `drive_pending_work_applies` with
/// NO provider publishes the delta-applied manifest and advances the row in
/// the resolve. `candidate_commit_id` stays EMPTY — the leg's whole effect is
/// CAS content — and a second drive converges.
#[test]
fn a_cas_only_head_applies_its_delta_without_a_provider() {
    let dir = tempfile::tempdir().unwrap();
    let fx = cas_fixture(dir.path());
    assert_eq!(
        fx.head.candidate_commit_id, "",
        "the seeded head has no checkout behind it"
    );
    assert!(
        fx.planes
            .db
            .pending_work_apply_for_stage(fx.execution_id, STAGE)
            .unwrap(),
        "the capsule's delta owes the apply"
    );
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            None,
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the CAS leg owes no workspace provider");
    assert!(
        !fx.planes
            .db
            .pending_work_apply_for_stage(fx.execution_id, STAGE)
            .unwrap(),
        "the accepted apply releases the successors"
    );
    let moved = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(moved.head_seq, fx.head.head_seq + 1);
    assert_eq!(
        moved.candidate_commit_id, "",
        "a CAS-only head never grows a candidate"
    );
    assert_ne!(moved.work_tree_artifact_id, fx.head.work_tree_artifact_id);
    // The applied manifest, read out of the CAS: the seed's `a.txt` plus `r`.
    let manifest = manifest_of(&fx.planes, moved.work_tree_artifact_id);
    let mut paths: Vec<&str> = manifest
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    paths.sort_unstable();
    assert_eq!(paths, ["a.txt", "r"]);
    assert_eq!(
        r_content(&fx.planes, &manifest).as_slice(),
        MEMBER,
        "r's bytes are the delta's member"
    );
    // The re-drive converges: nothing pending, the head does not move again.
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            None,
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the re-drive is a no-op");
    let again = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(again.head_seq, moved.head_seq);
    assert_eq!(again.work_tree_artifact_id, moved.work_tree_artifact_id);
}

/// The CAS leg's SWEEP half: an apply attempt claimed but never resolved — the
/// claim-commit crash window's residue — is reconciled off the head row alone:
/// no provider is attached because there is no checkout to classify, the
/// row still naming the delta's base is the whole question, and the re-publish
/// is content-identical.
#[test]
fn a_pending_cas_apply_reconciles_off_the_head_row_alone() {
    let dir = tempfile::tempdir().unwrap();
    let fx = cas_fixture(dir.path());
    // Mint the apply attempt at `pending` exactly as the live leg would —
    // the same spec the driver rebuilds from the pending row — then let the
    // sweep find it `AlreadyLive`.
    let stage_id = kata_types::workflow::StageId(smol_str::SmolStr::new(STAGE));
    let lowered = kata_program::execution_program::lower_stage_operation(&fx.program, &stage_id)
        .expect("the digest stage lowers");
    let spec = MainAttemptSpec {
        stage_id: work_apply_stage_id(STAGE),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(fx.execution_id),
                fx.program.program_hash,
                work_apply_operation_contract(lowered.contract.id()),
                lowered.path.clone(),
            ),
            None,
            None,
        ),
    };
    let attempt_id = Ulid::new();
    let claimed = fx
        .planes
        .db
        .claim_work_apply_attempt(attempt_id, &spec, "", fx.delta.base().id().0.0)
        .expect("the claim runs");
    assert!(
        matches!(claimed, WorkApplyClaimOutcome::Claimed { .. }),
        "the claim mints the pending attempt: {claimed:?}"
    );
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            None,
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the CAS sweep reconciles without a provider");
    let moved = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        moved.head_seq,
        fx.head.head_seq + 1,
        "the reconcile resolved and advanced"
    );
    assert_eq!(moved.candidate_commit_id, "");
    let manifest = manifest_of(&fx.planes, moved.work_tree_artifact_id);
    assert_eq!(
        r_content(&fx.planes, &manifest).as_slice(),
        MEMBER,
        "the reconciled apply's manifest carries the delta's member"
    );
    let payload = last_transition_payload(&fx.planes.op_path, attempt_id);
    assert!(
        payload.contains("\"recovered\":true"),
        "the sweep's resolve is marked recovered: {payload}"
    );
}

#[test]
fn an_empty_delta_resolves_without_a_jj_call() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    declare_environment(&planes);
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    init_git_repo_at(&repo);
    std::fs::write(repo.join("a.txt"), "committed\n").unwrap();
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
    let backend = JjBackend::open(&repo).expect("the colocated jj backend opens");
    let execution_id = Ulid::new();
    let program = program_with_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let workspace = kata_vcs::test_support::create_trunk_workspace(&backend, &key)
        .expect("the workspace creates");
    let head = kata_core::work_tree::publish_base_tree_head(
        &planes.db,
        &planes.cas,
        execution_id,
        |put| {
            ExecutionWorkspaceProvider::committed_base_tree(
                &backend,
                &workspace,
                WorkTreeInputBounds::default(),
                put,
            )
        },
    )
    .expect("the committed base head publishes");
    let (occurrence, _stage) = occurrence_ref(execution_id, &program);
    // The EMPTY delta: published and adopted exactly like a real no-change
    // completion's.
    let base_ref = head_artifact_ref(&planes, &head);
    let empty = TreeDelta::new(base_ref.clone(), Vec::new()).unwrap();
    let bytes = empty.delta_bytes().unwrap();
    let durable = planes.cas.put_durable(&bytes).unwrap();
    let declaration = kata_core::operational::ArtifactDeclaration::for_durable_delta(
        &empty,
        ArtifactPrivacy::Private,
        kata_core::operational::CasRootOwner::Execution(execution_id),
        &durable,
    )
    .unwrap();
    planes.db.declare_artifact(&declaration).unwrap();
    accept_capsule_with_delta(
        &planes,
        execution_id,
        &occurrence,
        &base_ref,
        &ArtifactRef::new(
            durable.object_id(),
            durable.size(),
            ArtifactPrivacy::Private,
        ),
    );
    let dispatcher = dispatcher(&planes.db);
    dispatcher
        .drive_pending_work_applies(
            execution_id,
            &program,
            Some(&backend),
            Some(planes.cas.as_ref()),
        )
        .expect("the empty apply drives");
    let after = planes
        .db
        .execution_work_tree_head(execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        after.candidate_commit_id, head.candidate_commit_id,
        "an empty delta never rewrites the candidate"
    );
    assert_eq!(
        after.head_seq, head.head_seq,
        "an empty delta advances nothing"
    );
    assert!(
        planes
            .db
            .pending_work_applies(execution_id)
            .unwrap()
            .is_empty(),
        "the empty delta's apply is resolved, not pending"
    );
}

#[test]
fn a_diverged_candidate_is_recorded_failed_and_never_retries() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    // Move `@` — an outside rewrite, which the apply's expected-commit fence
    // must refuse rather than append to.
    let other_member = fx.planes.cas.put_durable(b"outside\n").unwrap();
    let other = TreeDelta::new(
        head_artifact_ref(&fx.planes, &fx.head),
        vec![TreeChange {
            path: TreePath::new("outside.txt").unwrap(),
            change: TreeChangeKind::Write {
                node: TreeNode::File {
                    mode: TreeEntryMode::Regular,
                    object: other_member.object_id(),
                    size_bytes: other_member.size(),
                },
            },
        }],
    )
    .unwrap();
    let members = |object_id: kata_types::primitives::ObjectId, size: u64| {
        fx.planes.cas.get_verified(
            &object_id,
            size,
            kata_types::tree_artifact::MAX_MEMBER_BYTES,
        )
    };
    let _foreign = ExecutionWorkspaceProvider::apply_work_delta(
        &fx.backend,
        &fx.workspace,
        &fx.head.candidate_commit_id,
        &other,
        &members,
        "someone-elses-effect",
    )
    .expect("the foreign apply lands and moves @");
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            Some(&fx.backend),
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the drive runs and records the refusal");
    let after = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        after.candidate_commit_id, fx.head.candidate_commit_id,
        "the diverged apply does not advance the head"
    );
    assert_eq!(after.head_seq, fx.head.head_seq);
    assert!(
        fx.planes
            .db
            .pending_work_applies(fx.execution_id)
            .unwrap()
            .is_empty(),
        "a recorded divergence is terminal for the sweep"
    );
}

/// A crash AFTER the jj apply published but BEFORE the resolve committed: the
/// sweep's `classify_work_apply` finds the `kata.effect` tag and resolves the
/// recorded attempt with the head advance — never re-applying.
#[test]
fn a_published_but_unresolved_apply_is_recovered_not_repeated() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    // Half-run: claim the apply attempt, run the jj effect under its tag, then
    // STOP — the resolve never commits, exactly the crash's wound.
    let row = fx
        .planes
        .db
        .pending_work_applies(fx.execution_id)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let spec = MainAttemptSpec {
        stage_id: work_apply_stage_id(&row.stage_id),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(fx.execution_id),
                ContentHash::new(row.program_hash),
                work_apply_operation_contract(OperationContractId(ContentHash::new(
                    row.operation_contract_id,
                ))),
                OperationPath::from_canonical_bytes(&row.operation_path).unwrap(),
            ),
            None,
            None,
        ),
    };
    let attempt_id = Ulid::new();
    fx.planes
        .db
        .claim_work_apply_attempt(attempt_id, &spec, "", fx.delta.base().id().0.0)
        .unwrap();
    let members = |object_id: kata_types::primitives::ObjectId, size: u64| {
        fx.planes.cas.get_verified(
            &object_id,
            size,
            kata_types::tree_artifact::MAX_MEMBER_BYTES,
        )
    };
    let applied = ExecutionWorkspaceProvider::apply_work_delta(
        &fx.backend,
        &fx.workspace,
        &fx.head.candidate_commit_id,
        &fx.delta,
        &members,
        &attempt_id.to_string(),
    )
    .expect("the effect lands — the crash lands between publish and resolve");
    // The drive now runs the sweep leg: classify sees the tag, resolves the
    // recorded attempt, advances the head — no second jj apply.
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            Some(&fx.backend),
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the sweep recovers the published apply");
    let moved = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(moved.candidate_commit_id, applied.commit_id);
    assert_eq!(moved.head_seq, fx.head.head_seq + 1);
    assert!(
        fx.planes
            .db
            .pending_work_applies(fx.execution_id)
            .unwrap()
            .is_empty()
    );
}

// -- crash cells ------------------------------------------------------------
//
// `operational_crash_point` aborts the process, so the armed leg runs in a
// re-executed copy of this binary keyed on the env markers — the same pattern
// `operational_crash_matrix` runs.

const CHILD_MARKER: &str = "KATA_WORK_APPLY_CHILD";
const CHILD_DIR: &str = "KATA_WORK_APPLY_CHILD_DIR";

/// The armed child's whole drive: rebuild the dispatcher, the planes, the jj
/// backend and the execution workspace from the fixture dir, then run the
/// sweep — aborting at whichever boundary `KATA_FAULT_INJECT` names.
fn work_apply_child_entry() {
    if std::env::var(CHILD_MARKER).is_err() {
        return;
    }
    let dir = std::path::PathBuf::from(std::env::var(CHILD_DIR).expect("CHILD_DIR"));
    let execution_id: Ulid = std::fs::read_to_string(dir.join("execution_id"))
        .unwrap()
        .parse()
        .unwrap();
    let planes = planes(&dir);
    let program = program_with_scope();
    let backend =
        JjBackend::open(&dir.join("repo")).expect("the child opens the repo's jj backend");
    let dispatcher = dispatcher(&planes.db);
    dispatcher
        .drive_pending_work_applies(
            execution_id,
            &program,
            Some(&backend),
            Some(planes.cas.as_ref()),
        )
        .expect("the child's drive");
    panic!("the armed fault point was never reached — the cell proves nothing");
}

/// Run `drive_pending_work_applies` in an armed child at `boundary`, assert it
/// died there, then return the unarmed recovery answer.
fn crash_then_recover(
    boundary: &str,
    dir: &Path,
    test: &str,
) -> (ExecutionWorkTreeHead, JjBackend, Planes, Ulid) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(test)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .env(CHILD_DIR, dir)
        .env("KATA_FAULT_INJECT", format!("operational.{boundary}"))
        .output()
        .expect("spawn the crash child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "{test}: the armed child must abort at {boundary}, not exit cleanly"
    );
    assert!(
        stderr.contains(&format!("crash point reached: operational.{boundary}")),
        "{test}: the child must die AT the boundary — stderr:\n{stderr}"
    );
    let planes = planes(dir);
    let execution_id: Ulid = std::fs::read_to_string(dir.join("execution_id"))
        .unwrap()
        .parse()
        .unwrap();
    let backend = JjBackend::open(&dir.join("repo")).unwrap();
    let program = program_with_scope();
    let dispatcher = dispatcher(&planes.db);
    dispatcher
        .drive_pending_work_applies(
            execution_id,
            &program,
            Some(&backend),
            Some(planes.cas.as_ref()),
        )
        .expect("the recovery drive");
    let head = planes
        .db
        .execution_work_tree_head(execution_id)
        .unwrap()
        .unwrap();
    (head, backend, planes, execution_id)
}

/// Armed crash AFTER the claim committed, BEFORE the leg's effect runs: the
/// recorded pending attempt is the sweep's input, and the recovery apply lands
/// once.
#[test]
fn crash_after_work_apply_claimed_before_apply() {
    work_apply_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    let (head, backend, planes, execution_id) = crash_then_recover(
        "after_work_apply_claimed_before_apply",
        dir.path(),
        "crash_after_work_apply_claimed_before_apply",
    );
    assert_eq!(
        head.head_seq,
        fx.head.head_seq + 1,
        "the retry applied once"
    );
    assert_eq!(
        git_show(
            dir.path().join("repo").as_path(),
            &head.candidate_commit_id,
            "r"
        )
        .as_deref(),
        Some(std::str::from_utf8(MEMBER).unwrap()),
        "the recovered apply's commit carries the delta"
    );
    drop((backend, planes, execution_id));
}

/// Armed crash AFTER the apply's effect published (the `kata.effect` op is
/// durable) but BEFORE the resolve — the sweep must CLASSIFY the published
/// effect and advance the head, never re-apply.
#[test]
fn crash_after_work_apply_published_before_resolve() {
    work_apply_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    let (head, backend, planes, execution_id) = crash_then_recover(
        "after_work_apply_published_before_resolve",
        dir.path(),
        "crash_after_work_apply_published_before_resolve",
    );
    assert_eq!(head.head_seq, fx.head.head_seq + 1);
    assert_eq!(
        git_show(
            dir.path().join("repo").as_path(),
            &head.candidate_commit_id,
            "r"
        )
        .as_deref(),
        Some(std::str::from_utf8(MEMBER).unwrap()),
        "the published apply is adopted, not repeated"
    );
    // And the reconcile does not mint a second commit — the head's candidate
    // IS the child's published commit.
    let attempt = planes.db.pending_work_applies(execution_id).unwrap();
    assert!(attempt.is_empty(), "the recovered apply drains the sweep");
    drop(backend);
}

// -- scope cells --------------------------------------------------------------

/// A delta writing outside the stage's `produces_files` fails the attempt
/// PERFORMED BUT FAILED — named `work_delta_out_of_scope`, every undeclared
/// path listed — and nothing of the delta is adopted.
#[test]
fn a_delta_outside_the_declared_scope_is_a_performed_but_failed_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    declare_environment(&planes);
    let execution_id = Ulid::new();
    let program = program_with_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let (occurrence, _) = occurrence_ref(execution_id, &program);
    let work = empty_work(&planes, execution_id);
    let (attempt_id, _, _) = claim_capsule_attempt(&planes, execution_id, &occurrence, &work);
    let base_ref = work.clone();
    let (delta_ref, _delta) =
        write_delta_at(&planes, execution_id, &base_ref, "outside.txt", b"nope\n");
    let recovered = planes.db.recovered_attempt(attempt_id).unwrap().unwrap();
    let dispatcher = dispatcher(&planes.db);
    let settled = dispatcher
        .judge_work_delta_scope(&recovered, occurrence.id(), Some(&delta_ref), None)
        .expect("the judge runs");
    assert!(settled, "an out-of-scope delta settles the attempt");
    let attempt = planes.db.attempt(attempt_id).unwrap().unwrap();
    assert!(
        attempt.finished_at_ms.is_some(),
        "performed but failed is recorded"
    );
    let reason = last_transition_payload(&planes.op_path, attempt_id);
    assert!(reason.contains("work_delta_out_of_scope"), "{reason}");
    assert!(reason.contains("outside.txt"), "{reason}");
}

/// A `.gitattributes` WRITE carrying `filter=lfs` is a checkout conversion the
/// admission census already refuses — the delta cannot smuggle it back in.
#[test]
fn a_delta_writing_a_converting_gitattributes_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    declare_environment(&planes);
    let execution_id = Ulid::new();
    let program = program_with_scope(); // declares .gitattributes in scope
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let (occurrence, _) = occurrence_ref(execution_id, &program);
    let work = empty_work(&planes, execution_id);
    let (attempt_id, _, _) = claim_capsule_attempt(&planes, execution_id, &occurrence, &work);
    let (delta_ref, _delta) = write_delta_at(
        &planes,
        execution_id,
        &work,
        ".gitattributes",
        b"* filter=lfs\n",
    );
    let recovered = planes.db.recovered_attempt(attempt_id).unwrap().unwrap();
    let dispatcher = dispatcher(&planes.db);
    let settled = dispatcher
        .judge_work_delta_scope(&recovered, occurrence.id(), Some(&delta_ref), None)
        .expect("the judge runs");
    assert!(settled, "the conversion write settles the attempt");
    let reason = last_transition_payload(&planes.op_path, attempt_id);
    assert!(
        reason.contains("work_delta_unsupported_repository"),
        "{reason}"
    );
}

/// The in-scope twin: a delta writing only `r` passes the judge and proceeds
/// to adoption.
#[test]
fn an_in_scope_delta_passes_the_judge() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    declare_environment(&planes);
    let execution_id = Ulid::new();
    let program = program_with_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let (occurrence, _) = occurrence_ref(execution_id, &program);
    let work = empty_work(&planes, execution_id);
    let (attempt_id, _, _) = claim_capsule_attempt(&planes, execution_id, &occurrence, &work);
    let (delta_ref, _delta) = write_delta_at(&planes, execution_id, &work, "r", MEMBER);
    let recovered = planes.db.recovered_attempt(attempt_id).unwrap().unwrap();
    let dispatcher = dispatcher(&planes.db);
    let settled = dispatcher
        .judge_work_delta_scope(&recovered, occurrence.id(), Some(&delta_ref), None)
        .expect("the judge runs");
    assert!(!settled, "an in-scope delta proceeds to adoption");
    let attempt = planes.db.attempt(attempt_id).unwrap().unwrap();
    assert!(
        attempt.finished_at_ms.is_none(),
        "the attempt is still live"
    );
}

/// A `workspace = "ro"` stage reporting ANY `/work` delta is PERFORMED BUT
/// FAILED — `work_delta_out_of_scope` — because the posture gives the stage
/// no writable workspace at all. (Pairing `produces_files` with a read-only
/// workspace does not compile: CHECK refuses it,
/// `a_produces_files_on_read_only_workspace_is_refused_at_check` below.) Under `oci`
/// the capsule mounts `/work` read-write, so adoption is where the posture is
/// enforced; an ro stage that reports no delta passes the same judge.
///
/// **Would red if:** the judge did not read `fs` — this cell's reported delta
/// would adopt cleanly (`settled` `false`) and the run doc would call the ro
/// stage's write a completed output.
#[test]
fn a_workspace_ro_stage_reporting_a_delta_is_a_performed_but_failed_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    declare_environment(&planes);
    let execution_id = Ulid::new();
    let program = program_with_ro_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let (occurrence, _) = occurrence_ref(execution_id, &program);
    let work = empty_work(&planes, execution_id);
    let (attempt_id, _, _) = claim_capsule_attempt(&planes, execution_id, &occurrence, &work);
    let recovered = planes.db.recovered_attempt(attempt_id).unwrap().unwrap();
    let dispatcher = dispatcher(&planes.db);

    // The quiet twin: an ro stage that writes NOTHING reports no delta, and
    // there is nothing to judge — the attempt proceeds.
    assert!(
        !dispatcher
            .judge_work_delta_scope(&recovered, occurrence.id(), None, None)
            .expect("the judge runs"),
        "a ro stage reporting no delta is in scope"
    );

    // Any delta at all is out of scope — the stage may write nothing.
    // The declared-closure variant of this question is R-c's compile-time
    // refusal below, not a runtime judge outcome.
    let (delta_ref, _delta) = write_delta_at(&planes, execution_id, &work, "r", MEMBER);
    let settled = dispatcher
        .judge_work_delta_scope(&recovered, occurrence.id(), Some(&delta_ref), None)
        .expect("the judge runs");
    assert!(
        settled,
        "a delta reported by a ro stage settles the attempt"
    );
    let attempt = planes.db.attempt(attempt_id).unwrap().unwrap();
    assert!(
        attempt.finished_at_ms.is_some(),
        "performed but failed is recorded"
    );
    let reason = last_transition_payload(&planes.op_path, attempt_id);
    assert!(reason.contains("work_delta_out_of_scope"), "{reason}");
    assert!(
        reason.contains("workspace = \\\"ro\\\"")
            && reason.contains("(work_delta_out_of_scope): r"),
        "{reason}"
    );
}

// -- settlement charge cells ---------------------------------------------------

/// The `terminal_charge.token_usage` the attempt's LAST transition recorded, read off a
/// second, read-only SQLite handle — never through the plane under test.
fn settled_charge(op_path: &Path, attempt_id: Ulid) -> (String, serde_json::Value) {
    let conn =
        rusqlite::Connection::open_with_flags(op_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let (state, payload) = conn
        .query_row(
            "SELECT resulting_state, payload_json FROM transitions WHERE attempt_id = ?1 \
             ORDER BY seq DESC LIMIT 1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    (
        state,
        payload
            .pointer("/terminal_charge/token_usage")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
}

/// An agent turn's report as the completion frame carries it — the refs are never read
/// by a settlement, only the usage, adapter and model.
fn turn_report(
    usage: Option<kata_types::metering::StageUsage>,
) -> kata_types::agent::AgentTurnReport {
    let reference = ArtifactRef::new(
        kata_types::primitives::ObjectId::from([0x61; 32]),
        3,
        ArtifactPrivacy::Private,
    );
    kata_types::agent::AgentTurnReport {
        response: reference.clone(),
        usage,
        adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
        model_reported: Some("gpt-fake-review".into()),
        session_evidence: Some(reference),
        stop_reason: None,
    }
}

/// A `workspace = "ro"` agent attempt, dispatched and running, with a reported `/work`
/// delta its stage may not write — the review pack's trunk shape (E-prep ledger
/// `review-trunk`, transition 28).
fn ro_agent_attempt_with_delta(
    planes: &Planes,
) -> (
    Ulid,
    kata_core::operational::RecoveredAttempt,
    OccurrenceRef,
    ArtifactRef,
) {
    declare_environment(planes);
    let execution_id = Ulid::new();
    let program = program_with_ro_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let (occurrence, _) = occurrence_ref(execution_id, &program);
    let work = empty_work(planes, execution_id);
    let capsule = capsule_running(occurrence.id(), work.id(), agent_process());
    let (attempt_id, _, _) =
        claim_capsule_attempt_running(planes, execution_id, STAGE, &occurrence, capsule, &work);
    let (delta_ref, _delta) = write_delta_at(planes, execution_id, &work, "src/trunk.sh", MEMBER);
    let recovered = planes.db.recovered_attempt(attempt_id).unwrap().unwrap();
    (attempt_id, recovered, occurrence, delta_ref)
}

/// **A PERFORMED-BUT-FAILED agent attempt is charged what its turn reported.** The
/// container ran, the turn was issued and the vendor reported 500 in / 40 out, priced by
/// the worker; the main refuses the delta (`work_delta_out_of_scope`) and settles the
/// attempt `failed` — and that terminal records the reported usage verbatim as its
/// `terminal_charge`, read off a second handle.
///
/// **Would red if:** the settlement recorded no charge (the E-prep defect: the frame
/// carried only `delivery` + `reason`), or charged it as unknown or as `0`.
#[test]
fn a_refused_agent_delta_is_charged_the_usage_its_turn_reported() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    let (attempt_id, recovered, occurrence, delta_ref) = ro_agent_attempt_with_delta(&planes);
    let reported = kata_types::metering::StageUsage::metered(
        &kata_types::cache::TokenUsage {
            input: 500,
            output: 40,
            cache_read: 0,
            cache_write: 0,
        },
        kata_types::metering::MeteredCost::Estimated {
            micro_usd: 10_499,
            basis: kata_types::metering::EstimateBasis::UnknownModelFloor { model: "".into() },
        },
        0,
    );
    let report = turn_report(Some(reported.clone()));
    let settled = dispatcher(&planes.db)
        .judge_work_delta_scope(&recovered, occurrence.id(), Some(&delta_ref), Some(&report))
        .expect("the judge runs");
    assert!(settled, "the ro stage's delta settles the attempt");
    let (state, usage) = settled_charge(&planes.op_path, attempt_id);
    assert_eq!(state, "failed");
    assert_eq!(usage, serde_json::to_value(&reported).unwrap(), "{usage}");
    assert_eq!(usage["input"], 500);
    assert_eq!(usage["output"], 40);
    assert_eq!(usage["cost_micro_usd"], 10_499);
}

/// **An agent turn that reported NO usage is charged UNKNOWN naming its pair** — the
/// adapter and the model the vendor reported — never `0`.
#[test]
fn a_refused_agent_delta_without_reported_usage_is_charged_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    let (attempt_id, recovered, occurrence, delta_ref) = ro_agent_attempt_with_delta(&planes);
    let report = turn_report(None);
    assert!(
        dispatcher(&planes.db)
            .judge_work_delta_scope(&recovered, occurrence.id(), Some(&delta_ref), Some(&report))
            .expect("the judge runs")
    );
    let (state, usage) = settled_charge(&planes.op_path, attempt_id);
    assert_eq!(state, "failed");
    assert_eq!(
        usage["cost"],
        serde_json::json!({
            "quality": "unavailable",
            "backend": "nanocode_openai",
            "model": "gpt-fake-review",
        }),
        "{usage}"
    );
    assert!(usage.get("cost_micro_usd").is_none(), "{usage}");
}

/// **A LOST agent attempt is charged UNKNOWN naming the capsule's pair.** The worker died
/// with no report: the main settles PROVEN AMBIGUOUS, and the charge is `Unavailable`
/// naming the adapter and the declared model off the AUTHORIZED capsule (E-prep ledger
/// `agent-ambiguous`, transition 7, carried no charge at all).
#[tokio::test]
async fn a_lost_agent_attempt_is_charged_unavailable_naming_the_capsules_pair() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    let (attempt_id, _, _, _) = ro_agent_attempt_with_delta(&planes);
    assert!(
        dispatcher(&planes.db)
            .settle_lost_capsule_attempt_for_test(attempt_id, "worker w-1 died", Some("w-1"))
            .await
            .expect("the settlement runs")
    );
    let (state, usage) = settled_charge(&planes.op_path, attempt_id);
    assert_eq!(state, "failed");
    assert_eq!(
        usage["cost"],
        serde_json::json!({
            "quality": "unavailable",
            "backend": "nanocode_openai",
            "model": "gpt-declared",
        }),
        "{usage}"
    );
}

/// **A lost `Command` capsule is charged the authoritative `0`** — a shell process makes
/// no billable call, as its completion's null `token_usage` states — so a death never
/// fails a hard policy closed on a stage that cannot spend.
#[tokio::test]
async fn a_lost_command_attempt_is_charged_an_authoritative_zero() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    declare_environment(&planes);
    let execution_id = Ulid::new();
    let program = program_with_ro_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let (occurrence, _) = occurrence_ref(execution_id, &program);
    let work = empty_work(&planes, execution_id);
    let (attempt_id, _, _) = claim_capsule_attempt(&planes, execution_id, &occurrence, &work);
    assert!(
        dispatcher(&planes.db)
            .settle_lost_capsule_attempt_for_test(attempt_id, "worker w-1 died", Some("w-1"))
            .await
            .expect("the settlement runs")
    );
    let (state, usage) = settled_charge(&planes.op_path, attempt_id);
    assert_eq!(state, "failed");
    assert_eq!(
        usage["cost"],
        serde_json::json!({"quality": "authoritative", "micro_usd": 0}),
        "{usage}"
    );
}

/// The one base tree a `/work` census in this file's composition cell maps —
/// the resolver `publish_work_delta` reads the base through.
struct OneBase {
    reference: ArtifactRef,
    manifest: TreeManifest,
}

impl kata_worker::materialize::TreeResolver for OneBase {
    fn tree_manifest(&self, artifact: ArtifactId) -> kata_types::KataResult<TreeManifest> {
        assert_eq!(
            artifact,
            self.reference.id(),
            "the census reads the mapped base"
        );
        Ok(self.manifest.clone())
    }

    fn tree_reference(&self, artifact: ArtifactId) -> kata_types::KataResult<ArtifactRef> {
        assert_eq!(
            artifact,
            self.reference.id(),
            "the census reads the mapped base"
        );
        Ok(self.reference.clone())
    }
}

/// **`workspace = "ro"`'s refused set, through the REAL census: a change to a
/// tracked path, or to an untracked path the post-run tree's `.gitignore` does
/// not ignore. An untracked IGNORED path is neither refused nor applied — it
/// never enters the delta.**
///
/// The sibling cell above hands the judge a hand-built delta; this one
/// publishes the delta from a real post-run `/work` with
/// `kata_worker::work_delta::publish_work_delta`, the worker's own census, so
/// the composition the docs describe (a build's ignored `target/` under a
/// `workspace = "ro"` stage does not fail it) is read off the two halves
/// together. The verdict is read raw: the attempt row's `finished_at_ms` and
/// the last transition's payload, through a second SQLite handle.
///
/// **Would red if:** the census counted an ignored untracked path (the first
/// judge would settle the attempt), or the judge skipped a tracked path or an
/// unignored untracked one (the second would proceed to adoption).
#[test]
fn a_workspace_ro_stage_is_refused_for_exactly_its_unignored_changes() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    declare_environment(&planes);
    let execution_id = Ulid::new();
    let program = program_with_ro_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let (occurrence, _) = occurrence_ref(execution_id, &program);

    const GITIGNORE: &[u8] = b"target/\n";
    const LIB: &[u8] = b"pub fn f() {}\n";
    let member = |path: &str, bytes: &[u8]| {
        let durable = planes.cas.put_durable(bytes).unwrap();
        TreeEntry {
            path: TreePath::new(path).unwrap(),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object: durable.object_id(),
                size_bytes: durable.size(),
            },
        }
    };
    let manifest = TreeManifest::new(vec![
        member(".gitignore", GITIGNORE),
        member("src/lib.rs", LIB),
    ])
    .unwrap();
    let work = declared_work(&planes, execution_id, &manifest);
    let base = OneBase {
        reference: work.clone(),
        manifest,
    };
    let budgets = CapsuleBudgets {
        wall_time_ms: 30_000,
        output_bytes: 1 << 20,
        memory_bytes: 512 * 1024 * 1024,
        process_count: 64,
        result_bytes: 1 << 20,
        result_entries: 128,
        work_delta_bytes: kata_types::execution_contract::CAPSULE_WORK_DELTA_BYTES,
        work_delta_entries: 128,
    };
    let post_run = tempfile::tempdir().unwrap();
    let root = post_run.path();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("target/debug")).unwrap();
    std::fs::write(root.join(".gitignore"), GITIGNORE).unwrap();
    std::fs::write(root.join("src/lib.rs"), LIB).unwrap();
    // What `cargo build` leaves: untracked, under an ignored directory.
    std::fs::write(root.join("target/debug/build.o"), b"object\n").unwrap();
    let publish = || {
        kata_worker::work_delta::publish_work_delta(
            root,
            work.id(),
            &base,
            budgets,
            &kata_worker::result_publication::CasBlobSink(&planes.cas),
            None,
            None,
        )
        .expect("the census publishes")
    };
    let dispatcher = dispatcher(&planes.db);

    // The ignored build tree alone: no change the judge sees — the attempt
    // proceeds, and adoption has nothing of `target/` to apply.
    let (attempt_id, _, _) = claim_capsule_attempt(&planes, execution_id, &occurrence, &work);
    let recovered = planes.db.recovered_attempt(attempt_id).unwrap().unwrap();
    assert!(
        !dispatcher
            .judge_work_delta_scope(&recovered, occurrence.id(), Some(&publish()), None)
            .expect("the judge runs"),
        "an ro stage whose only write is an ignored untracked path is not refused"
    );
    let attempt = planes.db.attempt(attempt_id).unwrap().unwrap();
    assert!(
        attempt.finished_at_ms.is_none(),
        "the attempt is still live"
    );

    // A tracked modification and an unignored untracked file beside the same
    // build tree: refused whole, naming both and not the ignored path.
    std::fs::write(root.join("src/lib.rs"), b"pub fn g() {}\n").unwrap();
    std::fs::write(root.join("notes.txt"), b"left behind\n").unwrap();
    let (attempt_id, _, _) = claim_capsule_attempt(&planes, execution_id, &occurrence, &work);
    let recovered = planes.db.recovered_attempt(attempt_id).unwrap().unwrap();
    assert!(
        dispatcher
            .judge_work_delta_scope(&recovered, occurrence.id(), Some(&publish()), None)
            .expect("the judge runs"),
        "an ro stage's tracked and unignored changes settle the attempt"
    );
    let attempt = planes.db.attempt(attempt_id).unwrap().unwrap();
    assert!(
        attempt.finished_at_ms.is_some(),
        "performed but failed is recorded"
    );
    let reason = last_transition_payload(&planes.op_path, attempt_id);
    assert!(
        reason.contains("(work_delta_out_of_scope): notes.txt, src/lib.rs."),
        "exactly the unignored changes are named: {reason}"
    );
    assert!(
        !reason.contains("target/"),
        "the ignored path is never named: {reason}"
    );
}

/// **`produces_files` on a read-only `/work`
/// is refused AT CHECK — `produces_files_under_read_only_workspace` — named
/// stage and profile, on every engine, node-less and booted alike.**
///
/// The declared write closure names outputs the stage's posture lands none
/// of; letting it through would produce the adoption refusal
/// (`work_delta_out_of_scope`) on any write at all — a contradiction no run
/// could satisfy, so it is refused at load instead. A stage with the
/// materialized `confined_default` `/work` hits exactly this — the second arm
/// below.
///
/// **Watched red:** with `refuse_produces_files_under_read_only_workspace`
/// commented out this cell's pack COMPILES — measured; restored.
#[test]
fn a_produces_files_on_read_only_workspace_is_refused_at_check() {
    let refused = kata_program::execution_program::compile_starlark_execution_program(
        "probe = stage(\n\
         \x20   id = \"digest\",\n\
         \x20   agent = \"shell\",\n\
         \x20   sandbox = \"iso\",\n\
         \x20   produces_files = [\"r\"],\n\
         \x20   run = \"echo done > /work/r\",\n\
         )\n\
         workflow(\n\
         \x20   \"ro-closure-cell\",\n\
         \x20   root = [probe],\n\
         \x20   sandbox_profiles = {\n\
         \x20       \"iso\": sandbox_profile(workspace = \"ro\", net = \"offline\"),\n\
         \x20   },\n\
         )\n",
        "ro-closure-cell.star",
        &[],
    );
    let error = refused
        .expect_err("a write closure on a read-only workspace must be refused")
        .to_string();
    assert!(
        error.contains("produces_files_under_read_only_workspace"),
        "the refusal is named: {error}"
    );
    assert!(
        error.contains("\"digest\"") && error.contains("\"iso\""),
        "the refusal names the stage and the profile: {error}"
    );
    assert!(
        error.contains("workspace = \"rw\""),
        "the refusal names the recourse: {error}"
    );

    // The MATERIALIZED default is the same refusal: no authored sandbox is an
    // `ro` workspace (`SandboxProfile::confined_default`), so an un-sandboxed
    // stage declaring a write closure is refused identically.
    let defaulted = kata_program::execution_program::compile_starlark_execution_program(
        "probe = stage(\n\
         \x20   id = \"digest\",\n\
         \x20   agent = \"shell\",\n\
         \x20   produces_files = [\"r\"],\n\
         \x20   run = \"echo done > /work/r\",\n\
         )\n\
         workflow(\"ro-default-closure-cell\", root = [probe])\n",
        "ro-default-closure-cell.star",
        &[],
    );
    let error = defaulted
        .expect_err("the materialized default is the same refusal")
        .to_string();
    assert!(
        error.contains("produces_files_under_read_only_workspace"),
        "the materialized-default refusal is named: {error}"
    );

    // The admitted arms: `rw` + the same closure, and `ro` with NO closure.
    kata_program::execution_program::compile_starlark_execution_program(
        "probe = stage(\n\
         \x20   id = \"digest\",\n\
         \x20   agent = \"shell\",\n\
         \x20   sandbox = \"iso\",\n\
         \x20   produces_files = [\"r\"],\n\
         \x20   run = \"echo done > /work/r\",\n\
         )\n\
         workflow(\n\
         \x20   \"rw-closure-cell\",\n\
         \x20   root = [probe],\n\
         \x20   sandbox_profiles = {\n\
         \x20       \"iso\": sandbox_profile(workspace = \"rw\", net = \"offline\"),\n\
         \x20   },\n\
         )\n",
        "rw-closure-cell.star",
        &[],
    )
    .expect("a write closure on a writable workspace compiles");
    kata_program::execution_program::compile_starlark_execution_program(
        "probe = stage(\n\
         \x20   id = \"digest\",\n\
         \x20   agent = \"shell\",\n\
         \x20   sandbox = \"iso\",\n\
         \x20   run = \"true\",\n\
         )\n\
         workflow(\n\
         \x20   \"ro-plain-cell\",\n\
         \x20   root = [probe],\n\
         \x20   sandbox_profiles = {\n\
         \x20       \"iso\": sandbox_profile(workspace = \"ro\", net = \"offline\"),\n\
         \x20   },\n\
         )\n",
        "ro-plain-cell.star",
        &[],
    )
    .expect("a read-only stage with no declared closure compiles");
}

/// The `workspace = "rw"`, offline directive the scope-id cells assemble under.
fn scoped_directive() -> SandboxDirective {
    SandboxDirective {
        exec: ExecBackend::Oci,
        fs: FsPolicy::WorkspaceRw,
        net: NetPolicy::Offline,
        env: BTreeMap::new(),
        secret_tokens: BTreeMap::new(),
        image: None,
        confine_to_declared_inputs: true,
        content_cacheable: true,
        read_closure: Vec::new(),
        write_closure: Vec::new(),
        determinism_pinned: true,
    }
}

/// `produces_files` is PART OF THE CAPSULE IDENTITY — an approval binds the
/// stage's declared write scope because the action manifest folds it, and a
/// program that changes only the closure mints a DIFFERENT capsule (and a
/// different reuse key — the content-cache identity).
#[test]
fn produces_files_is_part_of_the_capsule_identity() {
    kata_types::node_profile::mark_node_installed();
    let build = |produces: &str| {
        let pack = format!(
            "probe = stage(\n\
             \x20   id = \"digest\",\n\
             \x20   agent = \"shell\",\n\
             \x20   sandbox = sandbox_profile(workspace = \"rw\"),\n\
             \x20   timeout_ms = 30000,\n\
             \x20   {produces}\n\
             \x20   prompt = \"echo done > /work/r\",\n\
             )\n\
             workflow(\n\
             \x20   \"work-apply-scope-id\",\n\
             \x20   root = [probe],\n\
             )\n"
        );
        kata_program::execution_program::compile_starlark_execution_program(
            &pack,
            "work-apply-scope-id.star",
            &[],
        )
        .unwrap()
    };
    let narrow = build("produces_files = [\"r\"],");
    let wide = build("produces_files = [\"r\", \"w\"],");
    let stage_id = kata_types::workflow::StageId(smol_str::SmolStr::new(STAGE));
    let assemble = |program: &kata_program::execution_program::ExecutionProgram| {
        let lowered =
            kata_program::execution_program::lower_stage_operation(program, &stage_id).unwrap();
        let stage = &program.stages[&stage_id];
        let occurrence = OccurrenceRef::new(
            kata_types::workflow::ExecutionId(Ulid::new()),
            program.program_hash,
            lowered.contract.id(),
            lowered.path.clone(),
        );
        let _ = &lowered;
        let (_action, capsule) = kata_workflow::capsule_assembly::assemble_capsule(
            &lowered,
            occurrence.id(),
            stage,
            &scoped_directive(),
            &kata_workflow::capsule_assembly::RenderedCommand::rendered("echo done > /work/r"),
            EnvironmentId(ContentHash::new([0x03; 32])),
            PlatformId(ContentHash::new([0x04; 32])),
            kata_workflow::capsule_assembly::empty_tree_artifact()
                .unwrap()
                .id(),
            kata_workflow::capsule_assembly::NodeBudgetDefaults {
                memory_bytes: 512 * 1024 * 1024,
                process_count: 64,
            },
            None,
            None,
        )
        .unwrap();
        capsule
    };
    let narrow_capsule = assemble(&narrow);
    let wide_capsule = assemble(&wide);
    assert_ne!(
        narrow_capsule.id(),
        wide_capsule.id(),
        "the declared output closure is folded into the capsule id"
    );
    assert_ne!(
        narrow_capsule.reuse_key(&kata_workflow::test_harness::oci_rig_executor_term()),
        wide_capsule.reuse_key(&kata_workflow::test_harness::oci_rig_executor_term()),
        "so the reuse key refuses to serve the wide stage the narrow capsule"
    );
}

/// CANCELLED CLOSEOUT — a cancel latched while an apply is still owed
/// settles the apply `cancelled` in the claim's own transaction — no jj write,
/// no head advance — and the sweep drains it; and a cancel latched AFTER the
/// apply leaves the parked head exactly where the apply put it.
#[test]
fn a_cancelled_closeout_settles_the_pending_apply_and_parks_the_applied_head() {
    // (a) Apply lands first, THEN cancel: the head stays on the applied
    // candidate — closeout must not unwind the committed effect.
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            Some(&fx.backend),
            Some(fx.planes.cas.as_ref()),
        )
        .unwrap();
    let applied = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(applied.head_seq, fx.head.head_seq + 1);
    fx.planes
        .db
        .latch_execution_cancel(fx.execution_id, "operator stop")
        .expect("the cancel latches");
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            Some(&fx.backend),
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the sweep is quiet — the apply already landed");
    let after_cancel = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        (after_cancel.head_seq, &after_cancel.candidate_commit_id),
        (applied.head_seq, &applied.candidate_commit_id),
        "cancel leaves the applied head parked where the apply put it"
    );

    // (b) Cancel latched BEFORE the apply runs: the claim settles `cancelled`
    // under the terminal-intent refusal — jj is never invoked and the head is
    // the admission's base head still.
    let dir2 = tempfile::tempdir().unwrap();
    let fx2 = fixture(dir2.path());
    fx2.planes
        .db
        .latch_execution_cancel(fx2.execution_id, "operator stop")
        .expect("the cancel latches");
    fx2.dispatcher
        .drive_pending_work_applies(
            fx2.execution_id,
            &fx2.program,
            Some(&fx2.backend),
            Some(fx2.planes.cas.as_ref()),
        )
        .expect("the sweep settles the apply cancelled");
    let head = fx2
        .planes
        .db
        .execution_work_tree_head(fx2.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        (head.head_seq, &head.candidate_commit_id),
        (fx2.head.head_seq, &fx2.head.candidate_commit_id),
        "a cancelled execution applies nothing"
    );
    assert!(
        fx2.planes
            .db
            .pending_work_applies(fx2.execution_id)
            .unwrap()
            .is_empty(),
        "the settled apply drains the sweep"
    );
    let apply_attempts: i64 = {
        let conn = rusqlite::Connection::open(&fx2.planes.op_path).unwrap();
        conn.query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = '#apply/digest'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(
        apply_attempts, 0,
        "no apply claim lands after terminal intent — the lifecycle conjunct drains the sweep and the head is the base's still"
    );
}

/// Armed crash AFTER the resolving transaction committed — head advanced,
/// apply accepted — but BEFORE the pass released the stage's successors.
/// Recovery is the gate itself: the row drains, the gate opens, nothing reruns.
#[test]
fn crash_after_work_apply_acceptance_before_successor_release() {
    work_apply_child_entry();
    if std::env::var(CHILD_MARKER).is_ok() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path());
    let (head, backend, planes, execution_id) = crash_then_recover(
        "after_work_apply_acceptance_before_successor_release",
        dir.path(),
        "crash_after_work_apply_acceptance_before_successor_release",
    );
    assert_eq!(head.head_seq, fx.head.head_seq + 1);
    assert_eq!(
        git_show(
            dir.path().join("repo").as_path(),
            &head.candidate_commit_id,
            "r"
        )
        .as_deref(),
        Some(std::str::from_utf8(MEMBER).unwrap()),
    );
    assert!(
        !planes
            .db
            .pending_work_apply_for_stage(execution_id, STAGE)
            .unwrap(),
        "the committed acceptance releases the successors — a second drive changes nothing"
    );
    drop(backend);
}

// -- regression cells ------------------------------------------------------------

/// A delta path carrying a VCS-internal component (`.git` at any depth)
/// is `work_delta_reserved_path` at adoption: the stage settles
/// performed-but-failed and nothing of the delta is applied — before scope or
/// `.gitattributes` conversion is even judged.
#[test]
fn a_delta_writing_vcs_internal_paths_is_refused_reserved() {
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    declare_environment(&planes);
    let execution_id = Ulid::new();
    let program = program_with_scope();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let (occurrence, _) = occurrence_ref(execution_id, &program);
    let work = empty_work(&planes, execution_id);
    let (attempt_id, _, _) = claim_capsule_attempt(&planes, execution_id, &occurrence, &work);
    let (delta_ref, _delta) = write_delta_at(
        &planes,
        execution_id,
        &work,
        ".git/config",
        b"[core]\n\tbare = false\n",
    );
    let recovered = planes.db.recovered_attempt(attempt_id).unwrap().unwrap();
    let dispatcher = dispatcher(&planes.db);
    let settled = dispatcher
        .judge_work_delta_scope(&recovered, occurrence.id(), Some(&delta_ref), None)
        .expect("the judge runs");
    assert!(settled, "a reserved-path delta settles the attempt");
    let reason = last_transition_payload(&planes.op_path, attempt_id);
    assert!(reason.contains("work_delta_reserved_path"), "{reason}");
    assert!(reason.contains(".git/config"), "{reason}");
}

/// A pending `#apply/` obligation cannot outlive its execution's
/// published outcome: `finish_terminalization` settles it `cancelled` in the
/// publication commit, and the sweep enumerates nothing to re-drive.
#[test]
fn a_pending_work_apply_is_settled_cancelled_at_terminalization() {
    let dir = tempfile::tempdir().unwrap();
    let fx = cas_fixture(dir.path());
    let stage_id = kata_types::workflow::StageId(smol_str::SmolStr::new(STAGE));
    let lowered = kata_program::execution_program::lower_stage_operation(&fx.program, &stage_id)
        .expect("the stage lowers");
    let spec = MainAttemptSpec {
        stage_id: work_apply_stage_id(STAGE),
        occurrence: OccurrenceBinding::new(
            OccurrenceRef::new(
                kata_types::workflow::ExecutionId(fx.execution_id),
                fx.program.program_hash,
                work_apply_operation_contract(lowered.contract.id()),
                lowered.path.clone(),
            ),
            None,
            None,
        ),
    };
    let attempt_id = Ulid::new();
    let claimed = fx
        .planes
        .db
        .claim_work_apply_attempt(attempt_id, &spec, "", fx.delta.base().id().0.0)
        .expect("the apply claim lands");
    assert!(
        matches!(claimed, WorkApplyClaimOutcome::Claimed { .. }),
        "the claim mints a pending apply: {claimed:?}"
    );
    // The execution's terminal outcome latches and publishes while the apply
    // is still pending — the drain settles it in the publication commit.
    fx.planes
        .db
        .begin_terminalization(
            fx.execution_id,
            kata_core::operational::LifecycleState::Cancelled,
            br#"{"kind":"cancelled","detail":"the operator cancelled under a pending apply"}"#,
        )
        .expect("the terminal intent latches and its cleanup discharges");
    fx.planes
        .db
        .finish_terminalization(fx.execution_id)
        .expect("the outcome publishes and drains the pending apply");
    let conn = rusqlite::Connection::open(&fx.planes.op_path).unwrap();
    let state: String = conn
        .query_row(
            "SELECT p.state FROM attempt_projection p
               JOIN attempts a ON a.execution_id = p.execution_id
                AND a.stage_id = p.stage_id AND a.attempt_ordinal = p.attempt_ordinal
              WHERE a.attempt_id = ?1",
            rusqlite::params![attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        state, "cancelled",
        "the pending apply is settled cancelled in the publication commit"
    );
    assert!(
        fx.planes
            .db
            .pending_work_applies(fx.execution_id)
            .unwrap()
            .is_empty(),
        "a terminal execution enumerates no pending applies"
    );
    // And a drive on the dead execution moves nothing.
    fx.dispatcher
        .drive_pending_work_applies(
            fx.execution_id,
            &fx.program,
            None,
            Some(fx.planes.cas.as_ref()),
        )
        .expect("the sweep is a no-op on a terminal execution");
    let head = fx
        .planes
        .db
        .execution_work_tree_head(fx.execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        head.head_seq, fx.head.head_seq,
        "no head advance — the cancelled apply never performed"
    );
}

/// A static `topology(..)` stage's dependents gate on its EXPANSION's
/// `/work` apply, not only a row under the stage's own name: the merged delta
/// is recorded under the `#op/<path>` program-operation attempt, so
/// `work_apply_blocks_successors` must find THE STAGE (and only expansion
/// stages) before asking that coordinate. Seeded: `#op/0` — the program-op
/// spelling of stage index 0 — accepted with a `/work` delta and no apply.
///
/// **Mutant die**: `id == stage` flipped to `!=` never matches the queried
/// stage (the gate answers false for `a_topo`); `&&` weakened to `||`
/// matches the FIRST expansion stage for ANY queried stage (`b_plain` reads
/// `a_topo`'s pending apply as its own gate); `topo || fanout` to `&&`
/// matches no real stage and drops the expansion arm entirely.
#[test]
fn a_topology_stages_pending_apply_gates_its_successors() {
    const PACK: &str = r#"a_topo = stage(
    id = "a_topo",
    agent = "shell",
    run = "printf ok",
    topology = topology(
        "root_with_parallel_workers",
        workers = [role("w", agent = "shell")],
    ),
)

b_plain = stage(
    id = "b_plain",
    agent = "shell",
    run = "printf ok",
    depends_on = ["a_topo"],
)

workflow("topo-apply-gate", root = [a_topo, b_plain])
"#;
    let dir = tempfile::tempdir().unwrap();
    let planes = planes(dir.path());
    declare_environment(&planes);
    let program = kata_program::execution_program::compile_starlark_execution_program(
        PACK,
        "topo-apply-gate.star",
        &[],
    )
    .expect("the two-stage pack compiles");
    assert_eq!(
        program
            .stages
            .keys()
            .map(|id| id.0.as_str())
            .collect::<Vec<_>>(),
        vec!["a_topo", "b_plain"],
        "a_topo is stage index 0 — its expansion's program op is `#op/0`"
    );
    let execution_id = Ulid::new();
    planes
        .db
        .submit_execution(execution_id, &program_record(&program), &invocation())
        .unwrap();
    let op0 = OperationPath(vec![0]).program_operation_stage_id();
    let base_ref = empty_work(&planes, execution_id);
    let (delta_ref, _delta) = write_delta(&planes, execution_id, &base_ref);
    let occurrence = OccurrenceRef::new(
        kata_types::workflow::ExecutionId(execution_id),
        program.program_hash,
        OperationContractId(ContentHash::new([0x6D; 32])),
        OperationPath(vec![0]),
    );
    accept_capsule_with_delta_at(
        &planes,
        execution_id,
        &op0,
        &occurrence,
        &base_ref,
        &delta_ref,
    );
    assert!(
        planes
            .db
            .pending_work_apply_for_stage(execution_id, &op0)
            .unwrap(),
        "the expansion's accepted delta is a pending apply under its #op coordinate"
    );
    let runner = kata_workflow::runner::WorkflowRunner::new_from_program(
        program.clone(),
        Arc::new(dispatcher(&planes.db)),
        execution_id,
    )
    .expect("the runner builds over the seeded plane");
    assert!(
        kata_workflow::runner::testing::work_apply_blocks_successors_for_test(&runner, "a_topo")
            .unwrap(),
        "the topology stage's successors stay gated on its expansion's apply"
    );
    assert!(
        !kata_workflow::runner::testing::work_apply_blocks_successors_for_test(&runner, "b_plain")
            .unwrap(),
        "a plain stage with no pending apply blocks nothing"
    );
}
