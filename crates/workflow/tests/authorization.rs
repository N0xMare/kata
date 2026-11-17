//! AUTHORIZATION, observed through a SECOND raw
//! rusqlite handle and the CAS's own files on disk.
//!
//! # Invariant
//!
//! EVERY durable assertion here reads `operational.db`, `cas.db` or the blob tree
//! through a connection this file opens itself. Asking `OperationalDb` whether
//! `OperationalDb` wrote the row is the shape that has let every composition defect
//! in this tree ship green, so the typed readers are never the witness.
//!
//! The one thing that is deliberately NOT read through a raw handle is the dispatch
//! command's PAYLOAD SHAPE: the payload is bytes, and the claim under test is that
//! those bytes decode as `DispatchFrame::Capsule`. That decode is the transport
//! crate's, over bytes this file lifts out of `attempt_commands.command_json` with
//! its own SQL.

use std::path::Path;
use std::sync::Arc;

use kata_core::store::cas::CasStore;
use kata_core::{
    EnvironmentDeclaration, InvocationKind, InvocationRecord, OperationalDb, ProgramRecord,
    SubmitOutcome,
};
use kata_program::execution_program::{
    ExecutionProgram, ExecutionProgramStage, LoweredOperation, compile_starlark_execution_program,
    lower_stage_operation, occurrence_for,
};
use kata_transport::types::DispatchFrame;
use kata_types::execution_contract::{
    ArtifactId, ArtifactRef, Capsule, EnvironmentId, OccurrenceRef, PlatformId, PreparedAction,
};
use kata_types::identity_algebra::AdmissionDigest;
use kata_types::primitives::{ContentHash, ObjectId};
use kata_types::sandbox::{ExecBackend, FsPolicy, NetPolicy, SandboxDirective};
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_types::workflow::{ExecutionId, StageId};
use kata_workflow::authorization::{AuthorizeInput, Authorized, authorize_attempt, prepare_action};
use kata_workflow::capsule_assembly::{
    NodeBudgetDefaults, RenderedCommand, assemble_capsule, empty_tree_artifact,
    sandbox_permissions_hash,
};
use smol_str::SmolStr;
use ulid::Ulid;

/// The RENDERED stage command every capsule in this file is assembled over.
///
/// A [`RenderedCommand`] constructed EXPLICITLY, which is the newtype's whole point: the
/// obligation is "these are the bytes a shell will run", and a test that wrote
/// `stage.op.prompt_template` here would be stating it falsely in one visible place
/// rather than invisibly at an argument position. `assemble_capsule` takes the rendered
/// text because a `Template` stage's command is a function of runtime context and there
/// is exactly one renderer for that; what this file exercises is the IDENTITY, so one
/// fixed command keeps every vector differing in the field under test.
fn stage_command() -> RenderedCommand {
    RenderedCommand::rendered("echo authorization")
}
/// The SHIPPED pack this class is defined over — the shell stage from
/// `workflows/smoke/sandbox-smoke-shell-offline.star`.
///
/// `include_str!` rather than a copy: a fixture copy of a shipped pack is a second
/// pack that stops being the shipped one the first time the real file moves, which
/// is exactly what "drive a SHIPPED stage" is meant to rule out.
const SHIPPED_PACK: &str =
    include_str!("../../../workflows/smoke/sandbox-smoke-shell-offline.star");
const SHIPPED_STAGE: &str = "probe";
const ENVIRONMENT_LABEL: &str = "pkgs-static-busybox";
const ROOT_STAGE_ID: &str = "01JZZZZZZZZZZZZZZZZZZZZZE1";
const WORKER: &str = "worker-capsule-1";

struct Rig {
    op_path: std::path::PathBuf,
    cas_path: std::path::PathBuf,
    blob_dir: std::path::PathBuf,
    db: Arc<OperationalDb>,
    cas: CasStore,
    /// Kept alive for the rig's lifetime when this rig owns a temporary directory.
    /// `None` when the rig was OPENED on a directory somebody else owns — the crash
    /// cell's recovered data dir, which the parent must still be able to read after
    /// the rig is dropped.
    owned_dir: Option<tempfile::TempDir>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let mut rig = open_rig(dir.path());
    rig.owned_dir = Some(dir);
    rig
}

/// Open (or create) the two planes beneath `root`.
fn open_rig(root: &Path) -> Rig {
    let op_path = root.join("operational.db");
    let cas_path = root.join("cas.db");
    let blob_dir = root.join("cas");
    let db = Arc::new(OperationalDb::open(&op_path).unwrap());
    let cas = CasStore::open(cas_path.as_path(), &blob_dir).unwrap();
    Rig {
        op_path,
        cas_path,
        blob_dir,
        db,
        cas,
        owned_dir: None,
    }
}

/// THE SECOND HANDLE. Read-only on purpose: an observer that can write is an
/// observer that can repair what it was meant to catch.
fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// THE CAS WITNESS: every object the store holds, as `(object_id, size)` read off
/// `cas.db` through a handle THIS function opens, plus every blob file on disk.
///
/// # Why the file tree alone was not a witness
///
/// `CasStore` stores an object under
/// `kata_core::store::INLINE_THRESHOLD` as a COLUMN inside `cas.db`, and a capsule's
/// canonical JSON is a few hundred bytes — so publishing one adds no file at all, and a
/// "the blob tree is unchanged" assertion was satisfied by a publish that had happened.
/// The row count is the fact that moves for every object; the file list is kept beside
/// it because a FILE-backed object would move that and not the other, and a witness
/// that can only see one of the two storage forms is the narrower claim.
fn cas_contents(rig: &Rig) -> (Vec<(Vec<u8>, i64)>, Vec<std::path::PathBuf>) {
    let conn = raw(&rig.cas_path);
    let mut statement = conn
        .prepare("SELECT object_id, size FROM cas_objects ORDER BY object_id")
        .unwrap();
    let objects: Vec<(Vec<u8>, i64)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    (objects, blob_files(rig))
}

/// Every blob file the CAS holds, by path.
fn blob_files(rig: &Rig) -> Vec<std::path::PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&rig.blob_dir, &mut out);
    out.sort();
    out
}

fn program_record() -> ProgramRecord {
    ProgramRecord {
        program_hash: ContentHash::new([7u8; 32]),
        schema_version: 4,
        program_json: b"{\"program\":1}".to_vec(),
    }
}

fn invocation_record() -> InvocationRecord {
    let bytes = kata_types::idempotency::canonicalize_args(&serde_json::json!({
        "schema_version": 1
    }));
    let digest = *blake3::hash(&bytes).as_bytes();
    InvocationRecord {
        schema_version: 1,
        kind: InvocationKind::Workflow,
        admission_digest: AdmissionDigest(ContentHash::new(digest)),
        invocation_json: bytes,
    }
}

/// Admit one execution, so the `occurrences` foreign key has a parent.
fn submit(rig: &Rig) -> ExecutionId {
    submit_id(rig, Ulid::new())
}

/// Admit `execution_id`, tolerating a RE-admission of the same identity — which is
/// what the crash cell's second half performs when it rebuilds its fixture on a data
/// dir the crashed child already wrote.
fn submit_id(rig: &Rig, execution_id: Ulid) -> ExecutionId {
    assert!(matches!(
        rig.db
            .submit_execution(execution_id, &program_record(), &invocation_record())
            .unwrap(),
        SubmitOutcome::Submitted { .. } | SubmitOutcome::AlreadySubmitted
    ));
    ExecutionId(execution_id)
}

/// Declare a Nix environment and PROMOTE its gc root, which is what the
/// authorization gate demands.
/// The fixture environment provides `sh`, which is every assembled capsule's `argv[0]`.
static SH_ONLY: std::sync::LazyLock<kata_workflow::test_harness::FixtureProgramProbe> =
    std::sync::LazyLock::new(|| kata_workflow::test_harness::FixtureProgramProbe(vec!["sh"]));

fn declare_promoted_environment(rig: &Rig) -> EnvironmentId {
    let id = declare_environment(rig);
    rig.db
        .promote_environment_root(id.0.0, chrono::Utc::now().timestamp_millis())
        .unwrap();
    id
}

fn declare_environment(rig: &Rig) -> EnvironmentId {
    let manifest = rig
        .cas
        .put_durable(&kata_workflow::test_harness::fixture_environment_manifest_bytes())
        .unwrap();
    let environment_id = [0x5A; 32];
    let declaration = EnvironmentDeclaration::for_staged_root(
        environment_id,
        &manifest,
        [0x5C; 32],
        ENVIRONMENT_LABEL,
        [0x33; 32],
        ROOT_STAGE_ID,
    )
    .unwrap();
    rig.db.declare_environment(&declaration).unwrap();
    EnvironmentId(ContentHash::new(environment_id))
}

/// Publish and declare the two artifacts every assembled capsule maps: the
/// execution's recorded `/work` head, and the canonical EMPTY tree `/out` and
/// `/tmp` share.
///
/// The head is written by the production seed verb —
/// [`publish_scratch_tree_head`] walks the one-file scratch dir ONCE and
/// records the root `execution_work_tree_heads` row — and the empty tree is
/// declared through `for_durable_tree`, which re-derives the address from the
/// manifest — so the rows this rig writes are the rows production writes,
/// not a blob standing in for a tree.
fn declare_capsule_inputs(
    rig: &Rig,
    execution: ExecutionId,
) -> kata_core::operational::ExecutionWorkTreeHead {
    // THE PRODUCTION SEED over a real scratch dir: walked, published, declared
    // retained by the execution, and RECORDED as the root /work head — the row
    // is the only `/work` authorization accepts.
    let workspace = tempfile::tempdir().unwrap();
    let script = workspace.path().join("run.sh");
    std::fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let head = kata_core::work_tree::publish_scratch_tree_head(
        &rig.db,
        &rig.cas,
        execution.0,
        workspace.path(),
    )
    .unwrap();
    // The EMPTY tree `assemble_capsule` maps at `/out` and `/tmp`, through the producer's
    // own door.
    let empty = kata_core::work_tree::declare_empty_tree(&rig.db, &rig.cas, execution.0).unwrap();
    assert_eq!(
        empty_tree_artifact().unwrap().id(),
        empty.id(),
        "the producer must declare the SAME empty tree `capsule_assembly` maps"
    );
    head
}

/// The shipped pack, compiled.
fn shipped_program() -> ExecutionProgram {
    compile_starlark_execution_program(SHIPPED_PACK, "sandbox-smoke-shell-offline.star", &[])
        .expect("the shipped pack compiles")
}

/// The shipped pack with a declared `timeout_ms` on its one stage.
///
/// # Why the fixture has to differ from the shipped text by this one kwarg
///
/// `assemble_capsule` REFUSES a stage that declares no `timeout_ms`, because a
/// capsule commits to a wall-time bound and kata refuses to invent one. The shipped
/// pack declares none, so the end-to-end drive adds the one kwarg and
/// changes nothing else: the same prompt, the same outputs, the same `iso` profile.
/// Stated rather than quietly patched, because "we drove the shipped stage" would
/// otherwise be a claim wider than what ran.
fn timed_program() -> ExecutionProgram {
    let patched = SHIPPED_PACK.replace(
        "    agent = \"shell\",\n    sandbox = \"iso\",",
        "    agent = \"shell\",\n    sandbox = \"iso\",\n    timeout_ms = 30000,",
    );
    assert_ne!(
        patched, SHIPPED_PACK,
        "the one-kwarg patch must actually apply, or this fixture silently becomes \
         the shipped pack and the assembly below would refuse"
    );
    compile_starlark_execution_program(&patched, "sandbox-smoke-shell-offline.star", &[])
        .expect("the shipped pack plus a declared timeout compiles")
}

fn stage_of(program: &ExecutionProgram) -> &ExecutionProgramStage {
    program
        .stages
        .iter()
        .find(|(id, _)| *id == &StageId(SmolStr::new(SHIPPED_STAGE)))
        .map(|(_, stage)| stage)
        .expect("the shipped pack carries its one stage")
}

fn lowered_of(program: &ExecutionProgram) -> LoweredOperation {
    lower_stage_operation(program, &StageId(SmolStr::new(SHIPPED_STAGE)))
        .expect("the shipped shell stage lowers to a typed operation")
}

/// The `iso` profile's POSTURE as an at-rest directive, with the main-resolved
/// workspace path absent.
///
/// # What is and is not the shipped profile here
///
/// `workspace = "rw"`, `net = "offline"` and the oci backend are the shipped
/// profile's, asserted against `program.sandbox_profiles` below. The production
/// `Dispatcher::resolve_sandbox` stamps no `env` at all, so this fixture is the
/// shape production resolves: the capsule's `/work` mapping is the workspace.
fn iso_directive(program: &ExecutionProgram) -> SandboxDirective {
    let profile = program
        .sandbox_profiles
        .get("iso")
        .expect("the shipped pack declares the `iso` profile");
    assert_eq!(profile.fs, FsPolicy::WorkspaceRw);
    assert_eq!(profile.net, NetPolicy::Offline);
    SandboxDirective {
        exec: ExecBackend::Oci,
        fs: profile.fs.clone(),
        net: profile.net.clone(),
        env: std::collections::BTreeMap::new(),
        secret_tokens: std::collections::BTreeMap::new(),
        image: None,
        confine_to_declared_inputs: false,
        content_cacheable: false,
        read_closure: Vec::new(),
        write_closure: Vec::new(),
        determinism_pinned: false,
    }
}

fn budgets() -> NodeBudgetDefaults {
    NodeBudgetDefaults {
        memory_bytes: 512 * 1024 * 1024,
        process_count: 64,
    }
}

fn platform() -> PlatformId {
    PlatformId(ContentHash::new([0x33; 32]))
}

/// Everything one authorization needs, assembled from values.
struct Prepared {
    execution: ExecutionId,
    program: ExecutionProgram,
    lowered: LoweredOperation,
    occurrence: OccurrenceRef,
    action: PreparedAction,
    capsule: Capsule,
    environment: EnvironmentId,
    work_head: kata_core::operational::ExecutionWorkTreeHead,
}

fn prepare(rig: &Rig, environment: EnvironmentId) -> Prepared {
    let execution = submit(rig);
    prepare_for(rig, environment, execution)
}

fn prepare_for(rig: &Rig, environment: EnvironmentId, execution: ExecutionId) -> Prepared {
    let program = timed_program();
    let lowered = lowered_of(&program);
    let occurrence = occurrence_for(&program, execution, &lowered);
    let work_head = declare_capsule_inputs(rig, execution);
    let directive = iso_directive(&program);
    let (action, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage_of(&program),
        &directive,
        &stage_command(),
        environment,
        platform(),
        ArtifactId(kata_types::primitives::FixedBytes(
            work_head.work_tree_artifact_id,
        )),
        budgets(),
        None,
        None,
    )
    .expect("the shipped stage plus a declared timeout assembles");
    Prepared {
        execution,
        program,
        lowered,
        occurrence,
        action,
        capsule,
        environment,
        work_head,
    }
}

fn input_of(prepared: &Prepared) -> AuthorizeInput<'_> {
    AuthorizeInput {
        execution: prepared.execution,
        program_hash: prepared.program.program_hash,
        lowered: &prepared.lowered,
        occurrence: prepared.occurrence.clone(),
        prepared: prepared.action.clone(),
        capsule: prepared.capsule.clone(),
        environment: prepared.environment,
        work_head: Some(&prepared.work_head),
        programs: &*SH_ONLY,
        checked_stage: stage_of(&prepared.program),
        place: &|| Ok(WORKER.into()),
        approval_bypass_reason: None,
    }
}

/// THE END-TO-END DRIVE, and the row-by-row accounting of what it wrote.
///
/// Lowering → assembly → authorization, over the SHIPPED shell stage, and then every
/// durable fact counted through the raw handle: one occurrence, one attempt bound to
/// it, one `claimed` transition, one capsule, one dispatch command carrying
/// `DispatchFrame::Capsule`. The ORDER is asserted too, from the sequence numbers and
/// the enqueue instant, because "all five rows exist" is a weaker claim than "the
/// occurrence was authorized before the dispatch was enqueued".
#[test]
fn authorizing_a_shipped_shell_stage_writes_one_of_each_row_in_order() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let prepared = prepare(&rig, environment);

    let authorized: Authorized = authorize_attempt(&rig.db, &rig.cas, input_of(&prepared))
        .expect("the authorization lands")
        .dispatched()
        .expect("an ungated stage dispatches");
    assert_eq!(authorized.occurrence_id, prepared.occurrence.id());
    assert_eq!(authorized.capsule_id, prepared.capsule.id());

    let conn = raw(&rig.op_path);
    let occurrences: i64 = conn
        .query_row("SELECT count(*) FROM occurrences", [], |row| row.get(0))
        .unwrap();
    assert_eq!(occurrences, 1, "exactly one occurrence row");

    let (stored_occurrence, stored_action, stored_capsule): (Vec<u8>, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT occurrence_id, prepared_action_id, capsule_id FROM occurrences",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(stored_occurrence, prepared.occurrence.id().0.0.to_vec());
    assert_eq!(
        stored_action,
        prepared.action.id().0.0.to_vec(),
        "the authorization must bind `prepared_action_id`, never leave it NULL"
    );
    assert_eq!(stored_capsule, prepared.capsule.id().0.0.to_vec());

    let (attempts, bound): (i64, i64) = conn
        .query_row(
            "SELECT count(*), count(occurrence_id) FROM attempts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((attempts, bound), (1, 1), "one attempt, and it is BOUND");

    let capsules: i64 = conn
        .query_row("SELECT count(*) FROM capsules", [], |row| row.get(0))
        .unwrap();
    assert_eq!(capsules, 1, "exactly one capsules row");

    let claimed: i64 = conn
        .query_row(
            "SELECT count(*) FROM transitions WHERE kind = 'claimed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(claimed, 1, "exactly one claiming transition");

    // THE ORDER. The claim's sequence must precede the dispatch's, which is the
    // durable expression of "the occurrence was authorized before anything was
    // enqueued for it" — the window `after_occurrence_authorized_before_dispatch` names.
    let (claim_seq, dispatch_seq): (i64, i64) = conn
        .query_row(
            "SELECT
               (SELECT seq FROM transitions WHERE kind = 'claimed'),
               (SELECT seq FROM transitions WHERE resulting_state = 'dispatched')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(
        claim_seq < dispatch_seq,
        "the claim must be recorded before the dispatch: {claim_seq} vs {dispatch_seq}"
    );

    // ONE DISPATCH COMMAND, and its payload carries the CAPSULE ARM.
    let (commands, payload): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT count(*), (SELECT command_json FROM attempt_commands) FROM attempt_commands",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(commands, 1, "exactly one dispatch command");
    let command: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(command["kind"], "dispatch");
    assert_eq!(command["worker_id"], WORKER);
    let frame: DispatchFrame = serde_json::from_value(command["frame"].clone())
        .expect("the command payload's frame decodes as a DispatchFrame");
    let DispatchFrame::Capsule(capsule_frame) = &frame;
    assert_eq!(capsule_frame.attempt_id, authorized.attempt_id);
    assert_eq!(capsule_frame.occurrence_id, prepared.occurrence.id());
    assert_eq!(capsule_frame.capsule.id, prepared.capsule.id());
    assert_eq!(
        capsule_frame.capsule.size_bytes,
        kata_types::idempotency::canonicalize_args(
            &serde_json::to_value(&prepared.capsule).unwrap()
        )
        .len() as u64,
        "the frame's length must be the capsule's canonical length, which is what a \
         worker's verified read is bounded by"
    );

    // THE WORKER'S OWN RESOLVER READS WHAT THE MAIN PUBLISHED.
    //
    // This is the cross-crate half, and it is the one that kills the mirror: until now
    // the authorization's bytes were only ever checked by `kata-workflow`'s encoder
    // against `kata-workflow`'s expectations. `kata_worker::capsule_frame::resolve`
    // shares no code with the publishing path — it re-derives the address of the bytes
    // it read, decodes them through `Capsule`'s own `Deserialize` (which recomputes the
    // capsule id from the body), and compares the result against the frame. A capsule
    // that round-trips through THAT is a capsule a worker can run.
    assert_eq!(
        capsule_frame.occurrence_id,
        prepared.occurrence.id(),
        "the frame the main assembled names the occurrence it authorized"
    );
    let resolved = kata_worker::capsule_frame::resolve(
        &kata_worker::capsule_frame::OpenCasBlobSource(&rig.cas),
        capsule_frame,
    )
    .expect("the worker's resolver reads the capsule the main published");
    assert_eq!(
        resolved, prepared.capsule,
        "the capsule a WORKER resolves out of the store must be the capsule the main \
         assembled, field for field"
    );

    // THE FRAME CARRIES NO HOST PATH, BY CONSTRUCTION — and the frame's own
    // inventory says so rather than this test re-deriving it.
    assert!(
        frame.shared_filesystem_presumptions().is_empty(),
        "a capsule frame's shared-filesystem inventory is empty by construction"
    );
    let raw_payload = String::from_utf8(payload).unwrap();
    assert!(
        !raw_payload.contains("/tmp/"),
        "no main-host path may reach the durable command: {raw_payload}"
    );
    drop(rig);
}

/// The shipped stage as SHIPPED: it lowers, and it ASSEMBLES — committing to the
/// AUTHORING default wall clock, because it declares none of its own.
///
/// # Why this is a test and not a comment
///
/// The obligation is discharged at the AUTHORING layer — `stage()` resolves an
/// undeclared `timeout_ms=` to `DEFAULT_STAGE_TIMEOUT_MS` — and what this pins is
/// the SUBSTITUTION reaching the capsule: the stage declares nothing, and the capsule commits to
/// exactly the default rather than to `0`, to the node's configured floor, or to a number no layer
/// can name.
#[test]
fn the_shipped_shell_stage_assembles_on_the_authoring_default_wall_clock() {
    let rig = rig();
    let program = shipped_program();
    let stage = stage_of(&program);
    assert_eq!(
        stage.policies.timeout_ms,
        kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
        "the shipped pack declares no timeout_ms, so the checked IR must carry the authoring \
         default; a different value here means something between `stage()` and the program \
         chose its own number"
    );
    let lowered = lowered_of(&program);
    assert_eq!(
        lowered.contract.source_stage,
        StageId(SmolStr::new(SHIPPED_STAGE)),
        "the SHIPPED stage lowers, which is the half that always did work"
    );

    let (_, capsule) = assemble_capsule(
        &lowered,
        occurrence_for(&program, ExecutionId(Ulid::new()), &lowered).id(),
        stage,
        &iso_directive(&program),
        &stage_command(),
        declare_promoted_environment(&rig),
        platform(),
        ArtifactId(ContentHash::new([0x11; 32])),
        budgets(),
        None,
        None,
    )
    .expect("the shipped stage assembles now that every checked stage carries a wall clock");
    assert_eq!(
        capsule.budgets().wall_time_ms,
        kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS,
        "and the capsule commits to the stage's bound, which for this pack IS the default"
    );
    drop(rig);
}

/// RE-AUTHORIZING the same occurrence CONVERGES: no second occurrence row, and no
/// second capsule row, while the ATTEMPT is a new generation of the same logical work.
#[test]
fn re_authorizing_one_occurrence_converges_on_its_row() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let prepared = prepare(&rig, environment);

    let first = authorize_attempt(&rig.db, &rig.cas, input_of(&prepared))
        .unwrap()
        .dispatched()
        .unwrap();
    let second = authorize_attempt(&rig.db, &rig.cas, input_of(&prepared))
        .unwrap()
        .dispatched()
        .unwrap();

    assert_eq!(
        first.occurrence_id, second.occurrence_id,
        "both generations name ONE occurrence"
    );
    assert_eq!(first.capsule_id, second.capsule_id);
    assert_ne!(
        first.attempt_id, second.attempt_id,
        "and they are DIFFERENT attempts — a re-dispatch is a second generation, not \
         a second occurrence"
    );

    let conn = raw(&rig.op_path);
    let (occurrences, capsules, attempts, commands): (i64, i64, i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM occurrences), (SELECT count(*) FROM capsules),
                    (SELECT count(*) FROM attempts), (SELECT count(*) FROM attempt_commands)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        (occurrences, capsules, attempts, commands),
        (1, 1, 2, 2),
        "one occurrence and one capsule, two attempts and two commands"
    );
    let bound: i64 = conn
        .query_row(
            "SELECT count(DISTINCT occurrence_id) FROM attempts",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bound, 1, "both attempts are bound to the SAME occurrence");
    drop(rig);
}

/// A DIVERGENT presentation at the same coordinates REFUSES rather than converging.
///
/// Two clauses, because the refusal has two doors and only one of them is this
/// module's: an occurrence that does not describe its own coordinates is refused by
/// `authorize_attempt` before anything is written, and a second capsule at an
/// already-authorized occurrence is refused by `claim_attempt`'s stored-row
/// comparison.
#[test]
fn a_divergent_presentation_at_one_occurrence_refuses() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let prepared = prepare(&rig, environment);
    authorize_attempt(&rig.db, &rig.cas, input_of(&prepared)).unwrap();

    // (a) the occurrence disagrees with the coordinates presented beside it.
    let mut incoherent = input_of(&prepared);
    incoherent.program_hash = ContentHash::new([0xEE; 32]);
    let error = authorize_attempt(&rig.db, &rig.cas, incoherent)
        .expect_err("an occurrence that does not fold its own coordinates must be refused");
    assert!(
        error.to_string().contains("program_hash"),
        "the refusal must name the field that disagrees: {error}"
    );

    // (b) a DIFFERENT capsule at the same occurrence. Built by re-assembling with a
    // different node budget, which rotates `CapsuleId` without touching the
    // occurrence — the aliasing the divergence refusal exists for.
    let (other_action, other_capsule) = assemble_capsule(
        &prepared.lowered,
        prepared.occurrence.id(),
        stage_of(&prepared.program),
        &iso_directive(&prepared.program),
        &stage_command(),
        environment,
        platform(),
        ArtifactId(kata_types::primitives::FixedBytes(
            prepared.work_head.work_tree_artifact_id,
        )),
        NodeBudgetDefaults {
            memory_bytes: 1024 * 1024 * 1024,
            process_count: 128,
        },
        None,
        None,
    )
    .unwrap();
    assert_ne!(other_capsule.id(), prepared.capsule.id());
    let other_capsule_for_witness = other_capsule.clone();
    let mut divergent = input_of(&prepared);
    divergent.prepared = other_action;
    divergent.capsule = other_capsule;
    let error = authorize_attempt(&rig.db, &rig.cas, divergent)
        .expect_err("a second capsule at one occurrence must be refused");
    assert!(
        error.to_string().contains("is already bound to capsule"),
        "the refusal must come from the PRE-PUBLISH door and must name the capsule the \
         stored occurrence is already bound to, because a refusal one step later (the \
         claim's `capsule_id` divergence check, which still stands as the authority) \
         would already have declared this capsule: {error}"
    );

    let conn = raw(&rig.op_path);
    let (occurrences, attempts, capsules): (i64, i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM occurrences), (SELECT count(*) FROM attempts),
                    (SELECT count(*) FROM capsules)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        (occurrences, attempts, capsules),
        (1, 1, 1),
        "neither refusal left a row behind — and `capsules` is the load-bearing count: \
         the divergent capsule must not have been DECLARED before the \
         claim refused it, because a declared capsule's bytes are retained by a \
         node-owned cas_roots row and the capsules plane has no release verb, so that \
         retention would be permanent"
    );
    // And the divergent capsule's BYTES were never published either, observed on the
    // store rather than inferred from the row count.
    let divergent_bytes = kata_types::idempotency::canonicalize_args(
        &serde_json::to_value(&other_capsule_for_witness).unwrap(),
    );
    let address = kata_types::cache::object_id_for_canonical_bytes(&divergent_bytes)
        .0
        .to_vec();
    assert!(
        !cas_contents(&rig)
            .0
            .iter()
            .any(|(object, _)| object == &address),
        "the refused capsule's canonical bytes must be absent from `cas_objects`"
    );
    drop(rig);
}

/// AN UNPROMOTED OR RELEASED ENVIRONMENT REFUSES BEFORE ANY BYTE IS PUBLISHED, and
/// the CAS is observed UNCHANGED ON DISK — file for file, not by row count.
#[test]
fn an_unauthorized_environment_refuses_before_the_cas_is_touched() {
    for (case, promote, release) in [
        ("unpromoted", false, false),
        ("released", true, true),
        ("undeclared", false, false),
    ] {
        let rig = rig();
        let environment = if case == "undeclared" {
            // Never declared at all — a closure this node has no row for.
            let _ = declare_promoted_environment(&rig);
            EnvironmentId(ContentHash::new([0x99; 32]))
        } else {
            let id = declare_environment(&rig);
            if promote {
                rig.db
                    .promote_environment_root(id.0.0, chrono::Utc::now().timestamp_millis())
                    .unwrap();
            }
            if release {
                rig.db
                    .release_environment(id.0.0, chrono::Utc::now().timestamp_millis() + 1)
                    .unwrap();
            }
            id
        };

        // The capsule is assembled against the SAME environment id, so the refusal
        // under test is the gate's and not a coherence mismatch.
        let execution = submit(&rig);
        let program = timed_program();
        let lowered = lowered_of(&program);
        let occurrence = occurrence_for(&program, execution, &lowered);
        let work_head = declare_capsule_inputs(&rig, execution);
        let directive = iso_directive(&program);
        let (action, capsule) = assemble_capsule(
            &lowered,
            occurrence.id(),
            stage_of(&program),
            &directive,
            &stage_command(),
            environment,
            platform(),
            ArtifactId(kata_types::primitives::FixedBytes(
                work_head.work_tree_artifact_id,
            )),
            budgets(),
            None,
            None,
        )
        .unwrap();

        // THE WITNESS: every `cas_objects` ROW and every blob file, before. The row
        // count is what a capsule publish actually moves — its canonical JSON is well
        // under `INLINE_THRESHOLD`, so it is stored as a column and adds no file.
        let before = cas_contents(&rig);
        assert!(
            !before.0.is_empty(),
            "the rig must have published SOMETHING already, or 'unchanged' is \
             vacuous ({case})"
        );
        // NON-VACUITY OF THE WITNESS ITSELF: the bytes this authorization WOULD publish
        // are not in the store yet, so a publish is observable as a new row. Without
        // this, "unchanged" could hold because the object was already there.
        let would_publish =
            kata_types::idempotency::canonicalize_args(&serde_json::to_value(&capsule).unwrap());
        let address = kata_types::cache::object_id_for_canonical_bytes(&would_publish)
            .0
            .to_vec();
        assert!(
            !before.0.iter().any(|(object, _)| object == &address),
            "{case}: the capsule's object must be ABSENT before the refusal, or the \
             witness cannot tell a refusal from a deduplicated publish"
        );

        let error = authorize_attempt(
            &rig.db,
            &rig.cas,
            AuthorizeInput {
                execution,
                program_hash: program.program_hash,
                lowered: &lowered,
                occurrence: occurrence.clone(),
                prepared: action,
                capsule,
                environment,
                work_head: Some(&work_head),
                programs: &*SH_ONLY,
                checked_stage: stage_of(&program),
                place: &|| Ok(WORKER.into()),
                approval_bypass_reason: None,
            },
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("authorization refused"),
            "{case}: {message}"
        );
        let expected = match case {
            "unpromoted" => "UNPROMOTED gc root",
            "released" => "was released at",
            _ => "is not declared on this node",
        };
        assert!(message.contains(expected), "{case}: {message}");

        let after = cas_contents(&rig);
        assert_eq!(
            after.0, before.0,
            "{case}: the refusal must publish NO object — `cas_objects` is the witness \
             that moves for an INLINE object, which a capsule is"
        );
        assert_eq!(
            after.1, before.1,
            "{case}: and no blob file either, for the file-backed case"
        );
        let conn = raw(&rig.op_path);
        let (occurrences, capsules): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT count(*) FROM occurrences), (SELECT count(*) FROM capsules)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((occurrences, capsules), (0, 0), "{case}: and no row either");
        drop(rig);
    }
}

/// `prepare_action` is the ONE constructor: the identity it computes must be the one
/// `assemble_capsule` folds into the capsule it returns.
///
/// Asserted by execution rather than by reading both call sites, because "one
/// spelling" is a property that survives only as long as somebody checks.
#[test]
fn the_prepared_action_the_assembler_folds_is_the_one_prepare_action_computes() {
    let program = timed_program();
    let lowered = lowered_of(&program);
    let directive = iso_directive(&program);
    let environment = EnvironmentId(ContentHash::new([0x5A; 32]));

    let direct = prepare_action(
        stage_of(&program),
        &lowered,
        environment,
        platform(),
        &directive,
    )
    .unwrap();
    let (through_assembly, capsule) = assemble_capsule(
        &lowered,
        occurrence_for(&program, ExecutionId(Ulid::new()), &lowered).id(),
        stage_of(&program),
        &directive,
        &stage_command(),
        environment,
        platform(),
        ArtifactId(ContentHash::new([0x11; 32])),
        budgets(),
        None,
        None,
    )
    .unwrap();
    assert_eq!(direct, through_assembly);
    assert_eq!(
        capsule.action(),
        direct.id(),
        "and the capsule binds that identity, not a second computation of it"
    );
    assert_eq!(
        direct.permissions,
        sandbox_permissions_hash(&directive).unwrap(),
        "the permissions half comes from the one hash door"
    );
}

/// A never-constructed handle to the two identities this file compares, so a rename
/// in `kata_types` cannot leave the assertions above comparing stale spellings.
#[allow(dead_code)]
fn type_witness(object: ObjectId, capsule: &Capsule) -> (String, String) {
    (object.to_string(), capsule.id().0.to_string())
}

// -- the K BOUNDARY CELL: `after_occurrence_authorized_before_dispatch` -----------

/// The marker that turns this binary into the ARMED CHILD.
const CRASH_CHILD: &str = "KATA_AUTHORIZE_CRASH_CHILD";
/// The data directory the child authorizes into and the parent reads afterwards.
const CRASH_DIR: &str = "KATA_AUTHORIZE_CRASH_DIR";
/// A FIXED execution id, so the parent can rebuild the child's occurrence exactly.
/// The occurrence id folds the execution, so a minted one would make the second half
/// a different occurrence and the convergence claim vacuous.
const CRASH_EXECUTION: &str = "01JZZZZZZZZZZZZZZZZZZZZZG1";
/// The test whose name the child is re-exec'd with.
const CRASH_CELL: &str =
    "the_occurrence_authorized_boundary_leaves_one_occurrence_that_a_re_presentation_adopts_once";

/// THE CRASH CELL. Kill the process at
/// `operational.after_occurrence_authorized_before_dispatch` — inside
/// `authorize_attempt`, one statement past the claim's commit — and prove two things
/// on the data dir it leaves:
///
/// 1. the occurrence, its attempt and its capsule are DURABLE and NO dispatch was
///    enqueued (the window the boundary names);
/// 2. PRESENTING the occurrence to `authorize_attempt` again on that data dir
///    dispatches the SAME attempt ONCE — no second occurrence row, no second capsule
///    row, no second attempt.
///
/// # What this cell is NOT
///
/// It is not the restart's recovery. Half 2 is this test calling `authorize_attempt`
/// itself, and a restarted main never presents the occurrence again: the resumed
/// runner dispatches the claim off its durable row
/// (`Dispatcher::dispatch_claims_left_undispatched`). That path is pinned where it
/// ships, by `crates/api/tests/boot_recovery_after_teardown.rs`'s
/// `a_main_killed_after_the_occurrence_was_authorized_boots_and_dispatches_it_once`
/// (and its `after_claim_commit` twin), which boot a main through the executor's
/// resume over the same window. What this cell holds is the door's own convergence:
/// an authorization that finds an undispatched claim at its occurrence adopts it
/// rather than minting a second generation.
///
/// # The crash model, and why it is a real process
///
/// `operational_crash_point` calls `std::process::abort()`, so the cell re-execs THIS
/// test binary as a child with `KATA_FAULT_INJECT` armed. The parent then opens the
/// child's data directory with its own handles. Nothing is simulated: the child's
/// address space is gone, its WAL is whatever `synchronous=FULL` left on disk, and
/// the parent's `OperationalDb::open` is the open a restart makes.
///
/// # Accounting
///
/// The boundary this cell arms is asserted to be the REGISTERED one, by name, out of
/// `kata_core::fault_inject`'s own registry rather than from a literal this file
/// chose. A cell that armed a misspelled boundary would otherwise run an unarmed
/// child, observe a complete authorization, and pass while proving nothing — which is
/// precisely the failure mode the registry lookup closes.
#[test]
fn the_occurrence_authorized_boundary_leaves_one_occurrence_that_a_re_presentation_adopts_once() {
    if std::env::var_os(CRASH_CHILD).is_some() {
        return armed_child();
    }

    // ACCOUNTING: the armed boundary is the registered one, and it is in the DISPATCH
    // family — the family whose handoff obligation this cell discharges.
    let registered = kata_core::fault_inject::OPERATIONAL_CRASH_BOUNDARIES
        .iter()
        .find(|boundary| boundary.name == BOUNDARY)
        .unwrap_or_else(|| panic!("`{BOUNDARY}` must be a registered operational boundary"));
    assert_eq!(
        registered.family,
        kata_core::fault_inject::OperationalBoundaryFamily::Dispatch,
        "the occurrence-authorized window is a HANDOFF claim, not a transaction one"
    );

    let dir = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CRASH_CELL, "--nocapture"])
        .env(CRASH_CHILD, "1")
        .env(CRASH_DIR, dir.path())
        .env("KATA_FAULT_INJECT", format!("operational.{BOUNDARY}"))
        .status()
        .expect("the armed child runs");
    assert!(
        status.code().is_none(),
        "the child must die on the ABORT the fault point raises, not exit normally — a \
         normal exit means the seam was never reached and this cell observed a complete \
         authorization: {status:?}"
    );

    // HALF 1 — the window, read through this process's own handles.
    let conn = raw(&dir.path().join("operational.db"));
    let (occurrences, attempts, bound, capsules, commands): (i64, i64, i64, i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM occurrences), (SELECT count(*) FROM attempts),
                    (SELECT count(occurrence_id) FROM attempts),
                    (SELECT count(*) FROM capsules), (SELECT count(*) FROM attempt_commands)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        (occurrences, attempts, bound, capsules, commands),
        (1, 1, 1, 1, 0),
        "the boundary's own state: a durable, BOUND occurrence with its capsule, and \
         NOTHING enqueued for it"
    );
    let (crashed_occurrence, crashed_attempt, crashed_blob): (Vec<u8>, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT (SELECT occurrence_id FROM occurrences),
                    (SELECT attempt_id FROM attempts),
                    (SELECT assignment_json FROM attempts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    drop(conn);

    // HALF 2 — the re-presentation. The same authorization, called again by this
    // test on the data dir the crash left (not the restart's recovery; see the doc).
    let rig = open_rig(dir.path());
    let environment = declare_promoted_environment(&rig);
    let prepared = prepare_for(
        &rig,
        environment,
        submit_id(&rig, CRASH_EXECUTION.parse().unwrap()),
    );
    assert_eq!(
        prepared.occurrence.id().0.0.to_vec(),
        crashed_occurrence,
        "the re-presentation must rebuild the SAME occurrence, or the convergence below \
         is about two different rows"
    );
    let recovered = authorize_attempt(&rig.db, &rig.cas, input_of(&prepared))
        .expect("re-authorizing after the crash must converge, not refuse")
        .dispatched()
        .expect("the adopted claim dispatches");
    assert_eq!(recovered.occurrence_id.0.0.to_vec(), crashed_occurrence);
    // THE DOOR ADOPTED THE CRASHED ATTEMPT. Not "an attempt exists for the
    // occurrence": THE attempt the crashed claim wrote, by id. Minting a second
    // generation would satisfy every count below except this one, which is why it is
    // asserted before them.
    assert_eq!(
        recovered.attempt_id.to_bytes().to_vec(),
        crashed_attempt,
        "the re-presentation must DISPATCH the bound, undispatched attempt the crash \
         left, never claim a second generation that strands it pending forever"
    );
    drop(rig);

    let conn = raw(&dir.path().join("operational.db"));
    let (occurrences, capsules, attempts, commands, distinct): (i64, i64, i64, i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM occurrences), (SELECT count(*) FROM capsules),
                    (SELECT count(*) FROM attempts), (SELECT count(*) FROM attempt_commands),
                    (SELECT count(DISTINCT occurrence_id) FROM attempts)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        (occurrences, capsules, distinct),
        (1, 1, 1),
        "NO SECOND ROW: the re-presentation converged on the occurrence and its capsule"
    );
    assert_eq!(
        (attempts, commands),
        (1, 1),
        "ONE ATTEMPT, ONE DISPATCH. The door ADOPTED the crashed attempt rather than \
         minting a second, so the occurrence holds exactly one dispatch and no pending \
         orphan. A second minted attempt reads (2, 1) here"
    );

    // THE ADOPTED ATTEMPT'S BLOB WAS NOT REWRITTEN. The adoption reconstructs the
    // frame to build the command payload; the at-rest bytes must still be the crashed
    // claim's, byte for byte, or the reconstruction was a second opinion rather than the
    // same pure function of the same values.
    let after_blob: Vec<u8> = conn
        .query_row("SELECT assignment_json FROM attempts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        after_blob, crashed_blob,
        "the adoption must not rewrite the durable frame it adopted"
    );
    drop(dir);
}

/// The boundary this cell arms, spelled once.
const BOUNDARY: &str = "after_occurrence_authorized_before_dispatch";

/// The ARMED CHILD: build the fixture, authorize, and never return.
///
/// The fault target is armed from the process environment, so `KATA_FAULT_INJECT` is
/// already set when the fixture is built. That is safe rather than lucky: the target
/// selector matches ONE boundary name, so every other seam the fixture crosses (the
/// CAS's K8, the environment plane's K14/K15) is the production no-op.
fn armed_child() {
    let root = std::path::PathBuf::from(std::env::var_os(CRASH_DIR).expect("the child's data dir"));
    let rig = open_rig(&root);
    let environment = declare_promoted_environment(&rig);
    let prepared = prepare_for(
        &rig,
        environment,
        submit_id(&rig, CRASH_EXECUTION.parse().unwrap()),
    );
    let _ = authorize_attempt(&rig.db, &rig.cas, input_of(&prepared));
    panic!(
        "the armed child reached the end of `authorize_attempt` without aborting: the \
         `{BOUNDARY}` seam did not fire, so the parent's data dir would be a COMPLETE \
         authorization rather than the window under test"
    );
}

/// Declare a one-file tree artifact retained by `execution` — a REAL declared
/// tree that is not the recorded `/work` head.
fn declare_member_tree(rig: &Rig, execution: ExecutionId, payload: &[u8]) -> ArtifactRef {
    let member = rig.cas.put_durable(payload).unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("moved.txt").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .unwrap();
    let durable = rig
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    kata_core::work_tree::declare_work_tree(&rig.db, &rig.cas, execution.0, &manifest, &durable)
        .unwrap()
}

/// THE ROLE IS A MECHANISM: a capsule that maps an execution-retained tree which is NOT
/// the recorded `/work` head — here a previous stage's adopted `/out`, declared exactly as
/// `adopt_capsule_result` declares one (a `Private` tree retained by the execution) — at
/// `/work` is refused BY NAME, before its bytes are published. Retention alone does not
/// admit it.
#[test]
fn a_previous_out_tree_mapped_as_work_is_refused_as_not_role_bound() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let prepared = prepare(&rig, environment);
    // A prior stage's /out: a real tree, retained by THIS execution, never walked.
    let out_member = rig.cas.put_durable(b"stage one's result\n").unwrap();
    let out_manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("result.txt").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: out_member.object_id(),
            size_bytes: out_member.size(),
        },
    }])
    .unwrap();
    let out_durable = rig
        .cas
        .put_durable(&out_manifest.manifest_bytes().unwrap())
        .unwrap();
    let prior_out = kata_core::work_tree::declare_work_tree(
        &rig.db,
        &rig.cas,
        prepared.execution.0,
        &out_manifest,
        &out_durable,
    )
    .unwrap();
    let (action, capsule) = assemble_capsule(
        &prepared.lowered,
        prepared.occurrence.id(),
        stage_of(&prepared.program),
        &iso_directive(&prepared.program),
        &stage_command(),
        environment,
        platform(),
        prior_out.id(),
        budgets(),
        None,
        None,
    )
    .unwrap();
    let mut input = input_of(&prepared);
    input.prepared = action;
    input.capsule = capsule;
    let error = authorize_attempt(&rig.db, &rig.cas, input)
        .expect_err("a tree that is not the recorded head is not this attempt's /work");
    assert!(
        error
            .to_string()
            .contains(kata_workflow::authorization::WORK_TREE_NOT_ROLE_BOUND),
        "refused by name: {error}"
    );
    let conn = raw(&rig.op_path);
    let (occurrences, capsules): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM occurrences), (SELECT count(*) FROM capsules)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (occurrences, capsules),
        (0, 0),
        "nothing was declared or claimed"
    );
}

/// THE SAME OCCURRENCE RE-PRESENTED AFTER THE HEAD MOVED is a divergent
/// re-declaration, refused by name — the occurrence row RECORDS the head
/// artifact it bound by role, read through a second handle, and a second
/// submission of one occurrence may not name a different one.
#[test]
fn a_resubmission_after_the_head_moved_is_a_refused_divergent_redeclaration() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let prepared = prepare(&rig, environment);
    authorize_attempt(&rig.db, &rig.cas, input_of(&prepared)).unwrap();
    let recorded: Vec<u8> = raw(&rig.op_path)
        .query_row("SELECT work_tree_artifact_id FROM occurrences", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        recorded,
        prepared.work_head.work_tree_artifact_id.to_vec(),
        "the occurrence records the /work head artifact by role"
    );

    // The head ADVANCED — as an accepted apply would move it: a new declared
    // tree lands on the row, then the same occurrence re-presents over it.
    let moved = declare_member_tree(&rig, prepared.execution, b"the workspace changed\n");
    {
        let writable = rusqlite::Connection::open(&rig.op_path).unwrap();
        writable
            .execute(
                "UPDATE execution_work_tree_heads SET work_tree_artifact_id = ?1 \
                 WHERE execution_id = ?2 AND branch = ''",
                rusqlite::params![
                    moved.id().0.0.as_slice(),
                    prepared.execution.0.to_bytes().as_slice()
                ],
            )
            .unwrap();
    }
    let head = rig
        .db
        .work_tree_head_at(prepared.execution.0, "")
        .unwrap()
        .expect("the advanced head row reads back");
    let (action, capsule) = assemble_capsule(
        &prepared.lowered,
        prepared.occurrence.id(),
        stage_of(&prepared.program),
        &iso_directive(&prepared.program),
        &stage_command(),
        environment,
        platform(),
        moved.id(),
        budgets(),
        None,
        None,
    )
    .unwrap();
    let error = authorize_attempt(
        &rig.db,
        &rig.cas,
        AuthorizeInput {
            prepared: action,
            capsule,
            work_head: Some(&head),
            ..input_of(&prepared)
        },
    )
    .expect_err("one occurrence may not run over two different head artifacts");
    assert!(
        error
            .to_string()
            .contains(kata_core::work_tree::WORK_TREE_DIVERGENT_REDECLARATION),
        "refused by name: {error}"
    );
}

/// RELEASE HAS ITS LIVE-ATTEMPT CONJUNCT: an environment a NON-TERMINAL attempt's capsule
/// binds is refused `environment_bound_to_live_attempt`; once that attempt is terminal the
/// same release lands. Read through a second raw handle.
#[test]
fn releasing_an_environment_a_live_capsule_attempt_binds_is_refused_until_it_is_terminal() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let prepared = prepare(&rig, environment);
    let authorized = authorize_attempt(&rig.db, &rig.cas, input_of(&prepared))
        .unwrap()
        .dispatched()
        .unwrap();
    let roots_dir = tempfile::tempdir().unwrap();
    let refusal =
        kata_core::environment::release_environment(&rig.db, roots_dir.path(), environment.0.0)
            .expect_err("a dispatched capsule attempt binds this closure")
            .to_string();
    assert!(
        refusal.contains(kata_core::operational::ENVIRONMENT_BOUND_TO_LIVE_ATTEMPT),
        "refused by name: {refusal}"
    );
    rig.db
        .record_main_side_transition(
            authorized.attempt_id,
            &kata_core::operational::MainSideTransition {
                reason: Some("settled for the release cell"),
                // A dispatched attempt's terminal states its charge
                // (`terminal_charge_required`); a shell capsule bills nothing.
                terminal_charge: Some(&kata_types::metering::TerminalCharge::of_usage(
                    kata_types::metering::StageUsage::unbilled(),
                )),
                ..kata_core::operational::MainSideTransition::bare("failed")
            },
        )
        .unwrap();
    kata_core::environment::release_environment(&rig.db, roots_dir.path(), environment.0.0)
        .expect("a terminal attempt no longer binds it");
    let released: Option<i64> = raw(&rig.op_path)
        .query_row(
            "SELECT released_at_ms FROM nix_environments WHERE environment_id = ?1",
            [environment.0.0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(released.is_some());
}

/// **A capsule whose `argv[0]` its environment does not provide is refused BY NAME, and
/// nothing is published or written.**
///
/// The probe answers for the fixture environment's `bin` directory and knows no `sh`, so
/// the shipped shell stage's program is absent from the guest `PATH`. The host is never
/// consulted: the probe is the fixture's.
///
/// **Would red if:** the check were dropped (the container would report 127 for a
/// reason the environment owns), or ran after the capsule publish.
#[test]
fn a_program_the_environment_does_not_provide_is_refused_by_name() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let prepared = prepare(&rig, environment);
    let before = cas_contents(&rig);
    let none = kata_workflow::test_harness::FixtureProgramProbe(Vec::new());
    let error = authorize_attempt(
        &rig.db,
        &rig.cas,
        AuthorizeInput {
            programs: &none,
            ..input_of(&prepared)
        },
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains(kata_workflow::authorization::CAPSULE_PROGRAM_NOT_IN_ENVIRONMENT),
        "{error}"
    );
    assert!(
        error.contains(kata_workflow::test_harness::FIXTURE_ENVIRONMENT_STORE_PATH),
        "the refusal names the PATH it searched: {error}"
    );
    assert_eq!(cas_contents(&rig), before, "nothing is published");
    let (occurrences, capsules): (i64, i64) = raw(&rig.op_path)
        .query_row(
            "SELECT (SELECT count(*) FROM occurrences), (SELECT count(*) FROM capsules)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((occurrences, capsules), (0, 0), "and no row is written");
    // Non-vacuity: the same input with `sh` on the fixture PATH authorizes.
    authorize_attempt(&rig.db, &rig.cas, input_of(&prepared))
        .expect("with the program present the same capsule authorizes");
}

// -- the COMMITTED-BASE /work head ----------------
//
// An isolated `oci` execution's `/work` is the execution's recorded
// `execution_work_tree_heads` row — published at admission, bound at the
// execution, deliberately carrying no occurrence. The cells below drive the
// REAL producer (`publish_base_tree_head`) for the head, assemble the capsule
// over the recorded artifact, present the head as `AuthorizeInput::work_head`,
// and read every durable fact through the raw handle.

/// Publish a one-member committed base tree for `execution` and record the head —
/// the admission path's own producer, so the row under test is the row production
/// writes.
fn recorded_head(
    rig: &Rig,
    execution: ExecutionId,
    base_commit: &str,
    member: &[u8],
) -> kata_core::operational::ExecutionWorkTreeHead {
    kata_core::work_tree::publish_base_tree_head(&rig.db, &rig.cas, execution.0, |put_member| {
        let object = put_member(member)?;
        let manifest = TreeManifest::new(vec![TreeEntry {
            path: TreePath::new("base.txt").unwrap(),
            node: TreeNode::File {
                mode: TreeEntryMode::Regular,
                object,
                size_bytes: member.len() as u64,
            },
        }])
        .unwrap();
        let manifest_bytes = manifest.manifest_bytes().unwrap();
        Ok(kata_types::tree_artifact::CommittedBaseTree {
            base_commit: base_commit.to_owned(),
            manifest,
            manifest_bytes,
            candidate_commit_id: format!("{base_commit}wc"),
        })
    })
    .expect("the committed base publishes")
}

/// `prepare_for` with the recorded head as `/work`: the capsule's `/work` mapping
/// is the head's artifact — the same bytes the production submit path assembles.
fn prepare_committed_base(
    rig: &Rig,
    environment: EnvironmentId,
    execution: ExecutionId,
    head: &kata_core::operational::ExecutionWorkTreeHead,
) -> Prepared {
    let program = timed_program();
    let lowered = lowered_of(&program);
    let occurrence = occurrence_for(&program, execution, &lowered);
    // `/out` and `/tmp` still map the canonical empty tree — the declare the
    // capsule's other mappings owe.
    kata_core::work_tree::declare_empty_tree(&rig.db, &rig.cas, execution.0).unwrap();
    let directive = iso_directive(&program);
    let (action, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage_of(&program),
        &directive,
        &stage_command(),
        environment,
        platform(),
        ArtifactId(kata_types::primitives::FixedBytes(
            head.work_tree_artifact_id,
        )),
        budgets(),
        None,
        None,
    )
    .expect("the stage assembles over the recorded head");
    Prepared {
        execution,
        program,
        lowered,
        occurrence,
        action,
        capsule,
        environment,
        work_head: head.clone(),
    }
}

/// The committed-base arm authorizes end to end: the capsule binds the recorded
/// artifact at `/work`, the occurrence row records it, and the durable row — not
/// the presented copy — is what the binding answered to.
#[test]
fn a_committed_base_head_authorizes_and_the_occurrence_binds_the_recorded_artifact() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let execution = submit(&rig);
    let head = recorded_head(&rig, execution, "d1basecommit", b"committed base content\n");
    let prepared = prepare_committed_base(&rig, environment, execution, &head);

    let authorized = authorize_attempt(
        &rig.db,
        &rig.cas,
        AuthorizeInput {
            work_head: Some(&head),
            ..input_of(&prepared)
        },
    )
    .expect("the committed-base authorization lands")
    .dispatched()
    .expect("an ungated stage dispatches");
    assert_eq!(authorized.occurrence_id, prepared.occurrence.id());
    assert_eq!(authorized.capsule_id, prepared.capsule.id());

    // The occurrence row names the RECORDED artifact — raw handle, not the API.
    let bound: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT work_tree_artifact_id FROM occurrences WHERE occurrence_id = ?1",
            [prepared.occurrence.id().0.0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        bound,
        head.work_tree_artifact_id.to_vec(),
        "the occurrence binds the execution's recorded head"
    );
    // And a RE-PRESENTATION of the same occurrence over the same head converges —
    // the committed base is stable across a resume where a walk would re-run.
    let again = authorize_attempt(
        &rig.db,
        &rig.cas,
        AuthorizeInput {
            work_head: Some(&head),
            ..input_of(&prepared)
        },
    )
    .expect("a re-presented occurrence over the same head converges")
    .dispatched()
    .expect("the re-presentation still dispatches nothing new");
    assert_eq!(again.occurrence_id, prepared.occurrence.id());
}

/// The durable row is the authority: a presented committed-base head that
/// DISAGREES with the recorded one is refused `work_tree_not_role_bound` — the
/// caller's copy is never trusted over the row.
#[test]
fn a_presented_head_that_disagrees_with_the_recorded_one_is_refused() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let execution = submit(&rig);
    let head = recorded_head(&rig, execution, "d1basecommit", b"committed base content\n");
    let prepared = prepare_committed_base(&rig, environment, execution, &head);

    // A second execution's head — a REAL row elsewhere — presented for THIS
    // execution: the refusal cannot be a fabricated-row artifact.
    let other = submit(&rig);
    let foreign = recorded_head(&rig, other, "d1othercommit", b"other base\n");

    let error = authorize_attempt(
        &rig.db,
        &rig.cas,
        AuthorizeInput {
            work_head: Some(&foreign),
            ..input_of(&prepared)
        },
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains(kata_workflow::authorization::WORK_TREE_NOT_ROLE_BOUND),
        "the refusal is named: {error}"
    );
    assert_eq!(
        raw(&rig.op_path)
            .query_row("SELECT count(*) FROM occurrences", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0i64,
        "the refused authorization wrote no occurrence"
    );
}

/// No recorded row at all: a committed base presented to an execution that records
/// no head is refused — an isolated execution has no scratch walk to substitute.
#[test]
fn a_committed_base_provenance_without_a_recorded_head_is_refused() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let execution = submit(&rig);
    let head = recorded_head(&rig, execution, "d1basecommit", b"committed base content\n");
    let prepared = prepare_committed_base(&rig, environment, execution, &head);

    // Delete the durable row directly — the crash window's residue, produced by
    // hand rather than through the head plane's writers.
    raw(&rig.op_path);
    {
        let writable = rusqlite::Connection::open(&rig.op_path).unwrap();
        writable.pragma_update(None, "foreign_keys", "OFF").unwrap();
        writable
            .execute(
                "DELETE FROM execution_work_tree_heads WHERE execution_id = ?1",
                [execution.0.to_bytes().as_slice()],
            )
            .unwrap();
    }

    let error = authorize_attempt(
        &rig.db,
        &rig.cas,
        AuthorizeInput {
            work_head: Some(&head),
            ..input_of(&prepared)
        },
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains(kata_workflow::authorization::WORK_TREE_NOT_ROLE_BOUND),
        "the refusal is named: {error}"
    );
    assert!(
        error.contains("records no /work head"),
        "the refusal says what is missing: {error}"
    );
}

/// A capsule whose `/work` maps anything BUT the recorded head — here, a
/// second declared tree's artifact — is refused even with a true head
/// presented: the head must be the mapping, not merely exist.
#[test]
fn a_capsule_mapping_something_other_than_the_recorded_head_is_refused() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let execution = submit(&rig);
    let head = recorded_head(&rig, execution, "d1basecommit", b"committed base content\n");

    // Assemble over a DIFFERENT declared tree — a real, execution-retained
    // artifact that is simply not the recorded head.
    let program = timed_program();
    let lowered = lowered_of(&program);
    let occurrence = occurrence_for(&program, execution, &lowered);
    kata_core::work_tree::declare_empty_tree(&rig.db, &rig.cas, execution.0).unwrap();
    let other = declare_member_tree(&rig, execution, b"not the head\n");
    let directive = iso_directive(&program);
    let (action, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage_of(&program),
        &directive,
        &stage_command(),
        environment,
        platform(),
        other.id(),
        budgets(),
        None,
        None,
    )
    .unwrap();

    let error = authorize_attempt(
        &rig.db,
        &rig.cas,
        AuthorizeInput {
            execution,
            program_hash: program.program_hash,
            lowered: &lowered,
            occurrence,
            prepared: action,
            capsule,
            environment,
            work_head: Some(&head),
            programs: &*SH_ONLY,
            checked_stage: stage_of(&program),
            place: &|| Ok(WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains(kata_workflow::authorization::WORK_TREE_NOT_ROLE_BOUND),
        "the refusal is named: {error}"
    );
    assert_eq!(
        raw(&rig.op_path)
            .query_row("SELECT count(*) FROM occurrences", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0i64,
        "the refused authorization wrote no occurrence"
    );
}

/// A scratch `/work` binds no head. The `ReadWriteScratch` mapping names the
/// canonical empty tree — the one artifact that role may name — and authorizes
/// with NO `work_head` presented, because a scratch stage has none. The
/// occurrence row binds the empty tree; a scratch `/work` mapping anything else
/// is `work_tree_not_role_bound`, the same door a wrong workspace head takes.
#[test]
fn a_scratch_work_needs_no_head_and_names_only_the_empty_tree() {
    let rig = rig();
    let environment = declare_promoted_environment(&rig);
    let execution = submit(&rig);
    // The canonical empty tree is the capsule's only real input — `/out`,
    // `/tmp` and the scratch `/work` all map it — so it is declared the way
    // production declares it. NO head row is written: a scratch stage has no
    // durable workspace to name, which is exactly what this cell proves.
    kata_core::work_tree::declare_empty_tree(&rig.db, &rig.cas, execution.0).unwrap();
    let program = timed_program();
    let lowered = lowered_of(&program);
    let occurrence = occurrence_for(&program, execution, &lowered);
    let occurrence_id = occurrence.id();
    let mut directive = iso_directive(&program);
    directive.fs = FsPolicy::Scratch;
    // `assemble_capsule`'s `work_tree` argument folds only for a workspace
    // directive — a scratch arm maps the canonical empty tree regardless of
    // it — so any declared tree stands in the slot.
    let (action, capsule) = assemble_capsule(
        &lowered,
        occurrence.id(),
        stage_of(&program),
        &directive,
        &stage_command(),
        environment,
        platform(),
        ArtifactId(kata_types::primitives::FixedBytes([0x77; 32])),
        budgets(),
        None,
        None,
    )
    .expect("a scratch directive assembles");

    // The refused half FIRST — before any occurrence row exists, so the door
    // that answers is the role check itself, never a divergent re-presentation:
    // a scratch `/work` naming any artifact but the canonical empty tree is
    // `work_tree_not_role_bound`, named for the arm it took. The stand-in is a
    // genuinely FOREIGN tree — published and execution-retained, just not the
    // empty one — because `/out` and `/tmp` map the same empty artifact a
    // scratch `/work` does, so borrowing `/out`'s would leave the capsule
    // unchanged.
    let foreign = declare_member_tree(&rig, execution, b"foreign content\n");
    let fields = capsule.fields();
    let mut inputs: Vec<kata_types::execution_contract::GuestMapping> = fields.inputs.to_vec();
    for mapping in &mut inputs {
        if mapping.guest_path.as_str() == "/work" {
            mapping.artifact = foreign.id();
        }
    }
    let misused = Capsule::new(
        fields.occurrence,
        fields.action,
        fields.environment,
        fields.platform,
        inputs,
        fields.process.clone(),
        fields.network.clone(),
        fields.git_view.cloned(),
        fields.budgets,
        None,
    )
    .expect("the contract admits the shape — the ROLE check is what refuses it");
    let error = authorize_attempt(
        &rig.db,
        &rig.cas,
        AuthorizeInput {
            execution,
            program_hash: program.program_hash,
            lowered: &lowered,
            occurrence: occurrence_for(&program, execution, &lowered),
            prepared: action.clone(),
            capsule: misused,
            environment,
            work_head: None,
            programs: &*SH_ONLY,
            checked_stage: stage_of(&program),
            place: &|| Ok(WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains(kata_workflow::authorization::WORK_TREE_NOT_ROLE_BOUND),
        "a scratch /work over foreign content is refused by name: {error}"
    );
    assert!(
        error.contains("read_write_scratch"),
        "the refusal names the arm it refused: {error}"
    );
    assert_eq!(
        raw(&rig.op_path)
            .query_row("SELECT count(*) FROM occurrences", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0i64,
        "the refused authorization wrote no occurrence"
    );

    // The admitted half: a scratch `/work` authorizes with NO `work_head`
    // presented — a scratch stage has none, which is exactly the point.
    let authorized = authorize_attempt(
        &rig.db,
        &rig.cas,
        AuthorizeInput {
            execution,
            program_hash: program.program_hash,
            lowered: &lowered,
            occurrence,
            prepared: action,
            capsule,
            environment,
            work_head: None,
            programs: &*SH_ONLY,
            checked_stage: stage_of(&program),
            place: &|| Ok(WORKER.into()),
            approval_bypass_reason: None,
        },
    )
    .expect("a scratch /work needs no head to authorize")
    .dispatched()
    .expect("an ungated scratch stage dispatches");
    assert_eq!(authorized.occurrence_id, occurrence_id);

    // The durable row binds the canonical EMPTY tree — raw handle, not the API.
    let bound: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT work_tree_artifact_id FROM occurrences WHERE occurrence_id = ?1",
            [occurrence_id.0.0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let empty = kata_workflow::capsule_assembly::empty_tree_artifact()
        .expect("the canonical empty tree declares")
        .id();
    assert_eq!(
        bound,
        empty.0.0.to_vec(),
        "a scratch occurrence binds the canonical empty tree, not a recorded head"
    );
}
