//! The CONTENT CACHE on the `oci` capsule route, driven through
//! the production runner (`WorkflowRunner::run` and the capsule submit door), observed
//! through a SECOND raw rusqlite handle and through the frames a stub worker received.
//!
//! # Invariant
//!
//! "No container ran" is read off the WORKER end of a real `InProcessTransport` (no
//! frame) and off the plane (no capsule or command row for the adopting
//! execution); "adopted" is read off the adopting occurrence's accepting attempt
//! (`executor = 'main'`) and the adopter's own `cas_roots` row. The pack is the SHIPPED
//! `workflows/smoke/capsule-reuse-smoke.star`, compiled under the installed `oci` profile.

use std::path::Path;
use std::time::Duration;

use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_transport::types::DispatchFrame;
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_workflow::capsule_assembly::RenderedCommand;
use kata_workflow::test_harness::{OCI_RIG_WORKER, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

const PACK: &str = include_str!("../../../workflows/smoke/capsule-reuse-smoke.star");
const STAGE: &str = "digest";
const STDOUT: &str = "{\"work_files\": 1}\n";

fn program_of(pack: &str) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(pack, "capsule-reuse-smoke.star", &[])
        .expect("the reuse smoke compiles under oci")
}

fn shipped() -> ExecutionProgram {
    program_of(PACK)
}

/// The shipped pack with one textual edit — the variants the admission cells need.
fn variant(from: &str, to: &str) -> ExecutionProgram {
    assert!(PACK.contains(from), "the shipped pack still says {from:?}");
    program_of(&PACK.replacen(from, to, 1))
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle")
}

fn count(rig: &OciNodeRig, sql: &str) -> i64 {
    raw(&rig.op_path)
        .query_row(sql, [], |row| row.get(0))
        .expect("a count")
}

fn reactor(rig: &OciNodeRig) -> kata_workflow::reactor::ResultReactor {
    kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        std::sync::Arc::clone(&rig.worker_side)
            as std::sync::Arc<dyn kata_transport::WorkerResultTransport>,
        std::sync::Arc::clone(&rig.dispatcher),
        std::sync::Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    )
}

/// Publish the `/out` tree the stub worker reports: one member, `result.txt`.
fn publish_result(rig: &OciNodeRig) -> ArtifactRef {
    let member = rig.cas.put_durable(b"d1e8  ./README\n").unwrap();
    let manifest = TreeManifest::new(vec![TreeEntry {
        path: TreePath::new("result.txt").unwrap(),
        node: TreeNode::File {
            mode: TreeEntryMode::Regular,
            object: member.object_id(),
            size_bytes: member.size(),
        },
    }])
    .unwrap();
    let receipt = rig
        .cas
        .put_durable(&manifest.manifest_bytes().unwrap())
        .unwrap();
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    )
}

/// Publish one capture BLOB — the shape a `CompletedCapsule` frame's `stdout`/`stderr`
/// carries (the provider spools the bytes and the worker publishes them).
fn publish_capture(rig: &OciNodeRig, bytes: &[u8]) -> ArtifactRef {
    let receipt = rig.cas.put_durable(bytes).unwrap();
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    )
}

async fn next_frame(rig: &OciNodeRig) -> kata_transport::types::CapsuleAssignment {
    match tokio::time::timeout(Duration::from_secs(30), rig.worker_side.recv_frame())
        .await
        .expect("a capsule frame reaches the worker")
        .expect("the transport delivers it")
    {
        DispatchFrame::Capsule(capsule) => *capsule,
    }
}

/// THE STUB WORKER: take the next capsule frame and report it COMPLETED with a published
/// `/out` tree and the pack's stdout, through the reactor — the production adoption door.
async fn complete_next(rig: &OciNodeRig, reactor: &kata_workflow::reactor::ResultReactor) {
    complete_next_with_stdout(rig, reactor, STDOUT.as_bytes()).await;
}

/// [`complete_next`] with the stub's reported stdout chosen by the caller — the
/// completion's `content` is those verified capture bytes, so a cell that wants a
/// particular envelope asks for it here rather than patching the record.
async fn complete_next_with_stdout(
    rig: &OciNodeRig,
    reactor: &kata_workflow::reactor::ResultReactor,
    stdout: &[u8],
) {
    let frame = next_frame(rig).await;
    reactor
        .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
            result: publish_result(rig),
            work_delta: kata_workflow::test_harness::stub_work_delta(
                &rig.db,
                &rig.cas,
                frame.occurrence_id,
            ),
            exit_code: Some(0),
            stdout: publish_capture(rig, stdout),
            stderr: publish_capture(rig, b""),
            capture_exceeded: false,
            agent: None,
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "capsule reuse cell",
            ),
            egress_refusals: vec![],
        })
        .expect("the completion is adopted and accepted");
}

/// Nothing reaches the worker within a short window.
async fn no_frame(rig: &OciNodeRig) {
    let received =
        tokio::time::timeout(Duration::from_millis(300), rig.worker_side.recv_frame()).await;
    assert!(
        received.is_err(),
        "no frame may reach the worker, and one did: {received:?}"
    );
}

/// DRIVE one execution of `program` through `WorkflowRunner::run`, the stub worker
/// answering every capsule it is handed. Answers the run's outputs and how many capsules
/// were delivered.
async fn drive(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
) -> (
    std::collections::BTreeMap<SmolStr, serde_json::Value>,
    usize,
) {
    drive_runner(rig, rig.runner(program, execution)).await
}

/// [`drive`] over a runner the caller built — a cell that hands it another store.
async fn drive_runner(
    rig: &OciNodeRig,
    runner: kata_workflow::runner::WorkflowRunner,
) -> (
    std::collections::BTreeMap<SmolStr, serde_json::Value>,
    usize,
) {
    let reactor = reactor(rig);
    let mut delivered = 0;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                () = complete_next(rig, &reactor) => delivered += 1,
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    (outcome.expect("the execution completes"), delivered)
}

/// Submit `STAGE` of `program` once through the capsule door.
async fn submit(
    rig: &OciNodeRig,
    runner: &kata_workflow::runner::WorkflowRunner,
    program: &ExecutionProgram,
    execution: Ulid,
) {
    let directive = rig.directive(program, STAGE, execution).await;
    let prompt = program.stages[&kata_types::workflow::StageId(SmolStr::new(STAGE))]
        .op
        .prompt_template
        .clone();
    runner
        .submit_stage_as_capsule_for_test(
            &SmolStr::new(STAGE),
            directive,
            &RenderedCommand::rendered(prompt),
        )
        .await
        .expect("the capsule submit path answers");
}

/// Run `program` once through the submit door and the stub worker, and record the
/// accepted occurrence as the hint for its capsule's key — the source an admission cell
/// needs for a stage the runner itself would never record a hint for.
async fn seed_by_hand(rig: &OciNodeRig, program: &ExecutionProgram) -> Ulid {
    let execution = Ulid::new();
    let runner = rig.runner(program, execution);
    submit(rig, &runner, program, execution).await;
    complete_next(rig, &reactor(rig)).await;
    record_hint_by_hand(rig, execution);
    execution
}

/// Record `execution`'s accepted occurrence as the hint for its capsule's key under the
/// rig node's executor term — the hint the runner's own flush may have declined to write.
fn record_hint_by_hand(rig: &OciNodeRig, execution: Ulid) {
    let occurrence: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT occurrence_id FROM occurrences WHERE execution_id = ?1 \
               AND accepted_attempt_id IS NOT NULL",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the source is accepted");
    let occurrence = kata_types::execution_contract::OccurrenceId(
        kata_types::primitives::ContentHash::new(occurrence.try_into().unwrap()),
    );
    let key = rig
        .db
        .authorized_capsule(occurrence)
        .expect("the source's capsule")
        .reuse_key(&kata_workflow::test_harness::oci_rig_executor_term());
    rig.store
        .record_capsule_reuse_hint(&key, occurrence)
        .unwrap();
}

/// `(occurrence accepted-by executor, capsules, commands)` for one execution, raw.
fn execution_facts(rig: &OciNodeRig, execution: Ulid) -> (Option<String>, i64, i64) {
    raw(&rig.op_path)
        .query_row(
            "SELECT
                (SELECT a.executor FROM occurrences o
                   JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
                  WHERE o.execution_id = ?1),
                (SELECT count(*) FROM capsules c JOIN occurrences o
                    ON o.occurrence_id = c.occurrence_id WHERE o.execution_id = ?1),
                (SELECT count(*) FROM attempt_commands WHERE attempt_id IN
                    (SELECT attempt_id FROM attempts WHERE execution_id = ?1))",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

/// The executor term an execution's accepted outcome was stamped with at acceptance,
/// raw — `None` for a `null` stamp.
fn accepted_executor_term(rig: &OciNodeRig, execution: Ulid) -> Option<String> {
    raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(t.payload_json, '$.output.executor_term')
               FROM occurrences o
               JOIN transitions t ON t.attempt_id = o.accepted_attempt_id
                                 AND t.resulting_state = 'completed'
              WHERE o.execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// How many reuse hints the node's `workflow.db` holds, raw.
fn hint_rows(dir: &Path) -> i64 {
    raw(&dir.join("workflow.db"))
        .query_row("SELECT count(*) FROM capsule_reuse_v1", [], |row| {
            row.get(0)
        })
        .unwrap()
}

/// A standalone worker's executor term that is not the rig node's: a `kata-worker` built
/// from another kata, whose fence differs.
fn skewed_worker_term() -> kata_types::execution_platform::ExecutorTerm {
    let term = kata_types::execution_platform::ExecutorTerm::derive(&[(
        "oci_seccomp_rules",
        b"another build's deny list",
    )])
    .unwrap();
    assert_ne!(term, kata_workflow::test_harness::oci_rig_executor_term());
    term
}

/// The result artifact id an execution's accepted occurrence names, raw.
fn accepted_result(rig: &OciNodeRig, execution: Ulid) -> String {
    raw(&rig.op_path)
        .query_row(
            "SELECT json_extract(t.payload_json, '$.output.result_artifact_id')
               FROM occurrences o
               JOIN transitions t ON t.attempt_id = o.accepted_attempt_id
                                 AND t.resulting_state = 'completed'
              WHERE o.execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// Two whole drives of the shipped pack: the first runs its capsule, the second
/// (over an equal workspace) should adopt.
async fn two_drives(
    rig: &OciNodeRig,
) -> (
    (
        Ulid,
        std::collections::BTreeMap<SmolStr, serde_json::Value>,
        usize,
    ),
    (
        Ulid,
        std::collections::BTreeMap<SmolStr, serde_json::Value>,
        usize,
    ),
) {
    rig.declare_bound_environment();
    let program = shipped();
    let first = Ulid::new();
    let (first_outputs, first_delivered) = drive(rig, &program, first).await;
    let second = Ulid::new();
    let (second_outputs, second_delivered) = drive(rig, &program, second).await;
    (
        (first, first_outputs, first_delivered),
        (second, second_outputs, second_delivered),
    )
}

/// **A SECOND EXECUTION WITH EQUAL INPUTS ADOPTS AND RUNS NO CONTAINER** — through the
/// whole drive, both halves in production: execution 1 MISSES, runs its capsule, and its
/// drive loop records the hint once the occurrence is accepted; execution 2 consults it and
/// ADOPTS. Raw: execution 2's occurrence is accepted by an `executor = 'main'` attempt,
/// execution 2 has no capsule or command row, both accepted outcomes name ONE
/// result artifact, and execution 2 holds its own live root over it.
///
/// **Watched red:** with the hint lookup skipped in `consult_capsule_reuse`, execution 2
/// assembles and delivers a capsule like execution 1.
#[tokio::test]
async fn a_second_execution_with_equal_inputs_adopts_and_runs_no_container() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    let ((first, _, first_delivered), (second, _, second_delivered)) = two_drives(&rig).await;
    assert_eq!(first_delivered, 1, "execution 1 ran its capsule");
    assert_eq!(second_delivered, 0, "execution 2 was handed NO capsule");
    no_frame(&rig).await;
    assert_eq!(
        execution_facts(&rig, first),
        (Some("worker".to_owned()), 1, 1)
    );
    assert_eq!(
        execution_facts(&rig, second),
        (Some("main".to_owned()), 0, 0),
        "adopted MAIN-side: no capsule, no command"
    );
    assert_eq!(
        accepted_result(&rig, second),
        accepted_result(&rig, first),
        "the SAME result artifact"
    );
    let adopter_roots: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM cas_roots r JOIN artifacts a ON a.object_id = r.object_digest
              WHERE r.purpose = 'artifact_object' AND r.owner_execution_id = ?1
                AND r.released_at_ms IS NULL AND a.kind = 'tree'
                AND lower(hex(a.artifact_id)) = ?2",
            rusqlite::params![second.to_bytes().as_slice(), accepted_result(&rig, first)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(adopter_roots, 1, "the adopter holds its own root");
    let hints: i64 = rusqlite::Connection::open(dir.path().join("workflow.db"))
        .unwrap()
        .query_row("SELECT count(*) FROM capsule_reuse_v1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(hints, 1, "execution 1's drive recorded one hint");
    assert_eq!(
        accepted_executor_term(&rig, first),
        Some(
            kata_workflow::test_harness::oci_rig_executor_term()
                .digest()
                .to_string()
        ),
        "execution 1's result is stamped with the term of the worker that delivered it, \
         which is the node's own: that is what made it a source"
    );
}

/// **A REUSED HIT AMENDS `parsed` IDENTICALLY TO ITS SOURCE** — the adopting runner's
/// ordinary fold re-validates the adopted outcome against the stage's `outputs` and
/// amends it, and the two executions' stage outputs agree on everything but the
/// provenance the reuse adds.
///
/// **Would red if:** the reuse accepted an outcome the fold could not validate (no
/// `content`), or the fold skipped the amendment for a main-resolved acceptance.
#[tokio::test]
async fn a_reused_hit_amends_parsed_identically_to_its_source() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    let ((first, first_outputs, _), (second, second_outputs, second_delivered)) =
        two_drives(&rig).await;
    assert_eq!(second_delivered, 0);
    let first_stage = &first_outputs[STAGE];
    let second_stage = &second_outputs[STAGE];
    assert_eq!(first_stage["parsed"], serde_json::json!({"work_files": 1}));
    assert_eq!(second_stage["parsed"], first_stage["parsed"]);
    let amended = |execution: Ulid| -> serde_json::Value {
        rig.db
            .accepted_occurrence_outputs(execution)
            .unwrap()
            .into_iter()
            .find(|(stage, _)| stage == STAGE)
            .map(|(_, output)| output)
            .expect("the stage's accepted output")
    };
    assert_eq!(amended(second)["parsed"], amended(first)["parsed"]);
    assert_eq!(
        amended(second)["reused_from"]["execution"],
        first.to_string(),
        "and says where it came from"
    );
    // THE AMENDMENT IS A FRAME ON A MAIN ATTEMPT, and every reader of the chain must read
    // past it — including the assignment population the execution's terminalization reads
    // first of all (refusing `attempt metadata has no preceding admission` there would cost
    // the main its authority over the execution).
    let population =
        kata_workflow::attempt_delivery::AttemptDeliveryMapper::new(std::sync::Arc::clone(&rig.db))
            .execution_assignment_states(second)
            .expect("the population reads past a reused stage's amended main attempt");
    assert!(
        population.is_empty(),
        "a main attempt has no work unit to populate: {population:?}"
    );
}

/// **A GATED CONTENT-CACHE STAGE PARKS AND IS NEVER REUSED**, even over an accepted source
/// with the SAME reuse key and a hint naming it: the gate wins.
///
/// **Watched red:** with `capsule_reuse_admission`'s approval check removed, the second
/// submission adopts the source instead of parking.
#[tokio::test]
async fn a_gated_content_cache_stage_parks_and_is_never_reused() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let gated = variant(
        "cache_policy = \"content_cache\",",
        "cache_policy = \"content_cache\",\n    approval = True,",
    );
    // THE SOURCE: the same gated stage, approved, run and accepted.
    let source = Ulid::new();
    let runner = rig.runner(&gated, source);
    submit(&rig, &runner, &gated, source).await;
    let parked: Vec<u8> = raw(&rig.op_path)
        .query_row("SELECT attempt_id FROM attempts", [], |row| row.get(0))
        .unwrap();
    rig.dispatcher
        .approve_capsule_gate(
            Ulid::from_bytes(parked.try_into().unwrap()),
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
        )
        .await
        .expect("the source's gate is approved");
    complete_next(&rig, &reactor(&rig)).await;
    let occurrence: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT occurrence_id FROM occurrences WHERE accepted_attempt_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let occurrence = kata_types::execution_contract::OccurrenceId(
        kata_types::primitives::ContentHash::new(occurrence.try_into().unwrap()),
    );
    let key = rig
        .db
        .authorized_capsule(occurrence)
        .unwrap()
        .reuse_key(&kata_workflow::test_harness::oci_rig_executor_term());
    rig.store
        .record_capsule_reuse_hint(&key, occurrence)
        .unwrap();

    // THE SECOND SUBMISSION parks.
    let second = Ulid::new();
    let runner = rig.runner(&gated, second);
    submit(&rig, &runner, &gated, second).await;
    no_frame(&rig).await;
    let (state, executor): (String, String) = raw(&rig.op_path)
        .query_row(
            "SELECT p.state, a.executor FROM attempts a JOIN attempt_projection p
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
               AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.execution_id = ?1",
            [second.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("exactly one attempt for the second execution");
    assert_eq!(
        (state.as_str(), executor.as_str()),
        ("awaiting_approval", "worker")
    );
    assert_eq!(
        count(
            &rig,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0
    );
}

/// **AN OMITTED-POLICY ELIGIBLE STAGE IS NOT REUSED** on the
/// capsule route — authored-only until a falsifier capsule arm exists — even over an
/// accepted source with the same key and a hint naming it.
///
/// **Watched red:** with the authored-only check admitting `Omitted`, the second
/// submission adopts.
#[tokio::test]
async fn an_omitted_policy_eligible_stage_is_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let omitted = variant("    cache_policy = \"content_cache\",\n", "");
    let stage = &omitted.stages[&kata_types::workflow::StageId(SmolStr::new(STAGE))];
    assert_eq!(
        stage.policies.cache_policy,
        kata_types::cache::CachePolicy::Omitted
    );
    assert!(
        stage.is_content_cacheable(),
        "the premise: the derived class IS eligible, so a default would admit it"
    );
    seed_by_hand(&rig, &omitted).await;
    let second = Ulid::new();
    let runner = rig.runner(&omitted, second);
    submit(&rig, &runner, &omitted, second).await;
    next_frame(&rig).await;
    assert_eq!(
        count(
            &rig,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0,
        "nothing was adopted"
    );
}

/// With `KATA_RERUN_REPEATABILITY` on, the cache is not consulted: the capsule runs.
///
/// **Would red if:** the admission ignored the runner's rerun toggle.
#[tokio::test]
async fn rerun_repeatability_turns_capsule_reuse_off() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = shipped();
    seed_by_hand(&rig, &program).await;
    let second = Ulid::new();
    let runner = rig.runner(&program, second).with_rerun_repeatability(true);
    submit(&rig, &runner, &program, second).await;
    next_frame(&rig).await;
    assert_eq!(
        count(
            &rig,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0
    );
}

/// **A DELETED STAGE CACHE IS A MISS, NOT AN ERROR.** The hint store is rebuildable: a
/// node restarted over a data directory whose `stage_cache.db` (here the rig's
/// `workflow.db`) is gone recreates it empty, and the next equal capsule simply runs.
#[tokio::test]
async fn a_deleted_stage_cache_is_a_miss_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    {
        let rig = OciNodeRig::open(dir.path());
        rig.declare_bound_environment();
        seed_by_hand(&rig, &shipped()).await;
    }
    for suffix in ["", "-wal", "-shm"] {
        let path = dir.path().join(format!("workflow.db{suffix}"));
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
    let rig = OciNodeRig::open(dir.path());
    let program = shipped();
    let second = Ulid::new();
    let runner = rig.runner(&program, second);
    submit(&rig, &runner, &program, second).await;
    next_frame(&rig).await;
    assert_eq!(
        count(
            &rig,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0
    );
}

/// **THE CAPSULE ROUTE'S `parsed` IS THE MAIN-SIDE PARSER'S OUTPUT, BYTE FOR BYTE**
/// A reviewer's verdict is read off `parsed`; on this route `parsed`
/// is produced by the fold every accepted completion passes through —
/// `inject_parsed_if_declared`, the `runner::json` validation — so a FENCED `content` on an
/// accepted capsule outcome must land a `parsed` identical to what that parser produces over the
/// same envelope.
///
/// **Would red if:** the capsule route shaped `parsed` any other way — a re-parse
/// without the fence strip fails the whole drive, and any other shape disagrees
/// with the parser's own output on the same bytes.
#[tokio::test]
async fn a_capsule_accepted_parsed_is_the_main_side_parsers_output_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = shipped();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    // A FENCED completion — CLI agents wrap JSON in fences even when asked not to,
    // which is what the fence strip exists for.
    let fenced = format!("```json\n{STDOUT}```");
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                () = complete_next_with_stdout(&rig, &reactor, fenced.as_bytes()) => {}
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    outcome.expect("a fenced completion validates under oci");
    let accepted = rig
        .db
        .accepted_occurrence_outputs(execution)
        .expect("the accepted outputs read")
        .into_iter()
        .find(|(stage, _)| stage == STAGE)
        .map(|(_, output)| output)
        .expect("the stage's accepted output");
    // PARITY: `parsed` is byte-identical to the main-side parser's own output over
    // the same envelope — the fold's parser, reached through
    // `runner::testing`'s forwarding wrapper so the cell asks the parser directly.
    let expected = kata_workflow::runner::testing::validate_and_inject_parsed(
        &SmolStr::new(STAGE),
        &[kata_types::workflow::StageOutput {
            name: SmolStr::new("work_files"),
            ty: SmolStr::new("u32"),
        }],
        serde_json::json!({ "content": fenced }),
    )
    .expect("the parser accepts the fenced content");
    assert_eq!(accepted["content"], serde_json::json!(fenced));
    assert_eq!(accepted["parsed"], serde_json::json!({"work_files": 1}));
    assert_eq!(
        accepted["parsed"], expected["parsed"],
        "the capsule route's parsed IS the shared parser's output"
    );
}

/// **A CONTENT-CACHE SOURCE OF ANY AGE IS SERVED** — the memoised-spend age
/// bound is the MODEL-REUSE regime's alone. A content-cache key commits to the bytes
/// that produced the result, so its age carries no information. The source's
/// acceptance is aged 400 days through a second, writable raw handle — far past the
/// 7-day model-reuse default — and the second equal execution still adopts.
///
/// **Watched red:** with the age check applied to every regime (its `ModelReuse`
/// guard removed), execution 2 runs its capsule.
#[tokio::test]
async fn a_content_cache_source_of_any_age_is_served() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = shipped();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    let aged = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .saturating_sub(Duration::from_hours(400 * 24));
    let conn = rusqlite::Connection::open(&rig.op_path).expect("a writable raw handle");
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    let rows = conn
        .execute(
            "UPDATE occurrences SET accepted_at_ms = ?1
              WHERE execution_id = ?2 AND accepted_attempt_id IS NOT NULL
                AND capsule_id IS NOT NULL",
            rusqlite::params![
                i64::try_from(aged.as_millis()).unwrap(),
                first.to_bytes().as_slice()
            ],
        )
        .unwrap();
    assert_eq!(rows, 1, "the source occurrence was aged");

    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &program, second).await;
    assert_eq!(
        second_delivered, 0,
        "a 400-day-old content-cache source is served"
    );
    no_frame(&rig).await;
    assert_eq!(
        execution_facts(&rig, second),
        (Some("main".to_owned()), 0, 0)
    );
    assert_eq!(accepted_result(&rig, second), accepted_result(&rig, first));
}

/// The capsule an execution's ACCEPTED occurrence ran (or adopted under), read from the
/// plane.
fn accepted_capsule(rig: &OciNodeRig, execution: Ulid) -> kata_types::execution_contract::Capsule {
    let occurrence: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT occurrence_id FROM occurrences WHERE execution_id = ?1 \
               AND accepted_attempt_id IS NOT NULL AND capsule_id IS NOT NULL",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the execution's capsule occurrence is accepted");
    rig.db
        .authorized_capsule(kata_types::execution_contract::OccurrenceId(
            kata_types::primitives::ContentHash::new(occurrence.try_into().unwrap()),
        ))
        .expect("its capsule")
}

/// **A NODE WHOSE EXECUTOR TERM MOVED MISSES — AND NOTHING IDENTITY-BEARING
/// MOVES WITH IT.** Execution 1 runs on a node under one executor term and records its
/// hint; the node restarts under ANOTHER term (a kata upgrade that changed the fence)
/// and execution 2, over the same pack and workspace, is handed a capsule and runs it.
/// Both capsules are the SAME work — equal under one term, the same platform, the
/// node's own — so the miss is the key's alone. Restarted under the FIRST term again,
/// execution 3 adopts execution 1's result: the miss was the term, not a lost hint.
/// Raw: who accepted each occurrence, the capsule rows, and the hint table's two keys.
///
/// **Would red if:** `Capsule::reuse_key` stopped folding the term (execution 2 would
/// adopt a result the other fence produced), or the term reached a capsule field such
/// as the platform (the two capsules would stop being equal work).
#[tokio::test]
async fn a_node_whose_executor_term_moved_misses_and_moves_no_identity() {
    use kata_types::execution_platform::ExecutorTerm;
    let dir = tempfile::tempdir().unwrap();
    let old_fence = ExecutorTerm::derive(&[("oci_seccomp_rules", b"deny ptrace")]).unwrap();
    let new_fence = ExecutorTerm::derive(&[("oci_seccomp_rules", b"deny ptrace, bpf")]).unwrap();
    let program = shipped();

    let first = Ulid::new();
    {
        let rig = OciNodeRig::open_with_executor_term(dir.path(), old_fence);
        rig.declare_bound_environment();
        let (_, delivered) = drive(&rig, &program, first).await;
        assert_eq!(delivered, 1, "execution 1 ran its capsule");
    }

    let second = Ulid::new();
    {
        let rig = OciNodeRig::open_with_executor_term(dir.path(), new_fence);
        let (_, delivered) = drive(&rig, &program, second).await;
        assert_eq!(
            delivered, 1,
            "the node whose executor moved is handed a capsule: no hint the old fence wrote \
             names its key"
        );
        no_frame(&rig).await;
        assert_eq!(
            execution_facts(&rig, second),
            (Some("worker".to_owned()), 1, 1),
            "a worker ran execution 2; nothing was adopted main-side"
        );
        let source = accepted_capsule(&rig, first);
        let rerun = accepted_capsule(&rig, second);
        assert_eq!(
            rerun.reuse_key(&old_fence),
            source.reuse_key(&old_fence),
            "the two capsules are the same work: every identity-bearing field is equal"
        );
        assert_eq!(rerun.platform(), source.platform());
        assert_eq!(
            source.platform(),
            kata_types::node_profile::node_platform()
                .expect("the reference host is x86_64-linux")
                .id(),
            "the platform is the node's fixed profile, untouched by the term"
        );
        assert_ne!(
            rerun.reuse_key(&new_fence),
            source.reuse_key(&old_fence),
            "the keys differ by the term alone"
        );
        let hints: i64 = raw(&dir.path().join("workflow.db"))
            .query_row("SELECT count(*) FROM capsule_reuse_v1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(hints, 2, "one hint per executor term");
    }

    let third = Ulid::new();
    let rig = OciNodeRig::open_with_executor_term(dir.path(), old_fence);
    let (_, delivered) = drive(&rig, &program, third).await;
    assert_eq!(
        delivered, 0,
        "under the old term again, execution 1's hint serves"
    );
    no_frame(&rig).await;
    assert_eq!(
        execution_facts(&rig, third),
        (Some("main".to_owned()), 0, 0)
    );
    assert_eq!(accepted_result(&rig, third), accepted_result(&rig, first));
}

/// **A SKEWED WORKER'S COMPLETED CAPSULE IS NOT RECORDED AS A REUSE HINT**. The node's one worker
/// is a standalone `kata-worker` that STATED another build's executor term on Hello. Placement is
/// unchanged — it runs both executions' capsules — but its accepted result is stamped with ITS
/// term, so execution 1's drive records no hint and execution 2 over an equal workspace is handed a
/// capsule again. Raw: both outcomes' stamps, both executions worker-accepted with a capsule,
/// command row each, and an empty hint table.
///
/// **Watched red:** with the executor-term comparison removed from
/// `flush_pending_capsule_reuse_hints`, execution 1 records a hint and execution 2
/// adopts it main-side.
#[tokio::test]
async fn a_skewed_worker_s_completed_capsule_is_not_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let worker_term = skewed_worker_term();
    let rig = OciNodeRig::open_with_worker_executor_term(dir.path(), worker_term);
    let ((first, _, first_delivered), (second, _, second_delivered)) = two_drives(&rig).await;
    assert_eq!(
        first_delivered, 1,
        "the skewed worker still takes execution 1"
    );
    assert_eq!(
        second_delivered, 1,
        "and execution 2: nothing it ran seeded the cache"
    );
    no_frame(&rig).await;
    for execution in [first, second] {
        assert_eq!(
            execution_facts(&rig, execution),
            (Some("worker".to_owned()), 1, 1)
        );
        assert_eq!(
            accepted_executor_term(&rig, execution),
            Some(worker_term.digest().to_string()),
            "the result is stamped with the worker's own term"
        );
    }
    assert_eq!(hint_rows(dir.path()), 0, "no hint names a skewed result");
}

/// **A SKEWED WORKER'S COMPLETED CAPSULE IS NOT SERVED AS A REUSE SOURCE**, even when a
/// hint names it: the hint is a rebuildable cache, and the
/// operational door that adopts re-reads the source's stamp. Execution 1 is driven on a
/// worker that stated another build's term and its hint is then recorded BY HAND under
/// the node's key; execution 2 consults it, the door misses
/// (`source_executor_term_differs`), forgets the hint, and the capsule runs. Raw:
/// execution 2 worker-accepted with its own capsule and command row, and the
/// hint table empty.
///
/// **Watched red:** with the executor-term comparison removed from
/// `OperationalDb::reusable_source`, execution 2 adopts the skewed result main-side.
#[tokio::test]
async fn a_skewed_worker_s_completed_capsule_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open_with_worker_executor_term(dir.path(), skewed_worker_term());
    rig.declare_bound_environment();
    let program = shipped();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    assert_eq!(hint_rows(dir.path()), 0, "the drive itself recorded none");
    record_hint_by_hand(&rig, first);
    assert_eq!(
        hint_rows(dir.path()),
        1,
        "the premise: a hint names the source"
    );
    let second = Ulid::new();
    let (_, delivered) = drive(&rig, &program, second).await;
    assert_eq!(
        delivered, 1,
        "the skewed source is not adopted: the capsule runs"
    );
    no_frame(&rig).await;
    assert_eq!(
        execution_facts(&rig, second),
        (Some("worker".to_owned()), 1, 1)
    );
    assert_eq!(
        hint_rows(dir.path()),
        0,
        "the stale hint was forgotten, and the rerun on the skewed worker recorded none"
    );
}

/// **A STORE CARRYING NO EXECUTOR TERM SERVES AND RECORDS NO HINT** (the executor-term refused set
/// at the consult). Execution 1 runs on the rig's node and records its hint; execution 2 runs with
/// a runner handed a store over the SAME `workflow.db` opened without a term — what a process that
/// never booted a node holds — and is handed a capsule, and the hint table still holds the one row:
/// no key was computed, so none was looked up or recorded.
///
/// **Would red if:** the consult keyed a term-less store under some substitute term
/// (a hint would be looked up — and, keyed alike, two fences would share it).
#[tokio::test]
async fn a_store_carrying_no_executor_term_serves_and_records_no_hint() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let program = shipped();
    let (_, first_delivered) = drive(&rig, &program, Ulid::new()).await;
    assert_eq!(first_delivered, 1);
    let hints = || -> i64 {
        raw(&dir.path().join("workflow.db"))
            .query_row("SELECT count(*) FROM capsule_reuse_v1", [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    assert_eq!(hints(), 1, "execution 1 recorded its hint");

    let termless = std::sync::Arc::new(
        kata_core::store::SqliteWorkflowStore::open(dir.path().join("workflow.db"))
            .expect("the stage-cache store re-opens"),
    );
    assert!(termless.executor_term().is_none());
    let second = Ulid::new();
    let runner = rig.runner(&program, second).with_cache_store(termless);
    let (_, delivered) = drive_runner(&rig, runner).await;
    assert_eq!(delivered, 1, "no term, no hint: the capsule runs");
    no_frame(&rig).await;
    assert_eq!(execution_facts(&rig, second).0, Some("worker".to_owned()));
    assert_eq!(
        hints(),
        1,
        "and nothing was recorded under a substitute key"
    );
}
