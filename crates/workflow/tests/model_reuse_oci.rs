//! `cache_policy = "model_reuse"` on the `oci` capsule route,
//! driven through the production runner (`WorkflowRunner::run` and the capsule
//! submit door), observed through a SECOND raw rusqlite handle and through the
//! frames a stub worker received.
//!
//! # Invariant
//!
//! "No turn ran" is read off the WORKER end of a real `InProcessTransport` (no
//! frame) and off the plane (no capsule or command row for the adopting
//! execution); "adopted" is read off the adopting occurrence's accepting attempt
//! (`executor = 'main'`), the accepting payload's `reused_from`, and the
//! adopter's own `cas_roots` rows — never off the verdict the door returned.
//!
//! The stub answers the delivered AGENT capsule with a fabricated
//! `AgentTurnReport` — metered usage, a published response blob and a session
//! evidence blob — through `ResultReactor`, the production adoption door, so the
//! source a reuse adopts is the plane a real agent completion leaves.
//!
//! # Keying
//!
//! The reuse key is the capsule's (`Capsule::reuse_key`): rendered prompt,
//! adapter, model, credential reference, declared env and egress, the walked
//! `/work` tree and every budget — and NOT the workflow identity, so two packs
//! whose equal stages mint equal capsules share a hit; no workflow-class scope
//! applies on this route.

use std::path::Path;
use std::time::Duration;

use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_transport::types::DispatchFrame;
use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};
use kata_workflow::capsule_assembly::RenderedCommand;
use kata_workflow::test_harness::{OCI_RIG_WORKER, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

const STAGE: &str = "verdict";
/// The response blob the stub vendor's turn "produces" — the stage's `content`.
const RESPONSE: &[u8] = b"{\"verdict\": \"ship\"}\n";
/// The session evidence blob — the serialized-empty `SessionEvidence` shape.
const EVIDENCE: &[u8] = b"{\"events\":[],\"events_dropped\":0,\"scratch_commits\":[]}";

/// The shipped-shaped pack the cells vary: an agent stage that AUTHORS
/// `model_reuse` over a read-only workspace — the shape `verdict`/`review`
/// stages in the shipped packs carry.
const PACK: &str = "verdict = stage(\n\
     \x20   id = \"verdict\",\n\
     \x20   agent = \"codex\",\n\
     \x20   prompt = \"inspect the diff and return a verdict\",\n\
     \x20   sandbox = \"work\",\n\
     \x20   cache_policy = \"model_reuse\",\n\
     \x20   outputs = {\"verdict\": \"string\"},\n\
     )\n\
     workflow(\"model-reuse-oci\", root = [verdict], sandbox_profiles = \
     {\"work\": sandbox_profile(workspace = \"ro\", net = \"host\")})\n";

/// The node's `[agents.codex]` block — the embedded harness under kata's own
/// login, the declaration the `oci` CHECK judges — and the `[node]
/// egress_allow` authority that fills the stage's `net = "host"` allowlist,
/// which is `egress_undeclared` empty.
fn install_agent() {
    let mut agents = std::collections::BTreeMap::new();
    agents.insert(
        "codex".to_owned(),
        kata_program::test_harness::rig_agent_backend_config(),
    );
    kata_types::node_profile::install_node_agents(agents);
    kata_types::node_profile::install_node_egress_allow(std::collections::BTreeSet::from([
        kata_types::execution_contract::EgressAuthority::from_authority_str("api.example.com:443")
            .expect("an authority parses"),
    ]));
}

fn program_of(pack: &str) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    install_agent();
    compile_starlark_execution_program(pack, "model-reuse-oci.star", &[])
        .expect("an agent stage authoring model_reuse compiles under oci")
}

fn program() -> ExecutionProgram {
    program_of(PACK)
}

/// The rig over `path`, its fixture environment providing `sh` AND the agent
/// adapter's `argv[0]` — an `oci` agent capsule is asked the same
/// `capsule_program_not_in_environment` question a `Command` capsule is.
fn rig(path: &Path) -> OciNodeRig {
    OciNodeRig::open_with_programs(path, &["sh", "codex"])
}

/// `PACK` with one textual edit — the variants the cells need.
fn variant(from: &str, to: &str) -> ExecutionProgram {
    assert!(PACK.contains(from), "the pack still says {from:?}");
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

/// Publish one capture-shaped BLOB (the `/out` member, a capture, the response,
/// the evidence) — the shape the worker publishes off its spool.
fn publish_blob(rig: &OciNodeRig, bytes: &[u8]) -> ArtifactRef {
    let receipt = rig.cas.put_durable(bytes).unwrap();
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    )
}

/// The `/out` result tree the stub reports: one member, `result.txt`.
fn publish_result(rig: &OciNodeRig) -> ArtifactRef {
    let member = rig.cas.put_durable(b"verdict = ship\n").unwrap();
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

/// A MUTATING turn's `/work` delta: one `Write` of `notes.md` over the
/// occurrence's recorded base — `stub_work_delta`'s shape, non-empty.
fn publish_mutating_work_delta(
    rig: &OciNodeRig,
    occurrence: kata_types::execution_contract::OccurrenceId,
) -> ArtifactRef {
    let work_tree = rig
        .db
        .occurrence(occurrence.0.0)
        .unwrap()
        .unwrap()
        .work_tree_artifact_id
        .expect("the occurrence was bound to a walked /work tree");
    let row = rig.db.artifact(work_tree).unwrap().unwrap();
    let base = ArtifactRef::new(
        kata_types::primitives::FixedBytes(row.object_id),
        row.size_bytes,
        row.privacy,
    );
    let member = rig.cas.put_durable(b"the agent's note\n").unwrap();
    let delta = TreeDelta::new(
        base,
        vec![TreeChange {
            path: TreePath::new("notes.md").unwrap(),
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
    let receipt = rig.cas.put_durable(&delta.delta_bytes().unwrap()).unwrap();
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

/// THE STUB VENDOR: take the next capsule frame and report it COMPLETED as an
/// agent turn — `AgentTurnReport` carrying a published response blob, metered
/// usage and the session evidence — through the reactor, the production
/// adoption door. `work_delta` decides the `/work` the turn left.
async fn complete_agent_next(
    rig: &OciNodeRig,
    reactor: &kata_workflow::reactor::ResultReactor,
    work_delta: Option<ArtifactRef>,
) {
    let frame = next_frame(rig).await;
    let report = kata_types::agent::AgentTurnReport {
        response: publish_blob(rig, RESPONSE),
        usage: Some(kata_types::metering::StageUsage::metered(
            &kata_types::cache::TokenUsage {
                input: 4_200,
                output: 300,
                cache_read: 0,
                cache_write: 0,
            },
            kata_types::metering::MeteredCost::Authoritative { micro_usd: 1_250 },
            0,
        )),
        adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
        model_reported: Some(SmolStr::new("gpt-5-codex")),
        session_evidence: Some(publish_blob(rig, EVIDENCE)),
        stop_reason: None,
    };
    reactor
        .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
            result: publish_result(rig),
            work_delta: work_delta.or_else(|| {
                kata_workflow::test_harness::stub_work_delta(&rig.db, &rig.cas, frame.occurrence_id)
            }),
            exit_code: Some(0),
            stdout: publish_blob(rig, b""),
            stderr: publish_blob(rig, b""),
            capture_exceeded: false,
            agent: Some(report),
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "model reuse cell",
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

/// DRIVE one execution of `program` through `WorkflowRunner::run`, the stub
/// vendor answering every agent capsule it is handed.
async fn drive(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
) -> (
    std::collections::BTreeMap<SmolStr, serde_json::Value>,
    usize,
) {
    let runner = rig.runner(program, execution);
    let reactor = reactor(rig);
    let mut delivered = 0;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                () = complete_agent_next(rig, &reactor, None) => delivered += 1,
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

/// The accepting transition's `output` object for an execution's stage, raw.
fn accepted_output(rig: &OciNodeRig, execution: Ulid) -> serde_json::Value {
    let payload: String = raw(&rig.op_path)
        .query_row(
            "SELECT CAST(t.payload_json AS TEXT)
               FROM occurrences o
               JOIN transitions t ON t.attempt_id = o.accepted_attempt_id
                                 AND t.resulting_state = 'completed'
              WHERE o.execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
    payload["output"].clone()
}

/// The occurrence id an execution's accepted stage carries, raw.
fn accepted_occurrence(rig: &OciNodeRig, execution: Ulid) -> String {
    raw(&rig.op_path)
        .query_row(
            "SELECT lower(hex(o.occurrence_id)) FROM occurrences o
              WHERE o.execution_id = ?1 AND o.accepted_attempt_id IS NOT NULL",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap()
}

/// Two whole drives of `program`: the first runs its agent capsule, the second
/// should adopt.
async fn two_drives(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
) -> ((Ulid, usize), (Ulid, usize)) {
    rig.declare_bound_environment();
    let first = Ulid::new();
    let (_, first_delivered) = drive(rig, program, first).await;
    let second = Ulid::new();
    let (_, second_delivered) = drive(rig, program, second).await;
    ((first, first_delivered), (second, second_delivered))
}

/// **A SECOND EXECUTION WITH EQUAL INPUTS ADOPTS AND RUNS NO TURN — AND BILLS
/// NOTHING.** Execution 1 misses, runs its agent capsule (the stub vendor's
/// metered turn), and the drive records the hint once the occurrence is
/// accepted; execution 2's equal capsule consults it and ADOPTS: accepted by an
/// `executor = 'main'` attempt, no capsule/command row, the SAME result
/// artifact, the response adopted byte-for-byte as `content`, `reused_from`
/// naming the source, and `token_usage` rewritten to `unbilled` — the hit made
/// no provider call, so copying the source's metered spend would bill it twice.
///
/// **Watched red:** with the `ModelReuse` arm of `capsule_reuse_admission`
/// removed, execution 2 assembles and DELIVERS a capsule like execution 1; with
/// the `token_usage` rewrite removed, execution 2's accepted output reports the
/// source's 4200-input metered turn as its own.
#[tokio::test]
async fn a_second_execution_with_equal_inputs_adopts_and_runs_no_turn() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    let program = program();
    let ((first, first_delivered), (second, second_delivered)) = two_drives(&rig, &program).await;
    assert_eq!(first_delivered, 1, "execution 1 ran its agent capsule");
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

    let source = accepted_output(&rig, first);
    let adopted = accepted_output(&rig, second);
    assert_eq!(
        adopted["result_artifact_id"], source["result_artifact_id"],
        "the SAME result artifact"
    );
    assert_eq!(
        adopted["content"], source["content"],
        "the response adopted byte-for-byte"
    );
    assert_eq!(adopted["content"], std::str::from_utf8(RESPONSE).unwrap());
    assert_eq!(
        adopted["reused_from"]["occurrence"],
        accepted_occurrence(&rig, first),
        "the provenance names the source occurrence"
    );
    assert_eq!(adopted["reused_from"]["execution"], first.to_string());
    assert_eq!(
        adopted["token_usage"]["cost"]["quality"], "authoritative",
        "the hit's usage is an authoritative zero, not the source's metered turn"
    );
    assert_eq!(adopted["token_usage"]["cost"]["micro_usd"], 0);
    assert_eq!(adopted["token_usage"]["input"], 0);
    assert_eq!(
        source["token_usage"]["input"], 4200,
        "the source's own spend stays metered on the source"
    );
    // The adopting runner's ordinary fold re-validated and amended the adopted
    // output like a fresh completion's.
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
    let hints: i64 = rusqlite::Connection::open(dir.path().join("workflow.db"))
        .unwrap()
        .query_row("SELECT count(*) FROM capsule_reuse_v1", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(hints, 1, "execution 1's drive recorded one hint");
}

/// **A MUTATING AGENT STAGE REUSES, AND THE HIT ADOPTS ITS RECORDED `/work`
/// DELTA** — the widening clause 4 is written against: under
/// `oci` the agent stage's capsule maps the workspace, the recorded delta is the
/// outcome's own artifact, and the adoption declares it under the ADOPTER.
/// A `workspace = "rw"` agent stage with `model_reuse` compiles (the clause-4
/// arm does not apply on this profile), runs, and its second equal drive
/// adopts — delta artifact id and entry count carried verbatim.
///
/// **Watched red:** with the clause-4 arm ungated by profile, this pack does not
/// compile under `oci` at all.
#[tokio::test]
async fn a_mutating_agent_stage_reuses_and_adopts_the_recorded_work_delta() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    let program = variant("workspace = \"ro\"", "workspace = \"rw\"");
    rig.declare_bound_environment();
    let first = Ulid::new();
    // THE SOURCE RUN reports a non-empty /work delta — a Write of notes.md.
    let runner = rig.runner(&program, first);
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let report = kata_types::agent::AgentTurnReport {
                        response: publish_blob(&rig, RESPONSE),
                        usage: Some(kata_types::metering::StageUsage::metered(
                            &kata_types::cache::TokenUsage::default(),
                            kata_types::metering::MeteredCost::Authoritative { micro_usd: 1_250 },
                            0,
                        )),
                        adapter: kata_types::agent::AdapterKind::NanocodeOpenai,
                        model_reported: Some(SmolStr::new("gpt-5-codex")),
                        session_evidence: Some(publish_blob(&rig, EVIDENCE)),
                        stop_reason: None,
                    };
                    let delta = publish_mutating_work_delta(&rig, frame.occurrence_id);
                    reactor
                        .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
                            attempt_id: frame.attempt_id,
                            fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                            result: publish_result(&rig),
                            work_delta: Some(delta),
                            exit_code: Some(0),
                            stdout: publish_blob(&rig, b""),
                            stderr: publish_blob(&rig, b""),
                            capture_exceeded: false,
                            agent: Some(report),
                            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                                "model reuse cell",
                            ),
                            egress_refusals: vec![],
                        })
                        .expect("the mutating completion is adopted and accepted");
                }
            }
        }
    })
    .await
    .expect("the mutating drive reaches a terminal");
    outcome.expect("the mutating execution completes");
    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &program, second).await;
    assert_eq!(second_delivered, 0, "the second run adopted");
    no_frame(&rig).await;
    assert_eq!(
        execution_facts(&rig, second),
        (Some("main".to_owned()), 0, 0)
    );
    let source = accepted_output(&rig, first);
    let adopted = accepted_output(&rig, second);
    assert_eq!(
        source["work_delta_entries"], 1,
        "the source's delta is the recorded write"
    );
    assert_eq!(
        adopted["work_delta_artifact_id"], source["work_delta_artifact_id"],
        "the hit adopted the SAME recorded delta artifact"
    );
    assert_eq!(adopted["work_delta_entries"], 1);
}

/// **ONE CHANGED PROMPT BYTE MISSES** — the key folds the rendered prompt
/// artifact. The variant changes nothing else: same agent, same sandbox, same
/// policy.
///
/// **Would red if:** the key omitted the prompt — the second drive would adopt
/// an answer to a question it never asked.
#[tokio::test]
async fn a_different_prompt_misses() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program(), first).await;
    assert_eq!(first_delivered, 1);
    let other = variant("inspect the diff", "inspect the RESULTS");
    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &other, second).await;
    assert_eq!(
        second_delivered, 1,
        "a different rendered prompt is a different capsule"
    );
}

/// **A DIFFERENT MODEL SELECTION MISSES** — `model_hint` folds into the agent
/// turn's spec and therefore the key.
///
/// **Would red if:** the key omitted `model` — a hit would serve one model's
/// answer to another's request.
#[tokio::test]
async fn a_different_model_hint_misses() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program(), first).await;
    assert_eq!(first_delivered, 1);
    let other = variant(
        "cache_policy = \"model_reuse\",",
        "cache_policy = \"model_reuse\",\n    model_hint = \"gpt-5.2\",",
    );
    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &other, second).await;
    assert_eq!(
        second_delivered, 1,
        "a different model is a different capsule"
    );
}

/// **A CHANGED `/work` TREE MISSES** — the walked workspace is a mapping in the
/// key. The rig materializes each execution's scratch `/work` from
/// `rig-scratch/<execution>`; writing one byte into the second execution's
/// scratch changes the tree its capsule maps.
///
/// **Would red if:** the key omitted the mappings — the hit would adopt a turn
/// that read other bytes.
#[tokio::test]
async fn a_different_work_tree_misses() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let program = program();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    let second = Ulid::new();
    // Seed the second execution's scratch with content BEFORE its head is
    // walked — `runner()`'s `seed_scratch_head` walks what is there.
    let scratch = dir.path().join("rig-scratch").join(second.to_string());
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(scratch.join("changed.txt"), b"one byte different\n").unwrap();
    let (_, second_delivered) = drive(&rig, &program, second).await;
    assert_eq!(
        second_delivered, 1,
        "a different /work tree is a different capsule"
    );
}

/// **AN UNAUTHORED AGENT STAGE IS NEVER REUSED** on this route — authored-only,
/// the same rule the content cache follows — even over an accepted source whose
/// capsule key matches and a hint that names it.
///
/// **Watched red:** with the admission's `Omitted` arm consulting, the second
/// submission adopts.
#[tokio::test]
async fn an_unauthored_agent_stage_is_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let unauthored = variant("    cache_policy = \"model_reuse\",\n", "");
    // THE SOURCE: run it once by hand and record the hint the same way the
    // drive loop would have, had the stage consulted the cache.
    let first = Ulid::new();
    let runner = rig.runner(&unauthored, first);
    submit(&rig, &runner, &unauthored, first).await;
    complete_agent_next(&rig, &reactor(&rig), None).await;
    let occurrence: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT occurrence_id FROM occurrences WHERE execution_id = ?1 \
               AND accepted_attempt_id IS NOT NULL",
            [first.to_bytes().as_slice()],
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

    let second = Ulid::new();
    let runner = rig.runner(&unauthored, second);
    submit(&rig, &runner, &unauthored, second).await;
    next_frame(&rig).await;
    assert_eq!(
        count(
            &rig,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0,
        "an unauthored stage consults nothing: the capsule was dispatched"
    );
}

/// **A GATED `model_reuse` STAGE PARKS AND IS NEVER REUSED** — `approval = True`
/// beats the cache exactly as it does for `content_cache`: the consult stands
/// down and the authorization parks the attempt for an operator.
///
/// **Watched red:** with the approval arm of `capsule_reuse_admission` removed,
/// the second submission adopts instead of parking.
#[tokio::test]
async fn a_gated_model_reuse_agent_stage_parks_and_is_never_reused() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let gated = variant(
        "cache_policy = \"model_reuse\",",
        "cache_policy = \"model_reuse\",\n    approval = True,",
    );
    // THE SOURCE: the same gated stage, approved, run and accepted.
    let first = Ulid::new();
    let runner = rig.runner(&gated, first);
    submit(&rig, &runner, &gated, first).await;
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
    complete_agent_next(&rig, &reactor(&rig), None).await;
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

    // THE SECOND SUBMISSION parks — it does not adopt.
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
        ("awaiting_approval", "worker"),
        "the gate parked the attempt instead of adopting"
    );
    assert_eq!(
        count(
            &rig,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0
    );
}

/// **`KATA_RERUN_REPEATABILITY` DISABLES THE CONSULT** — the second submission
/// runs its capsule even over a hint that names a live equal source.
///
/// **Watched red:** with the admission ignoring the runner's repeatability flag,
/// the second submission adopts.
#[tokio::test]
async fn rerun_repeatability_disables_model_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let program = program();
    let first = Ulid::new();
    let runner = rig.runner(&program, first);
    submit(&rig, &runner, &program, first).await;
    complete_agent_next(&rig, &reactor(&rig), None).await;
    let occurrence: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT occurrence_id FROM occurrences WHERE execution_id = ?1 \
               AND accepted_attempt_id IS NOT NULL",
            [first.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the source is accepted");
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
    let second = Ulid::new();
    let runner = rig.runner(&program, second).with_rerun_repeatability(true);
    submit(&rig, &runner, &program, second).await;
    next_frame(&rig).await;
    assert_eq!(
        count(
            &rig,
            "SELECT count(*) FROM attempts WHERE executor = 'main'"
        ),
        0,
        "repeatability ran the capsule rather than adopting"
    );
}

/// **EQUAL CAPSULES SHARE A HIT ACROSS PACKS** — the key has no workflow-class
/// scope: the same stage authored under a different `workflow(...)` name mints
/// an equal capsule, and its execution adopts. This is a deliberate widening:
/// the reuse scope is not the workflow class.
///
/// **Would red if:** the key folded the program or pack identity — pack B's
/// equal capsule would miss and run.
#[tokio::test]
async fn equal_agent_capsules_across_two_packs_share_a_hit() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let pack_a = program();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &pack_a, first).await;
    assert_eq!(first_delivered, 1);
    // PACK B: the same stage, only the workflow's own name differs — so the
    // program hash differs while the stage's capsule is equal.
    let pack_b = variant("model-reuse-oci", "model-reuse-oci-b");
    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &pack_b, second).await;
    assert_eq!(
        second_delivered, 0,
        "an equal capsule in another pack shares the hit"
    );
    let adopted = accepted_output(&rig, second);
    assert_eq!(
        adopted["reused_from"]["execution"],
        first.to_string(),
        "the hit names pack A's execution as its source"
    );
}

/// One day — the unit the 7-day default memoised-spend bound is stated in.
const DAY: Duration = Duration::from_hours(24);

/// Wall-clock milliseconds since the epoch, `age` ago — read off `SystemTime`, not off
/// any kata clock.
fn epoch_ms_ago(age: Duration) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    i64::try_from(now.saturating_sub(age).as_millis()).unwrap()
}

/// Main-side attempts on a STAGE occurrence — the attempts a reuse adoption writes. A
/// driven execution also accepts a main-resolved occurrence with no prepared action,
/// and an ADOPTING occurrence carries no capsule, so the count is scoped to
/// occurrences that carry a prepared action.
const MAIN_ATTEMPTS_ON_STAGE_OCCURRENCES: &str = "SELECT count(*) FROM attempts a \
       JOIN occurrences o ON o.occurrence_id = a.occurrence_id \
      WHERE a.executor = 'main' AND o.prepared_action_id IS NOT NULL";

/// PLANT the age of `execution`'s accepted source: rewrite its CAPSULE occurrence's
/// `accepted_at_ms` through a second, WRITABLE raw handle. That column is the instant
/// the source's turn was accepted — the one the memoised-spend bound is measured
/// from — so the age is moved without a sleep and without asking kata to move it.
/// (A driven execution also accepts a main-resolved occurrence; the stage's is the one
/// that ran a capsule.)
fn plant_acceptance_age(rig: &OciNodeRig, execution: Ulid, age: Duration) {
    let conn = rusqlite::Connection::open(&rig.op_path).expect("a writable raw handle");
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    let rows = conn
        .execute(
            "UPDATE occurrences SET accepted_at_ms = ?1
              WHERE execution_id = ?2 AND accepted_attempt_id IS NOT NULL
                AND capsule_id IS NOT NULL",
            rusqlite::params![epoch_ms_ago(age), execution.to_bytes().as_slice()],
        )
        .unwrap();
    assert_eq!(rows, 1, "exactly one accepted source occurrence was aged");
}

/// How many reuse hints the node holds, raw.
fn hint_rows(dir: &Path) -> i64 {
    raw(&dir.join("workflow.db"))
        .query_row("SELECT count(*) FROM capsule_reuse_v1", [], |row| {
            row.get(0)
        })
        .expect("a hint count")
}

/// The `(source occurrence hex, recorded_at_ms)` the node's single reuse hint holds,
/// raw.
fn hint_row(dir: &Path) -> (String, i64) {
    assert_eq!(hint_rows(dir), 1, "the node holds exactly one hint row");
    raw(&dir.join("workflow.db"))
        .query_row(
            "SELECT lower(hex(source_occurrence_id)), recorded_at_ms FROM capsule_reuse_v1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the hint row")
}

/// The fmt output of the test thread's tracing, captured — the runner's miss lines are
/// what an operator reads when a reuse is skipped.
#[derive(Clone, Default)]
struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

struct CapturedLogWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("captured logs poisoned").extend(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
    type Writer = CapturedLogWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CapturedLogWriter(std::sync::Arc::clone(&self.0))
    }
}

impl CapturedLogs {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("captured logs poisoned").clone())
            .expect("tracing output is UTF-8")
    }
}

/// The accepted CAPSULE occurrence of `execution` — the stage's — raw.
fn capsule_occurrence(rig: &OciNodeRig, execution: Ulid) -> Vec<u8> {
    raw(&rig.op_path)
        .query_row(
            "SELECT occurrence_id FROM occurrences WHERE execution_id = ?1 \
               AND accepted_attempt_id IS NOT NULL AND capsule_id IS NOT NULL",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the stage's capsule occurrence is accepted")
}

/// `bytes` as lower-case hex — the spelling `hint_row` reads off SQLite.
fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        hex
    })
}

/// [`capsule_occurrence`], as the typed id the store takes.
fn capsule_occurrence_id(
    rig: &OciNodeRig,
    execution: Ulid,
) -> kata_types::execution_contract::OccurrenceId {
    kata_types::execution_contract::OccurrenceId(kata_types::primitives::ContentHash::new(
        capsule_occurrence(rig, execution).try_into().unwrap(),
    ))
}

/// **A SOURCE OLDER THAN THE NODE'S MEMOISED-SPEND BOUND IS NOT SERVED** (model
/// reuse is bounded in TIME, default 7 days, read at lookup, hard). The
/// source's turn is accepted, then aged 8 days in the plane; the second equal
/// execution runs its OWN turn — handed a capsule, accepted by a worker attempt, no
/// main attempt anywhere. Nothing is deleted: the aged source is still accepted. The
/// fresh turn re-points the hint at its own occurrence, and a third execution IS
/// served from that fresh source — the window is measured from each source's own
/// acceptance.
///
/// **Would red if:** `consult_capsule_reuse` had no age check — execution 2 would
/// adopt the 8-day-old turn.
#[tokio::test]
async fn a_source_older_than_the_memoised_spend_bound_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let program = program();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    plant_acceptance_age(&rig, first, 8 * DAY);

    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &program, second).await;
    assert_eq!(
        second_delivered, 1,
        "an aged source is not served: execution 2 ran its own turn"
    );
    assert_eq!(
        execution_facts(&rig, second),
        (Some("worker".to_owned()), 1, 1)
    );
    assert_eq!(
        count(&rig, MAIN_ATTEMPTS_ON_STAGE_OCCURRENCES),
        0,
        "no main attempt adopted the aged turn"
    );
    assert_eq!(
        execution_facts(&rig, first),
        (Some("worker".to_owned()), 1, 1),
        "the aged source is NOT REMOVED: still accepted, its capsule row kept"
    );
    assert_eq!(
        hint_row(dir.path()).0,
        lower_hex(&capsule_occurrence(&rig, second)),
        "the fresh turn re-pointed the hint at its own occurrence"
    );

    let third = Ulid::new();
    let (_, third_delivered) = drive(&rig, &program, third).await;
    assert_eq!(third_delivered, 0, "the fresh source IS served");
    assert_eq!(
        accepted_output(&rig, third)["reused_from"]["execution"],
        second.to_string()
    );
}

/// **A FRESHLY STAMPED HINT OVER AN AGED SOURCE DOES NOT SLIDE THE WINDOW.** The age is
/// the SOURCE's — its occurrence's `accepted_at_ms` — never the hint's
/// `recorded_at_ms`: a hint is stamped whenever its key is re-pointed, and an age read
/// off it would restart every time — a sliding window, which the bound forbids. Here the source is
/// aged 8 days, the hint is re-recorded at that same source, and its row is stamped NOW through a
/// raw handle besides — the hint looks fresh, the source is not — and the second execution still
/// runs its own turn.
///
/// **Would red if:** there were no age check (execution 2 would adopt), or the
/// check read the hint's stamp (it would adopt too).
#[tokio::test]
async fn a_freshly_stamped_hint_over_an_aged_source_does_not_slide_the_window() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let program = program();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    plant_acceptance_age(&rig, first, 8 * DAY);

    let source = capsule_occurrence_id(&rig, first);
    let key = rig
        .db
        .authorized_capsule(source)
        .unwrap()
        .reuse_key(&kata_workflow::test_harness::oci_rig_executor_term());
    rig.store.record_capsule_reuse_hint(&key, source).unwrap();
    let hints = rusqlite::Connection::open(dir.path().join("workflow.db")).unwrap();
    hints
        .execute(
            "UPDATE capsule_reuse_v1 SET recorded_at_ms = ?1",
            [epoch_ms_ago(Duration::ZERO)],
        )
        .unwrap();
    assert_eq!(
        hint_row(dir.path()).0,
        lower_hex(&capsule_occurrence(&rig, first)),
        "the hint still names the aged source"
    );

    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &program, second).await;
    assert_eq!(
        second_delivered, 1,
        "a freshly stamped hint over an aged source is still not served"
    );
    assert_eq!(
        count(&rig, MAIN_ATTEMPTS_ON_STAGE_OCCURRENCES),
        0,
        "no main attempt adopted the aged turn"
    );
}

/// **A SOURCE INSIDE THE BOUND IS SERVED** — the bound refuses only what is OLDER
/// than it. A source aged 6 days under the 7-day default adopts exactly as a
/// just-accepted one does.
///
/// **Watched red:** with the age check refusing every model-reuse source, execution 2
/// runs its own turn.
#[tokio::test]
async fn a_source_inside_the_memoised_spend_bound_is_served() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let program = program();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    plant_acceptance_age(&rig, first, 6 * DAY);

    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &program, second).await;
    assert_eq!(second_delivered, 0, "a 6-day-old source is served");
    no_frame(&rig).await;
    assert_eq!(
        count(&rig, MAIN_ATTEMPTS_ON_STAGE_OCCURRENCES),
        1,
        "the hit is one main attempt on the adopting stage occurrence"
    );
    assert_eq!(
        execution_facts(&rig, second),
        (Some("main".to_owned()), 0, 0)
    );
    assert_eq!(
        accepted_output(&rig, second)["reused_from"]["execution"],
        first.to_string()
    );
}

/// **`"unbounded"` SERVES A SOURCE OF ANY AGE** — the operator's explicit "I chose no
/// bound", which is kept distinct from `0` (the default). The node's store
/// carries `ModelReuseMaxAge::Unbounded`, as boot installs it from `[runtime]
/// model_reuse_max_age_secs = "unbounded"`; a source aged 400 days is adopted.
///
/// **Watched red:** with the bound read as the default whatever the node carries, the
/// 400-day-old source is not served and execution 2 runs its own turn.
#[tokio::test]
async fn an_unbounded_node_serves_a_source_of_any_age() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open_with_model_reuse_max_age(
        dir.path(),
        &["sh", "codex"],
        kata_types::config::ModelReuseMaxAge::Unbounded,
    );
    rig.declare_bound_environment();
    let program = program();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    plant_acceptance_age(&rig, first, 400 * DAY);

    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &program, second).await;
    assert_eq!(
        second_delivered, 0,
        "a 400-day-old source is served when unbounded"
    );
    no_frame(&rig).await;
    assert_eq!(
        execution_facts(&rig, second),
        (Some("main".to_owned()), 0, 0)
    );
    assert_eq!(
        accepted_output(&rig, second)["reused_from"]["execution"],
        first.to_string()
    );
}

/// **AN EXPLICIT BOUND IS THE OPERATOR'S, NOT THE DEFAULT.** The node carries a
/// one-hour bound; a source accepted two hours ago — well inside the 7-day default —
/// is not served, and execution 2 runs its own turn.
///
/// **Watched red:** with the bound read as the default whatever the node carries,
/// execution 2 adopts the two-hour-old turn.
#[tokio::test]
async fn an_explicit_bound_refuses_a_source_the_default_would_serve() {
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open_with_model_reuse_max_age(
        dir.path(),
        &["sh", "codex"],
        kata_types::config::ModelReuseMaxAge::Secs(3_600),
    );
    rig.declare_bound_environment();
    let program = program();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    plant_acceptance_age(&rig, first, Duration::from_hours(2));

    let second = Ulid::new();
    let (_, second_delivered) = drive(&rig, &program, second).await;
    assert_eq!(
        second_delivered, 1,
        "a two-hour-old source is not served under a one-hour bound"
    );
    assert_eq!(
        execution_facts(&rig, second),
        (Some("worker".to_owned()), 1, 1)
    );
}

/// **AN AGED SOURCE IS REPORTED AS A REUSE MISS, AND ITS HINT IS KEPT** — bounded at
/// lookup, never by deletion, and observable the way the operational door's misses
/// are. One submission consults a hint over an 8-day-old source: the stage is handed
/// its capsule, the hint row still names the aged source (read raw — nothing forgot
/// it), and the runner's miss line carries the tag `source_older_than_model_reuse_bound`
/// the operator guide promises.
///
/// **Watched red:** with the miss tag dropped from the runner's log line, the captured
/// output does not carry it.
#[tokio::test]
async fn an_aged_source_is_reported_as_a_reuse_miss_and_its_hint_is_kept() {
    let logs = CapturedLogs::default();
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(logs.clone())
            .finish(),
    );
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let program = program();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    plant_acceptance_age(&rig, first, 8 * DAY);
    let aged_source = lower_hex(&capsule_occurrence(&rig, first));

    let second = Ulid::new();
    let runner = rig.runner(&program, second);
    submit(&rig, &runner, &program, second).await;
    next_frame(&rig).await;
    assert_eq!(
        hint_row(dir.path()).0,
        aged_source,
        "the aged source's hint is kept: the bound refuses at lookup and deletes nothing"
    );
    let text = logs.text();
    assert!(
        text.contains("miss=\"source_older_than_model_reuse_bound\""),
        "the skip is reported with its miss tag; captured:\n{text}"
    );
}

/// **A HINT NAMING A SOURCE THE PLANE DOES NOT HOLD IS FORGOTTEN, NOT AGED.** The
/// memoised-spend bound judges only an ACCEPTED source; for a source with no row it
/// defers to the operational door, whose `SourceNotAccepted` miss forgets the stale
/// hint. The node's hint is re-pointed, through a writable raw handle, at an
/// occurrence id no execution minted; one submission consults it, the stage is handed
/// its capsule, and the hint row is GONE (read raw).
///
/// **Watched red:** with the bound answering "too old" for a source with no
/// acceptance, the consult never reaches the door and the stale hint survives.
#[tokio::test]
async fn a_hint_naming_an_unknown_source_is_forgotten_by_the_door() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    rig.declare_bound_environment();
    let program = program();
    let first = Ulid::new();
    let (_, first_delivered) = drive(&rig, &program, first).await;
    assert_eq!(first_delivered, 1);
    let unknown = [0xab_u8; 32];
    let hints = rusqlite::Connection::open(dir.path().join("workflow.db")).unwrap();
    hints.busy_timeout(Duration::from_secs(5)).unwrap();
    let rows = hints
        .execute(
            "UPDATE capsule_reuse_v1 SET source_occurrence_id = ?1",
            [unknown.as_slice()],
        )
        .unwrap();
    assert_eq!(rows, 1, "the one hint was re-pointed at the unknown source");

    let second = Ulid::new();
    let runner = rig.runner(&program, second);
    submit(&rig, &runner, &program, second).await;
    next_frame(&rig).await;
    assert_eq!(
        hint_rows(dir.path()),
        0,
        "the door's SourceNotAccepted miss forgot the hint naming an unknown source"
    );
}
