//! The shared EXPANSION substrate under `oci`, driven through the
//! production runner's claim/member doors and read back through a SECOND raw
//! rusqlite handle, never kata's own reader.
//!
//! # Invariant
//!
//! One `ExpandBounded` claims ONE `pending` main attempt at its own `#op/<path>`
//! coordinate carrying the whole durable spec; iteration `N`'s member `m`
//! dispatches as an ordinary capsule attempt at `expand_path.child(N).child(m)`
//! — still wearing the member stage's authored `stage_id`, distinguished by the
//! coordinate; and the accepted `{"expansion": …}` record reads back
//! verbatim.
//!
//! The pack is the SHIPPED `workflows/smoke/multistage-loop-smoke.star`, compiled
//! under `oci` — the compile door admits `loop()` and static topologies — run
//! on an `oci` rig.

use std::path::Path;
use std::sync::Arc;

use kata_program::execution_program::{
    ExecutionProgram, compile_starlark_execution_program, lower_review_loop,
    lower_topology_expansion,
};
use kata_test_utils::git::{hermetic_git_in, init_git_repo_at, run_git};
use kata_transport::types::DispatchFrame;
use kata_types::execution_contract::{OperationPath, RuntimeOperation};
use kata_vcs::VcsBackend;
use kata_workflow::test_harness::OciNodeRig;
use smol_str::SmolStr;
use ulid::Ulid;

mod common;

const PACK: &str = include_str!("../../../workflows/smoke/multistage-loop-smoke.star");

fn program() -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(PACK, "multistage-loop-smoke.star", &[])
        .expect("the loop pack compiles under oci")
}

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle")
}

/// The program's one expansion lowering.
fn expansion(program: &ExecutionProgram) -> kata_program::execution_program::LoweredOperation {
    assert_eq!(program.review_loops.len(), 1, "the pack carries one loop");
    lower_review_loop(program, 0).expect("the loop lowers to an ExpandBounded")
}

#[test]
fn an_expansion_claim_writes_a_pending_main_attempt_with_its_durable_spec() {
    let program = program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let outcome = runner.claim_expansion_for_test(0).expect("the claim lands");
    assert!(
        matches!(
            outcome,
            kata_core::operational::ExpansionClaimOutcome::Claimed { .. }
        ),
        "a fresh claim claims, got {outcome:?}"
    );

    let coordinate = expansion.path.program_operation_stage_id();
    let (executor, state, blob): (String, String, Vec<u8>) = raw(&rig.op_path)
        .query_row(
            "SELECT a.executor, p.state, a.assignment_json
               FROM attempts a
               JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.execution_id = ?1 AND a.stage_id = ?2",
            rusqlite::params![execution.to_bytes().as_slice(), coordinate.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the expansion attempt row exists");
    assert_eq!(executor, "main", "an expansion resolves at the main");
    assert_eq!(
        state, "pending",
        "the expansion sits pending while members run"
    );

    let blob: serde_json::Value = serde_json::from_slice(&blob).unwrap();
    assert_eq!(blob["main"]["operation"], "expansion");
    let spec = &blob["main"]["spec"];
    assert_eq!(
        spec["operation"].as_str().unwrap(),
        expansion.contract.id().0.to_string(),
        "the durable spec names the lowered contract id"
    );
    let RuntimeOperation::ExpandBounded {
        template, maximum, ..
    } = &expansion.contract.operation
    else {
        panic!("the loop lowers to ExpandBounded")
    };
    assert_eq!(
        serde_json::from_value::<Vec<OperationPath>>(spec["template"].clone()).unwrap(),
        *template,
        "the durable spec carries the template verbatim"
    );
    assert_eq!(spec["maximum"].as_u64().unwrap(), u64::from(*maximum));
    assert_eq!(
        spec["stage"].as_str().unwrap(),
        expansion.contract.source_stage.0.as_str()
    );

    // And the occurrence minted, unaccepted.
    let accepted: Option<Vec<u8>> = raw(&rig.op_path)
        .query_row(
            "SELECT accepted_attempt_id FROM occurrences
              WHERE execution_id = ?1 AND operation_path = ?2",
            [
                execution.to_bytes().as_slice(),
                expansion.path.canonical_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .expect("the expansion occurrence minted at its own coordinate");
    assert!(accepted.is_none(), "a claimed expansion accepts nothing");

    // The claim is the double-spend guard: a second claim converges.
    let again = runner
        .claim_expansion_for_test(0)
        .expect("a convergent claim is not an error");
    assert!(
        matches!(
            again,
            kata_core::operational::ExpansionClaimOutcome::AlreadyLive { ref state, .. }
                if state == "pending"
        ),
        "a second claim converges on the live attempt, got {again:?}"
    );
}

/// THE STUB WORKER: take the next capsule frame and report it COMPLETED with a
/// published `/out` tree and `stdout` chosen by the caller — the identical
/// drive `capsule_reuse.rs` uses. The member's authored `stage_id` comes back
/// on the frame, which is how the stub scripts the gate.
async fn next_frame(rig: &OciNodeRig) -> kata_transport::types::CapsuleAssignment {
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        rig.worker_side.recv_frame(),
    )
    .await
    .expect("a capsule frame reaches the worker")
    .expect("the transport delivers it")
    {
        DispatchFrame::Capsule(capsule) => *capsule,
    }
}

fn publish_result(rig: &OciNodeRig) -> kata_types::execution_contract::ArtifactRef {
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
    use kata_types::tree_artifact::{TreeEntry, TreeEntryMode, TreeManifest, TreeNode, TreePath};
    let member = rig.cas.put_durable(b"d1e8  ./result\n").unwrap();
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

fn publish_capture(rig: &OciNodeRig, bytes: &[u8]) -> kata_types::execution_contract::ArtifactRef {
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
    let receipt = rig.cas.put_durable(bytes).unwrap();
    ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        ArtifactPrivacy::Private,
    )
}

fn reactor(rig: &OciNodeRig) -> kata_workflow::reactor::ResultReactor {
    kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(kata_workflow::test_harness::OCI_RIG_WORKER),
        std::sync::Arc::clone(&rig.worker_side)
            as std::sync::Arc<dyn kata_transport::WorkerResultTransport>,
        std::sync::Arc::clone(&rig.dispatcher),
        std::sync::Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(30),
        )),
    )
}

/// The member's authored stage id, read off the attempt row — a member is an
/// ordinary capsule attempt that keeps its stage's own `stage_id`.
fn frame_stage_id(rig: &OciNodeRig, frame: &kata_transport::types::CapsuleAssignment) -> String {
    raw(&rig.op_path)
        .query_row(
            "SELECT stage_id FROM attempts WHERE attempt_id = ?1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the member's attempt row")
}

/// The durable coordinate the member frame is bound at — `expand_path.child(N).child(M)`
/// decoded off the occurrence row, returned as `(iteration, member)`.
fn member_coordinate(
    rig: &OciNodeRig,
    frame: &kata_transport::types::CapsuleAssignment,
) -> (u32, u32) {
    let bytes: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT operation_path FROM occurrences WHERE occurrence_id = ?1",
            [frame.occurrence_id.0.0.as_slice()],
            |row| row.get(0),
        )
        .expect("the member's occurrence row");
    let path = OperationPath::from_canonical_bytes(&bytes).expect("the path decodes");
    let member = *path.0.last().expect("a member coordinate carries a tail");
    let iteration = path.0[path.0.len() - 2];
    (iteration, member)
}

/// Complete `frame` through the reactor with `stdout` as the staged verdict —
/// the envelope's `parsed` is the stdout JSON, so the gate script only needs
/// to feed the controller frames `{"decision": ...}`.
fn complete_frame(
    rig: &OciNodeRig,
    reactor: &kata_workflow::reactor::ResultReactor,
    frame: &kata_transport::types::CapsuleAssignment,
    stdout: &[u8],
) {
    complete_frame_with(
        rig,
        reactor,
        frame,
        stdout,
        kata_workflow::test_harness::stub_work_delta(&rig.db, &rig.cas, frame.occurrence_id),
    );
}

/// [`complete_frame`] with the caller's own `/work` delta — a stage whose
/// capsule the cell REALLY ran on the host reports the delta its produced
/// files name, not the stub's empty one.
fn complete_frame_with(
    rig: &OciNodeRig,
    reactor: &kata_workflow::reactor::ResultReactor,
    frame: &kata_transport::types::CapsuleAssignment,
    stdout: &[u8],
    work_delta: Option<kata_types::execution_contract::ArtifactRef>,
) {
    reactor
        .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: kata_transport::types::AttemptFence::echoing_capsule(frame),
            result: publish_result(rig),
            work_delta,
            exit_code: Some(0),
            stdout: publish_capture(rig, stdout),
            stderr: publish_capture(rig, b""),
            capture_exceeded: false,
            agent: None,
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "expansion drive cell",
            ),
            egress_refusals: vec![],
        })
        .expect("the member completion is adopted");
}

/// The stdout one member frame reports: the body stages' own marker JSON; the
/// gate's `decision` is `continue` for its first two completions, `promote`
/// for the third — the shipped pack's own sequence, scripted.
fn member_stdout(stage_id: &str, controller_seen: u32) -> String {
    match stage_id {
        "stage_a" => "{\"stage\":\"a\",\"marker\":0}".to_owned(),
        "stage_b" => "{\"stage\":\"b\",\"marker\":0}".to_owned(),
        "controller" => {
            if controller_seen < 2 {
                format!(
                    "{{\"decision\":\"continue\",\"feedback\":\"iteration {controller_seen}, run the body again\"}}"
                )
            } else {
                "{\"decision\":\"promote\",\"feedback\":\"body ran 3 times, done\"}".to_owned()
            }
        }
        other => panic!("the pack has no stage {other}"),
    }
}

/// The pack's stage order is fixed: `stage_a` (member 0), `stage_b` (the
/// worker, member 1), `controller` (the gate, member 2).
const MEMBER_ORDER: [&str; 3] = ["stage_a", "stage_b", "controller"];

/// Drive one `runner.run()` to its terminal, the stub worker scripting the
/// gate `continue, continue, promote` — returns the run's outputs and every
/// frame delivered, as `(stage_id, (iteration, member))`.
async fn drive_to_terminal(
    rig: &OciNodeRig,
    runner: &kata_workflow::runner::WorkflowRunner,
) -> (
    std::collections::BTreeMap<SmolStr, serde_json::Value>,
    Vec<(String, (u32, u32))>,
) {
    let reactor = reactor(rig);
    let mut frames: Vec<(String, (u32, u32))> = Vec::new();
    let mut controller_seen: u32 = 0;
    let run = runner.run();
    tokio::pin!(run);
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome.expect("the run completes"),
                frame = next_frame(rig) => {
                    let stage_id = frame_stage_id(rig, &frame);
                    let coordinate = member_coordinate(rig, &frame);
                    let stdout = member_stdout(&stage_id, controller_seen);
                    if stage_id == "controller" {
                        controller_seen += 1;
                    }
                    complete_frame(rig, &reactor, &frame, stdout.as_bytes());
                    frames.push((stage_id, coordinate));
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    (outputs, frames)
}

#[tokio::test(flavor = "current_thread")]
async fn the_multistage_loop_drives_three_iterations_and_resolves_approved() {
    let program = program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let (outputs, frames) = drive_to_terminal(&rig, &runner).await;

    // NINE member capsules, in the pack's member order, at
    // `expand_path.child(iteration).child(member)` — and nothing else reached
    // the worker.
    assert_eq!(frames.len(), 9, "three iterations of three members ran");
    for (index, (stage_id, (iteration, member))) in frames.iter().enumerate() {
        assert_eq!(
            stage_id.as_str(),
            MEMBER_ORDER[index % 3],
            "frame {index} is iteration {}'s member {}",
            index / 3,
            index % 3,
        );
        assert_eq!(*iteration, u32::try_from(index / 3).unwrap());
        assert_eq!(*member, u32::try_from(index % 3).unwrap());
        assert_eq!(
            OperationPath::from_canonical_bytes(
                &raw(&rig.op_path)
                    .query_row::<Vec<u8>, _, _>(
                        "SELECT operation_path FROM occurrences
                           WHERE execution_id = ?1 AND operation_path = ?2",
                        rusqlite::params![
                            execution.to_bytes().as_slice(),
                            expansion
                                .path
                                .child(*iteration)
                                .child(*member)
                                .canonical_bytes()
                                .as_slice(),
                        ],
                        |row| row.get(0),
                    )
                    .expect("the member occurrence sits at its child coordinate")
            )
            .unwrap()
            .0
            .len(),
            expansion.path.0.len() + 2,
            "the member coordinate strictly extends the expansion's"
        );
    }

    // Every member occurrence is accepted — the expansion's input is durable.
    let accepted_members: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM occurrences o
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE o.execution_id = ?1 AND a.executor = 'worker'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the member count reads");
    assert_eq!(accepted_members, 9);

    // The expansion record is the bound decision, off the raw handle.
    let output: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT t.payload_json FROM transitions t
               JOIN occurrences o ON o.accepted_attempt_id = t.attempt_id
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE o.execution_id = ?1 AND a.stage_id = ?2
                AND t.resulting_state = 'completed'",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| row.get(0),
        )
        .expect("the expansion's accepting transition");
    let output: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let record =
        kata_program::execution_program::expansion::ExpansionRecord::from_output(&output["output"])
            .expect("the accepted output is an expansion record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Approved {
                iteration: 2
            }
        ),
        "the loop resolves Approved at iteration 2, got {:?}",
        record.resolution
    );
    assert_eq!(record.members.len(), 9, "the record names every member run");
    assert_eq!(record.verdicts.len(), 3, "the record names every verdict");
    assert_eq!(record.verdicts[0].verdict, "continue");
    assert_eq!(record.verdicts[1].verdict, "continue");
    assert_eq!(record.verdicts[2].verdict, "promote");

    // The run's outputs carry the member stages' terminal envelopes — the
    // record's apply completed all three authored stages.
    for stage in ["stage_a", "stage_b", "controller"] {
        assert!(
            outputs.contains_key(&SmolStr::new(stage)),
            "the run outputs carry {stage}'s completion"
        );
    }
}

/// THE RESOLVING-ITERATION PROJECTION pack — the shipped loop's shape plus a
/// `summary` stage behind the gate that consumes `stage_a`'s authored output.
/// The member stdout scripts `marker = iteration`, so which envelope the
/// authored name carried is legible in what `summary` writes.
const CONSUME_PACK: &str = r#"
stage_a = stage(
    id = "stage_a",
    run = "printf a",
    agent = "shell",
    sandbox = sandbox_profile(workspace = "rw"),
    outputs = {"stage": "string", "marker": "number"},
)

stage_b = stage(
    id = "stage_b",
    run = "printf b",
    agent = "shell",
    sandbox = sandbox_profile(workspace = "rw"),
    depends_on = ["stage_a"],
    outputs = {"stage": "string", "marker": "number"},
)

controller = stage(
    id = "controller",
    run = "printf c",
    agent = "shell",
    depends_on = ["stage_b"],
    outputs = {"decision": "string", "feedback": "string"},
)

summary = stage(
    id = "summary",
    run = """
printf '%s' '{{ stages.stage_a.parsed.marker }}' > consumed.txt
printf '{"consumed":{{ stages.stage_a.parsed.marker }}}\\n'
""",
    agent = "shell",
    sandbox = sandbox_profile(workspace = "rw"),
    depends_on = ["controller"],
    outputs = {"consumed": "number"},
)

loop(
    body = sequence(stage_a, stage_b),
    gate = controller,
    max_iterations = 3,
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)

workflow("loop-consume", root = [stage_a, stage_b, controller, summary])
"#;

/// THE RESOLVING-ITERATION PROJECTION, READ OUT OF THE LANDED DELTA: a
/// downstream stage's `{{ stages.stage_a.parsed.marker }}` renders the
/// RESOLVING iteration's envelope — iteration 2's for an approved
/// three-iteration loop — the same answer `run show` projects off the
/// member's last attempt. The cell runs the summary capsule's own argv on
/// the host shell, reports the file it really wrote as the `/work` delta,
/// and reads `consumed.txt` back out of the execution's durable head
/// manifest. No stale iteration-0 member is projected beside the approved
/// worker.
#[tokio::test(flavor = "current_thread")]
async fn a_downstream_stage_consumes_the_resolving_iterations_member_output() {
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(CONSUME_PACK, "loop-consume.star", &[])
        .expect("the consume pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);

    let mut controller_seen: u32 = 0;
    let run = runner.run();
    tokio::pin!(run);
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome.expect("the run completes"),
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    match stage_id.as_str() {
                        "summary" => {
                            // The capsule's own argv — rendered against the
                            // record's completed `stage_a` — runs on the host
                            // shell and writes `consumed.txt` for real.
                            let bytes = rig
                                .cas
                                .get(&frame.capsule.object)
                                .expect("the CAS reads")
                                .expect("the capsule object is published");
                            let capsule: kata_types::execution_contract::Capsule =
                                serde_json::from_slice(&bytes).expect("the capsule decodes");
                            let argv: Vec<String> = match capsule.process() {
                                kata_types::execution_contract::CapsuleProcess::Command { argv } => {
                                    argv.iter().map(ToString::to_string).collect()
                                }
                                kata_types::execution_contract::CapsuleProcess::Agent(..) => {
                                    panic!("summary is a Command capsule")
                                }
                            };
                            let scratch = tempfile::tempdir().unwrap();
                            let ran = std::process::Command::new("sh")
                                .args(&argv[1..])
                                .current_dir(scratch.path())
                                .output()
                                .expect("the host shell runs the summary command");
                            assert!(ran.status.success(), "the rendered command runs: {argv:?}");
                            let consumed = std::fs::read(scratch.path().join("consumed.txt"))
                                .expect("the rendered command wrote consumed.txt");
                            // The delta the real stage's files name — the
                            // write the worker would report — declared and
                            // carried on the completion.
                            use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
                            use kata_types::tree_artifact::{TreeEntryMode, TreeNode, TreePath};
                            use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};
                            let work_tree = rig
                                .db
                                .occurrence(frame.occurrence_id.0.0)
                                .unwrap()
                                .unwrap()
                                .work_tree_artifact_id
                                .expect("summary's /work binds the execution tree");
                            let row = rig.db.artifact(work_tree).unwrap().unwrap();
                            let base = ArtifactRef::new(
                                kata_types::primitives::FixedBytes(row.object_id),
                                row.size_bytes,
                                row.privacy,
                            );
                            let member = rig.cas.put_durable(&consumed).unwrap();
                            let delta = TreeDelta::new(
                                base,
                                vec![TreeChange {
                                    path: TreePath::new("consumed.txt").unwrap(),
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
                            let durable = rig
                                .cas
                                .put_durable(&delta.delta_bytes().unwrap())
                                .unwrap();
                            rig.db
                                .declare_artifact(
                                    &kata_core::operational::ArtifactDeclaration::for_durable_delta(
                                        &delta,
                                        ArtifactPrivacy::Private,
                                        kata_core::operational::CasRootOwner::Execution(execution),
                                        &durable,
                                    )
                                    .unwrap(),
                                )
                                .unwrap();
                            complete_frame_with(
                                &rig,
                                &reactor,
                                &frame,
                                &ran.stdout,
                                Some(ArtifactRef::new(
                                    durable.object_id(),
                                    durable.size(),
                                    ArtifactPrivacy::Private,
                                )),
                            );
                        }
                        member => {
                            let stdout = match member {
                                "stage_a" => format!("{{\"stage\":\"a\",\"marker\":{}}}", member_coordinate(&rig, &frame).0),
                                "stage_b" => format!("{{\"stage\":\"b\",\"marker\":{}}}", member_coordinate(&rig, &frame).0),
                                "controller" => {
                                    let decision = if controller_seen < 2 { "continue" } else { "promote" };
                                    controller_seen += 1;
                                    format!("{{\"decision\":\"{decision}\",\"feedback\":\"seen {controller_seen}\"}}")
                                }
                                other => panic!("no stage {other}"),
                            };
                            complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");

    // The resolving iteration's envelope is what every authored name carries:
    // `stage_a.parsed.marker` is 2, the approved iteration's — and it is what
    // `summary` consumed (`summary.parsed.consumed` is the same 2).
    assert_eq!(
        outputs[&SmolStr::new("stage_a")]["parsed"]["marker"],
        serde_json::json!(2),
        "stage_a's authored name carries the resolving iteration's envelope"
    );
    assert_eq!(
        outputs[&SmolStr::new("summary")]["parsed"]["consumed"],
        serde_json::json!(2),
        "the downstream stage consumed iteration 2's output, not iteration 0's"
    );

    // And the LANDED DELTA proves it end to end: `consumed.txt` in the
    // execution's durable head names the bytes the consumed value wrote.
    let head = rig
        .db
        .execution_work_tree_head(execution)
        .unwrap()
        .expect("the head row reads");
    let head_row = rig
        .db
        .artifact(head.work_tree_artifact_id)
        .unwrap()
        .expect("the head's artifact row");
    let manifest_bytes = rig
        .cas
        .get_verified(
            &kata_types::primitives::ObjectId::new(head_row.object_id),
            head_row.size_bytes,
            kata_types::tree_artifact::TreeManifest::MAXIMUM_ENCODED_BYTES,
        )
        .expect("the head manifest reads");
    let manifest: kata_types::tree_artifact::TreeManifest =
        serde_json::from_slice(&manifest_bytes).expect("the manifest decodes");
    let entry = manifest
        .entries()
        .iter()
        .find(|entry| entry.path.as_str() == "consumed.txt")
        .expect("the landed /work carries consumed.txt");
    let kata_types::tree_artifact::TreeNode::File {
        object, size_bytes, ..
    } = &entry.node
    else {
        panic!("consumed.txt is a file node")
    };
    let landed = rig
        .cas
        .get_verified(object, *size_bytes, 4096)
        .expect("the file's member bytes read");
    assert_eq!(
        landed, b"2",
        "the landed delta carries the resolving iteration's marker — \
         a stage rendering `{{{{ stages.stage_a.parsed.marker }}}}` saw 2"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_crashed_run_resumes_the_expansion_from_durable_member_state() {
    let program = program();
    let dir = tempfile::tempdir().unwrap().keep();
    let rig = OciNodeRig::open(&dir);
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let reactor = reactor(&rig);

    // Drive iteration 0, then drop the run future mid-loop — the crash.
    let runner = rig.runner(&program, execution);
    let mut frames = 0usize;
    {
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    _ = &mut run => panic!("the first drive must not finish; it dies at iteration 0"),
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        let stdout = member_stdout(&stage_id, 0);
                        complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                        frames += 1;
                        if frames == 3 {
                            return;
                        }
                    }
                }
            }
        })
        .await
        .expect("iteration 0's members complete within the budget");
    }
    drop(runner);

    // The RESUMED runner — a fresh in-memory runner over the same planes —
    // re-derives the expansion from durable occurrences and picks the loop up
    // at iteration 1's first member.
    let runner = rig.runner(&program, execution);
    let mut controller_seen: u32 = 1;
    let run = runner.run();
    tokio::pin!(run);
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome.expect("the resumed run completes"),
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let coordinate = member_coordinate(&rig, &frame);
                    assert_ne!(
                        coordinate.0, 0,
                        "iteration 0 is durable; a resumed drive never re-runs it"
                    );
                    let stdout = member_stdout(&stage_id, controller_seen);
                    if stage_id == "controller" {
                        controller_seen += 1;
                    }
                    complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                    frames += 1;
                }
            }
        }
    })
    .await
    .expect("the resumed drive reaches a terminal within the budget");

    assert_eq!(frames, 9, "nine members ran across the crash");
    for stage in ["stage_a", "stage_b", "controller"] {
        assert!(
            outputs.contains_key(&SmolStr::new(stage)),
            "the resumed run's outputs carry {stage}'s completion"
        );
    }
    let readback = runner
        .durable_expansion_record_for_test(0)
        .expect("the record reads")
        .expect("the record is present");
    let record =
        kata_program::execution_program::expansion::ExpansionRecord::from_output(&readback)
            .unwrap();
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Approved {
                iteration: 2
            }
        ),
        "the resumed expansion resolves Approved at iteration 2"
    );
}

#[test]
fn the_accepted_expansion_record_reads_back() {
    let program = program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    runner.claim_expansion_for_test(0).unwrap();

    // Nothing recorded yet.
    assert_eq!(runner.durable_expansion_record_for_test(0).unwrap(), None);

    // Resolve the pending attempt through the substrate door, as the driver
    // will: `completed` carrying the record's output.
    let attempt: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT attempt_id FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| row.get(0),
        )
        .unwrap();
    let record = kata_program::execution_program::expansion::ExpansionRecord {
        operation: expansion.contract.id().0.to_string(),
        path: expansion.path.program_operation_stage_id(),
        stage: expansion.contract.source_stage.0.to_string(),
        resolution: kata_program::execution_program::expansion::ExpansionResolution::Approved {
            iteration: 2,
        },
        members: vec![
            kata_program::execution_program::expansion::ExpansionMember {
                iteration: 0,
                member: 0,
                stage: "stage_a".to_owned(),
                occurrence: "ef".repeat(32),
            },
        ],
        verdicts: vec![],
        quorum_unmet: None,
    };
    let output = record.to_output();
    rig.db
        .resolve_expansion_attempt(
            Ulid::from_bytes(attempt.try_into().unwrap()),
            &kata_core::operational::MainResolution::Complete { output: &output },
        )
        .expect("the expansion resolves")
        .expect("a pending expansion resolves");

    let readback = runner
        .durable_expansion_record_for_test(0)
        .expect("the record reads")
        .expect("the record is present");
    assert_eq!(readback, output, "the accepted record reads back verbatim");

    // The durable conclusion is terminal: a fresh claim converges on the
    // ACCEPTED occurrence rather than minting another generation.
    let outcome = runner.claim_expansion_for_test(0).unwrap();
    assert!(
        matches!(
            outcome,
            kata_core::operational::ExpansionClaimOutcome::AlreadyAccepted { .. }
        ),
        "an accepted expansion answers AlreadyAccepted, got {outcome:?}"
    );
}

/// A tampered accepted record diverges from the recompute — the replay refuses
/// `expansion_decision_diverged` rather than applying a decision the durable
/// member outcomes do not support.
#[tokio::test(flavor = "current_thread")]
async fn a_durable_record_that_disagrees_with_the_recompute_is_refused() {
    let program = program();
    let dir = tempfile::tempdir().unwrap().keep();
    let rig = OciNodeRig::open(&dir);
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    drive_to_terminal(&rig, &runner).await;
    drop(runner);

    // TAMPER the accepting transition's output through the raw handle: the
    // durable record now says Approved at iteration 0; the member outcomes
    // still recompute iteration 2.
    let payload_bytes: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT t.payload_json FROM transitions t
               JOIN occurrences o ON o.accepted_attempt_id = t.attempt_id
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE o.execution_id = ?1 AND a.stage_id = ?2
                AND t.resulting_state = 'completed'",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| row.get(0),
        )
        .expect("the expansion's accepting transition");
    let payload = String::from_utf8(payload_bytes).expect("the payload is UTF-8 JSON");
    assert!(
        payload.contains("\"iteration\":2"),
        "the record encodes iteration 2"
    );
    let payload = payload.replace("\"iteration\":2", "\"iteration\":0");
    {
        let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
        conn.execute(
            "UPDATE transitions SET payload_json = ?1
              WHERE attempt_id = (
                SELECT o.accepted_attempt_id FROM occurrences o
                  JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
                 WHERE o.execution_id = ?2 AND a.stage_id = ?3)
                AND resulting_state = 'completed'",
            rusqlite::params![
                payload.as_bytes(),
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
        )
        .expect("the tamper lands");
    }

    // A fresh runner's boot fold reaches the `#op` Completed frame, recomputes
    // iteration 2 off the durable member outcomes, and refuses the divergence.
    let runner = rig.runner(&program, execution);
    let error = runner
        .run()
        .await
        .expect_err("a tampered record diverges from the recompute");
    assert!(
        error.to_string().contains("expansion_decision_diverged"),
        "the refusal is named: {error}"
    );
}

/// A member attempt that dies mid-loop resolves the expansion `failed` and
/// applies the abort: members that ran keep their iteration-0 completion, the
/// worker fails, the gate skips.
#[tokio::test(flavor = "current_thread")]
async fn a_member_death_mid_loop_fails_the_expansion_and_aborts() {
    let program = program();
    let dir = tempfile::tempdir().unwrap().keep();
    let rig = OciNodeRig::open(&dir);
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let mut delivered = 0u32;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    delivered += 1;
                    let stage_id = frame_stage_id(&rig, &frame);
                    if stage_id == "stage_b" {
                        reactor
                            .handle_message_for_test(
                                kata_transport::types::WorkerMessage::Failed {
                                    assignment_id: frame.attempt_id,
                                    reason: "the worker stage crashed".to_owned(),
                                    verdict: kata_types::effect::DeliveryFailureProvenance::PerformedButFailed,
                                    provider_failure: None,
                                    usage: None,
                                    fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                                },
                            )
                            .expect("the member failure is adjudicated");
                    } else {
                        let stdout = member_stdout(&stage_id, 0);
                        complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                    }
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");

    // Two frames — stage_a, then the failed stage_b — and the gate never ran.
    assert_eq!(delivered, 2, "the abort stops the member walk");
    let error = outcome.expect_err("a failed expansion fails the run");
    assert!(
        error.to_string().contains("stage_b"),
        "the failure names the member stage: {error}"
    );

    // Durable: the `#op` attempt resolved `failed`, the accepted-member count
    // is one (stage_a), and the failure is recorded against the expansion.
    let terminal: String = raw(&rig.op_path)
        .query_row(
            "SELECT t.resulting_state FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = ?2
              ORDER BY t.seq DESC LIMIT 1",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| row.get(0),
        )
        .expect("the expansion attempt's terminal transition");
    assert_eq!(terminal, "failed", "the expansion resolved failed");
    let accepted_members: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM occurrences o
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE o.execution_id = ?1 AND a.executor = 'worker'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the accepted member count reads");
    assert_eq!(accepted_members, 1, "only stage_a's occurrence is accepted");
    let recorded = runner
        .durable_expansion_record_for_test(0)
        .expect("the record reads")
        .expect("the conclusion is recorded");
    assert!(
        recorded.get("expansion_failed").is_some(),
        "the durable conclusion is a recorded failure, not a record: {recorded}"
    );
}

/// The escalate variant: a single-member body, bound 2, and a controller that
/// never stops refining — the bound always spends, and under
/// `on_exhaustion = "escalate"` the expansion parks `awaiting_approval` on the
/// operator instead of resolving itself.
const ESCALATE_PACK: &str = r#"
worker = stage(
    id = "worker",
    run = "printf '{\"stage\":\"w\",\"marker\":0}\\n'",
    agent = "shell",
    outputs = {
        "stage": "string",
        "marker": "number",
    },
    topology = topology(
        "deterministic_validation",
        root = role("worker_runner", agent = "shell"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
)

controller = stage(
    id = "controller",
    run = "printf '{\"decision\":\"continue\",\"feedback\":\"again\"}\\n'",
    agent = "shell",
    depends_on = ["worker"],
    outputs = {
        "decision": "string",
        "feedback": "string",
    },
    topology = topology(
        "deterministic_validation",
        root = role("controller_runner", agent = "shell"),
        max_concurrency = 1,
    ),
    progress_visibility = "summary",
)

loop(
    body = worker,
    gate = controller,
    max_iterations = 2,
    on_exhaustion = "escalate",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)

workflow(
    "escalate-loop-smoke",
    description = (
        "Model-free escalate smoke: the controller never stops refining, " +
        "the bound spends at 2, and the expansion parks on the operator."
    ),
    root = [worker, controller],
)
"#;

fn escalate_program() -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(ESCALATE_PACK, "escalate-loop-smoke.star", &[])
        .expect("the escalate pack compiles under oci")
}

/// The escalate pack's one member frame's stdout, by stage id.
fn escalate_stdout(stage_id: &str) -> &'static str {
    match stage_id {
        "worker" => "{\"stage\":\"w\",\"marker\":0}",
        "controller" => "{\"decision\":\"continue\",\"feedback\":\"again\"}",
        other => panic!("the escalate pack has no stage {other}"),
    }
}

/// What the operator's gate list exposes for one parked expansion gate.
struct ParkedExpansionGate {
    assignment_id: Ulid,
    execution_id: Ulid,
    reason: String,
    gate: kata_types::approval::PendingExpansionGate,
}

/// Drive `run` until the dispatcher lists one parked EXPANSION gate — every
/// delivered member frame answered the pack's own stdout — and answer
/// `(the parked gate, how many member frames ran)`.
async fn drive_to_parked_gate(
    rig: &OciNodeRig,
    run: &mut std::pin::Pin<
        &mut impl std::future::Future<
            Output = kata_types::error::KataResult<
                std::collections::BTreeMap<SmolStr, serde_json::Value>,
            >,
        >,
    >,
) -> (ParkedExpansionGate, u32) {
    let reactor = reactor(rig);
    let mut delivered = 0u32;
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = run.as_mut() => {
                    panic!("a parked escalate gate keeps the run live, got {outcome:?}")
                }
                frame = next_frame(rig) => {
                    delivered += 1;
                    let stage_id = frame_stage_id(rig, &frame);
                    complete_frame(rig, &reactor, &frame, escalate_stdout(&stage_id).as_bytes());
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    let gates = rig
                        .dispatcher
                        .parked_approval_gates()
                        .expect("the operator's gate list reads");
                    if let Some(gate) = gates.into_iter().find(|gate| gate.expansion.is_some()) {
                        assert!(
                            gate.capsule.is_none() && gate.workspace_effect.is_none(),
                            "an expansion gate binds only the expansion — it is no \
                             capsule or effect gate"
                        );
                        let gate = ParkedExpansionGate {
                            assignment_id: gate.assignment_id,
                            execution_id: gate.execution_id,
                            reason: gate.reason,
                            gate: gate.expansion.expect("selected on it"),
                        };
                        break (gate, delivered);
                    }
                }
            }
        }
    })
    .await
    .expect("the bound spends and the gate parks within the budget")
}

/// **The spent bound parks ONE operator gate, and the operator's approve
/// adopts the record the park carried.** Four member frames (two iterations
/// of worker + controller, all `continue`) exhaust the escalate loop's bound;
/// the expansion's `#op` attempt sits `awaiting_approval`, listed for the
/// operator with the loop's coordinate and spent bound; `decide_expansion_gate`
/// resolves it `completed` with exactly the `Exhausted { escalate }` record
/// the park recorded — the fold then finishes the member stages off the last
/// iteration's outputs and the run completes.
#[tokio::test(flavor = "current_thread")]
async fn an_exhausted_escalate_gate_parks_then_approve_adopts_the_parked_record() {
    let program = escalate_program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = {
        assert_eq!(program.review_loops.len(), 1);
        lower_review_loop(&program, 0).expect("the escalate loop lowers")
    };

    let run = runner.run();
    tokio::pin!(run);
    let (gate, delivered) = drive_to_parked_gate(&rig, &mut run).await;

    // Two iterations of two members ran; the bound spent; the gate parks.
    assert_eq!(delivered, 4, "worker + controller ran twice");
    assert_eq!(gate.execution_id, execution);
    assert!(!gate.reason.is_empty(), "a parked gate exists to be read");
    let parked = &gate.gate;
    assert_eq!(
        parked.path,
        expansion.path.program_operation_stage_id(),
        "the gate names the loop's own coordinate"
    );
    assert_eq!(parked.stage, "worker", "the gate names the authored stage");
    assert_eq!(parked.maximum, 2);
    assert_eq!(parked.iterations, 2, "both iterations' verdicts classified");

    rig.dispatcher
        .decide_expansion_gate(
            gate.assignment_id,
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
            kata_core::operational::ExpansionVerdict::Approve,
        )
        .expect("the operator's approve decides the parked gate");

    let outputs = tokio::time::timeout(std::time::Duration::from_secs(60), &mut run)
        .await
        .expect("the decided run settles within the budget")
        .expect("an approved escalate gate completes the run");

    // The `#op` attempt is `completed` and its occurrence accepted — with the
    // `Exhausted { on_max: escalate }` record the park itself recorded.
    let (state, output): (String, Vec<u8>) = raw(&rig.op_path)
        .query_row(
            "SELECT t.resulting_state, t.payload_json FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = ?2
                AND t.kind = 'main_resolved'
              ORDER BY t.seq DESC LIMIT 1",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the expansion's resolving transition");
    assert_eq!(
        state, "completed",
        "the approve resolved the gate completed"
    );
    let output: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let record =
        kata_program::execution_program::expansion::ExpansionRecord::from_output(&output["output"])
            .expect("the adopted output is an expansion record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 2,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Escalate,
            }
        ),
        "the adopted record is the park's own Exhausted decision: {:?}",
        record.resolution
    );
    assert_eq!(record.members.len(), 4);
    assert_eq!(record.verdicts.len(), 2);

    // The write-once latch: the same approve replays, the opposite refuses.
    rig.dispatcher
        .decide_expansion_gate(
            gate.assignment_id,
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
            kata_core::operational::ExpansionVerdict::Approve,
        )
        .expect("a repeated approve converges");
    let err = rig
        .dispatcher
        .decide_expansion_gate(
            gate.assignment_id,
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
            kata_core::operational::ExpansionVerdict::Reject { reason: "no" },
        )
        .expect_err("the opposite verdict refuses by name");
    assert!(
        err.to_string().contains("approval_already_decided"),
        "{err}"
    );

    // The adopted record completed every authored stage off the last
    // iteration's outputs.
    for stage in ["worker", "controller"] {
        assert!(
            outputs.contains_key(&SmolStr::new(stage)),
            "the run outputs carry {stage}'s completion"
        );
    }
}

/// **A parked escalate gate holds its gate's dependents until the operator decides.**
/// The escalate pack with `after` behind the gate (`controller`): two iterations of
/// `continue` spend the bound and the expansion parks. While it is parked `after` has
/// no row in the raw `attempts` table, though the park completes the gate's stage —
/// the worker's stage waits on the operator, and nothing behind the loop starts. The
/// operator's approve resolves the loop; `after` is then dispatched exactly once and
/// the run completes.
///
/// **Would red if:** the park released the stages behind the loop's gate (`after`
/// dispatches before the approve).
#[tokio::test(flavor = "current_thread")]
async fn a_parked_escalate_gate_holds_its_dependents_until_the_approve() {
    let source = ESCALATE_PACK
        .replace(
            "loop(\n",
            "after = stage(id = \"after\", agent = \"shell\", run = \"true\", \
             depends_on = [\"controller\"])\n\nloop(\n",
        )
        .replace(
            "root = [worker, controller],",
            "root = [worker, controller, after],",
        );
    assert!(
        source.contains("after = stage(") && source.contains("root = [worker, controller, after]"),
        "the pack carries `after` behind the gate: {source}"
    );
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(&source, "escalate-held.star", &[])
        .expect("the escalate pack with a stage behind its gate compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let mut frames = Vec::new();
    let gate = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = run.as_mut() => {
                    panic!("a parked escalate gate keeps the run live, got {outcome:?}")
                }
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let stdout = if stage_id == "after" {
                        "ran"
                    } else {
                        escalate_stdout(&stage_id)
                    };
                    complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                    frames.push(stage_id);
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    let gates = rig
                        .dispatcher
                        .parked_approval_gates()
                        .expect("the operator's gate list reads");
                    if let Some(gate) = gates.into_iter().find(|gate| gate.expansion.is_some()) {
                        break gate.assignment_id;
                    }
                }
            }
        }
    })
    .await
    .expect("the bound spends and the gate parks within the budget");
    assert_eq!(
        stage_attempts(&rig, execution, "after"),
        0,
        "nothing behind a parked gate starts: frames {frames:?}"
    );

    rig.dispatcher
        .decide_expansion_gate(
            gate,
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
            kata_core::operational::ExpansionVerdict::Approve,
        )
        .expect("the operator's approve decides the parked gate");
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = run.as_mut() => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    complete_frame(&rig, &reactor, &frame, b"ran");
                    frames.push(stage_id);
                }
            }
        }
    })
    .await
    .expect("the decided run settles within the budget")
    .unwrap_or_else(|error| panic!("an approved escalate gate completes the run: {error}"));
    assert_eq!(
        stage_attempts(&rig, execution, "after"),
        1,
        "the approve releases `after` once: frames {frames:?}"
    );
    assert!(outputs.contains_key(&SmolStr::new("after")), "{frames:?}");
}

/// **The operator's reject fails the expansion in place with the recorded
/// reason** — no member re-drives, no occurrence accepts, the run fails
/// naming the operator's reason.
#[tokio::test(flavor = "current_thread")]
async fn an_exhausted_escalate_gate_rejected_fails_the_expansion() {
    let program = escalate_program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = {
        assert_eq!(program.review_loops.len(), 1);
        lower_review_loop(&program, 0).expect("the escalate loop lowers")
    };

    let run = runner.run();
    tokio::pin!(run);
    let (gate, delivered) = drive_to_parked_gate(&rig, &mut run).await;
    assert_eq!(delivered, 4);

    rig.dispatcher
        .decide_expansion_gate(
            gate.assignment_id,
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
            kata_core::operational::ExpansionVerdict::Reject {
                reason: "the body never convinced me",
            },
        )
        .expect("the operator's reject decides the parked gate");

    let err = tokio::time::timeout(std::time::Duration::from_secs(60), &mut run)
        .await
        .expect("the decided run settles within the budget")
        .expect_err("a rejected escalate gate fails the run");
    assert!(
        err.to_string().contains("the body never convinced me")
            || err.to_string().contains("worker"),
        "the run's failure names the gate's reason or its stage: {err}"
    );

    // The `#op` attempt is `failed` with the operator's reason, and the
    // expansion occurrence never accepted.
    let (state,): (String,) = raw(&rig.op_path)
        .query_row(
            "SELECT t.resulting_state FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = ?2
                AND t.kind = 'main_resolved'
              ORDER BY t.seq DESC LIMIT 1",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| Ok((row.get(0)?,)),
        )
        .expect("the expansion's resolving transition");
    assert_eq!(state, "failed", "the reject resolved the gate failed");
    let accepted: Option<Vec<u8>> = raw(&rig.op_path)
        .query_row(
            "SELECT accepted_attempt_id FROM occurrences
              WHERE execution_id = ?1 AND operation_path = ?2",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.canonical_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .expect("the expansion occurrence row reads");
    assert!(
        accepted.is_none(),
        "a rejected gate adopts nothing — the occurrence stays unaccepted"
    );
    let reason = rig
        .db
        .attempt_terminal_reason(gate.assignment_id)
        .expect("the terminal reason reads");
    assert_eq!(
        reason.as_deref(),
        Some("rejected: the body never convinced me"),
        "the operator's reason is the recorded terminal"
    );
}

// ---------------------------------------------------------------------------
// The loop-cell coverage twins. Every loop-drive semantic has a host-free twin
// below: resolutions (block / exhaust-fail / exhaust-accept / escalate),
// per-loop bounds off the DURABLE member usage + claim timestamps, rollover
// generation math + distilled context + durable carry, per-iteration writeback,
// member approval gates, branch arms, unmatched verdicts, validate retries,
// mid-iteration resume, and per-iteration `/work` application.
// ---------------------------------------------------------------------------

/// The capsule argv one member frame binds — `["sh", "-c", <rendered>]` for a
/// Command member — the prompt's RENDERED text, which is where a member's
/// `{{ review.* }}` / `{{ stages.* }}` surface is legible.
fn member_argv(rig: &OciNodeRig, frame: &kata_transport::types::CapsuleAssignment) -> Vec<String> {
    let bytes = rig
        .cas
        .get(&frame.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let capsule: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&bytes).expect("the capsule decodes");
    match capsule.process() {
        kata_types::execution_contract::CapsuleProcess::Command { argv } => {
            argv.iter().map(ToString::to_string).collect()
        }
        kata_types::execution_contract::CapsuleProcess::Agent(_) => {
            panic!("the member is a Command capsule")
        }
    }
}

/// One member frame's report of writing `name` = `bytes` under its bound
/// `/work` — the real-delta path the CONSUME cell walked for `consumed.txt`,
/// parameterized so every iteration's landed write is legible in the head
/// manifest.
fn named_work_delta(
    rig: &OciNodeRig,
    execution: Ulid,
    frame: &kata_transport::types::CapsuleAssignment,
    name: &str,
    bytes: &[u8],
) -> kata_types::execution_contract::ArtifactRef {
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
    use kata_types::tree_artifact::{TreeEntryMode, TreeNode, TreePath};
    use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};
    let work_tree = rig
        .db
        .occurrence(frame.occurrence_id.0.0)
        .unwrap()
        .unwrap()
        .work_tree_artifact_id
        .expect("the member's /work binds the execution tree");
    let row = rig.db.artifact(work_tree).unwrap().unwrap();
    let base = ArtifactRef::new(
        kata_types::primitives::FixedBytes(row.object_id),
        row.size_bytes,
        row.privacy,
    );
    let member = rig.cas.put_durable(bytes).unwrap();
    let delta = TreeDelta::new(
        base,
        vec![TreeChange {
            path: TreePath::new(name).unwrap(),
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
    let durable = rig.cas.put_durable(&delta.delta_bytes().unwrap()).unwrap();
    rig.db
        .declare_artifact(
            &kata_core::operational::ArtifactDeclaration::for_durable_delta(
                &delta,
                ArtifactPrivacy::Private,
                kata_core::operational::CasRootOwner::Execution(execution),
                &durable,
            )
            .unwrap(),
        )
        .unwrap();
    ArtifactRef::new(
        durable.object_id(),
        durable.size(),
        ArtifactPrivacy::Private,
    )
}

/// The member occurrence's ACCEPTED output envelope, read off the raw handle
/// the way `accepted_attempt_output` composes it — the seq-latest of the
/// `completed`/`outcome_amended` frames ON THE MEMBER'S OWN accepted attempt
/// (a `#apply` occurrence shares this `operation_path` but its `main_*` frames
/// ride its own main-executor attempt, which `a.executor <> 'main'` excludes).
fn member_output(
    rig: &OciNodeRig,
    execution: Ulid,
    expansion: &kata_program::execution_program::LoweredOperation,
    iteration: u32,
    member: u32,
) -> serde_json::Value {
    let payload: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT t.payload_json FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
               JOIN occurrences o ON o.accepted_attempt_id = a.attempt_id
              WHERE o.execution_id = ?1 AND o.operation_path = ?2
                AND a.executor <> 'main'
                AND (t.kind = 'outcome_amended' OR t.resulting_state = 'completed')
              ORDER BY t.seq DESC LIMIT 1",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion
                    .path
                    .child(iteration)
                    .child(member)
                    .canonical_bytes()
                    .as_slice(),
            ],
            |row| row.get(0),
        )
        .expect("the member's accepted output frame reads");
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    payload
        .get("output")
        .cloned()
        .expect("the accepted frame carries the member envelope under output")
}

/// FAULT INJECTION into the durable member usage the bound recompute reads:
/// mutate EVERY output-bearing frame on the member's own accepted attempt —
/// the accepting `completed` frame the projected amendment re-derives from
/// AND any `outcome_amended` row the overlay already wrote. A resume
/// re-projects the amendment off the completed frame, so tampering only the
/// amendment gets clobbered by the re-derivation; tampering only the accept
/// leaves a stale amendment winning the overlay. `mutate` gets each frame's
/// member ENVELOPE (its `output` field).
fn tamper_member_output(
    rig: &OciNodeRig,
    execution: Ulid,
    expansion: &kata_program::execution_program::LoweredOperation,
    iteration: u32,
    member: u32,
    mutate: impl Fn(&mut serde_json::Value),
) {
    let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
    let rows: Vec<(i64, Vec<u8>)> = conn
        .prepare(
            "SELECT t.seq, t.payload_json FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
               JOIN occurrences o ON o.accepted_attempt_id = a.attempt_id
              WHERE o.execution_id = ?1 AND o.operation_path = ?2
                AND a.executor <> 'main'
                AND (t.kind = 'outcome_amended' OR t.resulting_state = 'completed')
              ORDER BY t.seq",
        )
        .unwrap()
        .query_map(
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion
                    .path
                    .child(iteration)
                    .child(member)
                    .canonical_bytes()
                    .as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .expect("the member's accepted output frames read");
    assert!(
        !rows.is_empty(),
        "the member's accepted attempt carries an output frame"
    );
    for (seq, payload) in rows {
        let mut payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        mutate(
            payload
                .get_mut("output")
                .expect("the accepted frame carries the member envelope under output"),
        );
        let affected = conn
            .execute(
                "UPDATE transitions SET payload_json = ?1 WHERE seq = ?2",
                rusqlite::params![serde_json::to_vec(&payload).unwrap(), seq],
            )
            .expect("the tamper lands");
        assert_eq!(
            affected, 1,
            "the tamper rewrites exactly the frame at seq={seq}"
        );
    }
}

/// The expansion's accepted record, decoded off the `#op` attempt's terminal
/// `main_resolved` frame — `None` while the attempt is unresolved.
fn expansion_record(
    rig: &OciNodeRig,
    execution: Ulid,
    expansion: &kata_program::execution_program::LoweredOperation,
) -> Option<kata_program::execution_program::expansion::ExpansionRecord> {
    let output: Option<Vec<u8>> = raw(&rig.op_path)
        .query_row(
            "SELECT t.payload_json FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = ?2
                AND t.kind = 'main_resolved' AND t.resulting_state = 'completed'
              ORDER BY t.seq DESC LIMIT 1",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| row.get(0),
        )
        .ok();
    output.map(|bytes| {
        let output: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        kata_program::execution_program::expansion::ExpansionRecord::from_output(&output["output"])
            .expect("the accepted output is an expansion record")
    })
}

/// The `#op` attempt's terminal `main_resolved` state — the expansion's own
/// resolution as the ledger records it.
fn expansion_terminal_state(
    rig: &OciNodeRig,
    execution: Ulid,
    expansion: &kata_program::execution_program::LoweredOperation,
) -> String {
    raw(&rig.op_path)
        .query_row(
            "SELECT t.resulting_state FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = ?2
                AND t.kind = 'main_resolved'
              ORDER BY t.seq DESC LIMIT 1",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| row.get(0),
        )
        .expect("the expansion's resolving transition")
}

/// THE RESOLUTION pack — the escalate pack's single-member shape with a
/// per-cell `on_exhaustion`: verdicts `promote` (approve), `continue`
/// (refine), `stop` (block), bound `max` (1..=3).
fn resolution_pack(max: u32, on_exhaustion: &str) -> String {
    format!(
        r#"worker = stage(
    id = "worker",
    run = "printf '{{\"stage\":\"w\",\"marker\":0}}\\n'",
    agent = "shell",
    outputs = {{
        "stage": "string",
        "marker": "number",
    }},
)

controller = stage(
    id = "controller",
    run = "printf '{{\"decision\":\"continue\",\"feedback\":\"again\"}}\\n'",
    agent = "shell",
    depends_on = ["worker"],
    outputs = {{
        "decision": "string",
        "feedback": "string",
    }},
)

loop(
    body = worker,
    gate = controller,
    max_iterations = {max},
    on_exhaustion = "{on_exhaustion}",
    gate_verdict = {{
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    }},
)

workflow("resolution-loop", root = [worker, controller])
"#
    )
}

fn resolution_program(max: u32, on_exhaustion: &str) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(
        &resolution_pack(max, on_exhaustion),
        "resolution-loop.star",
        &[],
    )
    .expect("the resolution pack compiles under oci")
}

/// The resolution pack's one member frame's stdout, scripted per `(stage,
/// coordinate)`: the worker reports its iteration as the marker so which
/// envelope a completed authored name carries is legible; the gate's decision
/// comes from `decisions[iteration]`.
fn resolution_stdout(stage_id: &str, iteration: u32, decisions: &[&str]) -> String {
    match stage_id {
        "worker" => format!("{{\"stage\":\"w\",\"marker\":{iteration}}}"),
        "controller" => format!(
            "{{\"decision\":\"{}\",\"feedback\":\"iter {iteration}\"}}",
            decisions[iteration as usize]
        ),
        other => panic!("the resolution pack has no stage {other}"),
    }
}

/// Drive the resolution pack to terminal, scripting the gate's decision per
/// iteration — returns `(the run outcome's outputs-or-error, frames)`.
async fn drive_resolution(
    rig: &OciNodeRig,
    runner: &kata_workflow::runner::WorkflowRunner,
    decisions: &[&str],
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, (u32, u32))>,
) {
    let reactor = reactor(rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let stage_id = frame_stage_id(rig, &frame);
                    let (iteration, member) = member_coordinate(rig, &frame);
                    complete_frame(
                        rig,
                        &reactor,
                        &frame,
                        resolution_stdout(&stage_id, iteration, decisions).as_bytes(),
                    );
                    frames.push((stage_id, (iteration, member)));
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    (outcome, frames)
}

/// The gate's `stop`
/// verdict resolves the expansion `Blocked` — the authored record completes
/// the `#op` attempt, the worker stage fails with the reviewer's feedback,
/// and the run errors naming the review, never dispatching a second
/// iteration.
#[tokio::test(flavor = "current_thread")]
async fn a_block_verdict_resolves_the_expansion_and_fails_the_worker() {
    let program = resolution_program(3, "fail");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let (outcome, frames) = drive_resolution(&rig, &runner, &["stop"]).await;

    assert_eq!(frames.len(), 2, "worker + one gate pass ran");
    let error = outcome.expect_err("a blocked review fails the run");
    assert!(
        error.to_string().contains("worker"),
        "the failure names the loop's worker: {error}"
    );
    assert_eq!(
        expansion_terminal_state(&rig, execution, &expansion),
        "completed"
    );
    let record = expansion_record(&rig, execution, &expansion).expect("the blocked record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Blocked {
                iteration: 0
            }
        ),
        "the record is Blocked at iteration 0: {:?}",
        record.resolution
    );
}

/// Every gate pass refines,
/// the bound spends, and `on_max = "fail"` resolves the expansion
/// `Exhausted { fail }` — the record carries all three classified verdicts
/// and the run fails on the loop's own exhaustion.
#[tokio::test(flavor = "current_thread")]
async fn an_exhausted_bound_under_fail_fails_the_run() {
    let program = resolution_program(3, "fail");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let (outcome, frames) =
        drive_resolution(&rig, &runner, &["continue", "continue", "continue"]).await;

    assert_eq!(frames.len(), 6, "three iterations of worker + gate ran");
    let error = outcome.expect_err("on_max = fail fails the exhausted run");
    assert!(
        error.to_string().contains("worker"),
        "the exhaustion names the worker: {error}"
    );
    let record = expansion_record(&rig, execution, &expansion).expect("the exhausted record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 3,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Fail,
            }
        ),
        "the record is Exhausted {{3, fail}}: {:?}",
        record.resolution
    );
    assert_eq!(
        record.verdicts.len(),
        3,
        "every classified verdict recorded"
    );
}

/// **A loop exhausted under `on_exhaustion = "fail"` releases nothing behind its gate.**
/// `after` depends on the gate `controller` directly. Every gate pass refines, the bound
/// spends, and the record is `Exhausted{3, fail}`: the worker fails and `after` — read off
/// the raw `attempts` table — never dispatches, skipped like a halt's dependents. The
/// same drive under `accept` runs `after`: the gate's completion is the loop's answer
/// there.
///
/// **Would red if:** the `fail` exhaustion completed the gate and left its dependents to
/// the DAG (`after` dispatches on a failed loop's candidate).
#[tokio::test(flavor = "current_thread")]
async fn a_failed_exhaustion_dispatches_no_stage_behind_the_gate() {
    for (on_exhaustion, after_runs) in [("fail", false), ("accept", true)] {
        let source = resolution_pack(3, on_exhaustion).replace(
            "workflow(\"resolution-loop\", root = [worker, controller])",
            "after = stage(id = \"after\", agent = \"shell\", run = \"true\", \
             depends_on = [\"controller\"])\n\n\
             workflow(\"resolution-loop\", root = [worker, controller, after])",
        );
        let program = compile_starlark_execution_program(&source, "gate-dependent.star", &[])
            .expect("the gate-dependent loop compiles under oci");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let expansion = expansion(&program);
        let reactor = reactor(&rig);
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stdout = match frame_stage_id(&rig, &frame).as_str() {
                            "worker" => "{\"stage\":\"w\",\"marker\":0}".to_owned(),
                            "controller" => {
                                "{\"decision\":\"continue\",\"feedback\":\"again\"}".to_owned()
                            }
                            _ => "after ran".to_owned(),
                        };
                        complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                    }
                }
            }
        })
        .await
        .expect("the drive settles within the budget");
        let record = expansion_record(&rig, execution, &expansion).expect("the exhausted record");
        assert!(
            matches!(
                record.resolution,
                kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                    iterations: 3,
                    ..
                }
            ),
            "{on_exhaustion}: the bound spent: {:?}",
            record.resolution
        );
        let after_attempts: i64 = raw(&rig.op_path)
            .query_row(
                "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'after'",
                [execution.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("the dependent's attempts count");
        assert_eq!(
            after_attempts > 0,
            after_runs,
            "{on_exhaustion}: the gate's dependent dispatched {after_attempts} time(s); outcome \
             {outcome:?}"
        );
        assert_eq!(
            outcome.is_ok(),
            after_runs,
            "{on_exhaustion}: the run's outcome follows the exhaustion: {outcome:?}"
        );
    }
}

/// **A loop BLOCKED by its gate, with no route on the gate, releases nothing behind it.**
/// `after` depends on the gate `controller` directly. The gate's first verdict is `stop` —
/// the record is `Blocked{0}` (raw `#op` outcome) and the worker fails with the gate's
/// feedback — and `after`, read off the raw `attempts` table, never dispatches, skipped as an
/// `Exhausted{fail}` loop's gate dependents are; the run fails naming the worker. With a route
/// on the gate a block routes its arm instead
/// (`a_terminal_block_with_a_branch_routes_the_arm_without_failing`).
///
/// **Would red if:** the no-route block completed the gate and left its dependents to the DAG
/// (`after` dispatches behind a loop whose worker failed).
#[tokio::test(flavor = "current_thread")]
async fn a_blocked_loop_with_no_route_dispatches_no_stage_behind_the_gate() {
    let source = resolution_pack(3, "fail").replace(
        "workflow(\"resolution-loop\", root = [worker, controller])",
        "after = stage(id = \"after\", agent = \"shell\", run = \"true\", \
         depends_on = [\"controller\"])\n\n\
         workflow(\"resolution-loop\", root = [worker, controller, after])",
    );
    let program = compile_starlark_execution_program(&source, "blocked-gate-dependent.star", &[])
        .expect("the gate-dependent loop compiles under oci");
    assert!(
        program.branch_routes.is_empty(),
        "no route on the gate: the block is the loop's own answer"
    );
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let stdout: &[u8] = match stage_id.as_str() {
                        "worker" => b"{\"stage\":\"w\",\"marker\":0}",
                        "controller" => b"{\"decision\":\"stop\",\"feedback\":\"not this\"}",
                        _ => b"after ran",
                    };
                    complete_frame(&rig, &reactor, &frame, stdout);
                    frames.push(stage_id);
                }
            }
        }
    })
    .await
    .expect("the drive settles within the budget");
    let record = expansion_record(&rig, execution, &expansion).map(|record| record.resolution);
    let after_attempts: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'after'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the dependent's attempts count");
    let failed = outcome
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("review blocked: not this"));
    assert!(
        matches!(
            record,
            Some(
                kata_program::execution_program::expansion::ExpansionResolution::Blocked {
                    iteration: 0
                }
            )
        ) && after_attempts == 0
            && failed,
        "frames {frames:?}, record {record:?}, `after` dispatched {after_attempts} time(s), the \
         run {outcome:?}"
    );
}

/// The accept-arm resolving-iteration projection: `on_max = "accept"` resolves the
/// expansion `Exhausted { accept }`, the run completes, and every authored
/// member stage's envelope is the LAST completed iteration's (the worker's
/// `marker` is 2, never iteration 0's).
#[tokio::test(flavor = "current_thread")]
async fn an_exhausted_bound_under_accept_completes_with_the_last_iterations_outputs() {
    let program = resolution_program(3, "accept");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let (outcome, frames) =
        drive_resolution(&rig, &runner, &["continue", "continue", "continue"]).await;

    assert_eq!(frames.len(), 6);
    let outputs = outcome.expect("on_max = accept completes the exhausted run");
    let record = expansion_record(&rig, execution, &expansion).expect("the exhausted record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 3,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Accept,
            }
        ),
        "the record is Exhausted {{3, accept}}: {:?}",
        record.resolution
    );
    assert_eq!(
        outputs[&SmolStr::new("worker")]["parsed"]["marker"],
        serde_json::json!(2),
        "the accepted worker envelope is the FINAL completed iteration's"
    );
    assert_eq!(
        outputs[&SmolStr::new("controller")]["parsed"]["decision"],
        serde_json::json!("continue"),
        "the authored gate carries its terminal envelope"
    );
}

/// THE BOUNDS pack — `resolution_pack` plus the workflow-scope `bounds` list
/// the bound cells hang their trip on. `cost_bound(0.0005)` USD is
/// 500 micro-USD; the cells tamper the DURABLE member envelope's
/// `token_usage.cost_micro_usd` — the same bytes the derive's
/// `loop_bounds_trip` recompute folds — so which bytes the bound reads is
/// the thing under test, never the clock.
fn bounds_pack(bound: &str, max: u32, on_exhaustion: &str) -> String {
    format!(
        r#"worker = stage(
    id = "worker",
    run = "printf '{{\"stage\":\"w\",\"marker\":0}}\\n'",
    agent = "shell",
    outputs = {{
        "stage": "string",
        "marker": "number",
    }},
)

controller = stage(
    id = "controller",
    run = "printf '{{\"decision\":\"continue\",\"feedback\":\"again\"}}\\n'",
    agent = "shell",
    depends_on = ["worker"],
    outputs = {{
        "decision": "string",
        "feedback": "string",
    }},
)

loop(
    body = worker,
    gate = controller,
    max_iterations = {max},
    bounds = [{bound}],
    on_exhaustion = "{on_exhaustion}",
    gate_verdict = {{
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    }},
)

workflow("bounded-loop", root = [worker, controller])
"#
    )
}

fn bounds_program(bound: &str, max: u32, on_exhaustion: &str) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(
        &bounds_pack(bound, max, on_exhaustion),
        "bounded-loop.star",
        &[],
    )
    .expect("the bounded pack compiles under oci")
}

/// A cost bound trips before `max_iterations`, even when the gate approves: the
/// worker's accepted
/// envelope — tampered to 600 micro-USD against a 500 bound — trips on the
/// NEXT derive even though the gate's `promote` envelope is durably
/// accepted beside it: the derive folds members IN ORDER, the bound check
/// rides every member fold, and the gate's verdict never classifies — the
/// record carries exactly the one folded member and an empty verdict list.
#[tokio::test(flavor = "current_thread")]
async fn a_cost_bound_trip_wins_over_the_gates_own_approve() {
    let program = bounds_program("cost_bound(0.0005)", 3, "accept");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let (iteration, member) = member_coordinate(&rig, &frame);
                    if member == 0 {
                        complete_frame(
                            &rig, &reactor, &frame,
                            b"{\"stage\":\"w\",\"marker\":0}",
                        );
                    } else {
                        if iteration == 0 {
                            // The gate's frame ARRIVING proves iteration 0's
                            // worker folded accepted — its durable envelope
                            // is the row the gate's own derive re-folds next.
                            // Tamper it between the fold and the completion.
                            tamper_member_output(&rig, execution, &expansion, 0, 0, |envelope| {
                                envelope["token_usage"] = serde_json::json!({
                                    "cost_micro_usd": 600
                                });
                            });
                        }
                        complete_frame(
                            &rig, &reactor, &frame,
                            b"{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                        );
                    }
                }
            }
        }
    })
    .await
    .expect("the bound resolve lands within the budget");
    outcome.expect("on_exhaustion = accept completes the tripped loop");

    let record = expansion_record(&rig, execution, &expansion).expect("the bound record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 1,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Accept,
            }
        ),
        "the bound spent at ONE iteration under accept: {:?}",
        record.resolution
    );
    assert_eq!(
        record.members.len(),
        1,
        "only the member the bound tripped on folded into the record"
    );
    assert!(
        record.verdicts.is_empty(),
        "the gate's approve was accepted but never classified — the bound won"
    );
    assert_eq!(
        member_output(&rig, execution, &expansion, 0, 1)["parsed"]["decision"],
        serde_json::json!("promote"),
        "the gate's promote envelope IS durable — it was simply never reached"
    );
}

/// **A loop `token_bound` trips on the tokens the accepted members RECORDED**, every
/// class counted: the worker's durable envelope — tampered to 50 in / 20 out / 40 cache
/// read (110 tokens) against a 100-token bound — trips on the NEXT derive before the
/// gate's `promote` is classified, exactly as the cost bound does. Then the same
/// tamper with no token count (the `unmetered` shape) trips the bound CLOSED.
///
/// **Would red if:** the loop derive folded no tokens (the gate's promote classifies and
/// the loop is approved), left a class out (input + output alone, 70, stays under), or
/// read an uncounted member as zero.
#[tokio::test(flavor = "current_thread")]
async fn a_loop_token_bound_trips_on_the_members_recorded_tokens() {
    for (usage, case) in [
        (
            serde_json::json!({
                "input": 50,
                "output": 20,
                "cache_read": 40,
                "cost": {"quality": "authoritative", "micro_usd": 1},
                "cost_micro_usd": 1,
            }),
            "110 recorded tokens",
        ),
        (
            serde_json::json!({
                "cost": {"quality": "unavailable", "backend": "nanocode_openai", "model": "m"},
            }),
            "an uncounted member",
        ),
    ] {
        let program = bounds_program("token_bound(100)", 3, "accept");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let expansion = expansion(&program);
        let reactor = reactor(&rig);

        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let (iteration, member) = member_coordinate(&rig, &frame);
                        if member == 0 {
                            complete_frame(
                                &rig, &reactor, &frame,
                                b"{\"stage\":\"w\",\"marker\":0}",
                            );
                        } else {
                            if iteration == 0 {
                                tamper_member_output(&rig, execution, &expansion, 0, 0, |envelope| {
                                    envelope["token_usage"] = usage.clone();
                                });
                            }
                            complete_frame(
                                &rig, &reactor, &frame,
                                b"{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                            );
                        }
                    }
                }
            }
        })
        .await
        .expect("the bound resolve lands within the budget");
        outcome.expect("on_exhaustion = accept completes the tripped loop");

        let record = expansion_record(&rig, execution, &expansion).expect("the bound record");
        assert!(
            matches!(
                record.resolution,
                kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                    iterations: 1,
                    on_max: kata_program::execution_program::expansion::ExpansionOnMax::Accept,
                }
            ),
            "{case}: the bound spent at ONE iteration: {:?}",
            record.resolution
        );
        assert!(
            record.verdicts.is_empty(),
            "{case}: the gate's approve was never classified — the bound won"
        );
    }
}

/// **A loop `cost_bound` trips CLOSED on a member of unknown cost.** The worker's
/// accepted completion — tampered, when the gate's frame arrives, to a usage whose cost
/// is `Unavailable` — leaves the loop's known total at 0, under `cost_bound(0.0005)`'s
/// 500 micro-USD; the next derive trips the bound closed before the gate's `promote`
/// classifies: `Exhausted{1, fail}` with no verdict off the raw `#op` record, and the
/// run fails naming the member and `metering_unavailable`.
///
/// **Would red if:** a loop cost bound summed only KNOWN costs (the loop approves at
/// iteration 0 and the run completes).
#[tokio::test(flavor = "current_thread")]
async fn a_loop_cost_bound_trips_closed_on_a_member_of_unknown_cost() {
    let program = bounds_program("cost_bound(0.0005)", 3, "fail");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let (iteration, member) = member_coordinate(&rig, &frame);
                    if member == 0 {
                        complete_frame(&rig, &reactor, &frame, b"{\"stage\":\"w\",\"marker\":0}");
                    } else {
                        if iteration == 0 {
                            tamper_member_output(&rig, execution, &expansion, 0, 0, |envelope| {
                                envelope["token_usage"] = serde_json::json!({
                                    "input": 50,
                                    "cost": {
                                        "quality": "unavailable",
                                        "backend": "nanocode_openai",
                                        "model": "m",
                                    },
                                });
                            });
                        }
                        complete_frame(
                            &rig, &reactor, &frame,
                            b"{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                        );
                    }
                }
            }
        }
    })
    .await
    .expect("the bound resolve lands within the budget");

    let record = expansion_record(&rig, execution, &expansion).expect("the bound record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 1,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Fail,
            }
        ) && record.verdicts.is_empty(),
        "the bound tripped closed before the gate classified: {:?}, {} verdict(s)",
        record.resolution,
        record.verdicts.len()
    );
    let error = outcome.expect_err("on_exhaustion = fail fails the tripped run");
    assert!(
        error.to_string().contains(
            "loop cost bound unenforceable: member \"worker\" recorded no measurable cost \
             (metering_unavailable)"
        ),
        "the failure names the member of unknown cost: {error}"
    );
}

/// **A loop bound charges a member's REJECTED structured-output turn.** The worker's
/// first completion fails its declared outputs and retries at the member seat's
/// `child(1)`; that rejected turn spent — its durable completion, tampered when the
/// retry's frame arrives to 50 in / 20 out / 40 cache read (110 tokens) or to 600
/// micro-USD — and the valid retry spent nothing. The bound trips on the member
/// before the gate is dispatched: `Exhausted{1, accept}` with one member and no
/// verdict, and the gate has no attempt (raw `attempts`).
///
/// **Would red if:** the loop fold read only the member's accepted VALID envelope:
/// the retry's 0 stays under both bounds, the gate's `promote` classifies and the
/// loop is approved.
#[tokio::test(flavor = "current_thread")]
async fn a_loop_bound_charges_a_members_rejected_structured_output_turn() {
    let mut wrong = Vec::new();
    for (bound, usage) in [
        (
            "token_bound(100)",
            serde_json::json!({
                "input": 50,
                "output": 20,
                "cache_read": 40,
                "cost": {"quality": "authoritative", "micro_usd": 1},
                "cost_micro_usd": 1,
            }),
        ),
        (
            "cost_bound(0.0005)",
            serde_json::json!({
                "cost": {"quality": "authoritative", "micro_usd": 600},
                "cost_micro_usd": 600,
            }),
        ),
    ] {
        let program = bounds_program(bound, 3, "accept");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let expansion = expansion(&program);
        let reactor = reactor(&rig);

        let run = runner.run();
        tokio::pin!(run);
        let mut worker_frames = 0u32;
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        if frame_stage_id(&rig, &frame) == "worker" {
                            worker_frames += 1;
                            if worker_frames == 1 {
                                complete_frame(&rig, &reactor, &frame, b"{\"wrong\":true}");
                            } else {
                                // The retry's frame ARRIVING proves the rejected
                                // seat is accepted: tamper its durable completion.
                                tamper_member_output(&rig, execution, &expansion, 0, 0, |envelope| {
                                    envelope["token_usage"] = usage.clone();
                                });
                                complete_frame(
                                    &rig, &reactor, &frame,
                                    b"{\"stage\":\"w\",\"marker\":0}",
                                );
                            }
                        } else {
                            complete_frame(
                                &rig, &reactor, &frame,
                                b"{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                            );
                        }
                    }
                }
            }
        })
        .await
        .expect("the bound resolve lands within the budget");
        outcome.expect("on_exhaustion = accept completes the tripped loop");
        assert_eq!(
            worker_frames, 2,
            "{bound}: the rejected attempt and its retry"
        );

        let record = expansion_record(&rig, execution, &expansion).expect("the bound record");
        let gate_attempts: i64 = raw(&rig.op_path)
            .query_row(
                "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'controller'",
                [execution.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("the gate's attempts count");
        let tripped = matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 1,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Accept,
            }
        ) && record.members.len() == 1
            && record.verdicts.is_empty()
            && gate_attempts == 0;
        if !tripped {
            wrong.push(format!(
                "{bound}: record {:?} with {} member(s) and {} verdict(s); the gate has \
                 {gate_attempts} attempt(s)",
                record.resolution,
                record.members.len(),
                record.verdicts.len()
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The reason the expansion `#op` attempt of `expansion` parked on, read off its raw
/// `awaiting_approval` transition — `None` while it has not parked.
fn expansion_park_reason(
    rig: &OciNodeRig,
    execution: Ulid,
    expansion: &kata_program::execution_program::LoweredOperation,
) -> Option<String> {
    use rusqlite::OptionalExtension;
    let payload: Option<Vec<u8>> = raw(&rig.op_path)
        .query_row(
            "SELECT t.payload_json FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = ?2
                AND t.resulting_state = 'awaiting_approval'
              ORDER BY t.seq DESC LIMIT 1",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| row.get(0),
        )
        .optional()
        .expect("the expansion's park transition reads");
    payload.map(|bytes| {
        serde_json::from_slice::<serde_json::Value>(&bytes).expect("the park payload is JSON")
            ["reason"]
            .as_str()
            .expect("the park names its reason")
            .to_owned()
    })
}

/// **A loop bound's trip parks NAMED as a walk-away under `on_exhaustion =
/// "escalate"` — an UNENFORCEABLE trip as much as an exceeded one.** The worker's
/// durable completion is tampered, when the gate's frame arrives, to a usage that states
/// no token count; the next derive trips the loop's `token_bound(100)` closed and parks
/// the expansion. The park reason, read off the raw `#op` `awaiting_approval`
/// transition, leads with `review loop walk-away: loop token bound unenforceable`.
///
/// **Would red if:** the park reason were chosen by searching the trip text for "bound
/// exceeded" — the unenforceable trip parked as `review loop exhausted after 3
/// iterations`, an iteration exhaustion that never happened.
#[tokio::test(flavor = "current_thread")]
async fn a_loop_bound_trip_parks_named_as_a_walk_away_under_escalate() {
    let program = bounds_program("token_bound(100)", 3, "escalate");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let reason = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => {
                    panic!("a parked escalate gate keeps the run live, got {outcome:?}")
                }
                frame = next_frame(&rig) => {
                    let (iteration, member) = member_coordinate(&rig, &frame);
                    if member == 0 {
                        complete_frame(&rig, &reactor, &frame, b"{\"stage\":\"w\",\"marker\":0}");
                    } else {
                        if iteration == 0 {
                            tamper_member_output(&rig, execution, &expansion, 0, 0, |envelope| {
                                envelope["token_usage"] = serde_json::json!({
                                    "cost": {
                                        "quality": "unavailable",
                                        "backend": "nanocode_openai",
                                        "model": "m",
                                    },
                                });
                            });
                        }
                        complete_frame(
                            &rig, &reactor, &frame,
                            b"{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                        );
                    }
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    if let Some(reason) = expansion_park_reason(&rig, execution, &expansion) {
                        break reason;
                    }
                }
            }
        }
    })
    .await
    .expect("the tripped loop parks within the budget");
    assert!(
        reason.starts_with(
            "review loop walk-away: loop token bound unenforceable: member \"worker\""
        ),
        "the park names the walk-away, not an iteration exhaustion: {reason}"
    );
}

/// Rewrite the `token_usage` of attempt `attempt`'s durable `completed` frame — the
/// bill the workflow-scope fold reads off that frame. Called inside the stub's
/// select arm, right after the completion is adopted and before the runner is polled
/// again, so the fold that charges the frame reads the rewritten bytes.
fn tamper_completion_usage(rig: &OciNodeRig, attempt: Ulid, usage: &serde_json::Value) {
    let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
    let (seq, payload): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT seq, payload_json FROM transitions
              WHERE attempt_id = ?1 AND resulting_state = 'completed'",
            [attempt.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the attempt's completed frame");
    let mut payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    payload["output"]["token_usage"] = usage.clone();
    let affected = conn
        .execute(
            "UPDATE transitions SET payload_json = ?1 WHERE seq = ?2",
            rusqlite::params![serde_json::to_vec(&payload).unwrap(), seq],
        )
        .expect("the tamper lands");
    assert_eq!(
        affected, 1,
        "the tamper rewrites exactly the frame at seq={seq}"
    );
}

/// Every walk-away row of `execution`, read raw: a FAILED stage-scope transition whose
/// stage id carries one of the three walk-away markers, spelled here rather than read
/// through kata's own predicate — `(stage id, reason)`, in chain order.
fn walkaway_rows(rig: &OciNodeRig, execution: Ulid) -> Vec<(String, String)> {
    raw(&rig.op_path)
        .prepare(
            "SELECT stage_id, payload_json FROM transitions
              WHERE execution_id = ?1 AND scope = 'stage' AND resulting_state = 'failed'
                AND (stage_id LIKE '%#bound-halt-%' OR stage_id LIKE '%#budget-halt'
                     OR stage_id LIKE '%#metering-halt')
              ORDER BY seq",
        )
        .unwrap()
        .query_map([execution.to_bytes().as_slice()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .unwrap()
        .map(|row| {
            let (stage, payload) = row.unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            (
                stage,
                payload["reason"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

/// 600 micro-USD, authoritative, and no token count — a cost bill.
fn billed_micro_usd(micro_usd: u64) -> serde_json::Value {
    serde_json::json!({
        "cost": {"quality": "authoritative", "micro_usd": micro_usd},
        "cost_micro_usd": micro_usd,
    })
}

/// `input` recorded tokens (and a 1-micro-USD cost) — a token bill.
fn billed_tokens(input: u64) -> serde_json::Value {
    serde_json::json!({
        "input": input,
        "cost": {"quality": "authoritative", "micro_usd": 1},
        "cost_micro_usd": 1,
    })
}

/// **A WORKFLOW-scope bound counts a `loop(..)` member's completed turn at its own frame,
/// and the walk-away it trips stops the loop.** The resolution loop runs under a
/// workflow `bounds = [..]` (no loop bound), with `after` behind the gate. The worker's
/// first completion bills 600 micro-USD against `cost_bound(0.0005)` (on_exhaustion
/// `accept`), or 110 tokens against `token_bound(100)` (`fail`): its fold trips the
/// workflow bound — the raw `worker#bound-halt-<kind>` row names the total and the
/// limit — and the loop dispatches nothing more: the gate never runs, the record is
/// `Exhausted{1, <on_exhaustion>}` with one member, `after` never runs and the run
/// fails on the walk-away.
///
/// **Would red if:** the member frame were not charged (the tokens lane's probe: no
/// halt row, the gate's `promote` approves and `after` runs), or a pending loop kept
/// dispatching past a walk-away (the halt row lands, but the gate runs and the loop
/// approves).
#[tokio::test(flavor = "current_thread")]
async fn a_workflow_bound_counts_a_loop_members_completed_turn_and_stops_the_loop() {
    use kata_program::execution_program::expansion::{ExpansionOnMax, ExpansionResolution};
    let mut wrong = Vec::new();
    for (bound, usage, on_exhaustion, on_max, halt, reason) in [
        (
            "cost_bound(0.0005)",
            billed_micro_usd(600),
            "accept",
            ExpansionOnMax::Accept,
            "worker#bound-halt-cost",
            "bound_exceeded: workflow cost bound reached 600 micro-USD (limit: 500 micro-USD)",
        ),
        (
            "token_bound(100)",
            billed_tokens(110),
            "fail",
            ExpansionOnMax::Fail,
            "worker#bound-halt-tokens",
            "bound_exceeded: workflow tokens bound reached 110 tokens (limit: 100 tokens)",
        ),
    ] {
        let source = resolution_pack(3, on_exhaustion).replace(
            "workflow(\"resolution-loop\", root = [worker, controller])",
            &format!(
                "after = stage(id = \"after\", agent = \"shell\", run = \"true\", \
                 depends_on = [\"controller\"])\n\n\
                 workflow(\"resolution-loop\", root = [worker, controller, after], \
                 bounds = [{bound}])"
            ),
        );
        let program =
            compile_starlark_execution_program(&source, "workflow-bounded-loop.star", &[])
                .expect("the workflow-bounded loop compiles under oci");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let expansion = expansion(&program);
        let reactor = reactor(&rig);
        let mut frames = Vec::new();
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        let stdout = match stage_id.as_str() {
                            "worker" => "{\"stage\":\"w\",\"marker\":0}",
                            "controller" => "{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                            _ => "after ran",
                        };
                        complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                        if frames.is_empty() {
                            tamper_completion_usage(&rig, frame.attempt_id, &usage);
                        }
                        frames.push(stage_id);
                    }
                }
            }
        })
        .await
        .expect("the drive settles within the budget");
        let rows = walkaway_rows(&rig, execution);
        let record = expansion_record(&rig, execution, &expansion);
        let stopped = matches!(
            record.as_ref().map(|record| (&record.resolution, record.members.len())),
            Some((ExpansionResolution::Exhausted { iterations: 1, on_max: got }, 1)) if *got == on_max
        );
        let halted = rows.len() == 1 && rows[0].0 == halt && rows[0].1.starts_with(reason);
        let failed = outcome
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains(halt));
        if !(stopped && halted && failed && frames == ["worker"]) {
            wrong.push(format!(
                "{bound}: frames {frames:?}, walk-away rows {rows:?}, record {:?}, the run {}",
                record.map(|record| (record.resolution, record.members.len())),
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// **A run walk-away releases nothing behind a pending loop's gate, under every
/// `on_exhaustion`.** `x`, a shell stage that is upstream of nothing in the loop, bills 600
/// micro-USD against its own `cost_budget("halt", 0.0005)`; `after` depends on the gate
/// `controller` directly. `x`'s frame is dispatched first and its fold trips the budget (the raw
/// `x#budget-halt` row, a walk-away of the run) before the loop dispatches its gate — before its
/// worker, too, when the loop's first drive comes after that fold — so the loop resolves
/// `Exhausted{0, <on_exhaustion>}` with no member, or `Exhausted{1, ..}` with the worker alone.
/// Either way `after` (raw `attempts`) never dispatches, under `accept`, under `fail`, and under
/// `escalate` once the operator approves the parked gate. The run fails on the walk-away. The
/// halt is `x`'s own budget, not a workflow bound, because a workflow bound re-trips on the
/// worker's later completion and skips the gate's dependents itself, which would hide the
/// apply's answer whenever the worker ran.
///
/// **Would red if:** a walk-away exhaustion under `accept`, or an adopted `escalate`,
/// completed the gate and left its dependents to the DAG (`after` dispatches after the run
/// walked away, on a candidate no gate judged).
#[tokio::test(flavor = "current_thread")]
async fn a_walk_away_exhaustion_dispatches_no_stage_behind_the_gate() {
    use kata_program::execution_program::expansion::{ExpansionOnMax, ExpansionResolution};
    let mut wrong = Vec::new();
    for (on_exhaustion, on_max) in [
        ("accept", ExpansionOnMax::Accept),
        ("fail", ExpansionOnMax::Fail),
        ("escalate", ExpansionOnMax::Escalate),
    ] {
        let source = resolution_pack(3, on_exhaustion).replace(
            "workflow(\"resolution-loop\", root = [worker, controller])",
            "x = stage(id = \"x\", agent = \"shell\", run = \"true\", \
             cost_budget = cost_budget(\"halt\", 0.0005))\n\n\
             after = stage(id = \"after\", agent = \"shell\", run = \"true\", \
             depends_on = [\"controller\"])\n\n\
             workflow(\"resolution-loop\", root = [x, worker, controller, after])",
        );
        let program = compile_starlark_execution_program(&source, "walk-away-gate.star", &[])
            .expect("the walk-away loop compiles under oci");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let expansion = expansion(&program);
        let reactor = reactor(&rig);
        let mut frames = Vec::new();
        let mut approved = false;
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        let stdout = match stage_id.as_str() {
                            "worker" => "{\"stage\":\"w\",\"marker\":0}",
                            "controller" => "{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                            _ => "ran",
                        };
                        complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                        if stage_id == "x" {
                            tamper_completion_usage(&rig, frame.attempt_id, &billed_micro_usd(600));
                        }
                        frames.push(stage_id);
                    }
                    () = tokio::time::sleep(std::time::Duration::from_millis(50)), if !approved => {
                        let gates = rig
                            .dispatcher
                            .parked_approval_gates()
                            .expect("the operator's gate list reads");
                        if let Some(gate) = gates.into_iter().find(|gate| gate.expansion.is_some()) {
                            rig.dispatcher
                                .decide_expansion_gate(
                                    gate.assignment_id,
                                    &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                                    kata_core::operational::ExpansionVerdict::Approve,
                                )
                                .expect("the operator's approve decides the parked gate");
                            approved = true;
                        }
                    }
                }
            }
        })
        .await
        .expect("the drive settles within the budget");
        let rows = walkaway_rows(&rig, execution);
        let record = expansion_record(&rig, execution, &expansion);
        let after_attempts: i64 = raw(&rig.op_path)
            .query_row(
                "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'after'",
                [execution.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("the dependent's attempts count");
        // The gate never runs: the loop stopped before it, at its worker or at its gate.
        let stopped = match record
            .as_ref()
            .map(|record| (&record.resolution, record.members.len()))
        {
            Some((
                ExpansionResolution::Exhausted {
                    iterations,
                    on_max: got,
                },
                members,
            )) if *got == on_max => {
                let (iterations, members) = (*iterations, members);
                (iterations, members) == (0, 0) && frames == ["x"]
                    || (iterations, members) == (1, 1) && frames == ["x", "worker"]
            }
            _ => false,
        };
        let halted = rows.len() == 1 && rows[0].0 == "x#budget-halt";
        let failed = outcome
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains("x#budget-halt"));
        let parked_as_authored = approved == (on_max == ExpansionOnMax::Escalate);
        if !(stopped && halted && failed && parked_as_authored && after_attempts == 0) {
            wrong.push(format!(
                "{on_exhaustion}: frames {frames:?}, walk-away rows {rows:?}, record {:?}, \
                 parked {approved}, `after` dispatched {after_attempts} time(s), the run {}",
                record.map(|record| (record.resolution, record.members.len())),
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// **A run walk-away stops a pending loop at a structured-output RETRY seat.** The worker's
/// first completion fails its declared outputs and bills 600 micro-USD against the workflow
/// `cost_bound(0.0005)`: charged at its own frame, the rejected turn trips the bound (the raw
/// `worker#bound-halt-cost` row), and the loop's next dispatch point is the worker's retry
/// seat `child(1)`. The retry never dispatches: the record is `Exhausted{1, accept}` with no
/// member (none was accepted valid), the worker ran once, and the run fails on the walk-away.
///
/// **Would red if:** the retry seat dispatched without consulting the walk-away (a second
/// `worker` frame, and a member the record then accepts).
#[tokio::test(flavor = "current_thread")]
async fn a_walk_away_stops_a_loop_at_its_members_retry_seat() {
    use kata_program::execution_program::expansion::{ExpansionOnMax, ExpansionResolution};
    let source = resolution_pack(3, "accept").replace(
        "workflow(\"resolution-loop\", root = [worker, controller])",
        "workflow(\"resolution-loop\", root = [worker, controller], \
         bounds = [cost_bound(0.0005)])",
    );
    let program = compile_starlark_execution_program(&source, "walk-away-retry.star", &[])
        .expect("the bounded loop compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let first = frames.is_empty();
                    let stdout: &[u8] = match (stage_id.as_str(), first) {
                        ("worker", true) => b"{\"wrong\":true}",
                        ("worker", false) => b"{\"stage\":\"w\",\"marker\":0}",
                        _ => b"{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                    };
                    complete_frame(&rig, &reactor, &frame, stdout);
                    if first {
                        tamper_completion_usage(&rig, frame.attempt_id, &billed_micro_usd(600));
                    }
                    frames.push(stage_id);
                }
            }
        }
    })
    .await
    .expect("the drive settles within the budget");
    let rows = walkaway_rows(&rig, execution);
    let record = expansion_record(&rig, execution, &expansion);
    let stopped = matches!(
        record
            .as_ref()
            .map(|record| (&record.resolution, record.members.len())),
        Some((
            ExpansionResolution::Exhausted {
                iterations: 1,
                on_max: ExpansionOnMax::Accept,
            },
            0
        ))
    );
    let halted = rows.len() == 1 && rows[0].0 == "worker#bound-halt-cost";
    let failed = outcome
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("worker#bound-halt-cost"));
    assert!(
        stopped && halted && failed && frames == ["worker"],
        "frames {frames:?}, walk-away rows {rows:?}, record {:?}, the run {}",
        record.map(|record| (record.resolution, record.members.len())),
        match &outcome {
            Ok(_) => "completed".to_owned(),
            Err(error) => format!("failed: {error}"),
        }
    );
}

/// **A run walk-away stops a pending loop before a member that is a NESTED topology.** The
/// loop-topology pack runs under the workflow `cost_bound(0.0005)`; iteration 0's `implement`
/// root is held until both its children have dispatched, then bills 600 micro-USD, which
/// trips the bound at its own frame (the raw `implement#bound-halt-cost` row). Every member
/// of the body topology already ran, so it settles, and the loop's next dispatch point is its
/// gate `review` — a static topology not yet minted. It is never claimed: no `review` root or
/// reviewer frame runs, the record is `Exhausted{1, fail}` with the body member alone, and
/// the run fails on the walk-away.
///
/// **Would red if:** an unminted nested-topology member dispatched without consulting the
/// walk-away (the `review` root and its reviewers run).
#[tokio::test(flavor = "current_thread")]
async fn a_walk_away_stops_a_loop_before_a_nested_topology_member() {
    use kata_program::execution_program::expansion::{ExpansionOnMax, ExpansionResolution};
    let source = LOOP_TOPOLOGY_PACK.replace(
        "    root = [implement, review, after],\n)",
        "    root = [implement, review, after],\n    bounds = [cost_bound(0.0005)],\n)",
    );
    assert_ne!(
        source, LOOP_TOPOLOGY_PACK,
        "the bound is spliced into the workflow"
    );
    let program = topology_program(&source, "loop-topology-walk-away.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let loop_expansion = expansion(&program);
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let mut held_root = None;
    let mut children = 0usize;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let stdout: &[u8] = if stage_id.starts_with("review") {
                        b"{\"verdict\":\"approve\",\"feedback\":\"ok\"}"
                    } else {
                        b"{\"note\":\"ok\"}"
                    };
                    frames.push(stage_id.clone());
                    if stage_id == "implement" && held_root.is_none() {
                        held_root = Some(frame);
                    } else {
                        complete_frame(&rig, &reactor, &frame, stdout);
                        children += usize::from(stage_id.starts_with("implement#child-"));
                    }
                }
            }
            // The root bills once both children dispatched: no body member is left unminted.
            if children == 2
                && let Some(root) = held_root.take()
            {
                complete_frame(&rig, &reactor, &root, b"{\"note\":\"ok\"}");
                tamper_completion_usage(&rig, root.attempt_id, &billed_micro_usd(600));
            }
        }
    })
    .await
    .expect("the loop-topology drive settles within the budget");
    let rows = walkaway_rows(&rig, execution);
    let record = expansion_record(&rig, execution, &loop_expansion);
    let stopped = matches!(
        record
            .as_ref()
            .map(|record| (&record.resolution, record.members.len())),
        Some((
            ExpansionResolution::Exhausted {
                iterations: 1,
                on_max: ExpansionOnMax::Fail,
            },
            1
        ))
    );
    let halted = rows.len() == 1 && rows[0].0 == "implement#bound-halt-cost";
    let failed = outcome
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("implement#bound-halt-cost"));
    let mut body = frames.clone();
    body.sort();
    assert!(
        stopped
            && halted
            && failed
            && body == ["implement", "implement#child-w1", "implement#child-w2"],
        "frames {frames:?}, walk-away rows {rows:?}, record {:?}, the run {}",
        record.map(|record| (record.resolution, record.members.len())),
        match &outcome {
            Ok(_) => "completed".to_owned(),
            Err(error) => format!("failed: {error}"),
        }
    );
}

/// `token_usage` that states a cost kata could not measure — the bill a hard cost policy
/// halts closed on.
fn billed_unmeasurable() -> serde_json::Value {
    serde_json::json!({
        "input": 50,
        "cost": {"quality": "unavailable", "backend": "nanocode_openai", "model": "m"},
    })
}

/// The walk-away halts a run's metrics counted, read off `snapshotter`'s recorder: every
/// `kata_workflow_bound_exceeded_total` and `kata_workflow_metering_halt_total` increment,
/// and `kata_workflow_budget_exceeded_total`'s under `mode = "halt"` (its `warn` mode is no
/// halt).
fn walk_away_metric_count(snapshotter: &metrics_util::debugging::Snapshotter) -> u64 {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            let key = key.key();
            let halt = match key.name() {
                "kata_workflow_bound_exceeded_total" | "kata_workflow_metering_halt_total" => true,
                "kata_workflow_budget_exceeded_total" => key
                    .labels()
                    .any(|label| label.key() == "mode" && label.value() == "halt"),
                _ => false,
            };
            match value {
                metrics_util::debugging::DebugValue::Counter(count) if halt => Some(count),
                _ => None,
            }
        })
        .sum()
}

/// THE UNIFORM WALK-AWAY pack: `x` and `y` are independent roots and `z` depends on `y`
/// alone, so only a walk-away can keep `z` from running once `y` completes. `workflow` and
/// `x` take the leg's limit.
fn uniform_walk_away_pack(workflow_kwargs: &str, x_kwargs: &str) -> String {
    format!(
        "x = stage(id = \"x\", agent = \"shell\", run = \"true\"{x_kwargs})\n\n\
         y = stage(id = \"y\", agent = \"shell\", run = \"true\")\n\n\
         z = stage(id = \"z\", agent = \"shell\", run = \"true\", depends_on = [\"y\"])\n\n\
         workflow(\"uniform-walk-away\", root = [x, y, z]{workflow_kwargs})\n"
    )
}

/// **ONE WALK-AWAY, WHATEVER ITS KIND: no stage completing after the walk-away releases its
/// dependents, and no second walk-away row is written.** `x` and `y` dispatch together; the
/// stub completes `x` with the leg's bill and `y` (the last leg billing `y` a cost kata
/// cannot measure) either once the raw `transitions` table holds `x`'s walk-away row — `y`'s
/// completion then lands on the chain after the row — or in the same turn as `x`'s, before
/// the runner folds either — committed before the row, `y`'s completion is folded after the
/// trip at `x`'s frame. `z`, behind `y` alone, never dispatches — zero rows in the raw
/// `attempts` table — either way, under each kind of walk-away: a workflow `cost_bound`,
/// `token_bound` and `time_bound` (`x#bound-halt-<kind>`), `x`'s own halting `cost_budget`
/// and the workflow's (`x#budget-halt`), and a metering halt on `x`'s unmeasurable cost or
/// uncounted tokens (`x#metering-halt`). Every leg records exactly ONE walk-away row — `x`'s
/// — though `y`'s completion re-crosses the workflow budget, and in the last leg trips a
/// metering halt of its own, after the run walked away — and the run's walk-away metrics
/// (`kata_workflow_bound_exceeded_total`, `kata_workflow_metering_halt_total` and the halt
/// mode of `kata_workflow_budget_exceeded_total`, read off a recorder installed for the leg)
/// count exactly that one. The run fails naming that row.
///
/// **Would red if:** a completion after the walk-away were checked only for a trip of its
/// own (`z` runs behind the stage budget and both metering legs, whose limits `y` does not
/// cross); the fold learned of the walk-away only from the row's own frame (`z` runs there
/// when `y` completes in `x`'s turn); a later trip wrote its own row (`y#budget-halt`
/// under the workflow budget, `y#metering-halt` after the cost bound); or a later trip were
/// acted on though the persist wrote nothing for it (a second walk-away metric).
#[tokio::test(flavor = "current_thread")]
async fn no_stage_completing_after_any_walk_away_releases_its_dependents() {
    kata_types::node_profile::mark_node_installed();
    let legs = [
        (
            "cost_bound",
            ", bounds = [cost_bound(0.0005)]",
            "",
            Some(billed_micro_usd(600)),
            None,
            "x#bound-halt-cost",
        ),
        (
            "token_bound",
            ", bounds = [token_bound(100)]",
            "",
            Some(billed_tokens(110)),
            None,
            "x#bound-halt-tokens",
        ),
        (
            "time_bound",
            ", bounds = [time_bound(10)]",
            "",
            None,
            None,
            "x#bound-halt-time",
        ),
        (
            "x's halting cost_budget",
            "",
            ", cost_budget = cost_budget(\"halt\", 0.0005)",
            Some(billed_micro_usd(600)),
            None,
            "x#budget-halt",
        ),
        (
            "the workflow's halting cost_budget",
            ", cost_budget = cost_budget(\"halt\", 0.0005)",
            "",
            Some(billed_micro_usd(600)),
            None,
            "x#budget-halt",
        ),
        (
            "a metering halt on an unmeasurable cost",
            ", bounds = [cost_bound(5.0)]",
            "",
            Some(billed_unmeasurable()),
            None,
            "x#metering-halt",
        ),
        (
            "a metering halt on an uncounted token total",
            ", bounds = [token_bound(1000)]",
            "",
            Some(billed_micro_usd(1)),
            None,
            "x#metering-halt",
        ),
        (
            "a cost_bound, then an unmeasurable completion",
            ", bounds = [cost_bound(0.0005)]",
            "",
            Some(billed_micro_usd(600)),
            Some(billed_unmeasurable()),
            "x#bound-halt-cost",
        ),
    ];
    let mut wrong = Vec::new();
    for together in [false, true] {
        for (leg, workflow_kwargs, x_kwargs, x_bill, y_bill, halt) in legs.clone() {
            let leg = if together {
                format!("{leg}, `y` completed in `x`'s turn")
            } else {
                format!("{leg}, `y` completed after the row")
            };
            let source = uniform_walk_away_pack(workflow_kwargs, x_kwargs);
            let program =
                compile_starlark_execution_program(&source, "uniform-walk-away.star", &[])
                    .unwrap_or_else(|error| {
                        panic!("{leg}: the pack compiles under oci: {error:?}")
                    });
            let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
            rig.declare_bound_environment();
            let execution = Ulid::new();
            let runner = rig.runner(&program, execution);
            let reactor = reactor(&rig);
            // The current-thread runtime folds on this thread, so the leg's recorder sees
            // every metric the runner emits.
            let recorder = metrics_util::debugging::DebuggingRecorder::new();
            let snapshotter = recorder.snapshotter();
            let recording = metrics::set_default_local_recorder(&recorder);
            let mut frames = Vec::new();
            let mut held_x = None;
            let mut held_y = None;
            let complete = |frame: &kata_transport::types::CapsuleAssignment,
                            bill: &Option<serde_json::Value>| {
                complete_frame(&rig, &reactor, frame, b"ran");
                if let Some(bill) = bill {
                    tamper_completion_usage(&rig, frame.attempt_id, bill);
                }
            };
            let run = runner.run();
            tokio::pin!(run);
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
                loop {
                    tokio::select! {
                        outcome = &mut run => break outcome,
                        frame = next_frame(&rig) => {
                            let stage_id = frame_stage_id(&rig, &frame);
                            match stage_id.as_str() {
                                "x" => held_x = Some(frame),
                                "y" => held_y = Some(frame),
                                _ => complete_frame(&rig, &reactor, &frame, b"ran"),
                            }
                            frames.push(stage_id);
                        }
                        () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
                    }
                    // `x` once both have dispatched — past the time leg's 10 ms bound —
                    // and `y` in the same turn, or once `x`'s row is durable.
                    if held_x.is_some() && held_y.is_some() {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        complete(&held_x.take().expect("x is held"), &x_bill);
                        if together {
                            complete(&held_y.take().expect("y is held"), &y_bill);
                        }
                    } else if held_x.is_none()
                        && held_y.is_some()
                        && !walkaway_rows(&rig, execution).is_empty()
                    {
                        complete(&held_y.take().expect("y is held"), &y_bill);
                    }
                }
            })
            .await
            .expect("the drive settles within the budget");
            drop(recording);
            let metrics = walk_away_metric_count(&snapshotter);
            let rows = walkaway_rows(&rig, execution);
            let z_attempts: i64 = raw(&rig.op_path)
                .query_row(
                    "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'z'",
                    [execution.to_bytes().as_slice()],
                    |row| row.get(0),
                )
                .expect("z's attempts count");
            let failed = outcome
                .as_ref()
                .err()
                .is_some_and(|error| error.to_string().contains(halt));
            let row_names: Vec<&str> = rows.iter().map(|(stage, _)| stage.as_str()).collect();
            if !(row_names == [halt] && z_attempts == 0 && metrics == 1 && failed) {
                wrong.push(format!(
                    "{leg}: frames {frames:?}, walk-away rows {row_names:?}, `z` dispatched \
                     {z_attempts} time(s), {metrics} walk-away metric(s), the run {}",
                    match &outcome {
                        Ok(_) => "completed".to_owned(),
                        Err(error) => format!("failed: {error}"),
                    }
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The raw `attempts` rows `stage` holds in `execution` — what a dispatch, a park or a claim
/// at the stage's own name writes.
fn stage_attempts(rig: &OciNodeRig, execution: Ulid, stage: &str) -> i64 {
    raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
            rusqlite::params![execution.to_bytes().as_slice(), stage],
            |row| row.get(0),
        )
        .expect("the stage's attempts count")
}

/// **NO STAGE STARTS AFTER A WALK-AWAY, whatever released it.** Each leg's tripping stage
/// bills 600 micro-USD against a 500 micro-USD halt, and the stage behind it in the leg is
/// one the walk-away did not skip at a terminal: an independent `w` the workflow's
/// `max_concurrency = 1` held `Pending` while `a` ran (`a`'s own halting `cost_budget`), and
/// `z` — a shell stage, then a `sleep()` — released by `y`'s completion in the same turn as
/// `x`'s, `y` first, so `y` folds before the trip and releases it (a workflow `cost_bound`).
/// Once the walk-away row is durable that stage never starts: zero rows in the raw `attempts`
/// table (a capsule's dispatch and a timer's park each write one), the walk-away rows are
/// exactly the tripping stage's, and the run fails naming it.
///
/// **Would red if:** the ready-advance promoted a stage after the walk-away (`w` and `z`
/// dispatch, `nap` parks its timer), or only the capsule submit consulted the walk-away
/// (`nap` parks).
#[tokio::test(flavor = "current_thread")]
async fn no_stage_starts_after_a_walk_away() {
    kata_types::node_profile::mark_node_installed();
    let throttled = "a = stage(id = \"a\", agent = \"shell\", run = \"true\", \
                     cost_budget = cost_budget(\"halt\", 0.0005))\n\n\
                     w = stage(id = \"w\", agent = \"shell\", run = \"true\")\n\n\
                     workflow(\"throttled-walk-away\", root = [a, w], max_concurrency = 1)\n"
        .to_owned();
    let released = uniform_walk_away_pack(", bounds = [cost_bound(0.0005)]", "");
    let slept = released
        .replace(
            "z = stage(id = \"z\", agent = \"shell\", run = \"true\", depends_on = [\"y\"])",
            "z = sleep(id = \"z\", for_ms = 1, depends_on = [\"y\"])",
        )
        .replace("root = [x, y, z]", "root = [x, y]");
    assert!(
        slept.contains("z = sleep(") && slept.contains("root = [x, y]"),
        "the sleep leg's `z` is a `sleep()`: {slept}"
    );
    let mut wrong = Vec::new();
    // (leg, pack, the stages held until all dispatched and then completed in this order,
    // the tripping stage, the stage behind the walk-away, its walk-away row)
    for (leg, source, order, tripping, behind, halt) in [
        (
            "an independent stage the throttle held",
            throttled,
            vec!["a"],
            "a",
            "w",
            "a#budget-halt",
        ),
        (
            "a shell stage released in the walk-away's turn",
            released,
            vec!["y", "x"],
            "x",
            "z",
            "x#bound-halt-cost",
        ),
        (
            "a sleep released in the walk-away's turn",
            slept,
            vec!["y", "x"],
            "x",
            "z",
            "x#bound-halt-cost",
        ),
    ] {
        let program = compile_starlark_execution_program(&source, "no-start.star", &[])
            .unwrap_or_else(|error| panic!("{leg}: the pack compiles under oci: {error:?}"));
        assert!(
            program
                .stages
                .keys()
                .any(|stage| stage.0.as_str() == behind),
            "{leg}: `{behind}` is a stage of the program"
        );
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let mut frames = Vec::new();
        let mut held = std::collections::BTreeMap::new();
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break Some(outcome),
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        if order.contains(&stage_id.as_str()) {
                            held.insert(stage_id.clone(), frame);
                        } else {
                            complete_frame(&rig, &reactor, &frame, b"ran");
                        }
                        frames.push(stage_id);
                    }
                    () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
                }
                if !held.is_empty() && held.len() == order.len() {
                    for stage in &order {
                        let frame = held.remove(*stage).expect("every ordered stage is held");
                        complete_frame(&rig, &reactor, &frame, b"ran");
                        if *stage == tripping {
                            tamper_completion_usage(&rig, frame.attempt_id, &billed_micro_usd(600));
                        }
                    }
                }
                // A timer the rig never sweeps holds the run open: its park is the answer.
                if stage_attempts(&rig, execution, behind) > 0 && held.is_empty() {
                    break None;
                }
            }
        })
        .await
        .expect("the drive settles within the budget");
        let rows: Vec<String> = walkaway_rows(&rig, execution)
            .into_iter()
            .map(|(stage, _)| stage)
            .collect();
        let behind_attempts = stage_attempts(&rig, execution, behind);
        let failed = outcome
            .as_ref()
            .and_then(|outcome| outcome.as_ref().err())
            .is_some_and(|error| error.to_string().contains(halt));
        if !(behind_attempts == 0 && rows == [halt] && failed) {
            wrong.push(format!(
                "{leg}: frames {frames:?}, `{behind}` started {behind_attempts} time(s), \
                 walk-away rows {rows:?}, the run {}",
                match &outcome {
                    None => "still running".to_owned(),
                    Some(Ok(_)) => "completed".to_owned(),
                    Some(Err(error)) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// **A run that ends STUCK names its walk-away.** `f` exits non-zero and fails, leaving
/// `g`, behind it alone, `Pending`; then `x`, independent of both, bills 600 micro-USD against
/// the workflow's `cost_bound(0.0005)` and walks the run away (the raw `x#bound-halt-cost`
/// row). Nothing is ready or in flight and `g` can never run, so the drive ends through its
/// stuck verdict, and that verdict names the walk-away row beside `f`'s failure — the same
/// two scans the finished-run verdict makes. `g` holds no row in the raw `attempts` table.
///
/// **Would red if:** the stuck verdict were built from the DAG's failed stages alone (it
/// names `f` and not `x#bound-halt-cost`).
#[tokio::test(flavor = "current_thread")]
async fn a_stuck_run_names_its_walk_away_beside_its_failed_stage() {
    kata_types::node_profile::mark_node_installed();
    let source = "f = stage(id = \"f\", agent = \"shell\", run = \"false\")\n\n\
                  g = stage(id = \"g\", agent = \"shell\", run = \"true\", depends_on = [\"f\"])\n\n\
                  x = stage(id = \"x\", agent = \"shell\", run = \"true\")\n\n\
                  workflow(\"stuck-walk-away\", root = [f, g, x], bounds = [cost_bound(0.0005)])\n";
    let program = compile_starlark_execution_program(source, "stuck-walk-away.star", &[])
        .unwrap_or_else(|error| panic!("the pack compiles under oci: {error:?}"));
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let mut held_x = None;
    let mut f_failed = false;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    match stage_id.as_str() {
                        "f" => {
                            reactor
                                .handle_message_for_test(
                                    kata_transport::types::WorkerMessage::CompletedCapsule {
                                        attempt_id: frame.attempt_id,
                                        fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                                        result: publish_result(&rig),
                                        work_delta: kata_workflow::test_harness::stub_work_delta(
                                            &rig.db,
                                            &rig.cas,
                                            frame.occurrence_id,
                                        ),
                                        exit_code: Some(1),
                                        stdout: publish_capture(&rig, b""),
                                        stderr: publish_capture(&rig, b"f exited 1"),
                                        capture_exceeded: false,
                                        agent: None,
                                        provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                                            "stuck walk-away cell",
                                        ),
                                        egress_refusals: vec![],
                                    },
                                )
                                .expect("f's exit failure is adjudicated");
                            f_failed = true;
                        }
                        "x" => held_x = Some(frame),
                        _ => complete_frame(&rig, &reactor, &frame, b"ran"),
                    }
                    frames.push(stage_id);
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
            }
            // `x` trips only once `f` has failed, so the walk-away comes second.
            if f_failed && let Some(frame) = held_x.take() {
                complete_frame(&rig, &reactor, &frame, b"ran");
                tamper_completion_usage(&rig, frame.attempt_id, &billed_micro_usd(600));
            }
        }
    })
    .await
    .expect("the drive settles within the budget");
    let rows: Vec<String> = walkaway_rows(&rig, execution)
        .into_iter()
        .map(|(stage, _)| stage)
        .collect();
    assert_eq!(rows, ["x#bound-halt-cost"], "frames {frames:?}");
    assert_eq!(
        stage_attempts(&rig, execution, "g"),
        0,
        "`g` never dispatches"
    );
    let error = outcome.expect_err("a stuck run fails").to_string();
    assert!(
        error.contains("workflow stuck after") && error.contains("x#bound-halt-cost"),
        "the stuck verdict names the walk-away row: {error}"
    );
    assert!(
        error.contains("\"f\"") || error.contains("f exited 1") || error.contains("stage f"),
        "the stuck verdict still names the failed stage: {error}"
    );
}

/// **A plain stage's structured-output retry seat dispatches nothing after a walk-away.**
/// `x`, upstream of nothing, bills 600 micro-USD against its own `cost_budget("halt",
/// 0.0005)` (the raw `x#budget-halt` row); `probe`, whose `outputs` contract admits a retry,
/// answers its first attempt with output that fails it — once the row is durable, or in
/// `x`'s turn before `x`, so the fold queues the retry before the trip. Either way the retry
/// is never dispatched: `probe` holds exactly one row in the raw `attempts` table, `after`,
/// behind it, none, the walk-away rows are exactly `x`'s, and the run fails naming the row
/// and `probe`'s failure, which says the run walked away.
///
/// **Would red if:** the validation-retry drain dispatched a queued retry without consulting
/// the durable walk-away (`probe` runs a second attempt), or only the fold consulted it
/// (the retry queued before the trip dispatches).
#[tokio::test(flavor = "current_thread")]
async fn a_plain_stages_validation_retry_dispatches_nothing_after_a_walk_away() {
    kata_types::node_profile::mark_node_installed();
    let source = format!(
        "x = stage(id = \"x\", agent = \"shell\", run = \"true\", \
         cost_budget = cost_budget(\"halt\", 0.0005))\n\n{VALIDATE_PLAIN_PACK}"
    )
    .replace("root = [probe, after]", "root = [x, probe, after]");
    assert!(
        source.contains("root = [x, probe, after]"),
        "`x` is spliced into the root list: {source}"
    );
    let program = compile_starlark_execution_program(&source, "walk-away-retry.star", &[])
        .expect("the pack compiles under oci");
    let mut wrong = Vec::new();
    for together in [false, true] {
        let leg = if together {
            "rejected in `x`'s turn, before it"
        } else {
            "rejected after the row"
        };
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let mut frames = Vec::new();
        let mut held_x = None;
        let mut held_probe = None;
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        match stage_id.as_str() {
                            "x" => held_x = Some(frame),
                            "probe" if !frames.iter().any(|seen| seen == "probe") => {
                                held_probe = Some(frame);
                            }
                            // A retry, when one dispatches, passes the contract.
                            _ => complete_frame(&rig, &reactor, &frame, b"{\"ok\": true}"),
                        }
                        frames.push(stage_id);
                    }
                    () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
                }
                if held_probe.is_some()
                    && let Some(x) = held_x.take()
                {
                    if together {
                        let probe = held_probe.take().expect("probe is held");
                        complete_frame(&rig, &reactor, &probe, b"not the declared outputs");
                    }
                    complete_frame(&rig, &reactor, &x, b"x ran");
                    tamper_completion_usage(&rig, x.attempt_id, &billed_micro_usd(600));
                } else if held_x.is_none()
                    && !walkaway_rows(&rig, execution).is_empty()
                    && let Some(probe) = held_probe.take()
                {
                    complete_frame(&rig, &reactor, &probe, b"not the declared outputs");
                }
            }
        })
        .await
        .expect("the drive settles within the budget");
        let rows: Vec<String> = walkaway_rows(&rig, execution)
            .into_iter()
            .map(|(stage, _)| stage)
            .collect();
        let probe_attempts = stage_attempts(&rig, execution, "probe");
        let after_attempts = stage_attempts(&rig, execution, "after");
        let failed = outcome.as_ref().err().is_some_and(|error| {
            let error = error.to_string();
            error.contains("x#budget-halt")
                && error.contains("\"probe\" failed")
                && error.contains("walked away")
        });
        if !(probe_attempts == 1 && after_attempts == 0 && rows == ["x#budget-halt"] && failed) {
            wrong.push(format!(
                "{leg}: frames {frames:?}, `probe` ran {probe_attempts} attempt(s), `after` \
                 {after_attempts}, walk-away rows {rows:?}, the run {}",
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// **An expansion whose record applies after the walk-away releases nothing.** `x`, upstream
/// of nothing, bills 600 micro-USD against its own `cost_budget("halt", 0.0005)`. The stub
/// completes an expansion's LAST member and `x` in one turn, the member first: the member's
/// frame folds before the walk-away and charges nothing past it, `x`'s trips it (the raw
/// `x#budget-halt` row), and the expansion's record — decided over members that all ran
/// before the walk-away — applies after it. A static `topology` settles and `successor`,
/// behind it, never dispatches; a loop whose gate approves completes its worker and gate,
/// and neither `after` (behind the gate) nor `side` (behind the worker) dispatches; a loop
/// whose gate refines its last iteration under `escalate` parks, the operator approves, and
/// neither `after` nor `side` dispatches; and a loop whose worker FAILS after its body's
/// `plan` completed aborts, and `notes`, behind `plan`, never dispatches — zero rows each in
/// the raw `attempts` table, the run failed naming `x#budget-halt`.
///
/// **Would red if:** a settled topology's or a loop record's completions — an abort's
/// completed body members included — released their dependents as the DAG says, the
/// walk-away notwithstanding (`successor`, `after`, `side`, `notes` run).
#[tokio::test(flavor = "current_thread")]
async fn an_expansion_record_applied_after_the_walk_away_releases_nothing() {
    kata_types::node_profile::mark_node_installed();
    let x_stage = "x = stage(id = \"x\", agent = \"shell\", run = \"true\", \
                   cost_budget = cost_budget(\"halt\", 0.0005))\n\n";
    let topology = format!("{x_stage}{TOPOLOGY_PACK}").replace(
        "    root = [parent, successor],\n)",
        "    root = [x, parent, successor],\n)",
    );
    let looped = |on_exhaustion: &str, max: u32| {
        resolution_pack(max, on_exhaustion).replace(
            "workflow(\"resolution-loop\", root = [worker, controller])",
            &format!(
                "{x_stage}after = stage(id = \"after\", agent = \"shell\", run = \"true\", \
                 depends_on = [\"controller\"])\n\n\
                 side = stage(id = \"side\", agent = \"shell\", run = \"true\", \
                 depends_on = [\"worker\"])\n\n\
                 workflow(\"resolution-loop\", root = [x, worker, controller, after, side])"
            ),
        )
    };
    let aborted = format!(
        "{x_stage}plan = stage(id = \"plan\", agent = \"shell\", run = \"true\", \
         outputs = {{\"note\": \"string\"}})\n\n\
         notes = stage(id = \"notes\", agent = \"shell\", run = \"true\", \
         depends_on = [\"plan\"])\n\n{}",
        resolution_pack(3, "fail")
            .replace(
                "    agent = \"shell\",\n    outputs = {\n        \"stage\": \"string\",",
                "    agent = \"shell\",\n    depends_on = [\"plan\"],\n    outputs = {\n        \
                 \"stage\": \"string\",",
            )
            .replace("    body = worker,", "    body = sequence(plan, worker),")
            .replace(
                "root = [worker, controller]",
                "root = [x, plan, worker, controller, notes]",
            ),
    );
    assert!(
        aborted.contains("body = sequence(plan, worker)")
            && aborted.contains("depends_on = [\"plan\"],\n    outputs")
            && aborted.contains("root = [x, plan, worker, controller, notes]"),
        "the aborted loop's body is `plan` then `worker`: {aborted}"
    );
    let mut wrong = Vec::new();
    // `None` fails the last member instead of completing it.
    for (leg, source, last_member, last_stdout, behind) in [
        (
            "a settled topology",
            topology,
            "parent#child-second_worker",
            Some("{\"note\":\"ok\"}"),
            vec!["successor"],
        ),
        (
            "an approved loop",
            looped("accept", 3),
            "controller",
            Some("{\"decision\":\"promote\",\"feedback\":\"ship it\"}"),
            vec!["after", "side"],
        ),
        (
            "an escalated loop the operator approves",
            looped("escalate", 1),
            "controller",
            Some("{\"decision\":\"continue\",\"feedback\":\"again\"}"),
            vec!["after", "side"],
        ),
        ("an aborted loop", aborted, "worker", None, vec!["notes"]),
    ] {
        assert!(source.contains("root = [x, "), "{leg}: `x` is spliced in");
        let program =
            compile_starlark_execution_program(&source, "record-after-walk-away.star", &[])
                .unwrap_or_else(|error| panic!("{leg}: the pack compiles under oci: {error:?}"));
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let mut frames = Vec::new();
        let mut held_x = None;
        let mut held_last = None;
        let mut approved = false;
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        if stage_id == "x" {
                            held_x = Some(frame);
                        } else if stage_id == last_member {
                            held_last = Some(frame);
                        } else {
                            let stdout: &[u8] = match stage_id.as_str() {
                                "worker" => b"{\"stage\":\"w\",\"marker\":0}",
                                "parent" | "parent#child-first_worker" | "plan" => {
                                    b"{\"note\":\"ok\"}"
                                }
                                _ => b"ran",
                            };
                            complete_frame(&rig, &reactor, &frame, stdout);
                        }
                        frames.push(stage_id);
                    }
                    () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {
                        if !approved
                            && let Some(gate) = rig
                                .dispatcher
                                .parked_approval_gates()
                                .expect("the operator's gate list reads")
                                .into_iter()
                                .find(|gate| gate.expansion.is_some())
                        {
                            rig.dispatcher
                                .decide_expansion_gate(
                                    gate.assignment_id,
                                    &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                                    kata_core::operational::ExpansionVerdict::Approve,
                                )
                                .expect("the operator's approve decides the parked gate");
                            approved = true;
                        }
                    }
                }
                // The last member first, then `x`, in one turn: one fold applies both.
                if held_x.is_some() && let Some(member) = held_last.take() {
                    match last_stdout {
                        Some(stdout) => complete_frame(&rig, &reactor, &member, stdout.as_bytes()),
                        None => {
                            reactor
                                .handle_message_for_test(
                                    kata_transport::types::WorkerMessage::Failed {
                                        assignment_id: member.attempt_id,
                                        reason: "the worker crashed".to_owned(),
                                        verdict: kata_types::effect::DeliveryFailureProvenance::PerformedButFailed,
                                        provider_failure: None,
                                        usage: None,
                                        fence: kata_transport::types::AttemptFence::echoing_capsule(&member),
                                    },
                                )
                                .expect("the member failure is adjudicated");
                        }
                    }
                    let x = held_x.take().expect("x is held");
                    complete_frame(&rig, &reactor, &x, b"x ran");
                    tamper_completion_usage(&rig, x.attempt_id, &billed_micro_usd(600));
                }
            }
        })
        .await
        .expect("the drive settles within the budget");
        let rows: Vec<String> = walkaway_rows(&rig, execution)
            .into_iter()
            .map(|(stage, _)| stage)
            .collect();
        let dispatched: Vec<(&str, i64)> = behind
            .iter()
            .map(|stage| {
                let count: i64 = raw(&rig.op_path)
                    .query_row(
                        "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
                        rusqlite::params![execution.to_bytes().as_slice(), stage],
                        |row| row.get(0),
                    )
                    .expect("the dependent's attempts count");
                (*stage, count)
            })
            .collect();
        let failed = outcome
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains("x#budget-halt"));
        if !(rows == ["x#budget-halt"] && dispatched.iter().all(|(_, count)| *count == 0) && failed)
        {
            wrong.push(format!(
                "{leg}: frames {frames:?}, walk-away rows {rows:?}, dispatched {dispatched:?}, \
                 approved {approved}, the run {}",
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The `#op` attempt of `expansion` that resolved `failed`, and the reason it records.
fn expansion_failure_reason(
    rig: &OciNodeRig,
    execution: Ulid,
    expansion: &kata_program::execution_program::LoweredOperation,
) -> Option<String> {
    use rusqlite::OptionalExtension;
    let payload: Option<Vec<u8>> = raw(&rig.op_path)
        .query_row(
            "SELECT t.payload_json FROM transitions t
               JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = ?2
                AND t.kind = 'main_resolved' AND t.resulting_state = 'failed'
              ORDER BY t.seq DESC LIMIT 1",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| row.get(0),
        )
        .optional()
        .expect("the expansion's failed resolution reads");
    payload.map(|bytes| {
        serde_json::from_slice::<serde_json::Value>(&bytes).expect("the payload is JSON")["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    })
}

/// **A pending `topology(..)` — static or a dynamic fan-out — dispatches nothing once the
/// run walked away, and fails.** `x`, upstream of nothing, bills 600 micro-USD against its
/// own `cost_budget("halt", 0.0005)` (the raw `x#budget-halt` row). In the first leg the
/// static topology's root parks on its authored `approval` gate — its declared children
/// mint only once it dispatches — `x` trips, and the operator approves the root after the
/// row is durable: the root runs, and the topology's next dispatch point is its children.
/// In the dynamic leg the stub holds the root until the row is durable and completes it
/// with a request for one child — the next dispatch point is that child. In the last leg the
/// static topology stage depends on `pre`, which completes in `x`'s turn, before it: `pre`
/// releases the topology, whose next dispatch point is its root. At each point the topology dispatches nothing — no member
/// frame past what had run — and its `#op` attempt resolves `failed` (raw `transitions`)
/// naming the walk-away row: a topology's only terminals are its settle, which needs every
/// member, and its failure. The topology stage's dependent has zero rows in the raw
/// `attempts` table, the walk-away rows are exactly `x`'s, and the run fails naming it.
///
/// **Would red if:** a topology's dispatch point minted its next members without consulting
/// the durable walk-away (the children, the requested child, or the root dispatch).
#[tokio::test(flavor = "current_thread")]
async fn a_walk_away_stops_a_pending_topology_at_its_next_dispatch_point() {
    kata_types::node_profile::mark_node_installed();
    let x_stage = "x = stage(id = \"x\", agent = \"shell\", run = \"true\", \
                   cost_budget = cost_budget(\"halt\", 0.0005))\n\n";
    let static_pack = format!("{x_stage}{TOPOLOGY_PACK}").replace(
        "    root = [parent, successor],\n)",
        "    root = [x, parent, successor],\n)",
    );
    let gated_pack = format!("{x_stage}{GATED_TOPOLOGY_PACK}")
        .replace(
            "workflow(\n    \"topology-gated-smoke\",",
            "successor = stage(id = \"successor\", agent = \"shell\", run = \"true\", \
             depends_on = [\"parent\"])\n\nworkflow(\n    \"topology-gated-smoke\",",
        )
        .replace(
            "    root = [parent],\n)",
            "    root = [x, parent, successor],\n)",
        );
    assert!(
        gated_pack.contains("successor = stage(")
            && gated_pack.contains("root = [x, parent, successor]"),
        "the gated pack carries `x` and `successor`: {gated_pack}"
    );
    let released_pack =
        format!("pre = stage(id = \"pre\", agent = \"shell\", run = \"true\")\n\n{static_pack}")
            .replace(
                "    id = \"parent\",\n",
                "    id = \"parent\",\n    depends_on = [\"pre\"],\n",
            )
            .replace(
                "root = [x, parent, successor]",
                "root = [pre, x, parent, successor]",
            );
    let dynamic_pack = format!("{x_stage}{DYNAMIC_PACK}").replace(
        "    root = [fan, after],\n)",
        "    root = [x, fan, after],\n)",
    );
    let mut wrong = Vec::new();
    // (leg, pack, topology stage, the stage released with `x`, the root held until the
    // row, the root's answer, the member frames that ran, its dependent, whether the root
    // parks on its gate until the row)
    for (leg, source, stage, with_x, held_root, root_stdout, members, behind, gated) in [
        (
            "a static topology's children",
            gated_pack,
            "parent",
            None,
            None,
            "",
            vec!["parent"],
            "successor",
            true,
        ),
        (
            "a dynamic fan-out's requested child",
            dynamic_pack,
            "fan",
            None,
            Some("fan"),
            r#"{"child_invocation_requests": [{"role": "w", "name": "a", "prompt": "do a", "owned_paths": ["a"]}]}"#,
            vec!["fan"],
            "after",
            false,
        ),
        (
            "a static topology's root",
            released_pack,
            "parent",
            Some("pre"),
            None,
            "",
            vec![],
            "successor",
            false,
        ),
    ] {
        assert!(
            source.contains("x = stage") && source.contains(&format!("x, {stage}, ")),
            "{leg}: `x` is spliced into the root list: {source}"
        );
        let program = compile_starlark_execution_program(&source, "walk-away-topology.star", &[])
            .unwrap_or_else(|error| panic!("{leg}: the pack compiles under oci: {error:?}"));
        let index = program
            .stages
            .keys()
            .position(|id| id.0.as_str() == stage)
            .expect("the topology stage is present");
        let expansion = lower_topology_expansion(&program, index)
            .or_else(|_| {
                kata_program::execution_program::lower_dynamic_fanout_expansion(&program, index)
            })
            .expect("the topology stage expands");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let mut frames = Vec::new();
        let mut held_x = None;
        let mut held_with = None;
        let mut held = None;
        let mut parked = None;
        let mut approved = false;
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        if stage_id == "x" {
                            held_x = Some(frame);
                        } else if Some(stage_id.as_str()) == with_x {
                            held_with = Some(frame);
                        } else if Some(stage_id.as_str()) == held_root {
                            held = Some(frame);
                        } else {
                            complete_frame(&rig, &reactor, &frame, b"{\"note\":\"ok\"}");
                        }
                        frames.push(stage_id);
                    }
                    () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {
                        if gated && parked.is_none() {
                            parked = rig
                                .dispatcher
                                .parked_approval_gates()
                                .expect("the gate list reads")
                                .into_iter()
                                .find(|gate| gate.capsule.is_some())
                                .map(|gate| gate.assignment_id);
                        }
                    }
                }
                // `x` trips once what must run before the walk-away has dispatched.
                let ready = (with_x.is_none() || held_with.is_some())
                    && (held_root.is_none() || held.is_some())
                    && (!gated || parked.is_some());
                if ready && let Some(x) = held_x.take() {
                    if let Some(pre) = held_with.take() {
                        complete_frame(&rig, &reactor, &pre, b"pre ran");
                    }
                    complete_frame(&rig, &reactor, &x, b"x ran");
                    tamper_completion_usage(&rig, x.attempt_id, &billed_micro_usd(600));
                }
                if held_x.is_some() || walkaway_rows(&rig, execution).is_empty() {
                    continue;
                }
                if let Some(root) = held.take() {
                    complete_frame(&rig, &reactor, &root, root_stdout.as_bytes());
                }
                if let Some(gate) = parked
                    && !approved
                {
                    rig.dispatcher
                        .approve_capsule_gate(
                            gate,
                            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                        )
                        .await
                        .expect("the operator's approve decides the parked root");
                    approved = true;
                }
            }
        })
        .await
        .expect("the drive settles within the budget");
        let rows: Vec<String> = walkaway_rows(&rig, execution)
            .into_iter()
            .map(|(stage, _)| stage)
            .collect();
        let ran: Vec<&str> = frames
            .iter()
            .map(String::as_str)
            .filter(|frame| frame.starts_with(stage))
            .collect();
        let behind_attempts: i64 = raw(&rig.op_path)
            .query_row(
                "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
                rusqlite::params![execution.to_bytes().as_slice(), behind],
                |row| row.get(0),
            )
            .expect("the dependent's attempts count");
        let reason = expansion_failure_reason(&rig, execution, &expansion);
        let named = reason.as_deref().is_some_and(|reason| {
            reason.contains("walked away") && reason.contains("x#budget-halt")
        });
        let failed = outcome
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains("x#budget-halt"));
        if !(ran == members && named && behind_attempts == 0 && rows == ["x#budget-halt"] && failed)
        {
            wrong.push(format!(
                "{leg}: frames {frames:?}, the topology's failure {reason:?}, `{behind}` \
                 dispatched {behind_attempts} time(s), walk-away rows {rows:?}, the run {}",
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// **A walk-away stops a loop's MEMBER topology at its own next dispatch point, and the loop
/// aborts on that member's death.** The loop-topology pack's body topology `implement` parks
/// its root on an authored `approval` gate at iteration 0 — its children mint only once the
/// root dispatches — while `x`, upstream of nothing, bills 600 micro-USD against its own
/// `cost_budget("halt", 0.0005)` (the raw `x#budget-halt` row). The operator then approves the
/// root, which runs; the body topology's next dispatch point is its children, and it mints
/// none and fails naming the row. The loop reads that as a member death: its `#op` attempt
/// resolves `failed` (raw `transitions`) with `review loop aborted by stage "implement"
/// failure: the run walked away …`, the gate topology `review` is never claimed, `after` has
/// zero rows in the raw `attempts` table, and the run fails naming `x#budget-halt`.
///
/// **Would red if:** a loop-seated topology's dispatch point minted its children without
/// consulting the durable walk-away (`implement#child-w1`/`w2` run, the body settles and the
/// loop resolves `Exhausted` at its gate instead).
#[tokio::test(flavor = "current_thread")]
async fn a_walk_away_stops_a_loop_member_topology_and_the_loop_aborts() {
    kata_types::node_profile::mark_node_installed();
    let source = format!(
        "x = stage(id = \"x\", agent = \"shell\", run = \"true\", \
         cost_budget = cost_budget(\"halt\", 0.0005))\n\n{LOOP_TOPOLOGY_PACK}"
    )
    .replace(
        "    sandbox = sandbox_profile(workspace = \"rw\"),\n    topology = topology(\n        \
         \"root_with_parallel_workers\",\n        root = role(\"impl_root\"",
        "    sandbox = sandbox_profile(workspace = \"rw\"),\n    approval = True,\n    \
         topology = topology(\n        \"root_with_parallel_workers\",\n        \
         root = role(\"impl_root\"",
    )
    .replace(
        "    root = [implement, review, after],\n)",
        "    root = [x, implement, review, after],\n)",
    );
    assert!(
        source.contains("approval = True") && source.contains("root = [x, implement"),
        "the body topology is gated and `x` is spliced in: {source}"
    );
    let program = topology_program(&source, "loop-topology-gated-walk-away.star");
    let loop_expansion = expansion(&program);
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let mut held_x = None;
    let mut parked = None;
    let mut approved = false;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    if stage_id == "x" {
                        held_x = Some(frame);
                    } else {
                        let stdout: &[u8] = if stage_id.starts_with("review") {
                            b"{\"verdict\":\"approve\",\"feedback\":\"ok\"}"
                        } else {
                            b"{\"note\":\"ok\"}"
                        };
                        complete_frame(&rig, &reactor, &frame, stdout);
                        frames.push(stage_id);
                    }
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {
                    if parked.is_none() {
                        parked = rig
                            .dispatcher
                            .parked_approval_gates()
                            .expect("the gate list reads")
                            .into_iter()
                            .find(|gate| gate.capsule.is_some())
                            .map(|gate| gate.assignment_id);
                    }
                }
            }
            // `x` trips while the body root is parked; the operator approves after the row.
            if parked.is_some()
                && let Some(x) = held_x.take()
            {
                complete_frame(&rig, &reactor, &x, b"x ran");
                tamper_completion_usage(&rig, x.attempt_id, &billed_micro_usd(600));
            }
            if let Some(gate) = parked
                && !approved
                && held_x.is_none()
                && !walkaway_rows(&rig, execution).is_empty()
            {
                rig.dispatcher
                    .approve_capsule_gate(
                        gate,
                        &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                    )
                    .await
                    .expect("the operator's approve decides the parked root");
                approved = true;
            }
        }
    })
    .await
    .expect("the drive settles within the budget");
    let rows: Vec<String> = walkaway_rows(&rig, execution)
        .into_iter()
        .map(|(stage, _)| stage)
        .collect();
    let reason = expansion_failure_reason(&rig, execution, &loop_expansion);
    let aborted = reason.as_deref().is_some_and(|reason| {
        reason.contains("review loop aborted by stage \"implement\" failure: the run walked away")
            && reason.contains("x#budget-halt")
    });
    let after_attempts: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'after'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the dependent's attempts count");
    let failed = outcome
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("x#budget-halt"));
    assert!(
        approved
            && frames == ["implement"]
            && aborted
            && after_attempts == 0
            && rows == ["x#budget-halt"]
            && failed,
        "approved {approved}, frames {frames:?}, the loop's failure {reason:?}, `after` \
         dispatched {after_attempts} time(s), walk-away rows {rows:?}, the run {outcome:?}"
    );
}

/// Drive the uniform walk-away pack's FIRST runner until `x`'s walk-away row is durable,
/// completing `a` (when the pack has one) before `x` and billing `x` 600 micro-USD, then
/// drop it — the crash — unless it settled first, as a run with nothing else in flight
/// does. `y`'s frame, when one arrives, is held unanswered and returned.
async fn drive_until_the_walk_away_row(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
) -> Option<kata_transport::types::CapsuleAssignment> {
    let runner = rig.runner(program, execution);
    let reactor = reactor(rig);
    let mut held_y = None;
    let mut held_x = None;
    let mut a_done = !program.stages.keys().any(|stage| stage.0.as_str() == "a");
    let run = runner.run();
    tokio::pin!(run);
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => {
                    assert!(outcome.is_err(), "the walked-away run fails: {outcome:?}");
                    assert!(held_y.is_none(), "a run with `y` in flight cannot settle");
                    break;
                }
                frame = next_frame(rig) => {
                    match frame_stage_id(rig, &frame).as_str() {
                        "y" => held_y = Some(frame),
                        "x" => held_x = Some(frame),
                        "a" => {
                            complete_frame(rig, &reactor, &frame, b"a ran");
                            a_done = true;
                        }
                        other => panic!("only a, x and y dispatch before the walk-away: {other}"),
                    }
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
            }
            if a_done && let Some(frame) = held_x.take() {
                complete_frame(rig, &reactor, &frame, b"x ran");
                tamper_completion_usage(rig, frame.attempt_id, &billed_micro_usd(600));
            }
            if !walkaway_rows(rig, execution).is_empty()
                && (held_y.is_some() || !program.stages.keys().any(|stage| stage.0 == "y"))
            {
                break;
            }
        }
    })
    .await
    .expect("x's walk-away lands within the budget");
    held_y
}

/// **A RESUMED fold writes no second walk-away row, whatever kind its own trip is.** `a`
/// completes, then `x` bills 600 micro-USD past the workflow `cost_bound(0.0005)` — the raw
/// `x#bound-halt-cost` row — and the runner dies. `a`'s durable completion is then rewritten
/// to state a cost kata could not measure, so a fresh runner's re-fold of it trips a
/// METERING halt — at an earlier frame than the live trip, of another kind, under another
/// stage's name. The chain already holds a walk-away row, so nothing is written: the raw
/// walk-away rows stay exactly `x#bound-halt-cost` and the resumed run fails naming it.
///
/// **Would red if:** the persist's idempotence were per kind or per stage (`a#metering-halt`
/// is written beside it).
#[tokio::test(flavor = "current_thread")]
async fn a_resumed_fold_writes_no_second_walk_away_row() {
    kata_types::node_profile::mark_node_installed();
    let source = uniform_walk_away_pack(", bounds = [cost_bound(0.0005)]", "")
        .replace(
            "y = stage(id = \"y\", agent = \"shell\", run = \"true\")\n\n\
             z = stage(id = \"z\", agent = \"shell\", run = \"true\", depends_on = [\"y\"])\n\n",
            "a = stage(id = \"a\", agent = \"shell\", run = \"true\")\n\n",
        )
        .replace("root = [x, y, z]", "root = [a, x]");
    assert!(
        source.contains("root = [a, x]") && !source.contains("\"y\""),
        "the pack is `a` and `x`: {source}"
    );
    let program = compile_starlark_execution_program(&source, "resumed-walk-away.star", &[])
        .expect("the pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    drive_until_the_walk_away_row(&rig, &program, execution).await;
    let live: Vec<String> = walkaway_rows(&rig, execution)
        .into_iter()
        .map(|(stage, _)| stage)
        .collect();
    assert_eq!(
        live,
        ["x#bound-halt-cost"],
        "the live run walked away on cost"
    );

    // The rewrite gives the resumed fold's re-fold of `a` a trip of its own.
    let a_attempt: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT attempt_id FROM attempts WHERE execution_id = ?1 AND stage_id = 'a'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("a's attempt");
    tamper_completion_usage(
        &rig,
        Ulid::from_bytes(a_attempt.try_into().expect("a ulid's 16 bytes")),
        &billed_unmeasurable(),
    );
    let runner = rig.runner(&program, execution);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), runner.run())
        .await
        .expect("the resumed fold settles within the budget");
    let rows: Vec<String> = walkaway_rows(&rig, execution)
        .into_iter()
        .map(|(stage, _)| stage)
        .collect();
    let failed = outcome
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("x#bound-halt-cost"));
    assert!(
        rows == ["x#bound-halt-cost"] && failed,
        "walk-away rows {rows:?}, the resumed run {outcome:?}"
    );
}

/// **A resumed fold releases nothing after a durable walk-away row, though its re-fold of
/// the tripping frame trips nothing — not even a stage the ready-advance lets through.** `x`
/// bills 600 micro-USD past the workflow `cost_bound(0.0005)` — the raw `x#bound-halt-cost`
/// row — with `y` still running, and the runner dies. `x`'s durable bill is then rewritten to
/// 0, so a fresh runner's re-fold of `x` trips nothing: only the row itself, at its own
/// position in the chain, says the run walked away. `y` then completes on the resumed run,
/// after that row. Behind `y` stands the static topology `parent` (and `successor` behind
/// it): a stage seating an expansion, which the ready-advance's walk-away skip passes over so
/// that a claim converges, so the fold's latch at the row is all that keeps `y`'s completion
/// from releasing it. The resumed run claims and dispatches nothing — the raw `attempts`
/// table holds `x` and `y` alone, beside their own `/work` applies — and fails naming the
/// row.
///
/// **Would red if:** the fold learned of the walk-away only from a trip it re-ran itself
/// (`latch_durable_walk_away` a no-op: `y` releases `parent`, whose claim writes its `#op`
/// attempt and resolves it failed naming the row). A plain stage behind `y` would not red
/// it: the ready-advance skips one off the durable row on its own
/// (`no_stage_starts_after_a_walk_away`).
#[tokio::test(flavor = "current_thread")]
async fn a_resumed_fold_releases_nothing_after_a_durable_walk_away_row() {
    kata_types::node_profile::mark_node_installed();
    let source = format!(
        "x = stage(id = \"x\", agent = \"shell\", run = \"true\")\n\n\
         y = stage(id = \"y\", agent = \"shell\", run = \"true\")\n\n{TOPOLOGY_PACK}"
    )
    .replace(
        "    id = \"parent\",\n",
        "    id = \"parent\",\n    depends_on = [\"y\"],\n",
    )
    .replace(
        "    root = [parent, successor],\n)",
        "    root = [x, y, parent, successor],\n    bounds = [cost_bound(0.0005)],\n)",
    );
    assert!(
        source.contains("depends_on = [\"y\"]")
            && source.contains("root = [x, y, parent, successor]"),
        "the topology `parent` stands behind `y`: {source}"
    );
    let program = compile_starlark_execution_program(&source, "resumed-walk-away.star", &[])
        .expect("the pack compiles under oci");
    let parent = program
        .stages
        .keys()
        .position(|id| id.0.as_str() == "parent")
        .expect("the topology stage is present");
    lower_topology_expansion(&program, parent).expect("`parent` seats an expansion");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let held_y = drive_until_the_walk_away_row(&rig, &program, execution)
        .await
        .expect("y is held running across the crash");
    // The crash leaves the row durable; the rewrite leaves `x`'s re-fold nothing to trip on.
    let x_attempt: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT attempt_id FROM attempts WHERE execution_id = ?1 AND stage_id = 'x'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("x's attempt");
    tamper_completion_usage(
        &rig,
        Ulid::from_bytes(x_attempt.try_into().expect("a ulid's 16 bytes")),
        &billed_micro_usd(0),
    );

    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let mut held_y = Some(held_y);
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    complete_frame(&rig, &reactor, &frame, b"{\"note\":\"ok\"}");
                    frames.push(stage_id);
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(20)), if held_y.is_some() => {
                    let frame = held_y.take().expect("y is held");
                    complete_frame(&rig, &reactor, &frame, b"y ran");
                }
            }
        }
    })
    .await
    .expect("the resumed run settles within the budget");
    let rows: Vec<String> = walkaway_rows(&rig, execution)
        .into_iter()
        .map(|(stage, _)| stage)
        .collect();
    let attempted: Vec<String> = {
        let connection = raw(&rig.op_path);
        let mut statement = connection
            .prepare(
                "SELECT DISTINCT stage_id FROM attempts
                  WHERE execution_id = ?1 AND stage_id NOT LIKE '#apply/%' ORDER BY stage_id",
            )
            .expect("the attempts read prepares");
        statement
            .query_map([execution.to_bytes().as_slice()], |row| row.get(0))
            .expect("the attempts read runs")
            .collect::<Result<_, _>>()
            .expect("every stage id reads")
    };
    let failed = outcome
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("x#bound-halt-cost"));
    assert!(
        rows == ["x#bound-halt-cost"] && attempted == ["x", "y"] && frames.is_empty() && failed,
        "resumed frames {frames:?}, walk-away rows {rows:?}, attempts at {attempted:?}, the \
         resumed run {outcome:?}"
    );
}

/// Record `frame`'s attempt as started at its own dispatch instant, as a real worker's
/// capsule reports — the durable anchor a resumed fold measures a `time_bound` from.
fn report_start(rig: &OciNodeRig, frame: &kata_transport::types::CapsuleAssignment) {
    let dispatched_at: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT dispatched_at_ms FROM attempts WHERE attempt_id = ?1",
            [frame.attempt_id.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the attempt's dispatch instant");
    rig.db
        .record_main_side_transition(
            frame.attempt_id,
            &kata_core::operational::MainSideTransition {
                started_at_ms: Some(dispatched_at),
                ..kata_core::operational::MainSideTransition::bare("running")
            },
        )
        .expect("the attempt's start is recorded");
}

/// Backdate `attempt`'s durable start report — the `started_at_ms` its `running` frame's
/// delivery snapshot carries, the anchor a fold absorbs from it — to `started_at_ms`, read
/// and rewritten raw. Only that frame moves: the attempt's later frames, and its row, keep
/// the start it reported live.
fn backdate_start_report(rig: &OciNodeRig, attempt: Ulid, started_at_ms: i64) {
    let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
    let (seq, payload): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT seq, payload_json FROM transitions
              WHERE attempt_id = ?1 AND resulting_state = 'running'",
            [attempt.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the attempt's running frame");
    let mut payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert!(
        payload["delivery"]["started_at_ms"].is_i64(),
        "the running frame carries its start report: {payload}"
    );
    payload["delivery"]["started_at_ms"] = serde_json::json!(started_at_ms);
    let affected = conn
        .execute(
            "UPDATE transitions SET payload_json = ?1 WHERE seq = ?2",
            rusqlite::params![serde_json::to_vec(&payload).unwrap(), seq],
        )
        .expect("the backdate lands");
    assert_eq!(
        affected, 1,
        "the backdate rewrites exactly the frame at seq={seq}"
    );
}

/// The workflow `time_bound` of [`a_resumed_fold_trips_a_time_bound_only_where_the_live_fold_did`]:
/// the live drive's own budget, so no frame the live drive records can sit past it, under
/// any load.
const RESUMED_TIME_BOUND_MS: i64 = 60_000;

/// **A resumed fold measures a `time_bound` at each frame's RECORDED instant, so it trips
/// it only where the live fold did.** `a → d → e` run under the workflow's
/// `time_bound(60000)` — the live drive's own 60 s budget, so the live fold cannot trip it
/// whatever the host's load. Each attempt reports its start (the durable anchor), `a` and
/// `d` complete, and the runner dies with `e` running. The cell then backdates `a`'s
/// start report (its `running` frame, read raw) to `d`'s recorded completion minus the
/// bound plus 250 ms: on the chain, `a`'s and `d`'s completions now sit inside the bound
/// by construction, 250 ms short of it, and 400 ms later a fresh runner folds the chain,
/// past it. `a`'s and `d`'s re-folds trip nothing — `d` is not skipped behind `a`, and
/// its own completion folds onto it. `e` then completes on the resumed run, past the
/// bound, and trips it at ITS frame: the raw walk-away rows are exactly
/// `e#bound-halt-time`, `d` and `e` each hold a completed transition in the raw table, and
/// the run fails naming the row. No instant the cell relies on is a race against the
/// host's scheduling: the only real-time gap it needs is its own 400 ms sleep.
///
/// **Would red if:** the fold measured the bound against the clock it runs under (the
/// resumed fold trips at `a`'s frame and writes `a#bound-halt-time`, skips `d`, and dies on
/// `d`'s completion: `cannot complete stage "d" in state Skipped`).
#[tokio::test(flavor = "current_thread")]
async fn a_resumed_fold_trips_a_time_bound_only_where_the_live_fold_did() {
    kata_types::node_profile::mark_node_installed();
    let source = format!(
        "a = stage(id = \"a\", agent = \"shell\", run = \"true\")\n\n\
         d = stage(id = \"d\", agent = \"shell\", run = \"true\", depends_on = [\"a\"])\n\n\
         e = stage(id = \"e\", agent = \"shell\", run = \"true\", depends_on = [\"d\"])\n\n\
         workflow(\"resumed-time-bound\", root = [a, d, e], bounds = \
         [time_bound({RESUMED_TIME_BOUND_MS})])\n"
    );
    let program = compile_starlark_execution_program(&source, "resumed-time-bound.star", &[])
        .expect("the pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let mut started = std::collections::BTreeMap::new();
    let held_e = {
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(
            std::time::Duration::from_millis(RESUMED_TIME_BOUND_MS.unsigned_abs()),
            async {
                loop {
                    tokio::select! {
                        outcome = &mut run => panic!("the run settles with `e` unanswered: {outcome:?}"),
                        frame = next_frame(&rig) => {
                            report_start(&rig, &frame);
                            let stage = frame_stage_id(&rig, &frame);
                            started.insert(stage.clone(), frame.attempt_id);
                            if stage == "e" {
                                break frame;
                            }
                            complete_frame(&rig, &reactor, &frame, b"ran");
                        }
                    }
                }
            },
        )
        .await
        .expect("`e` dispatches within the budget")
    };
    assert!(
        walkaway_rows(&rig, execution).is_empty(),
        "the live run walked away from nothing"
    );

    // The runner died. Backdate `a`'s start report so the chain's `d` completion sits
    // 250 ms inside the bound, then resume 400 ms later, past it.
    let d_completed_at: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT t.recorded_at_ms FROM transitions t
              WHERE t.attempt_id = ?1 AND t.resulting_state = 'completed'",
            [started["d"].to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("`d`'s completed frame");
    backdate_start_report(
        &rig,
        started["a"],
        d_completed_at - RESUMED_TIME_BOUND_MS + 250,
    );
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut held_e = Some(held_e);
    let mut resumed = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    resumed.push(frame_stage_id(&rig, &frame));
                    complete_frame(&rig, &reactor, &frame, b"ran");
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(20)), if held_e.is_some() => {
                    let frame = held_e.take().expect("e is held");
                    complete_frame(&rig, &reactor, &frame, b"e ran");
                }
            }
        }
    })
    .await
    .expect("the resumed run settles within the budget");
    let rows: Vec<String> = walkaway_rows(&rig, execution)
        .into_iter()
        .map(|(stage, _)| stage)
        .collect();
    let completed = |stage: &str| -> i64 {
        raw(&rig.op_path)
            .query_row(
                "SELECT COUNT(*) FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id
                  WHERE a.execution_id = ?1 AND a.stage_id = ?2 AND t.resulting_state = 'completed'",
                rusqlite::params![execution.to_bytes().as_slice(), stage],
                |row| row.get(0),
            )
            .expect("the stage's completions count")
    };
    let failed = outcome
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string().contains("e#bound-halt-time"));
    assert!(
        rows == ["e#bound-halt-time"]
            && completed("d") == 1
            && completed("e") == 1
            && resumed.is_empty()
            && failed,
        "walk-away rows {rows:?}, `d` completed {} time(s), `e` {}, resumed frames \
         {resumed:?}, the resumed run {outcome:?}",
        completed("d"),
        completed("e"),
    );
}

/// **A WORKFLOW `token_bound` counts a `topology(..)` child's completed tokens.** The
/// worker topology runs under `token_bound(100)`; its first worker child's completion
/// records 110 tokens. Charged at the child's own frame under its topology stage
/// `parent`, it trips the bound: the raw `parent#bound-halt-tokens` row, `successor`
/// (behind `parent`) never dispatched, and the run fails on the walk-away.
///
/// **Would red if:** a topology's children reached the workflow fold only through the
/// stage's fan-in summary, which carries their cost and no token count (no halt row,
/// `successor` runs), or a child's trip were anchored on its synthetic spelling, which
/// no stage depends on (`successor` runs).
#[tokio::test(flavor = "current_thread")]
async fn a_workflow_token_bound_counts_a_topology_childs_completed_tokens() {
    let source = TOPOLOGY_PACK.replace(
        "    root = [parent, successor],\n)",
        "    root = [parent, successor],\n    bounds = [token_bound(100)],\n)",
    );
    assert_ne!(
        source, TOPOLOGY_PACK,
        "the bound is spliced into the workflow"
    );
    let program = topology_program(&source, "topology-token-bound.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    complete_frame(&rig, &reactor, &frame, b"{\"note\":\"ok\"}");
                    if stage_id == "parent#child-first_worker" {
                        tamper_completion_usage(&rig, frame.attempt_id, &billed_tokens(110));
                    }
                    frames.push(stage_id);
                }
            }
        }
    })
    .await
    .expect("the topology drive settles within the budget");
    let rows = walkaway_rows(&rig, execution);
    assert_eq!(
        rows,
        [(
            "parent#bound-halt-tokens".to_owned(),
            "bound_exceeded: workflow tokens bound reached 110 tokens (limit: 100 tokens); \
             halted at stage \"parent\""
                .to_owned()
        )],
        "the child's tokens trip the workflow bound under its topology stage; frames {frames:?}"
    );
    assert!(
        !frames.iter().any(|stage| stage == "successor"),
        "the topology stage's dependent never dispatches: {frames:?}"
    );
    let error = outcome.expect_err("the walk-away fails the run");
    assert!(
        error.to_string().contains("parent#bound-halt-tokens"),
        "the run fails naming the walk-away: {error}"
    );
}

/// **A `topology(..)` child's FAILED turn is charged under its topology stage.** The worker
/// topology's `second_worker` is advisory (`required = False`); its frame fails, reporting the
/// 600 micro-USD its turn spent. That terminal charge is folded under the topology stage
/// `parent` — the stage a walk-away it trips must skip behind, and the stage whose own
/// `cost_budget` covers it — so it trips the workflow `cost_bound(0.0005)` (the raw
/// `parent#bound-halt-cost` row) or `parent`'s `cost_budget("halt", 0.0005)` (the raw
/// `parent#budget-halt` row). The advisory death leaves the topology to settle, yet `successor`
/// (behind `parent`) never dispatches, and the run fails on the walk-away.
///
/// **Would red if:** the failure arm anchored the charge on the child's synthetic
/// `parent#child-second_worker` spelling: the bound's row is named for no stage and skips
/// nothing behind `parent` (`successor` runs), and `parent`'s own budget never sees it.
#[tokio::test(flavor = "current_thread")]
async fn a_topology_childs_failed_turn_is_charged_under_its_topology_stage() {
    use kata_types::metering::{MeteredCost, StageUsage};
    let spent = StageUsage::metered(
        &kata_types::cache::TokenUsage {
            input: 10,
            output: 0,
            cache_read: 0,
            cache_write: 0,
        },
        MeteredCost::Authoritative { micro_usd: 600 },
        0,
    );
    let advisory = TOPOLOGY_PACK.replace(
        "role(\"second_worker\", agent = \"shell\"),",
        "role(\"second_worker\", agent = \"shell\", required = False),",
    );
    assert_ne!(
        advisory, TOPOLOGY_PACK,
        "the second worker is made advisory"
    );
    let mut wrong = Vec::new();
    for (scope, source, halt) in [
        (
            "the workflow cost_bound",
            advisory.replace(
                "    root = [parent, successor],\n)",
                "    root = [parent, successor],\n    bounds = [cost_bound(0.0005)],\n)",
            ),
            "parent#bound-halt-cost",
        ),
        (
            "the topology stage's cost_budget",
            advisory.replace(
                "    outputs = {\n        \"note\": \"string\",\n    },\n    topology = topology(",
                "    outputs = {\n        \"note\": \"string\",\n    },\n    \
                 cost_budget = cost_budget(\"halt\", 0.0005),\n    topology = topology(",
            ),
            "parent#budget-halt",
        ),
    ] {
        assert_ne!(source, advisory, "{scope}: the limit is spliced in");
        let program = topology_program(&source, "topology-failed-child.star");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let mut frames = Vec::new();
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        if stage_id == "parent#child-second_worker" {
                            reactor
                                .handle_message_for_test(
                                    kata_transport::types::WorkerMessage::Failed {
                                        assignment_id: frame.attempt_id,
                                        reason: format!("{stage_id} crashed"),
                                        verdict: kata_types::effect::DeliveryFailureProvenance::PerformedButFailed,
                                        provider_failure: None,
                                        usage: Some(spent.clone()),
                                        fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                                    },
                                )
                                .expect("the child failure is adjudicated");
                        } else {
                            complete_frame(&rig, &reactor, &frame, b"{\"note\":\"ok\"}");
                        }
                        frames.push(stage_id);
                    }
                }
            }
        })
        .await
        .expect("the topology drive settles within the budget");
        let rows = walkaway_rows(&rig, execution);
        let failed = outcome
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains(halt));
        let ran_successor = frames.iter().any(|stage| stage == "successor");
        if !(rows.len() == 1 && rows[0].0 == halt && failed && !ran_successor) {
            wrong.push(format!(
                "{scope}: frames {frames:?}, walk-away rows {rows:?}, the run {}",
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// **A WORKFLOW-scope bound charges a plain stage's REJECTED structured-output turn.**
/// `probe` declares a structured output; its first completion is not JSON and bills 600
/// micro-USD (or 110 tokens), and a retry would be valid and bill nothing. The rejected
/// turn, charged at its own frame, trips `cost_bound(0.0005)` (`token_bound(100)`): the
/// raw `probe#bound-halt-<kind>` row, the retry never dispatched (its seat comes after the
/// walk-away), `after` never dispatched, the run failed on it.
///
/// **Would red if:** the fold's retry arm queued the retry without charging the rejected
/// turn — the retry's free completion is the only one charged, no halt row lands and
/// `after` runs.
#[tokio::test(flavor = "current_thread")]
async fn a_workflow_bound_charges_a_plain_stages_rejected_structured_output_turn() {
    kata_types::node_profile::mark_node_installed();
    let mut wrong = Vec::new();
    for (bound, usage, halt) in [
        (
            "cost_bound(0.0005)",
            billed_micro_usd(600),
            "probe#bound-halt-cost",
        ),
        (
            "token_bound(100)",
            billed_tokens(110),
            "probe#bound-halt-tokens",
        ),
    ] {
        let source = VALIDATE_PLAIN_PACK.replace(
            "workflow(\"validate-plain\", root = [probe, after])",
            &format!("workflow(\"validate-plain\", root = [probe, after], bounds = [{bound}])"),
        );
        let program =
            compile_starlark_execution_program(&source, "validate-plain-bounded.star", &[])
                .expect("the bounded plain validate pack compiles under oci");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let mut frames = Vec::new();
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        let first_probe = stage_id == "probe" && frames.is_empty();
                        let stdout: &[u8] = match (stage_id.as_str(), first_probe) {
                            ("probe", true) => b"not json at all",
                            ("probe", false) => b"{\"ok\":true}",
                            _ => b"after ran",
                        };
                        complete_frame(&rig, &reactor, &frame, stdout);
                        if first_probe {
                            tamper_completion_usage(&rig, frame.attempt_id, &usage);
                        }
                        frames.push(stage_id);
                    }
                }
            }
        })
        .await
        .expect("the drive settles within the budget");
        let rows = walkaway_rows(&rig, execution);
        let failed = outcome
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains(halt));
        if !(rows.len() == 1 && rows[0].0 == halt && failed && frames == ["probe"]) {
            wrong.push(format!(
                "{bound}: frames {frames:?}, walk-away rows {rows:?}, the run {}",
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// **A topology stage's spend is charged ONCE at workflow scope.** The worker topology's
/// root bills 300 micro-USD (or 50 tokens) and its first worker child 150 micro-USD (40
/// tokens): 450 under `cost_bound(0.0005)`'s 500, 90 under `token_bound(100)`'s 100. Each
/// member is charged at its own frame and the settled stage's fan-in — whose summary
/// restates the children's cost — is charged nothing: no walk-away row, `successor`
/// runs, and the run completes.
///
/// **Would red if:** the settled stage were charged its fan-in envelope as well (root
/// plus the children's summary: 900 micro-USD, or 140 tokens — a halt row and no
/// `successor`).
#[tokio::test(flavor = "current_thread")]
async fn a_topology_stages_spend_is_charged_once_at_workflow_scope() {
    let mut wrong = Vec::new();
    for (bound, root_usage, child_usage) in [
        (
            "cost_bound(0.0005)",
            billed_micro_usd(300),
            billed_micro_usd(150),
        ),
        ("token_bound(100)", billed_tokens(50), billed_tokens(40)),
    ] {
        let source = TOPOLOGY_PACK.replace(
            "    root = [parent, successor],\n)",
            &format!("    root = [parent, successor],\n    bounds = [{bound}],\n)"),
        );
        let program = topology_program(&source, "topology-bounded.star");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let mut frames = Vec::new();
        let run = runner.run();
        tokio::pin!(run);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        complete_frame(&rig, &reactor, &frame, b"{\"note\":\"ok\"}");
                        match stage_id.as_str() {
                            "parent" => tamper_completion_usage(&rig, frame.attempt_id, &root_usage),
                            "parent#child-first_worker" => {
                                tamper_completion_usage(&rig, frame.attempt_id, &child_usage);
                            }
                            _ => {}
                        }
                        frames.push(stage_id);
                    }
                }
            }
        })
        .await
        .expect("the topology drive settles within the budget");
        let rows = walkaway_rows(&rig, execution);
        if !(rows.is_empty() && outcome.is_ok() && frames.iter().any(|stage| stage == "successor"))
        {
            wrong.push(format!(
                "{bound}: frames {frames:?}, walk-away rows {rows:?}, the run {}",
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The `time_bound` arm — elapsed is `accepted_at` minus the MIN member
/// `created_at` off durable occurrence rows, so tampering the occurrence's
/// claim timestamp is the deterministic trip: 60s of durable age against a
/// one-second bound.
#[tokio::test(flavor = "current_thread")]
async fn a_time_bound_trips_off_the_durable_claim_timestamp() {
    let program = bounds_program("time_bound(1)", 3, "fail");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let (iteration, member) = member_coordinate(&rig, &frame);
                    if member == 0 {
                        complete_frame(
                            &rig, &reactor, &frame,
                            b"{\"stage\":\"w\",\"marker\":0}",
                        );
                        if iteration == 0 {
                            rusqlite::Connection::open(&rig.op_path)
                                .unwrap()
                                .execute(
                                    "UPDATE occurrences SET created_at_ms = created_at_ms - 60000
                                      WHERE execution_id = ?1 AND operation_path = ?2",
                                    rusqlite::params![
                                        execution.to_bytes().as_slice(),
                                        expansion
                                            .path
                                            .child(0)
                                            .child(0)
                                            .canonical_bytes()
                                            .as_slice(),
                                    ],
                                )
                                .expect("the claim timestamp tamper lands");
                        }
                    } else {
                        complete_frame(
                            &rig, &reactor, &frame,
                            b"{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                        );
                    }
                }
            }
        }
    })
    .await
    .expect("the bound resolve lands within the budget");
    let error = outcome.expect_err("on_exhaustion = fail fails the tripped run");
    assert!(
        error.to_string().contains("time bound"),
        "the failure names the bound that tripped: {error}"
    );
    let record = expansion_record(&rig, execution, &expansion).expect("the bound record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 1,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Fail,
            }
        ),
        "one iteration folded before the trip: {:?}",
        record.resolution
    );
}

/// Loop-bound accounting continues across a resume — the TRIP arm:
/// a member envelope the bound can't hold lands durably, the runner dies,
/// and the RESUMED derive trips it off the durable bytes alone — zero new
/// member frames, zero live work, the record resolves `Exhausted`.
#[tokio::test(flavor = "current_thread")]
async fn a_resumed_drive_trips_the_bound_off_the_durable_envelopes_alone() {
    let program = bounds_program("cost_bound(0.0005)", 3, "accept");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let expansion = expansion(&program);

    {
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => panic!("iteration 0 only refines, got {outcome:?}"),
                    frame = next_frame(&rig) => {
                        let (_, member) = member_coordinate(&rig, &frame);
                        if member == 0 {
                            complete_frame(&rig, &reactor, &frame, b"{\"stage\":\"w\",\"marker\":0}");
                        } else {
                            complete_frame(
                                &rig, &reactor, &frame,
                                b"{\"decision\":\"continue\",\"feedback\":\"again\"}",
                            );
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("iteration 0 folds within the budget");
    }

    // The crash: the worker's 600-micro-USD envelope is durable, the runner
    // is gone. Nothing else happened.
    tamper_member_output(&rig, execution, &expansion, 0, 0, |envelope| {
        envelope["token_usage"] = serde_json::json!({"cost_micro_usd": 600});
    });

    let runner = rig.runner(&program, execution);
    // Generous on purpose, as the first drive's: a hang detector around a whole
    // resumed execution on a loaded host; no time property is under test.
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), runner.run())
        .await
        .expect("the resumed derive settles within the budget");
    outcome.expect("on_exhaustion = accept completes the tripped loop");

    let record = expansion_record(&rig, execution, &expansion).expect("the bound record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 1,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Accept,
            }
        ),
        "the resumed fold tripped the bound, no live work having run: {:?}",
        record.resolution
    );
}

/// Loop-bound accounting continues across a resume — the SINGLE-FOLD
/// arm: a 400-micro-USD envelope under the 500 bound survives the resume
/// recompute UNTRIPPED — proof each accepted member envelope folds its cost
/// exactly once into the running total (a double fold of 400 would pass
/// 500) — and the loop goes on to approve at iteration 1.
#[tokio::test(flavor = "current_thread")]
async fn a_resumed_drive_folds_each_member_envelope_once() {
    let program = bounds_program("cost_bound(0.0005)", 3, "accept");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let expansion = expansion(&program);

    {
        let runner = rig.runner(&program, execution);
        let reactor = reactor(&rig);
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => panic!("iteration 0 only refines, got {outcome:?}"),
                    frame = next_frame(&rig) => {
                        let (_, member) = member_coordinate(&rig, &frame);
                        if member == 0 {
                            complete_frame(&rig, &reactor, &frame, b"{\"stage\":\"w\",\"marker\":0}");
                        } else {
                            complete_frame(
                                &rig, &reactor, &frame,
                                b"{\"decision\":\"continue\",\"feedback\":\"again\"}",
                            );
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("iteration 0 folds within the budget");
    }

    tamper_member_output(&rig, execution, &expansion, 0, 0, |envelope| {
        envelope["token_usage"] = serde_json::json!({"cost_micro_usd": 400});
    });

    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let (iteration, member) = member_coordinate(&rig, &frame);
                    frames.push((iteration, member));
                    if member == 0 {
                        complete_frame(&rig, &reactor, &frame, b"{\"stage\":\"w\",\"marker\":1}");
                    } else {
                        complete_frame(
                            &rig, &reactor, &frame,
                            b"{\"decision\":\"promote\",\"feedback\":\"ship it\"}",
                        );
                    }
                }
            }
        }
    })
    .await
    .expect("the resumed drive settles within the budget");
    outcome.expect("the loop approves");

    assert_eq!(
        frames,
        vec![(1, 0), (1, 1)],
        "the resume dispatched exactly iteration 1 — iteration 0 replayed out of durable rows"
    );
    let record = expansion_record(&rig, execution, &expansion).expect("the approved record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Approved {
                iteration: 1
            }
        ),
        "400 micro-USD folded ONCE — a double fold would have tripped 800 > 500: {:?}",
        record.resolution
    );
}

/// THE ROLLOVER pack — `rollover_after_iterations = 2` over a four-iteration
/// window, the worker's prompt rendering `review.*` verbatim into its argv
/// so the rendered continue-as-new context is readable off the capsule.
/// `marker=` renders `previous_output`'s parsed marker when it is an
/// envelope and `-` at a generation boundary, where the value is the
/// distilled summary string. The `rollover` descriptor itself is NOT a
/// prompt-visible field — the load-time check refuses any reference
/// outside `iteration`/`previous_output`/`feedback` — so the render proves
/// the boundary through what those fields CONTAIN.
const ROLLOVER_PACK: &str = r#"worker = stage(
    id = "worker",
    run = "printf 'iter={{ review.iteration }} fb={{ review.feedback }} prev={{ 'summary' if review.previous_output is string else 'envelope' }} marker={{ review.previous_output.parsed.marker if review.previous_output.parsed is defined else '-' }}\n'; printf '{\"stage\":\"w\",\"marker\":0}\n'",
    agent = "shell",
    outputs = {
        "stage": "string",
        "marker": "number",
    },
)

controller = stage(
    id = "controller",
    run = "printf '{\"decision\":\"continue\",\"feedback\":\"again\"}\n'",
    agent = "shell",
    depends_on = ["worker"],
    outputs = {
        "decision": "string",
        "feedback": "string",
    },
)

loop(
    body = worker,
    gate = controller,
    max_iterations = 4,
    rollover_after_iterations = 2,
    on_exhaustion = "accept",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)

workflow("rollover-loop", root = [worker, controller])
"#;

fn rollover_program() -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(ROLLOVER_PACK, "rollover-loop.star", &[])
        .expect("the rollover pack compiles under oci")
}

/// The rollover drive's scripted stdout per `(stage, iteration)`: the worker
/// reports its iteration as the marker, so `marker=` in a later prompt names
/// the envelope a member rendered; the gate's feedback at iteration 1 is
/// 3 000 bytes of `x` — over `ROLLOVER_SUMMARY_MAX_BYTES` — so the
/// generation-1 carry's 2 048-byte truncation is directly assertable.
fn rollover_stdout(stage_id: &str, iteration: u32) -> String {
    match stage_id {
        "worker" => format!("{{\"stage\":\"w\",\"marker\":{iteration}}}"),
        "controller" => {
            let decision = if iteration == 3 {
                "promote"
            } else {
                "continue"
            };
            let feedback = match iteration {
                1 => "x".repeat(3000),
                2 => "iter2".to_owned(),
                n => format!("iter{n}"),
            };
            format!("{{\"decision\":\"{decision}\",\"feedback\":\"{feedback}\"}}")
        }
        other => panic!("the rollover pack has no stage {other}"),
    }
}

/// The writeback calls one drive observed — the hook's job is applying the
/// completed iteration's declared memory writebacks; the recorder only makes
/// WHICH completed iterations fired legible.
struct RecordingIterationWriteback(std::sync::Mutex<Vec<u32>>);

impl kata_workflow::runner::IterationWritebackHook for RecordingIterationWriteback {
    fn on_iteration_complete(
        &self,
        completed_iteration: u32,
    ) -> kata_types::error::KataResult<usize> {
        self.0.lock().unwrap().push(completed_iteration);
        Ok(0)
    }
}

/// THE ROLLOVER cell — the rendered rollover context, the distilled memory
/// snapshot, the persisted rollover summary object and the per-iteration
/// writeback, folded into one drive. At the generation-1 boundary
/// (iteration 2 under a 2-iteration window) the member-0 dispatch fires the
/// writeback for the completed iteration, persists the distilled carry under
/// `{execution}:rollover:worker:gen-1`, and renders `review.rollover` plus
/// the BOUNDED summary in place of the raw prior output and feedback — all
/// readable off the capsule argv the member binds.
#[tokio::test(flavor = "current_thread")]
async fn a_generation_boundary_renders_the_distilled_context_and_persists_the_carry() {
    let program = rollover_program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let store = std::sync::Arc::new(
        kata_core::store::SqliteNativeMemoryStore::open_in_memory()
            .expect("the in-memory memory store opens"),
    );
    let calls = std::sync::Arc::new(RecordingIterationWriteback(std::sync::Mutex::new(
        Vec::new(),
    )));
    let runner = rig
        .runner(&program, execution)
        .with_memory_store(std::sync::Arc::clone(&store))
        .with_iteration_writeback_hook(calls.clone());
    let reactor = reactor(&rig);

    let mut worker_argv: Vec<(u32, Vec<String>)> = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let (iteration, member) = member_coordinate(&rig, &frame);
                    if member == 0 {
                        worker_argv.push((iteration, member_argv(&rig, &frame)));
                    }
                    complete_frame(
                        &rig, &reactor, &frame,
                        rollover_stdout(&stage_id, iteration).as_bytes(),
                    );
                }
            }
        }
    })
    .await
    .expect("the rollover drive settles within the budget");
    outcome.expect("the loop approves at iteration 3");

    // The render: generation 0 carries no `rollover` descriptor at all; the
    // boundary iteration renders the descriptor, the bounded summary as
    // `previous_output`, and the SAME truncated bytes as `feedback`.
    let argv = |iteration: u32| {
        worker_argv
            .iter()
            .find(|(n, _)| *n == iteration)
            .map(|(_, argv)| argv.join(" "))
            .expect("the iteration's member-0 capsule ran")
    };
    let gen0 = argv(1);
    assert!(
        gen0.contains("iter=1") && gen0.contains("fb=iter0") && gen0.contains("prev=envelope"),
        "generation 0 renders the raw latest envelope + feedback: {gen0}"
    );
    let boundary = argv(2);
    for piece in ["iter=2", "prev=summary", "marker=-"] {
        assert!(
            boundary.contains(piece),
            "the boundary render carries {piece}: {boundary}"
        );
    }
    assert!(
        boundary.contains(&"x".repeat(64)) && boundary.contains('…'),
        "the boundary's feedback IS the distilled carry: {boundary}"
    );
    assert!(
        !boundary.contains(&"x".repeat(2049)),
        "the carry is truncated to the bound, not the raw 3 000 bytes"
    );
    // One iteration later `previous_output` is the ordinary latest envelope
    // and `feedback` is the latest feedback again — the distilled carry rode
    // the boundary alone.
    let intra = argv(3);
    for piece in ["iter=3", "fb=iter2", "prev=envelope", "marker=2"] {
        assert!(
            intra.contains(piece),
            "the intra-generation render carries {piece}: {intra}"
        );
    }

    // The durable carry: `{execution}:rollover:worker:gen-1` holds the
    // distilled summary — the SAME truncated bytes the boundary prompt
    // rendered.
    let object = store
        .get(&format!("{execution}:rollover:worker:gen-1"))
        .expect("the memory store reads")
        .expect("the generation-1 carry was persisted");
    assert_eq!(object.body["generation"], serde_json::json!(1));
    assert_eq!(object.body["iterations_elapsed"], serde_json::json!(2));
    assert_eq!(object.body["worker_stage"], serde_json::json!("worker"));
    assert_eq!(
        object.body["summary"],
        serde_json::json!(format!("{}…", "x".repeat(2048))),
        "the durable summary is the 2 048-byte truncation of the 3 000-byte feedback"
    );
    assert!(
        object.tags.iter().any(|tag| tag == "rollover"),
        "the carry is tagged rollover: {:?}",
        object.tags
    );

    // Member 0 of iterations 1, 2 and 3 is the per-iteration
    // seam — the completed iteration's writeback fires once each, in order.
    assert_eq!(
        *calls.0.lock().unwrap(),
        vec![0, 1, 2],
        "the completed iterations' writebacks fired at the member-0 seam"
    );
}

/// A rollover survives a crash-resume: the boundary is reached only in
/// the RESUMED drive — no durable marker survives to re-fire it, the
/// generation math replays off the accepted member rows alone — and the
/// carry lands exactly once, as though the crash never happened.
#[tokio::test(flavor = "current_thread")]
async fn a_crashed_run_replays_the_generation_boundary() {
    let program = rollover_program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let store = std::sync::Arc::new(
        kata_core::store::SqliteNativeMemoryStore::open_in_memory()
            .expect("the in-memory memory store opens"),
    );
    let calls = std::sync::Arc::new(RecordingIterationWriteback(std::sync::Mutex::new(
        Vec::new(),
    )));
    let reactor = reactor(&rig);

    {
        let runner = rig
            .runner(&program, execution)
            .with_memory_store(std::sync::Arc::clone(&store))
            .with_iteration_writeback_hook(calls.clone());
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                tokio::select! {
                    outcome = &mut run => panic!("iterations 0..=1 only refine, got {outcome:?}"),
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        let (iteration, member) = member_coordinate(&rig, &frame);
                        complete_frame(
                            &rig, &reactor, &frame,
                            rollover_stdout(&stage_id, iteration).as_bytes(),
                        );
                        if (iteration, member) == (1, 1) {
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("iterations 0 and 1 fold within the budget");
    }

    assert!(
        store
            .get(&format!("{execution}:rollover:worker:gen-1"))
            .expect("the memory store reads")
            .is_none(),
        "no carry landed before the crash — the boundary had not been reached"
    );

    let runner = rig
        .runner(&program, execution)
        .with_memory_store(std::sync::Arc::clone(&store))
        .with_iteration_writeback_hook(calls.clone());
    let mut boundary_argv = None;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let (iteration, member) = member_coordinate(&rig, &frame);
                    if (iteration, member) == (2, 0) {
                        boundary_argv = Some(member_argv(&rig, &frame).join(" "));
                    }
                    complete_frame(
                        &rig, &reactor, &frame,
                        rollover_stdout(&stage_id, iteration).as_bytes(),
                    );
                }
            }
        }
    })
    .await
    .expect("the resumed drive settles within the budget");
    outcome.expect("the resumed loop approves at iteration 3");

    // The boundary REPLAYED: the resumed member-0 dispatch rendered the
    // distilled context and persisted the carry — the derivation asked the
    // same generation question of the durable rows the first drive left.
    let boundary = boundary_argv.expect("the resumed drive dispatched iteration 2's worker");
    for piece in ["iter=2", "prev=summary", "marker=-"] {
        assert!(
            boundary.contains(piece),
            "the replayed boundary carries {piece}: {boundary}"
        );
    }
    let object = store
        .get(&format!("{execution}:rollover:worker:gen-1"))
        .expect("the memory store reads")
        .expect("the replayed boundary persisted the carry");
    assert_eq!(object.body["generation"], serde_json::json!(1));
    assert_eq!(
        *calls.0.lock().unwrap(),
        vec![0, 1, 2],
        "each completed iteration's writeback fired exactly once across the crash"
    );
}

/// THE VALIDATE pack — `outputs` declared so `inject_parsed_if_declared`'s
/// declared-output door runs on every member completion.
const VALIDATE_PACK: &str = r#"worker = stage(
    id = "worker",
    run = "printf '{\"stage\":\"w\",\"marker\":0}\n'",
    agent = "shell",
    outputs = {
        "stage": "string",
        "marker": "number",
    },
)

controller = stage(
    id = "controller",
    run = "printf '{\"decision\":\"promote\",\"feedback\":\"ship\"}\n'",
    agent = "shell",
    depends_on = ["worker"],
    outputs = {
        "decision": "string",
        "feedback": "string",
    },
)

loop(
    body = worker,
    gate = controller,
    max_iterations = 2,
    on_exhaustion = "fail",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)

workflow("validate-loop", root = [worker, controller])
"#;

/// Drive [`VALIDATE_PACK`] answering the worker's n-th frame with
/// `worker_stdout[n]` (the controller always promotes); returns the outcome and
/// every worker frame's occurrence path.
async fn drive_validate_loop(
    rig: &OciNodeRig,
    execution: Ulid,
    worker_stdout: &[&str],
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<Vec<u32>>,
) {
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(VALIDATE_PACK, "validate-loop.star", &[])
        .expect("the validate pack compiles under oci");
    let runner = rig.runner(&program, execution);
    let reactor = reactor(rig);
    let mut worker_paths = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let stdout = if frame_stage_id(rig, &frame) == "worker" {
                        let n = worker_paths.len();
                        worker_paths.push(frame_path(rig, &frame));
                        worker_stdout.get(n).copied().unwrap_or("{\"wrong\":true}")
                    } else {
                        "{\"decision\":\"promote\",\"feedback\":\"ship\"}"
                    };
                    complete_frame(rig, &reactor, &frame, stdout.as_bytes());
                }
            }
        }
    })
    .await
    .expect("the validate-loop drive settles within the budget");
    (outcome, worker_paths)
}

/// A loop member's invalid structured output RETRIES at the member seat's
/// `child(1)` (the member's own retry chain, read by the loop's derive), the
/// valid retry is the member's accepted envelope, and the loop approves.
///
/// **Watched red**: with the chain's retry arm disabled, attempt 0's invalid
/// output fails the loop (`missing declared field "marker"`).
#[tokio::test(flavor = "current_thread")]
async fn a_loop_members_invalid_output_retries_at_its_member_seat() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, worker_paths) = drive_validate_loop(
        &rig,
        execution,
        &["{\"wrong\":true}", "{\"stage\":\"w\",\"marker\":1}"],
    )
    .await;
    let outputs = outcome.expect("the retried member's loop approves");
    assert_eq!(outputs["worker"]["parsed"]["marker"], serde_json::json!(1));
    assert_eq!(worker_paths.len(), 2, "attempt 0 plus one retry");
    let seat = worker_paths[0].clone();
    assert_eq!(
        seat.len(),
        3,
        "attempt 0 sits at the member's own coordinate"
    );
    let mut retry_seat = seat.clone();
    retry_seat.push(1);
    assert_eq!(
        worker_paths[1], retry_seat,
        "the retry sits at the member seat's child(1)"
    );
}

/// A loop member whose every attempt fails its structured output
/// spends the member's `validate_retries` (default 2): three attempts on its
/// chain, then the run fails with the validator's own message — never a
/// refusal that retries are unavailable under `oci`.
#[tokio::test(flavor = "current_thread")]
async fn a_loop_member_spending_its_validation_budget_fails_the_loop() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, worker_paths) = drive_validate_loop(&rig, execution, &[]).await;
    let error = outcome.expect_err("a spent member budget fails the run");
    let text = error.to_string();
    assert!(
        text.contains("\"worker\"") && !text.contains("validate_retries_unavailable_under_oci"),
        "the validator's own message names the member: {text}"
    );
    assert_eq!(
        worker_paths.len(),
        3,
        "attempt 0 plus validate_retries = 2 retries"
    );
}

/// The plain-stage retry pack: `probe` declares a structured output (so it
/// carries the default `validate_retries = 2`), `after` depends on it.
const VALIDATE_PLAIN_PACK: &str = r#"
probe = stage(
    id = "probe",
    agent = "shell",
    run = "printf 'probe\\n'",
    sandbox = sandbox_profile(workspace = "rw"),
    outputs = {
        "ok": "bool",
    },
)

after = stage(
    id = "after",
    agent = "shell",
    run = "printf 'after\\n'",
    depends_on = ["probe"],
)

workflow("validate-plain", root = [probe, after])
"#;

/// Drive [`VALIDATE_PLAIN_PACK`] (optionally with `validate_retries` rewritten),
/// answering `probe`'s n-th frame with `probe_stdout[n]`; returns the outcome,
/// each `probe` frame's occurrence path and argv, in dispatch order.
async fn drive_validate_plain(
    validate_retries: Option<u32>,
    probe_stdout: &[&str],
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(Vec<u32>, String)>,
    OciNodeRig,
    Ulid,
) {
    kata_types::node_profile::mark_node_installed();
    let source = match validate_retries {
        Some(n) => VALIDATE_PLAIN_PACK.replacen(
            "    outputs = {\n        \"ok\"",
            &format!("    validate_retries = {n},\n    outputs = {{\n        \"ok\""),
            1,
        ),
        None => VALIDATE_PLAIN_PACK.to_owned(),
    };
    let program = compile_starlark_execution_program(&source, "validate-plain.star", &[])
        .expect("the plain validate pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut probes = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let stdout = if stage_id == "probe" {
                        let n = probes.len();
                        probes.push((frame_path(&rig, &frame), member_argv(&rig, &frame).join(" ")));
                        probe_stdout.get(n).copied().unwrap_or("not json at all")
                    } else {
                        "after ran"
                    };
                    complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                }
            }
        }
    })
    .await
    .expect("the validate drive settles within the budget");
    (outcome, probes, rig, execution)
}

/// A plain stage's structured output fails its contract: the
/// retry is a CAPSULE at the stage seat's retry coordinate `[i].child(1)` — a
/// command stage re-running its own command verbatim (an agent stage's retry
/// carries the validation feedback instead) — and the valid retry
/// completes the stage — `after` runs over it. Raw: both occurrences exist and
/// are accepted (the invalid attempt's output stays accepted — its `/work`
/// delta stands; the retry runs in the same tree).
///
/// **Watched red**: with the `oci` arm answering a terminal refusal instead, the
/// run fails after one attempt.
#[tokio::test(flavor = "current_thread")]
async fn a_plain_stage_retries_its_invalid_structured_output_as_a_capsule() {
    let (outcome, probes, rig, execution) =
        drive_validate_plain(None, &["not json at all", "{\"ok\": true}"]).await;
    let outputs = outcome.expect("the retry completes the stage");
    assert_eq!(outputs["probe"]["parsed"]["ok"], serde_json::json!(true));
    assert!(outputs.contains_key(&SmolStr::new("after")), "`after` ran");
    assert_eq!(probes.len(), 2, "one retry, no more");
    let seat = probes[0].0.clone();
    assert_eq!(
        seat.len(),
        1,
        "attempt 0 sits at the stage's own coordinate"
    );
    assert_eq!(
        probes[1].0,
        vec![seat[0], 1],
        "the retry sits at the seat's retry coordinate"
    );
    assert_eq!(
        probes[1].1, probes[0].1,
        "a COMMAND retry re-runs its own command verbatim — no prose appended to a shell line"
    );
    let accepted: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM occurrences o JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE o.execution_id = ?1 AND a.stage_id = 'probe'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the accepted probe count reads");
    assert_eq!(
        accepted, 2,
        "the invalid attempt and its retry are both accepted outcomes"
    );
}

/// The host-free twin of the live retry-drain cell:
/// attempt 0 completes INVALID *and carrying a `/work` delta* (a marker
/// write). The validation retry must mint only after the apply drive has
/// landed that delta — its capsule's `/work` is the POST-APPLY head, and the
/// run completes with BOTH writes on the final head's CAS manifest. Read off
/// the occurrence rows and the landed manifest — never kata's own judgement.
///
/// **Would red if:** `execute_validate_retries` ran before
/// `drive_pending_work_applies` — the retry would map the pre-apply
/// head and its own delta would die `work_delta_base_stale` at `#apply`,
/// failing a converged run.
#[tokio::test(flavor = "current_thread")]
async fn an_invalid_attempt_with_a_work_delta_retries_over_the_applied_head() {
    use kata_types::execution_contract::{ArtifactPrivacy, ArtifactRef};
    use kata_types::tree_artifact::{TreeEntryMode, TreeNode, TreePath};
    use kata_types::tree_delta::{TreeChange, TreeChangeKind, TreeDelta};

    kata_types::node_profile::mark_node_installed();
    let program =
        compile_starlark_execution_program(VALIDATE_PLAIN_PACK, "validate-plain.star", &[])
            .expect("the plain validate pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);

    // A real `/work` delta over the head the frame's occurrence names —
    // `writes` become `Write` members, published and declared before the
    // completion reports the delta.
    let delta_over_frame = |rig: &OciNodeRig,
                            frame: &kata_transport::types::CapsuleAssignment,
                            writes: &[(&str, &[u8])]| {
        let work_tree = rig
            .db
            .occurrence(frame.occurrence_id.0.0)
            .unwrap()
            .unwrap()
            .work_tree_artifact_id
            .expect("the occurrence binds a /work head");
        let row = rig.db.artifact(work_tree).unwrap().unwrap();
        let base = ArtifactRef::new(
            kata_types::primitives::FixedBytes(row.object_id),
            row.size_bytes,
            row.privacy,
        );
        let changes: Vec<TreeChange> = writes
            .iter()
            .map(|(path, bytes)| {
                let member = rig.cas.put_durable(bytes).unwrap();
                TreeChange {
                    path: TreePath::new(*path).unwrap(),
                    change: TreeChangeKind::Write {
                        node: TreeNode::File {
                            mode: TreeEntryMode::Regular,
                            object: member.object_id(),
                            size_bytes: member.size(),
                        },
                    },
                }
            })
            .collect();
        let delta = TreeDelta::new(base, changes).expect("the delta mints over the frame's base");
        let durable = rig.cas.put_durable(&delta.delta_bytes().unwrap()).unwrap();
        rig.db
            .declare_artifact(
                &kata_core::operational::ArtifactDeclaration::for_durable_delta(
                    &delta,
                    ArtifactPrivacy::Private,
                    kata_core::operational::CasRootOwner::Execution(execution),
                    &durable,
                )
                .unwrap(),
            )
            .unwrap();
        Some(ArtifactRef::new(
            durable.object_id(),
            durable.size(),
            ArtifactPrivacy::Private,
        ))
    };

    let mut work_heads = Vec::new();
    let mut probe_seen = 0usize;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    if stage_id == "probe" {
                        work_heads.push(
                            rig.db
                                .occurrence(frame.occurrence_id.0.0)
                                .unwrap()
                                .unwrap()
                                .work_tree_artifact_id
                                .expect("the probe capsule maps /work"),
                        );
                        if probe_seen == 0 {
                            // Attempt 0: INVALID structured output AND a
                            // `/work` write — the delta the drain reorder owes.
                            complete_frame_with(
                                &rig,
                                &reactor,
                                &frame,
                                b"not json at all",
                                delta_over_frame(&rig, &frame, &[("marker_a.txt", b"a\n")]),
                            );
                        } else {
                            // The retry: valid output and its own write.
                            complete_frame_with(
                                &rig,
                                &reactor,
                                &frame,
                                b"{\"ok\": true}",
                                delta_over_frame(&rig, &frame, &[("marker_b.txt", b"b\n")]),
                            );
                        }
                        probe_seen += 1;
                    } else {
                        complete_frame(&rig, &reactor, &frame, b"after ran");
                    }
                }
            }
        }
    })
    .await
    .expect("the validate drive settles within the budget");
    outcome.expect("the run completes — the retry minted over the applied head");

    assert_eq!(probe_seen, 2, "one retry, no more");
    assert_ne!(
        work_heads[0], work_heads[1],
        "the retry's /work is the POST-APPLY head — a different artifact than attempt 0's"
    );

    // BOTH writes on the landed head, read off the CAS manifest — never
    // kata's own summary.
    let head = rig
        .db
        .execution_work_tree_head(execution)
        .unwrap()
        .expect("the head row reads");
    let head_row = rig
        .db
        .artifact(head.work_tree_artifact_id)
        .unwrap()
        .expect("the head's artifact row");
    let manifest_bytes = rig
        .cas
        .get_verified(
            &kata_types::primitives::ObjectId::new(head_row.object_id),
            head_row.size_bytes,
            kata_types::tree_artifact::TreeManifest::MAXIMUM_ENCODED_BYTES,
        )
        .expect("the head manifest reads");
    let manifest: kata_types::tree_artifact::TreeManifest =
        serde_json::from_slice(&manifest_bytes).expect("the manifest decodes");
    let names: Vec<&str> = manifest
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(
        names,
        ["marker_a.txt", "marker_b.txt"],
        "the landed head carries the invalid attempt's write AND the retry's"
    );
}

/// Crash pair — the runner dies right after attempt 0's invalid output is
/// accepted (whether or not its retry was already dispatched): the resumed run
/// re-derives the retry from the durable chain — the invalid attempt re-folds,
/// the dedup reads the minted-or-not `[i].child(1)` occurrence — and completes
/// with EXACTLY one retry occurrence (raw SQLite), never a second.
#[tokio::test(flavor = "current_thread")]
async fn a_crash_after_the_invalid_attempt_resumes_with_exactly_one_retry() {
    kata_types::node_profile::mark_node_installed();
    let program =
        compile_starlark_execution_program(VALIDATE_PLAIN_PACK, "validate-plain.star", &[])
            .expect("the plain validate pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let reactor = reactor(&rig);
    let probe_path = {
        let runner = rig.runner(&program, execution);
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            tokio::select! {
                outcome = &mut run => panic!("the run cannot finish before the crash: {outcome:?}"),
                frame = next_frame(&rig) => {
                    let path = frame_path(&rig, &frame);
                    complete_frame(&rig, &reactor, &frame, b"not json at all");
                    path
                }
            }
        })
        .await
        .expect("attempt 0 lands within the budget")
    };
    let runner = rig.runner(&program, execution);
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stdout: &[u8] = if frame_stage_id(&rig, &frame) == "probe" {
                        b"{\"ok\": true}"
                    } else {
                        b"after ran"
                    };
                    complete_frame(&rig, &reactor, &frame, stdout);
                }
            }
        }
    })
    .await
    .expect("the resumed drive settles within the budget");
    outcome.expect("the resumed run completes over the retry");
    // The CAPSULE occurrences at a path — the `#apply/probe` occurrence that
    // lands each accepted delta shares the path under another contract.
    let at = |path: Vec<u32>| -> i64 {
        raw(&rig.op_path)
            .query_row(
                "SELECT COUNT(DISTINCT o.occurrence_id) FROM occurrences o
                   JOIN attempts a ON a.occurrence_id = o.occurrence_id
                  WHERE o.execution_id = ?1 AND o.operation_path = ?2 AND a.stage_id = 'probe'",
                rusqlite::params![
                    execution.to_bytes().as_slice(),
                    OperationPath(path).canonical_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .expect("the occurrence count reads")
    };
    assert_eq!(
        at(vec![probe_path[0], 1]),
        1,
        "exactly one retry occurrence"
    );
    assert_eq!(at(vec![probe_path[0], 2]), 0, "no second retry");
}

/// A retry attempt that DIES (the worker reports it failed — a
/// non-zero exit, a crash) fails the stage with its own reason: the chain does
/// not wait on an attempt that will never answer, and `after` never runs.
#[tokio::test(flavor = "current_thread")]
async fn a_failed_retry_attempt_fails_the_stage() {
    kata_types::node_profile::mark_node_installed();
    let program =
        compile_starlark_execution_program(VALIDATE_PLAIN_PACK, "validate-plain.star", &[])
            .expect("the plain validate pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut probes = 0usize;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    assert_eq!(frame_stage_id(&rig, &frame), "probe", "`after` never dispatches");
                    probes += 1;
                    if probes == 1 {
                        complete_frame(&rig, &reactor, &frame, b"not json at all");
                    } else {
                        // The retry's process exits non-zero — the exit policy's
                        // failure, adjudicated main-side off the completion.
                        reactor
                            .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
                                attempt_id: frame.attempt_id,
                                fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                                result: publish_result(&rig),
                                work_delta: kata_workflow::test_harness::stub_work_delta(&rig.db, &rig.cas, frame.occurrence_id),
                                exit_code: Some(2),
                                stdout: publish_capture(&rig, b""),
                                stderr: publish_capture(&rig, b"the retry crashed"),
                                capture_exceeded: false,
                                agent: None,
                                provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                                    "retry exit cell",
                                ),
                                egress_refusals: vec![],
                            })
                            .expect("the retry's exit failure is adjudicated");
                    }
                }
            }
        }
    })
    .await
    .expect("a dead retry settles the run within the budget");
    let error = outcome.expect_err("a dead retry fails the run");
    assert!(
        error.to_string().contains("the retry crashed"),
        "the stage fails with the retry's own reason: {error}"
    );
    assert_eq!(probes, 2, "attempt 0 and the one retry that died");
}

/// The budget spent: `validate_retries = 1` and both attempts
/// invalid → the stage fails with the validation message naming the
/// BASE stage; exactly two attempts ran; `after` never dispatches.
#[tokio::test(flavor = "current_thread")]
async fn a_spent_validation_budget_fails_the_stage_naming_the_base_stage() {
    let (outcome, probes, _rig, _execution) =
        drive_validate_plain(Some(1), &["not json at all", "still not json"]).await;
    let error = outcome.expect_err("a spent budget fails the run");
    let text = error.to_string();
    assert!(
        text.contains("\"probe\"") && !text.contains("validate_retries_unavailable_under_oci"),
        "the validation message names the base stage: {text}"
    );
    assert_eq!(probes.len(), 2, "attempt 0 plus exactly one retry");
}

/// THE UNMATCHED pack — a flat `decision` string, so a tag outside the
/// authored `gate_verdict` is a RUNTIME refusal, not a compile-time one: a
/// variant-typed gate makes the omission load-time (the variant's tag set
/// must be covered), which is the stronger guarantee — this pack exists to
/// prove the runtime door on the vocabulary that lacks it.
const UNMATCHED_PACK: &str = r#"worker = stage(
    id = "worker",
    run = "printf '{\"stage\":\"w\"}\n'",
    agent = "shell",
    outputs = {
        "stage": "string",
    },
)

controller = stage(
    id = "controller",
    run = "printf '{\"decision\":\"continue\",\"feedback\":\"again\"}\n'",
    agent = "shell",
    depends_on = ["worker"],
    outputs = {
        "decision": "string",
        "feedback": "string",
    },
)

loop(
    body = worker,
    gate = controller,
    max_iterations = 2,
    on_exhaustion = "fail",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop", "park"],
    },
)

workflow("unmatched-loop", root = [worker, controller])
"#;

/// A gate envelope whose `decision`
/// discriminant is `frob` — schema-valid, in no `gate_verdict` category —
/// fails the derive BY NAME, `unknown verdict`, and the run fails without
/// the expansion ever resolving.
#[tokio::test(flavor = "current_thread")]
async fn an_unmapped_gate_verdict_fails_the_run_by_name() {
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(UNMATCHED_PACK, "unmatched-loop.star", &[])
        .expect("the unmatched pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let (_, member) = member_coordinate(&rig, &frame);
                    if member == 0 {
                        complete_frame(&rig, &reactor, &frame, b"{\"stage\":\"w\"}");
                    } else {
                        complete_frame(
                            &rig, &reactor, &frame,
                            b"{\"decision\":\"frob\",\"feedback\":\"?\"}",
                        );
                    }
                }
            }
        }
    })
    .await
    .expect("the unmatched verdict settles within the budget");
    let error = outcome.expect_err("an unmapped verdict fails the loop");
    assert!(
        error.to_string().contains("frob"),
        "the failure names the tag the vocabulary never mapped: {error}"
    );
    assert_eq!(
        member_output(&rig, execution, &expansion, 0, 1)["parsed"]["decision"],
        serde_json::json!("frob"),
        "the unmatched verdict IS durable — its classification refused, not its landing"
    );
}

/// THE BRANCH pack — the loop's gate doubles as the branch condition: a
/// variant-typed `decision` and one arm per tag, exactly the
/// `check_branch_routes` exhaustiveness shape. The verdicts the cells
/// script decide whether the arm ever runs.
const BRANCH_PACK: &str = r#"worker = stage(
    id = "worker",
    run = "printf '{\"stage\":\"w\"}\n'",
    agent = "shell",
    outputs = {
        "stage": "string",
    },
)

controller = stage(
    id = "controller",
    run = "printf '{\"decision\":{\"continue\":{}},\"feedback\":\"again\"}\n'",
    agent = "shell",
    depends_on = ["worker"],
    produces = contract("Decision", {
        "decision": field(variant({
            "promote": contract("Promote", {}),
            "stop": contract("Stop", {}),
            "park": contract("Park", {}),
            "continue": contract("Continue", {}),
        })),
        "feedback": field("string"),
    }),
)

promote_arm = stage(
    id = "promote_arm",
    run = "printf '{\"arm\":\"promote\"}\n'",
    agent = "shell",
    outputs = {"arm": "string"},
)

stop_arm = stage(
    id = "stop_arm",
    run = "printf '{\"arm\":\"stop\"}\n'",
    agent = "shell",
    outputs = {"arm": "string"},
)

park_arm = stage(
    id = "park_arm",
    run = "printf '{\"arm\":\"park\"}\n'",
    agent = "shell",
    outputs = {"arm": "string"},
)

continue_arm = stage(
    id = "continue_arm",
    run = "printf '{\"arm\":\"continue\"}\n'",
    agent = "shell",
    outputs = {"arm": "string"},
)

loop(
    body = worker,
    gate = controller,
    max_iterations = 3,
    on_exhaustion = "accept",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote", "stop"],
        "refine": ["continue"],
        "block": ["park"],
    },
)

branch(
    on = controller,
    verdict_field = "decision",
    arms = {
        "promote": [promote_arm],
        "stop": [stop_arm],
        "park": [park_arm],
        "continue": [continue_arm],
    },
)

workflow("branch-loop", root = [worker, controller])
"#;

fn branch_program() -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(BRANCH_PACK, "branch-loop.star", &[])
        .expect("the branch pack compiles under oci")
}

/// How many attempts the arm stage
/// ever minted in this execution — 0 for a skipped arm, 1 for a taken one.
fn arm_attempt_count(rig: &OciNodeRig, execution: Ulid, arm: &str) -> i64 {
    raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
            rusqlite::params![execution.to_bytes().as_slice(), arm],
            |row| row.get(0),
        )
        .expect("the arm's attempt count reads")
}

/// How many program-operation attempts (`#op/<path>`: the loop's expansion
/// and each route's `Select`) this execution minted, read raw.
fn program_operation_attempts(rig: &OciNodeRig, execution: Ulid) -> i64 {
    raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id LIKE '#op/%'",
            rusqlite::params![execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the program-operation attempt count reads")
}

/// Drive the branch pack scripting the gate's discriminant per iteration —
/// arms complete `{"arm": <tag>}` when they dispatch.
async fn drive_branch(
    rig: &OciNodeRig,
    runner: &kata_workflow::runner::WorkflowRunner,
    decisions: &[&str],
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<String>,
) {
    let reactor = reactor(rig);
    let mut ran = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let stage_id = frame_stage_id(rig, &frame);
                    let stdout = match stage_id.as_str() {
                        "worker" => "{\"stage\":\"w\"}".to_owned(),
                        "controller" => {
                            let (iteration, _) = member_coordinate(rig, &frame);
                            format!(
                                "{{\"decision\":{{\"{}\":{{}}}},\"feedback\":\"iter {iteration}\"}}",
                                decisions[iteration as usize]
                            )
                        }
                        arm => {
                            ran.push(stage_id.clone());
                            format!("{{\"arm\":\"{arm}\"}}")
                        }
                    };
                    complete_frame(rig, &reactor, &frame, stdout.as_bytes());
                }
            }
        }
    })
    .await
    .expect("the branch drive settles within the budget");
    (outcome, ran)
}

/// A promote verdict routes, then its arm runs — through the
/// variant-discriminant verdict: the gate emits
/// `{"decision":{"promote":{}}}`, the expansion resolves `Approved`, the
/// fold routes the TERMINAL verdict once — `promote_arm` runs, the other
/// three arms never mint an attempt, and the run completes.
#[tokio::test(flavor = "current_thread")]
async fn a_variant_discriminant_approves_and_routes_its_arm() {
    let program = branch_program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let (outcome, ran) = drive_branch(&rig, &runner, &["promote"]).await;
    outcome.expect("an approved loop with a routed arm completes");
    assert_eq!(
        ran,
        vec!["promote_arm"],
        "exactly the routed arm dispatched"
    );
    for arm in ["stop_arm", "park_arm", "continue_arm"] {
        assert_eq!(
            arm_attempt_count(&rig, execution, arm),
            0,
            "the {arm} minted no attempt"
        );
    }
    assert!(matches!(
        expansion_record(&rig, execution, &expansion)
            .expect("the record")
            .resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Approved { iteration: 0 }
    ));
}

/// A block verdict whose
/// tag has an arm resolves `Blocked`, routes `park_arm`, and the WORKER
/// completes instead of failing — the branch owns the block's outcome — so
/// the run finishes green.
#[tokio::test(flavor = "current_thread")]
async fn a_terminal_block_with_a_branch_routes_the_arm_without_failing() {
    let program = branch_program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let (outcome, ran) = drive_branch(&rig, &runner, &["park"]).await;
    let outputs = outcome.expect("a blocked-but-branched loop completes");
    assert_eq!(ran, vec!["park_arm"], "the block tag's arm ran");
    for arm in ["promote_arm", "stop_arm", "continue_arm"] {
        assert_eq!(arm_attempt_count(&rig, execution, arm), 0);
    }
    assert!(matches!(
        expansion_record(&rig, execution, &expansion)
            .expect("the record")
            .resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Blocked { iteration: 0 }
    ));
    assert!(
        outputs.contains_key(&SmolStr::new("worker")),
        "the worker completed — the branch owns the block, the run is green"
    );
}

/// `on_exhaustion = "accept"` ADOPTS the last iteration's outcomes, the gate's
/// report included, so a branch on the gate routes that report exactly as it
/// routes a completion: the last verdict was `continue`, so `continue_arm`
/// runs once, every other arm mints nothing, the run completes, and no
/// `#branch-failure` row is written. This is what lets an implement → test
/// loop that never goes green reach its `failed` arm and park.
#[tokio::test(flavor = "current_thread")]
async fn an_accepted_exhaustion_routes_the_last_reports_arm() {
    let program = branch_program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let (outcome, ran) = drive_branch(&rig, &runner, &["continue", "continue", "continue"]).await;
    outcome.expect("on_exhaustion = accept completes the exhausted loop");
    assert!(
        matches!(
            expansion_record(&rig, execution, &expansion)
                .expect("the record")
                .resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 3,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Accept,
            }
        ),
        "the loop exhausted under accept"
    );
    assert_eq!(
        ran,
        vec!["continue_arm"],
        "exactly the last report's arm dispatched"
    );
    assert_eq!(arm_attempt_count(&rig, execution, "continue_arm"), 1);
    for arm in ["promote_arm", "stop_arm", "park_arm"] {
        assert_eq!(
            arm_attempt_count(&rig, execution, arm),
            0,
            "the accepted exhaustion's {arm} minted no attempt"
        );
    }
    let branch_failure: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM undispatched_stages
              WHERE execution_id = ?1 AND stage_name LIKE '%branch-failure%'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap_or(0);
    assert_eq!(
        branch_failure, 0,
        "a routed report writes no branch-failure row"
    );
    assert_eq!(
        program_operation_attempts(&rig, execution),
        2,
        "the expansion's `#op/` attempt and the route's ONE `Select` attempt"
    );
}

/// The accepted exhaustion's route survives a resume like a completion's: the
/// fresh runner re-reads the durable decision and never re-dispatches the arm.
#[tokio::test(flavor = "current_thread")]
async fn a_resumed_accepted_exhaustion_never_repeats_its_routing() {
    let program = branch_program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();

    {
        let runner = rig.runner(&program, execution);
        let (outcome, ran) =
            drive_branch(&rig, &runner, &["continue", "continue", "continue"]).await;
        outcome.expect("the first drive completes");
        assert_eq!(ran, vec!["continue_arm"]);
    }

    let runner = rig.runner(&program, execution);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), runner.run())
        .await
        .expect("the resumed fold settles within the budget");
    outcome.expect("the resumed run completes");
    assert_eq!(
        arm_attempt_count(&rig, execution, "continue_arm"),
        1,
        "the arm ran exactly once across the resume"
    );
}

/// The branch pack with a `cost_bound(0.0005)` (500 micro-USD) on its loop,
/// driven so the bound trips on iteration `trip`'s worker: when that
/// iteration's GATE frame arrives — proof its worker folded accepted — the
/// worker's durable envelope is tampered to 600 micro-USD, so the gate's own
/// derive trips before classifying the gate. Every earlier gate reports
/// `continue`; the tripping iteration's gate reports `promote`, durable but
/// never classified. Returns `(the rig, the execution, the expansion, the
/// run outcome, the arms that dispatched)`.
async fn drive_bound_tripped_branch(
    trip: u32,
) -> (
    OciNodeRig,
    Ulid,
    kata_program::execution_program::LoweredOperation,
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<String>,
) {
    kata_types::node_profile::mark_node_installed();
    let pack = BRANCH_PACK.replacen(
        "on_exhaustion = \"accept\",",
        "on_exhaustion = \"accept\",\n    bounds = [cost_bound(0.0005)],",
        1,
    );
    assert_ne!(pack, BRANCH_PACK, "the bound is spliced into the loop");
    let program = compile_starlark_execution_program(&pack, "branch-loop.star", &[])
        .expect("the bounded branch pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);
    let reactor = reactor(&rig);

    let mut ran = Vec::new();
    let outcome = {
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome,
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        let stdout = match stage_id.as_str() {
                            "worker" => "{\"stage\":\"w\"}".to_owned(),
                            "controller" => {
                                let (iteration, _) = member_coordinate(&rig, &frame);
                                if iteration == trip {
                                    tamper_member_output(
                                        &rig, execution, &expansion, iteration, 0,
                                        |envelope| {
                                            envelope["token_usage"] =
                                                serde_json::json!({"cost_micro_usd": 600});
                                        },
                                    );
                                    "{\"decision\":{\"promote\":{}},\"feedback\":\"ship it\"}"
                                        .to_owned()
                                } else {
                                    format!(
                                        "{{\"decision\":{{\"continue\":{{}}}},\"feedback\":\"iter {iteration}\"}}"
                                    )
                                }
                            }
                            arm => {
                                ran.push(stage_id.clone());
                                format!("{{\"arm\":\"{arm}\"}}")
                            }
                        };
                        complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                    }
                }
            }
        })
        .await
        .expect("the bound resolve lands within the budget")
    };
    (rig, execution, expansion, outcome, ran)
}

/// An accepted exhaustion with NO classified gate report has nothing to
/// route: the cost bound trips on iteration 0's worker before the gate's
/// verdict is ever classified, so every arm of the gate's branch is skipped
/// (zero attempts each), no route's `Select` is ever claimed, and the run
/// completes. The gate's durable `promote` envelope is never routed: it was
/// not classified, so it is not the loop's report.
#[tokio::test(flavor = "current_thread")]
async fn an_accepted_exhaustion_without_a_gate_report_skips_every_arm() {
    let (rig, execution, expansion, outcome, ran) = drive_bound_tripped_branch(0).await;
    outcome.expect("on_exhaustion = accept completes the tripped loop");

    let record = expansion_record(&rig, execution, &expansion).expect("the bound record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 1,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Accept,
            }
        ),
        "the bound spent at ONE iteration under accept: {:?}",
        record.resolution
    );
    assert!(
        record.verdicts.is_empty(),
        "the gate's report was never classified"
    );
    assert!(ran.is_empty(), "no arm dispatched: {ran:?}");
    for arm in ["promote_arm", "stop_arm", "park_arm", "continue_arm"] {
        assert_eq!(
            arm_attempt_count(&rig, execution, arm),
            0,
            "the report-less exhaustion's {arm} minted no attempt"
        );
    }
    assert_eq!(
        program_operation_attempts(&rig, execution),
        1,
        "only the expansion's own `#op/` attempt exists — no route's `Select` was ever claimed"
    );
}

/// A bound that trips MID-loop routes NOTHING: iteration 0's gate classified
/// `continue`, then iteration 1's worker was accepted (its `/work` delta, when
/// it writes one, is applied) and the bound tripped before iteration 1's gate
/// classified. Iteration 0's report judged iteration 0's candidate, not the one
/// the loop ended on, so routing it would let an arm act on a tree no gate
/// judged — a route on any other field of that report (`risk = "low"` →
/// promote) could land it. Every arm is skipped instead, exactly as for an
/// exhaustion with no report at all, and the run's closeout parks the
/// candidate. Iteration 1's durable `promote` envelope is never routed either:
/// it was never classified.
#[tokio::test(flavor = "current_thread")]
async fn a_mid_loop_bound_trip_routes_nothing() {
    let (rig, execution, expansion, outcome, ran) = drive_bound_tripped_branch(1).await;
    outcome.expect("on_exhaustion = accept completes the tripped loop");

    let record = expansion_record(&rig, execution, &expansion).expect("the bound record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 2,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Accept,
            }
        ),
        "the bound spent at iteration 1 under accept: {:?}",
        record.resolution
    );
    assert_eq!(
        record.verdicts.len(),
        1,
        "only iteration 0's gate classified"
    );
    assert!(ran.is_empty(), "no arm dispatched: {ran:?}");
    for arm in ["promote_arm", "stop_arm", "park_arm", "continue_arm"] {
        assert_eq!(
            arm_attempt_count(&rig, execution, arm),
            0,
            "the mid-loop trip's {arm} minted no attempt"
        );
    }
    assert_eq!(
        program_operation_attempts(&rig, execution),
        1,
        "only the expansion's own `#op/` attempt exists — no route's `Select` was ever claimed"
    );
    assert_eq!(
        member_output(&rig, execution, &expansion, 1, 1)["parsed"]["decision"],
        serde_json::json!({"promote": {}}),
        "iteration 1's gate envelope IS durable — it was simply never classified"
    );
}

/// A loop's branch route survives a resume: the arm dispatched and
/// completed before the crash; the resumed pure-fold re-derives the routing
/// without re-dispatching it — zero frames post-resume, the run completes.
#[tokio::test(flavor = "current_thread")]
async fn a_resumed_run_never_repeats_branch_routing() {
    let program = branch_program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let expansion = expansion(&program);

    {
        let runner = rig.runner(&program, execution);
        let (outcome, ran) = drive_branch(&rig, &runner, &["promote"]).await;
        outcome.expect("the first drive completes");
        assert_eq!(ran, vec!["promote_arm"]);
    }

    let runner = rig.runner(&program, execution);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), runner.run())
        .await
        .expect("the resumed fold settles within the budget");
    outcome.expect("the resumed run completes");
    assert_eq!(
        arm_attempt_count(&rig, execution, "promote_arm"),
        1,
        "the arm ran exactly once across the resume"
    );
    assert!(
        expansion_record(&rig, execution, &expansion).is_some(),
        "the resumed fold re-derived the recorded resolution"
    );
}

/// THE MEMBER-APPROVAL packs — `approval = true` on the WORKER arm and on
/// the GATE arm: the per-member approval cells split exactly this way,
/// iteration ≥ 1 body members bypassing while the reviewer parks every
/// pass.
fn approval_pack(gated_member: &str) -> String {
    let (worker_approval, controller_approval) = match gated_member {
        "worker" => ("True", "False"),
        "controller" => ("False", "True"),
        other => panic!("no member {other}"),
    };
    format!(
        r#"worker = stage(
    id = "worker",
    run = "printf '{{\"stage\":\"w\",\"marker\":0}}\\n'",
    agent = "shell",
    approval = {worker_approval},
    outputs = {{
        "stage": "string",
        "marker": "number",
    }},
)

controller = stage(
    id = "controller",
    run = "printf '{{\"decision\":\"continue\",\"feedback\":\"again\"}}\\n'",
    agent = "shell",
    depends_on = ["worker"],
    approval = {controller_approval},
    outputs = {{
        "decision": "string",
        "feedback": "string",
    }},
)

loop(
    body = worker,
    gate = controller,
    max_iterations = 2,
    on_exhaustion = "fail",
    gate_verdict = {{
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    }},
)

workflow("approval-loop", root = [worker, controller])
"#
    )
}

/// Drive `decisions` approving every parked member capsule gate, recording
/// `(stage_name, assignment_id)` per approval — returns the outcome and the
/// park log the cell asserts against.
async fn drive_member_approvals(
    rig: &OciNodeRig,
    runner: &kata_workflow::runner::WorkflowRunner,
    decisions: &[&str],
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, ulid::Ulid)>,
) {
    let reactor = reactor(rig);
    let mut parks: Vec<(String, ulid::Ulid)> = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let stage_id = frame_stage_id(rig, &frame);
                    let (iteration, member) = member_coordinate(rig, &frame);
                    let stdout = match stage_id.as_str() {
                        "controller" => format!(
                            "{{\"decision\":\"{}\",\"feedback\":\"iter {iteration}\"}}",
                            decisions[iteration as usize]
                        ),
                        _ => format!("{{\"stage\":\"w\",\"marker\":{iteration}}}"),
                    };
                    complete_frame(rig, &reactor, &frame, stdout.as_bytes());
                    let _ = member;
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    for gate in rig
                        .dispatcher
                        .parked_approval_gates()
                        .expect("the gate list reads")
                    {
                        if gate.capsule.is_none()
                            || parks.iter().any(|(_, id)| *id == gate.assignment_id)
                        {
                            continue;
                        }
                        parks.push((gate.stage_name.to_string(), gate.assignment_id));
                        rig.dispatcher
                            .approve_capsule_gate(
                                gate.assignment_id,
                                &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                            )
                            .await
                            .expect("the operator's approve decides the parked member");
                    }
                }
            }
        }
    })
    .await
    .expect("the approval drive settles within the budget");
    (outcome, parks)
}

/// The WORKER arm of per-iteration member approval: the authored `approval = true`
/// on a body member parks the member's capsule gate at iteration 0 — the operator
/// approves, the member dispatches — and
/// iteration 1's member DISPATCHES UNGATED under the loop's checked
/// iteration-bypass. Exactly one park, the loop approves on iteration 1.
#[tokio::test(flavor = "current_thread")]
async fn a_member_approval_gate_parks_only_the_first_iteration() {
    let program =
        compile_starlark_execution_program(&approval_pack("worker"), "approval-loop.star", &[])
            .expect("the worker-gated pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let (outcome, parks) = drive_member_approvals(&rig, &runner, &["continue", "promote"]).await;

    outcome.expect("the approved members' loop completes");
    assert_eq!(
        parks.len(),
        1,
        "exactly one member ever parked — iteration ≥ 1 bypasses: {parks:?}"
    );
    assert_eq!(parks[0].0, "worker", "the parked member is the worker");
    assert!(matches!(
        expansion_record(&rig, execution, &expansion)
            .expect("the record")
            .resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Approved { iteration: 1 }
    ));
}

/// The REVIEWER arm of per-iteration member approval: the authored `approval = true`
/// on the GATE parks the reviewer's capsule on EVERY iteration — the loop's bypass
/// reaches body members, never the
/// reviewer whose whole job is being checked per pass. Two parks, one per
/// iteration, and the run approves at iteration 1.
#[tokio::test(flavor = "current_thread")]
async fn the_gate_approval_parks_every_iteration() {
    let program =
        compile_starlark_execution_program(&approval_pack("controller"), "approval-loop.star", &[])
            .expect("the gate-gated pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = expansion(&program);

    let (outcome, parks) = drive_member_approvals(&rig, &runner, &["continue", "promote"]).await;

    outcome.expect("the approved reviewers' loop completes");
    assert_eq!(
        parks.len(),
        2,
        "the reviewer parks on every iteration: {parks:?}"
    );
    assert!(
        parks.iter().all(|(stage, _)| stage == "controller"),
        "only the gate ever parked: {parks:?}"
    );
    assert_ne!(
        parks[0].1, parks[1].1,
        "each iteration's park is its own attempt"
    );
    assert!(matches!(
        expansion_record(&rig, execution, &expansion)
            .expect("the record")
            .resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Approved { iteration: 1 }
    ));
}

/// The execution's landed `/work` tree as a path set — the durable fact a
/// per-iteration write claims.
fn head_manifest_paths(rig: &OciNodeRig, execution: Ulid) -> std::collections::BTreeSet<String> {
    let head = rig
        .db
        .execution_work_tree_head(execution)
        .unwrap()
        .expect("the head row reads");
    let row = rig
        .db
        .artifact(head.work_tree_artifact_id)
        .unwrap()
        .unwrap();
    let bytes = rig
        .cas
        .get_verified(
            &kata_types::primitives::ObjectId::new(row.object_id),
            row.size_bytes,
            kata_types::tree_artifact::TreeManifest::MAXIMUM_ENCODED_BYTES,
        )
        .expect("the head manifest reads");
    let manifest: kata_types::tree_artifact::TreeManifest =
        serde_json::from_slice(&bytes).expect("the manifest decodes");
    manifest
        .entries()
        .iter()
        .map(|entry| entry.path.as_str().to_owned())
        .collect()
}

/// A multi-stage loop resumed mid-iteration replays safely, with its
/// per-iteration `/work`-application rows: iteration 0 completes all
/// three members, iteration 1's FIRST member lands, the runner dies — the
/// resumed drive's first frame is member 1 of iteration 1 (member 0 is NOT
/// re-dispatched), the loop approves there, and every WRITING member's
/// reported `/work` write — four marker files, one per `rw` member —
/// is in the landed head manifest. `controller` authors `ro`, so the
/// scripted answer reports no delta for it.
#[tokio::test(flavor = "current_thread")]
async fn a_crashed_run_resumes_mid_iteration_at_the_next_pending_member() {
    let program = program();
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let expansion = expansion(&program);
    let reactor = reactor(&rig);

    {
        let runner = rig.runner(&program, execution);
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => panic!("the loop only refines pre-crash, got {outcome:?}"),
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        let (iteration, member) = member_coordinate(&rig, &frame);
                        // `controller` authors `ro` — only the WRITING members
                        // (`stage_a`/`stage_b`, both `workspace = "rw"`) may
                        // report a delta; the controller's is the empty delta
                        // an ro stage owes a /work-mapped frame.
                        let delta = if stage_id == "controller" {
                            kata_workflow::test_harness::stub_work_delta(
                                &rig.db, &rig.cas, frame.occurrence_id,
                            )
                        } else {
                            Some(named_work_delta(
                                &rig, execution, &frame,
                                &format!("marker-{iteration}-{member}.txt"), b"x",
                            ))
                        };
                        complete_frame_with(
                            &rig, &reactor, &frame,
                            member_stdout(&stage_id, iteration).as_bytes(),
                            delta,
                        );
                        if (iteration, member) == (1, 0) {
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("the pre-crash fold lands within the budget");
    }

    let runner = rig.runner(&program, execution);
    let mut first_resumed = None;
    let mut count = 0u32;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let (iteration, member) = member_coordinate(&rig, &frame);
                    count += 1;
                    first_resumed.get_or_insert((iteration, member));
                    let decision = if iteration == 1 && member == 2 {
                        "promote"
                    } else {
                        "continue"
                    };
                    let stdout = if stage_id == "controller" {
                        format!("{{\"decision\":\"{decision}\",\"feedback\":\"done\"}}")
                    } else {
                        member_stdout(&stage_id, iteration)
                    };
                    let delta = if stage_id == "controller" {
                        kata_workflow::test_harness::stub_work_delta(
                            &rig.db, &rig.cas, frame.occurrence_id,
                        )
                    } else {
                        Some(named_work_delta(
                            &rig, execution, &frame,
                            &format!("marker-{iteration}-{member}.txt"), b"x",
                        ))
                    };
                    complete_frame_with(&rig, &reactor, &frame, stdout.as_bytes(), delta);
                }
            }
        }
    })
    .await
    .expect("the resumed drive settles within the budget");
    outcome.expect("the resumed loop approves at iteration 1");

    assert_eq!(
        first_resumed,
        Some((1, 1)),
        "the resumed derive dispatched the NEXT pending member — iteration 1's member 0 never re-ran"
    );
    assert_eq!(
        count, 2,
        "members 1 and 2 of iteration 1 completed the loop"
    );
    let landed = head_manifest_paths(&rig, execution);
    for iteration in 0..=1u32 {
        for member in 0..2u32 {
            assert!(
                landed.contains(&format!("marker-{iteration}-{member}.txt")),
                "iteration {iteration}'s WRITING member {member} applied its /work: {landed:?}"
            );
        }
    }
    assert!(matches!(
        expansion_record(&rig, execution, &expansion)
            .expect("the record")
            .resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Approved { iteration: 1 }
    ));
}

/// A mid-iteration member death
/// resolves the expansion `failed` and the downstream `summary` never
/// dispatches — zero attempts at its authored name, the run's error naming
/// the dead member.
#[tokio::test(flavor = "current_thread")]
async fn a_member_death_aborts_the_loop_and_the_downstream_never_dispatches() {
    let program = compile_starlark_execution_program(CONSUME_PACK, "loop-consume.star", &[])
        .expect("the consume pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);

    let mut delivered = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    if stage_id == "stage_b" {
                        reactor
                            .handle_message_for_test(
                                kata_transport::types::WorkerMessage::Failed {
                                    assignment_id: frame.attempt_id,
                                    reason: "the member crashed".to_owned(),
                                    verdict: kata_types::effect::DeliveryFailureProvenance::PerformedButFailed,
                                    provider_failure: None,
                                    usage: None,
                                    fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                                },
                            )
                            .expect("the member failure is adjudicated");
                    } else {
                        delivered.push(stage_id.clone());
                        complete_frame(&rig, &reactor, &frame, b"{\"stage\":\"a\",\"marker\":0}");
                    }
                }
            }
        }
    })
    .await
    .expect("the abort settles within the budget");
    let error = outcome.expect_err("a member death fails the run");
    assert!(
        error.to_string().contains("stage_b"),
        "the abort names the dead member: {error}"
    );
    assert!(
        !delivered.iter().any(|stage| stage == "summary"),
        "the downstream stage never dispatched: {delivered:?}"
    );
    assert_eq!(
        arm_attempt_count(&rig, execution, "summary"),
        0,
        "no attempt ever minted for the downstream stage"
    );
}

/// The escalate park is DURABLE: drop the whole rig — dispatcher, runner and
/// all — reopen it on the same directory, and the operator's gate list still
/// carries the expansion gate. Approving through the REOPENED dispatcher
/// resolves the `#op` attempt and a fresh runner's run completes off the
/// recorded decision alone.
#[tokio::test(flavor = "current_thread")]
async fn a_parked_escalate_gate_survives_restart_and_approve_adopts() {
    let program = escalate_program();
    let dir = tempfile::tempdir().unwrap().keep();
    let execution = Ulid::new();
    let expansion = expansion(&program);

    let parked_assignment = {
        let rig = OciNodeRig::open(&dir);
        rig.declare_bound_environment();
        let runner = rig.runner(&program, execution);
        let run = runner.run();
        tokio::pin!(run);
        let (gate, delivered) = drive_to_parked_gate(&rig, &mut run).await;
        assert_eq!(delivered, 4, "two iterations ran before the park");
        gate.assignment_id
    };

    let rig = OciNodeRig::open(&dir);
    let listed = rig
        .dispatcher
        .parked_approval_gates()
        .expect("the reopened gate list reads")
        .into_iter()
        .find(|gate| gate.assignment_id == parked_assignment && gate.expansion.is_some())
        .expect("the parked expansion gate survives the restart");
    rig.dispatcher
        .decide_expansion_gate(
            listed.assignment_id,
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
            kata_core::operational::ExpansionVerdict::Approve,
        )
        .expect("the reopened dispatcher decides the gate");

    let runner = rig.runner(&program, execution);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), runner.run())
        .await
        .expect("the adopted run settles within the budget");
    outcome.expect("an approved gate completes the resumed run");
    assert!(
        expansion_record(&rig, execution, &expansion).is_some(),
        "the adopted record is durable"
    );
}

/// The escalate park is approved, the fold completes the worker under its
/// authored name with the LAST iteration's envelope, and the downstream
/// `summary` consumes exactly that — `consumed` is 1, the second
/// iteration's marker.
const ESCALATE_DOWNSTREAM_PACK: &str = r#"worker = stage(
    id = "worker",
    run = "printf '{\"stage\":\"w\",\"marker\":0}\n'",
    agent = "shell",
    outputs = {
        "stage": "string",
        "marker": "number",
    },
)

controller = stage(
    id = "controller",
    run = "printf '{\"decision\":\"continue\",\"feedback\":\"again\"}\n'",
    agent = "shell",
    depends_on = ["worker"],
    outputs = {
        "decision": "string",
        "feedback": "string",
    },
)

summary = stage(
    id = "summary",
    run = "printf '{\"consumed\":{{ stages.worker.parsed.marker }}}\n'",
    agent = "shell",
    depends_on = ["worker"],
    outputs = {"consumed": "number"},
)

loop(
    body = worker,
    gate = controller,
    max_iterations = 2,
    on_exhaustion = "escalate",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)

workflow("escalate-downstream", root = [worker, controller, summary])
"#;

#[tokio::test(flavor = "current_thread")]
async fn an_adopted_escalate_worker_output_renders_downstream() {
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(
        ESCALATE_DOWNSTREAM_PACK,
        "escalate-downstream.star",
        &[],
    )
    .expect("the escalate-downstream pack compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let gate = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => panic!("the park keeps the run live, got {outcome:?}"),
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let (iteration, _) = member_coordinate(&rig, &frame);
                    let stdout = if stage_id == "worker" {
                        format!("{{\"stage\":\"w\",\"marker\":{iteration}}}")
                    } else {
                        "{\"decision\":\"continue\",\"feedback\":\"again\"}".to_owned()
                    };
                    complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    if let Some(gate) = rig
                        .dispatcher
                        .parked_approval_gates()
                        .expect("the gate list reads")
                        .into_iter()
                        .find(|gate| gate.expansion.is_some())
                    {
                        break gate.assignment_id;
                    }
                }
            }
        }
    })
    .await
    .expect("the bound spends and the gate parks within the budget");

    rig.dispatcher
        .decide_expansion_gate(
            gate,
            &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
            kata_core::operational::ExpansionVerdict::Approve,
        )
        .expect("the operator's approve decides the parked gate");

    let outputs = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome.expect("the run completes"),
                frame = next_frame(&rig) => {
                    complete_frame(&rig, &reactor, &frame, b"{\"consumed\":1}");
                }
            }
        }
    })
    .await
    .expect("the decided run settles within the budget");
    assert_eq!(
        outputs[&SmolStr::new("summary")]["parsed"]["consumed"],
        serde_json::json!(1),
        "the downstream rendered the ADOPTED envelope — iteration 1's marker, not 0's"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// A STATIC `topology(..)` under `oci`. The stage lowers to
// `ExpandBounded` at its OWN stage coordinate: member 0 is the root attempt
// (the authored stage spelling), members `1..=children.len()` the declared
// children under their synthetic `<base>#child-<role>` stage ids — the durable
// child spellings. All of it is read back through the same raw second handle
// the loop cells use.
// ═══════════════════════════════════════════════════════════════════════════

/// The worker-topology pack: `parent` expands over two declared shell workers
/// (both REQUIRED — `role(..)`'s authored default), `successor` gates on the
/// parent's stage completion — which is the accepted expansion record's to
/// apply, never a member frame's.
const TOPOLOGY_PACK: &str = r#"
parent = stage(
    id = "parent",
    agent = "shell",
    run = "printf 'root ran\\n'",
    sandbox = sandbox_profile(workspace = "rw"),
    outputs = {
        "note": "string",
    },
    topology = topology(
        "root_with_parallel_workers",
        root = role("the_root", agent = "shell"),
        workers = [
            role("first_worker", agent = "shell"),
            role("second_worker", agent = "shell"),
        ],
        max_concurrency = 3,
    ),
)

successor = stage(
    id = "successor",
    agent = "shell",
    run = "printf 'successor ran\\n'",
    depends_on = ["parent"],
)

workflow(
    "topology-smoke",
    description = "Model-free smoke: a static topology fans out two declared workers.",
    root = [parent, successor],
)
"#;

/// The quorum pack: `review_parent` expands over two REQUIRED shell reviewers
/// behind `review_quorum(1, block_on_any_finding = True)` — one stage, no
/// successor, so its settlement answer IS the run's.
const QUORUM_PACK: &str = r#"
review_parent = stage(
    id = "review_parent",
    agent = "shell",
    run = "printf 'root ran\\n'",
    topology = topology(
        "review_quorum",
        root = role("the_root", agent = "shell"),
        reviewers = [
            role("first_reviewer", agent = "shell"),
            role("second_reviewer", agent = "shell"),
        ],
        review_quorum = review_quorum(1, block_on_any_finding = True),
        max_concurrency = 2,
    ),
)

workflow(
    "topology-quorum-smoke",
    description = "Model-free smoke: a static topology's review quorum gates the settle.",
    root = [review_parent],
)
"#;

/// The TOPOLOGY pack: identical to [`QUORUM_PACK`] except it also declares
/// a `successor`, so the release leg is proved. Every member is a SHELL
/// member — the rig assembles Command capsules only — so the member capsules
/// ride the stub's scripted stdout (the child prompt's `# `-prefixed header
/// keeps the authored `run` a valid script).
fn topology_program(source: &str, name: &str) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(source, name, &[])
        .expect("the topology pack compiles under oci")
}

/// The `ExpandBounded` of `stage` — the ONE lowering of the topology the
/// stage's own coordinate names.
fn topology_expansion(
    program: &ExecutionProgram,
    stage: &str,
) -> kata_program::execution_program::LoweredOperation {
    let index = program
        .stages
        .keys()
        .position(|id| id.0.as_str() == stage)
        .expect("the stage is present");
    lower_topology_expansion(program, index).expect("the stage expands")
}

/// The durable member index `frame` is bound at — `Some(m)` for a topology
/// member (its occurrence sits at `expansion.path.child(m)`, one level below
/// the expansion), `None` for an ordinary stage attempt.
fn topology_member_of(
    rig: &OciNodeRig,
    frame: &kata_transport::types::CapsuleAssignment,
    expansion: &kata_program::execution_program::LoweredOperation,
) -> Option<u32> {
    let bytes: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT operation_path FROM occurrences WHERE occurrence_id = ?1",
            [frame.occurrence_id.0.0.as_slice()],
            |row| row.get(0),
        )
        .expect("the member's occurrence row");
    let path = OperationPath::from_canonical_bytes(&bytes).expect("the path decodes");
    if path.0.len() == expansion.path.0.len() + 1
        && path.0[..expansion.path.0.len()] == expansion.path.0[..]
    {
        Some(*path.0.last().expect("non-empty"))
    } else {
        None
    }
}

/// SEMANTIC — the stage's claim mints one durable `#op` attempt; the drive
/// fans out root-first (member 0 alone: children mint once the parent
/// dispatches), then the one-pass child fanout; every member
/// mints its occurrence at `expansion.path.child(m)` under its durable stage
/// spelling; the accepted `Settled` record completes the STAGE with the
/// `child_invocations` fan-in and releases `successor`.
#[tokio::test(flavor = "current_thread")]
async fn a_static_topology_drives_root_then_children_and_settles() {
    let program = topology_program(TOPOLOGY_PACK, "topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = topology_expansion(&program, "parent");
    let reactor = reactor(&rig);

    let mut frames: Vec<(String, Option<u32>)> = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome.expect("the topology run completes"),
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let member = topology_member_of(&rig, &frame, &expansion);
                    let stdout = match stage_id.as_str() {
                        "parent" => "{\"note\":\"root ok\"}",
                        "parent#child-first_worker" => "{\"note\":\"first ok\"}",
                        "parent#child-second_worker" => "{\"note\":\"second ok\"}",
                        "successor" => "{\"note\":\"successor ok\"}",
                        other => panic!("no frame is scripted for {other}"),
                    };
                    complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                    frames.push((stage_id, member));
                }
            }
        }
    })
    .await
    .expect("the topology drive reaches a terminal within the budget");

    // FOUR capsules: member 0 wearing the authored `parent`, members 1,2
    // wearing the synthetic child spellings at `path.child(1..=2)`, then the
    // released `successor` at NO member coordinate.
    assert_eq!(
        frames,
        vec![
            ("parent".to_owned(), Some(0)),
            ("parent#child-first_worker".to_owned(), Some(1)),
            ("parent#child-second_worker".to_owned(), Some(2)),
            ("successor".to_owned(), None),
        ],
        "the member dispatch order is root, then the declared children, then the successor"
    );

    // The `Settled` record, read off the raw handle: the stage's own path,
    // maximum 1, the root plus both children in member order.
    let record = expansion_record(&rig, execution, &expansion)
        .expect("the expansion's accepted record resolves");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Settled
        ),
        "the static topology resolves Settled, got {:?}",
        record.resolution
    );
    assert_eq!(record.stage, "parent");
    assert_eq!(
        record
            .members
            .iter()
            .map(|member| (member.iteration, member.member, member.stage.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (0, 0, "parent"),
            (0, 1, "parent#child-first_worker"),
            (0, 2, "parent#child-second_worker"),
        ],
        "the record names the root then the children, in member order"
    );
    assert!(
        record.verdicts.is_empty(),
        "a topology carries no verdict rows"
    );

    // The stage completes with the fan-in envelope:
    // `child_invocations` one row per declared child, `child_invocation_summary`
    // beside it, the root's `parsed` injected at its member fold.
    let parent = outputs
        .get(&SmolStr::new("parent"))
        .expect("the stage completes with its envelope");
    let children = parent["child_invocations"]
        .as_array()
        .expect("the fan-in rows are an array");
    assert_eq!(children.len(), 2, "one fan-in row per declared child");
    for (index, role) in ["first_worker", "second_worker"].iter().enumerate() {
        assert_eq!(children[index]["role"].as_str().unwrap(), *role);
        assert_eq!(children[index]["kind"].as_str().unwrap(), "worker");
        assert!(children[index]["required"].as_bool().unwrap());
        assert_eq!(
            children[index]["stage_name"].as_str().unwrap(),
            format!("parent#child-{role}")
        );
        assert_eq!(children[index]["status"].as_str().unwrap(), "completed");
    }
    assert_eq!(parent["child_invocation_summary"]["total"], 2);
    assert_eq!(parent["child_invocation_summary"]["completed"], 2);
    assert_eq!(parent["child_invocation_summary"]["failed"], 0);
    assert_eq!(
        parent["parsed"]["note"].as_str().unwrap(),
        "root ok",
        "the root member's declared output is injected at its member fold"
    );

    assert!(
        outputs.contains_key(&SmolStr::new("successor")),
        "the record's apply released the successor"
    );
}

/// [`TOPOLOGY_PACK`] with the authored `approval = true` on the fanout stage:
/// the gate is the ROOT member's alone — a declared child bypasses it on a
/// named reason — so the run parks the root's capsule and mints no
/// child until the operator decides.
const GATED_TOPOLOGY_PACK: &str = r#"
parent = stage(
    id = "parent",
    agent = "shell",
    run = "printf 'root ran\\n'",
    approval = True,
    outputs = {
        "note": "string",
    },
    topology = topology(
        "root_with_parallel_workers",
        root = role("the_root", agent = "shell"),
        workers = [
            role("first_worker", agent = "shell"),
            role("second_worker", agent = "shell"),
        ],
        max_concurrency = 3,
    ),
)

workflow(
    "topology-gated-smoke",
    description = "Model-free smoke: an authored approval gate holds a topology's root.",
    root = [parent],
)
"#;

/// GATE — the authored `approval` gate applies to the topology's ROOT
/// member only. While the parked root waits on the operator NO child mints a
/// capsule (children mint once the parent dispatched, and a parked
/// root has not dispatched), and approving dispatches the root first, then
/// the children — never the other way.
///
/// **Watched red**: with the parked-member read inverted (or the root-parked
/// fold collapsed) the derive reads the parked root as live-or-missing and
/// mints the children under the gate; with the bypass arm inverted the ROOT
/// bypasses its own authored gate and never parks at all.
#[tokio::test(flavor = "current_thread")]
async fn an_authored_gate_parks_the_topology_root_and_holds_every_child() {
    let program = topology_program(GATED_TOPOLOGY_PACK, "topology-gated.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = topology_expansion(&program, "parent");
    let reactor = reactor(&rig);

    let mut frames: Vec<(String, Option<u32>)> = Vec::new();
    let mut approved = false;
    let mut children_before_approval = Vec::new();
    let mut parked_stage: Option<String> = None;
    let run = runner.run();
    tokio::pin!(run);
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome.expect("the approved topology completes"),
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    if !approved && stage_id.contains("#child-") {
                        children_before_approval.push(stage_id.clone());
                    }
                    let member = topology_member_of(&rig, &frame, &expansion);
                    let stdout = match stage_id.as_str() {
                        "parent" => "{\"note\":\"root ok\"}",
                        "parent#child-first_worker" => "{\"note\":\"first ok\"}",
                        "parent#child-second_worker" => "{\"note\":\"second ok\"}",
                        other => panic!("no frame is scripted for {other}"),
                    };
                    complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                    frames.push((stage_id, member));
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    if approved {
                        continue;
                    }
                    let gates = rig
                        .dispatcher
                        .parked_approval_gates()
                        .expect("the gate list reads");
                    if let Some(gate) = gates.iter().find(|gate| gate.capsule.is_some()) {
                        parked_stage = Some(gate.stage_name.to_string());
                        rig.dispatcher
                            .approve_capsule_gate(
                                gate.assignment_id,
                                &kata_types::approval::ApprovalPrincipal::UnauthenticatedLoopback,
                            )
                            .await
                            .expect("the operator's approve decides the parked root");
                        approved = true;
                    }
                }
            }
        }
    })
    .await
    .expect("the gated topology drive reaches a terminal within the budget");

    assert_eq!(
        parked_stage.as_deref(),
        Some("parent"),
        "the authored gate parks the ROOT member's capsule, spelled as the stage"
    );
    assert!(
        children_before_approval.is_empty(),
        "no child dispatches while the root is parked: {children_before_approval:?}"
    );
    assert_eq!(
        frames,
        vec![
            ("parent".to_owned(), Some(0)),
            ("parent#child-first_worker".to_owned(), Some(1)),
            ("parent#child-second_worker".to_owned(), Some(2)),
        ],
        "after approval the root runs, then the children, in member order"
    );
    let record = expansion_record(&rig, execution, &expansion)
        .expect("the expansion's accepted record resolves");
    assert!(matches!(
        record.resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Settled
    ));
    assert!(outputs.contains_key(&SmolStr::new("parent")));
}

/// Drive [`TOPOLOGY_PACK`] with every member reporting the `/work` write
/// `writes` names for its durable stage spelling — `(path, bytes)` — and
/// return the run's outcome.
async fn drive_writing_topology(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
    writes: &[(&str, &str, &[u8])],
) -> kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>> {
    let runner = rig.runner(program, execution);
    let reactor = reactor(rig);
    let run = runner.run();
    tokio::pin!(run);
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let stage_id = frame_stage_id(rig, &frame);
                    let delta = writes
                        .iter()
                        .find(|(stage, _, _)| *stage == stage_id)
                        .map(|(_, path, bytes)| named_work_delta(rig, execution, &frame, path, bytes))
                        .or_else(|| {
                            kata_workflow::test_harness::stub_work_delta(
                                &rig.db,
                                &rig.cas,
                                frame.occurrence_id,
                            )
                        });
                    complete_frame_with(rig, &reactor, &frame, b"{\"note\":\"ok\"}", delta);
                }
            }
        }
    })
    .await
    .expect("the writing topology reaches a terminal within the budget")
}

/// The bytes the execution's landed `/work` head holds at `path`.
fn head_file_bytes(rig: &OciNodeRig, execution: Ulid, path: &str) -> Option<Vec<u8>> {
    let head = rig
        .db
        .execution_work_tree_head(execution)
        .unwrap()
        .expect("the head row reads");
    let row = rig
        .db
        .artifact(head.work_tree_artifact_id)
        .unwrap()
        .unwrap();
    let bytes = rig
        .cas
        .get_verified(
            &kata_types::primitives::ObjectId::new(row.object_id),
            row.size_bytes,
            kata_types::tree_artifact::TreeManifest::MAXIMUM_ENCODED_BYTES,
        )
        .expect("the head manifest reads");
    let manifest: kata_types::tree_artifact::TreeManifest =
        serde_json::from_slice(&bytes).expect("the manifest decodes");
    let entry = manifest
        .entries()
        .iter()
        .find(|entry| entry.path.as_str() == path)?;
    let kata_types::tree_artifact::TreeNode::File {
        object, size_bytes, ..
    } = &entry.node
    else {
        return None;
    };
    Some(
        rig.cas
            .get_verified(object, *size_bytes, *size_bytes)
            .expect("the landed file reads"),
    )
}

/// WRITERS — every member of one topology writes `/work`: the root and both
/// workers each report a write to its OWN path. Each member is a `/work` BRANCH
/// forked from the parent's head at one point, so no member's delta goes stale
/// against a sibling's, and the settle merges all three into the parent head;
/// the successor runs over the merged tree. Read from the landed head manifest
/// in CAS, not from kata's report.
///
/// **Would red if:** every member mapped the PARENT's head — the second
/// worker's apply would be refused `work_delta_base_stale` and the run would
/// fail.
#[tokio::test(flavor = "current_thread")]
async fn every_writing_topology_member_lands_on_the_parent_head() {
    let program = topology_program(TOPOLOGY_PACK, "topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let outputs = drive_writing_topology(
        &rig,
        &program,
        execution,
        &[
            ("parent", "root.txt", b"root"),
            ("parent#child-first_worker", "first.txt", b"first"),
            ("parent#child-second_worker", "second.txt", b"second"),
        ],
    )
    .await
    .expect("three writers on disjoint paths complete the run");
    assert!(
        outputs.contains_key(&SmolStr::new("successor")),
        "the successor ran over the merged head"
    );
    for (path, bytes) in [
        ("root.txt", b"root".as_slice()),
        ("first.txt", b"first".as_slice()),
        ("second.txt", b"second".as_slice()),
    ] {
        assert_eq!(
            head_file_bytes(&rig, execution, path).as_deref(),
            Some(bytes),
            "{path} landed on the parent head with the member's bytes"
        );
    }

    // The settle's `owed` gate owes nothing once it has merged: every
    // completed-with-delta occurrence's `#apply` attempt is accepted, and the
    // execution owes no pending apply at all. (This is the invariant the
    // drive_topology pending-apply predicate can only ever observe: at
    // `Decided` every member is already terminal, so its apply was driven —
    // synchronously — in the same pass.)
    let unapplied: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM occurrences o
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
               JOIN transitions t
                 ON t.attempt_id = o.accepted_attempt_id AND t.resulting_state = 'completed'
              WHERE o.execution_id = ?1
                AND t.payload_json LIKE '%\"work_delta_artifact_id\"%'
                AND NOT EXISTS (
                    SELECT 1 FROM occurrences oa
                      JOIN attempts aa ON aa.attempt_id = oa.accepted_attempt_id
                     WHERE oa.execution_id = o.execution_id
                       AND oa.operation_path = o.operation_path
                       AND aa.stage_id LIKE '#apply/%')",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the unapplied-delta count reads");
    assert_eq!(
        unapplied, 0,
        "every completed member delta has its accepted apply — the settle owes \
         no member apply once it merges"
    );
}

/// CONFLICT — two members write ONE path differently: the settle's merge is
/// contested, the expansion resolves `failed` with `work_fanin_conflict`, the
/// stage fails, nothing lands (the parent head is byte-for-byte the admitted
/// tree, read off the raw head row) and the successor never dispatches.
#[tokio::test(flavor = "current_thread")]
async fn two_topology_members_writing_one_path_differently_fail_the_stage() {
    let program = topology_program(TOPOLOGY_PACK, "topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let expansion = topology_expansion(&program, "parent");
    let error = drive_writing_topology(
        &rig,
        &program,
        execution,
        &[
            ("parent#child-first_worker", "shared.txt", b"first"),
            ("parent#child-second_worker", "shared.txt", b"second"),
        ],
    )
    .await
    .expect_err("a contested merge fails the run");
    assert!(
        error.to_string().contains("work_fanin_conflict"),
        "the failure names the fan-in conflict: {error}"
    );
    assert_eq!(
        expansion_terminal_state(&rig, execution, &expansion),
        "failed",
        "the expansion's #op attempt resolved failed"
    );
    assert_eq!(
        head_file_bytes(&rig, execution, "shared.txt"),
        None,
        "neither contested write landed on the parent head"
    );
    let root_head_seq: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT head_seq FROM execution_work_tree_heads WHERE execution_id = ?1 AND branch = ''",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the root head row reads");
    assert_eq!(
        root_head_seq, 0,
        "the parent head never advanced: it is still the admitted tree"
    );
    let successor_attempts: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'successor'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the successor attempt count reads");
    assert_eq!(
        successor_attempts, 0,
        "a failed stage's successor never dispatches"
    );
}

/// A topology ROOT whose output fails its declared contract
/// retries at the root seat's `child(1)` (the topology derive walks the root's
/// chain); the valid retry is the root's envelope — the fan-in carries its
/// `parsed`. The declared children run ONCE: they dispatched beside the live
/// root, and a root retry re-runs the root alone.
///
/// **Watched red**: with the root chain's retry arm disabled the root's
/// invalid output fails the run (`missing declared field "note"`).
#[tokio::test(flavor = "current_thread")]
async fn a_topology_roots_invalid_output_retries_at_its_root_seat() {
    let program = topology_program(TOPOLOGY_PACK, "topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let mut frames: Vec<(String, Vec<u32>, String)> = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let roots = frames.iter().filter(|(stage, _, _)| stage == "parent").count();
                    let stdout = match stage_id.as_str() {
                        "parent" if roots == 0 => "{\"wrong\":true}",
                        _ => "{\"note\":\"ok\"}",
                    };
                    frames.push((
                        stage_id,
                        frame_path(&rig, &frame),
                        member_argv(&rig, &frame).join(" "),
                    ));
                    complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget")
    .expect("the retried root's topology settles");
    let roots: Vec<&(String, Vec<u32>, String)> = frames
        .iter()
        .filter(|(stage, _, _)| stage == "parent")
        .collect();
    assert_eq!(roots.len(), 2, "attempt 0 plus one root retry: {frames:?}");
    let mut retry_seat = roots[0].1.clone();
    retry_seat.push(1);
    assert_eq!(
        roots[1].1, retry_seat,
        "the retry sits at the root seat's child(1)"
    );
    assert_eq!(
        roots[1].2, roots[0].2,
        "a COMMAND root's retry re-runs the same rendered command — the \
         feedback-prompt rebuild is an AGENT root's arm only"
    );
    for child in ["parent#child-first_worker", "parent#child-second_worker"] {
        assert_eq!(
            frames.iter().filter(|(stage, _, _)| stage == child).count(),
            1,
            "{child} runs once"
        );
    }
    assert_eq!(outputs["parent"]["parsed"]["note"], serde_json::json!("ok"));
    assert_eq!(
        outputs["parent"]["child_invocation_summary"]["total"],
        serde_json::json!(2)
    );
}

/// The dynamic-fanout pack: `fan`'s root prints its request array; the one
/// declared role `w` is a REQUIRED shell worker; `mutation_policy =
/// "owned_paths"` makes every worker request name its `owned_paths`; `after`
/// depends on `fan`.
const DYNAMIC_PACK: &str = r#"
fan = stage(
    id = "fan",
    agent = "shell",
    run = "printf 'plan\\n'",
    sandbox = sandbox_profile(workspace = "rw"),
    topology = topology(
        "root_with_parallel_workers",
        root = role("planner", agent = "shell"),
        workers = [
            role("w", agent = "shell"),
        ],
        dynamic_fanout = True,
        mutation_policy = "owned_paths",
        max_concurrency = 3,
        fanout_limit = 3,
    ),
)

after = stage(
    id = "after",
    agent = "shell",
    run = "printf 'after\\n'",
    depends_on = ["fan"],
)

workflow(
    "dynamic-fanout-smoke",
    description = "Model-free smoke: a dynamic fanout under oci.",
    root = [fan, after],
)
"#;

/// The request array the cells' root prints: two owned-path workers.
const TWO_REQUESTS: &str = r#"{"child_invocation_requests": [{"role": "w", "name": "a", "prompt": "do a", "owned_paths": ["a"]}, {"role": "w", "name": "b", "prompt": "do b", "owned_paths": ["b"]}]}"#;

/// What one dynamic-cell frame does: complete with `stdout` and (optionally)
/// one `/work` write, or die.
enum DynamicAnswer {
    Complete(String, Option<(&'static str, &'static [u8])>),
    Die,
}

/// Drive [`DYNAMIC_PACK`] (compiled under `oci` — CHECK admits a dynamic
/// fanout) with `answer(stage)` scripting every frame; returns the
/// outcome and every frame's `(stage, path, argv)` in dispatch order.
async fn drive_dynamic(
    rig: &OciNodeRig,
    execution: Ulid,
    answer: impl Fn(&str) -> DynamicAnswer,
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, Vec<u32>, String)>,
) {
    drive_dynamic_pack(rig, execution, DYNAMIC_PACK, "dynamic-fanout.star", answer).await
}

/// [`drive_dynamic`]'s pack-parameterized body — a second fanout pack needs
/// the same scripted drive, not a copy of it.
async fn drive_dynamic_pack(
    rig: &OciNodeRig,
    execution: Ulid,
    pack: &str,
    name: &str,
    answer: impl Fn(&str) -> DynamicAnswer,
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, Vec<u32>, String)>,
) {
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(pack, name, &[])
        .expect("a dynamic fanout compiles under oci");
    let runner = rig.runner(&program, execution);
    let reactor = reactor(rig);
    let mut frames = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let stage_id = frame_stage_id(rig, &frame);
                    frames.push((
                        stage_id.clone(),
                        frame_path(rig, &frame),
                        member_argv(rig, &frame).join(" "),
                    ));
                    match answer(&stage_id) {
                        DynamicAnswer::Complete(stdout, write) => {
                            let delta = match write {
                                Some((path, bytes)) => {
                                    Some(named_work_delta(rig, execution, &frame, path, bytes))
                                }
                                None => kata_workflow::test_harness::stub_work_delta(
                                    &rig.db,
                                    &rig.cas,
                                    frame.occurrence_id,
                                ),
                            };
                            complete_frame_with(rig, &reactor, &frame, stdout.as_bytes(), delta);
                        }
                        DynamicAnswer::Die => {
                            reactor
                                .handle_message_for_test(kata_transport::types::WorkerMessage::Failed {
                                    assignment_id: frame.attempt_id,
                                    reason: format!("{stage_id} crashed"),
                                    verdict: kata_types::effect::DeliveryFailureProvenance::PerformedButFailed,
                                    provider_failure: None,
                                    usage: None,
                                    fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                                })
                                .expect("the member failure is adjudicated");
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("the dynamic drive reaches a terminal within the budget");
    (outcome, frames)
}

/// The root `/work` head's `head_seq`, read raw.
fn root_head_seq(rig: &OciNodeRig, execution: Ulid) -> i64 {
    raw(&rig.op_path)
        .query_row(
            "SELECT head_seq FROM execution_work_tree_heads WHERE execution_id = ?1 AND branch = ''",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the root head row reads")
}

/// A dynamic fanout runs under `oci`: the root's request array mints one
/// capsule per request at `[i].child(n)` under the
/// `<base>#child-<role>-<label>` spelling, each child's prompt is the
/// dynamic header (owned paths named) over the request's own prompt, each
/// owned-path child writes inside its scope on its OWN `/work` branch, and the
/// settle merges both writes onto the stage's head (read from the CAS
/// manifest) before `after` runs. The fan-in is the dynamic envelope:
/// `dynamic_fanout: true`, the per-request `owned_paths`, and the enforced
/// mutation scope — observed over the recorded deltas (`work_delta`).
///
/// **Would red if:** a dynamic fanout had no capsule form — the pack would be
/// refused at CHECK (`DYNAMIC FANOUT`).
#[tokio::test(flavor = "current_thread")]
async fn a_dynamic_fanout_dispatches_its_requests_and_merges_their_owned_writes() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, frames) = drive_dynamic(&rig, execution, |stage| match stage {
        "fan" => DynamicAnswer::Complete(TWO_REQUESTS.to_owned(), None),
        "fan#child-w-a" => {
            DynamicAnswer::Complete("{\"ok\":1}".to_owned(), Some(("a/x.txt", b"x")))
        }
        "fan#child-w-b" => {
            DynamicAnswer::Complete("{\"ok\":2}".to_owned(), Some(("b/y.txt", b"y")))
        }
        _ => DynamicAnswer::Complete("after".to_owned(), None),
    })
    .await;
    let outputs = outcome.expect("the dynamic fanout settles and `after` runs");
    assert!(outputs.contains_key(&SmolStr::new("after")), "`after` ran");
    let stages: Vec<&str> = frames.iter().map(|(stage, _, _)| stage.as_str()).collect();
    assert_eq!(stages[0], "fan", "the root dispatches alone, first");
    let mut children: Vec<(&str, &Vec<u32>)> = frames
        .iter()
        .filter(|(stage, _, _)| stage.starts_with("fan#child-"))
        .map(|(stage, path, _)| (stage.as_str(), path))
        .collect();
    children.sort();
    let seat = frames[0].1[0];
    assert_eq!(
        children,
        vec![
            ("fan#child-w-a", &vec![seat, 1]),
            ("fan#child-w-b", &vec![seat, 2]),
        ],
        "one child per request at the stage's child coordinates, in request order"
    );
    let child_a_argv = &frames
        .iter()
        .find(|(stage, _, _)| stage == "fan#child-w-a")
        .expect("child a ran")
        .2;
    assert!(
        child_a_argv.contains("Owned paths:") && child_a_argv.contains("do a"),
        "the child runs the dynamic header over its request's prompt: {child_a_argv}"
    );
    assert_eq!(
        head_file_bytes(&rig, execution, "a/x.txt").as_deref(),
        Some(b"x".as_slice())
    );
    assert_eq!(
        head_file_bytes(&rig, execution, "b/y.txt").as_deref(),
        Some(b"y".as_slice())
    );
    let summary = &outputs["fan"]["child_invocation_summary"];
    assert_eq!(
        summary["dynamic_fanout"],
        serde_json::json!(true),
        "the fan-in is the dynamic envelope: {}",
        outputs["fan"]
    );
    assert_eq!(summary["total"], serde_json::json!(2));
    // The scope carries exactly what it enforced — every changed path and the
    // owned set it was held to — and no constant label for the one observer
    // (each member's recorded `/work` delta) that exists.
    let scope_keys: std::collections::BTreeSet<&str> = summary["mutation_scope"]
        .as_object()
        .expect("the enforced scope is an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        scope_keys,
        std::collections::BTreeSet::from(["changed_paths", "enforced", "owned_paths"]),
        "{}",
        summary["mutation_scope"]
    );
    assert_eq!(
        summary["mutation_scope"]["changed_paths"],
        serde_json::json!(["a/x.txt", "b/y.txt"])
    );
    assert_eq!(
        outputs["fan"]["child_invocations"][0]["owned_paths"],
        serde_json::json!(["a"]),
        "the fan-in rows carry each request's owned paths: {}",
        outputs["fan"]["child_invocations"]
    );
}

/// A child that writes OUTSIDE its `owned_paths` fails the stage with
/// the owned-paths phrasing, before any branch merges: the stage's head never
/// advances (raw `head_seq` 0) and `after` never dispatches.
#[tokio::test(flavor = "current_thread")]
async fn a_dynamic_child_writing_outside_its_owned_paths_fails_the_stage() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, frames) = drive_dynamic(&rig, execution, |stage| match stage {
        "fan" => DynamicAnswer::Complete(TWO_REQUESTS.to_owned(), None),
        "fan#child-w-a" => DynamicAnswer::Complete("{}".to_owned(), Some(("b/stolen.txt", b"!"))),
        _ => DynamicAnswer::Complete("{}".to_owned(), None),
    })
    .await;
    let error = outcome.expect_err("an out-of-scope write fails the run");
    assert!(
        error.to_string().contains(
            "dynamic child \"fan#child-w-a\" observed changed path(s) outside declared owned_paths"
        ),
        "named by the owned-paths phrasing: {error}"
    );
    assert_eq!(
        root_head_seq(&rig, execution),
        0,
        "nothing landed on the stage's head"
    );
    assert!(frames.iter().all(|(stage, _, _)| stage != "after"));
}

/// The request array is held to the CHECKED plan by the request
/// validator: a request for an undeclared role fails the stage with its
/// phrasing and mints no child.
#[tokio::test(flavor = "current_thread")]
async fn a_request_for_an_undeclared_role_fails_the_stage_and_mints_nothing() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, frames) = drive_dynamic(&rig, execution, |stage| match stage {
        "fan" => DynamicAnswer::Complete(
            r#"{"child_invocation_requests": [{"role": "ghost", "prompt": "boo", "owned_paths": ["g"]}]}"#
                .to_owned(),
            None,
        ),
        _ => DynamicAnswer::Complete("{}".to_owned(), None),
    })
    .await;
    let error = outcome.expect_err("an undeclared role fails the run");
    assert!(
        error
            .to_string()
            .contains("role \"ghost\" is not declared in topology"),
        "the request validator's phrasing: {error}"
    );
    assert_eq!(frames.len(), 1, "only the root ran");
}

/// A dead REQUIRED child fails the stage with the dynamic phrasing.
#[tokio::test(flavor = "current_thread")]
async fn a_dead_required_dynamic_child_fails_the_stage() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, _) = drive_dynamic(&rig, execution, |stage| match stage {
        "fan" => DynamicAnswer::Complete(TWO_REQUESTS.to_owned(), None),
        "fan#child-w-b" => DynamicAnswer::Die,
        _ => DynamicAnswer::Complete("{}".to_owned(), None),
    })
    .await;
    let error = outcome.expect_err("a dead required child fails the run");
    assert!(
        error
            .to_string()
            .contains("required dynamic child invocation \"w\" failed"),
        "the dynamic phrasing: {error}"
    );
}

/// A dynamic child never plans children: one whose output carries its
/// own request array fails the stage `dynamic_fanout_nested`.
#[tokio::test(flavor = "current_thread")]
async fn a_dynamic_child_requesting_children_is_refused_nested() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, _) = drive_dynamic(&rig, execution, |stage| match stage {
        // The root and child `a` both print a request array — the child's is
        // the nested request the drive refuses.
        "fan" | "fan#child-w-a" => DynamicAnswer::Complete(TWO_REQUESTS.to_owned(), None),
        _ => DynamicAnswer::Complete("{}".to_owned(), None),
    })
    .await;
    let error = outcome.expect_err("a nested request fails the run");
    assert!(
        error.to_string().contains("dynamic_fanout_nested"),
        "refused by name: {error}"
    );
}

/// The nested-request refusal reads request KEYS only: a dynamic child
/// whose stdout is a bare JSON array (which the ROOT's reader would take as
/// its request list) is an ordinary answer, and the stage settles.
///
/// **Watched red**: with the nested check reading `dynamic_child_request_payload`
/// (which accepts a bare array) the stage fails `dynamic_fanout_nested`.
#[tokio::test(flavor = "current_thread")]
async fn a_dynamic_child_printing_a_json_array_is_no_nested_request() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, _) = drive_dynamic(&rig, execution, |stage| match stage {
        "fan" => DynamicAnswer::Complete(TWO_REQUESTS.to_owned(), None),
        "fan#child-w-a" => DynamicAnswer::Complete("[1, 2, 3]".to_owned(), None),
        _ => DynamicAnswer::Complete("{}".to_owned(), None),
    })
    .await;
    let outputs = outcome.expect("an array-printing child is an ordinary answer");
    assert_eq!(
        outputs["fan"]["child_invocation_summary"]["total"],
        serde_json::json!(2)
    );
}

/// K-pair — the runner dies mid-fanout (the root and child `a` accepted,
/// child `b` dispatched but unanswered): the resumed run re-derives the roster
/// from the durable root output, re-dispatches no accepted member, and settles
/// once — exactly one occurrence per member (raw SQLite).
#[tokio::test(flavor = "current_thread")]
async fn a_crash_mid_fanout_resumes_with_only_the_missing_child() {
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(DYNAMIC_PACK, "dynamic-fanout.star", &[])
        .expect("a dynamic fanout compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let reactor = reactor(&rig);
    {
        let runner = rig.runner(&program, execution);
        let run = runner.run();
        tokio::pin!(run);
        let mut answered = 0usize;
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            while answered < 2 {
                tokio::select! {
                    outcome = &mut run => panic!("the run cannot finish before the crash: {outcome:?}"),
                    frame = next_frame(&rig) => {
                        match frame_stage_id(&rig, &frame).as_str() {
                            "fan" => complete_frame(&rig, &reactor, &frame, TWO_REQUESTS.as_bytes()),
                            "fan#child-w-a" => complete_frame(&rig, &reactor, &frame, b"{}"),
                            // Child `b` is the frame the crash strands.
                            _ => continue,
                        }
                        answered += 1;
                    }
                }
            }
        })
        .await
        .expect("the root and child a land within the budget");
    }
    let runner = rig.runner(&program, execution);
    let run = runner.run();
    tokio::pin!(run);
    let mut resumed: Vec<String> = Vec::new();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage = frame_stage_id(&rig, &frame);
                    complete_frame(&rig, &reactor, &frame, b"{}");
                    resumed.push(stage);
                }
            }
        }
    })
    .await
    .expect("the resumed drive settles within the budget");
    outcome.expect("the resumed fanout settles");
    assert!(
        !resumed
            .iter()
            .any(|stage| stage == "fan" || stage == "fan#child-w-a"),
        "no accepted member re-dispatches: {resumed:?}"
    );
    for stage in ["fan", "fan#child-w-a", "fan#child-w-b"] {
        let occurrences: i64 = raw(&rig.op_path)
            .query_row(
                "SELECT COUNT(DISTINCT occurrence_id) FROM attempts WHERE execution_id = ?1 AND stage_id = ?2",
                rusqlite::params![execution.to_bytes().as_slice(), stage],
                |row| row.get(0),
            )
            .expect("the occurrence count reads");
        assert_eq!(occurrences, 1, "{stage}: exactly one occurrence");
    }
}

/// An EMPTY request array settles the stage with no children (the
/// empty-request arm): the fan-in records zero children and `after`
/// runs.
#[tokio::test(flavor = "current_thread")]
async fn an_empty_request_array_settles_the_stage_with_no_children() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, frames) = drive_dynamic(&rig, execution, |stage| match stage {
        "fan" => DynamicAnswer::Complete(r#"{"child_invocation_requests": []}"#.to_owned(), None),
        _ => DynamicAnswer::Complete("after".to_owned(), None),
    })
    .await;
    let outputs = outcome.expect("an empty fanout settles");
    assert_eq!(
        outputs["fan"]["child_invocation_summary"]["total"],
        serde_json::json!(0)
    );
    assert_eq!(
        frames
            .iter()
            .map(|(stage, _, _)| stage.as_str())
            .collect::<Vec<_>>(),
        ["fan", "after"]
    );
}

/// A fanout of exactly ONE request settles and merges: the settle's
/// fan-in lowers member 1 through its REQUEST — a dynamic expansion's checked
/// template is `[path.child(0)]` alone, so the member-index lowering that
/// serves an undeclared seat has no entry for member 1.
///
/// **Watched red**: with `topology_fan_in`'s member→child match inverted the
/// single child no longer matches member 1, the `None` arm lowers member 1 by
/// index into a one-entry template, and the run dies `UnknownMember`.
#[tokio::test(flavor = "current_thread")]
async fn a_single_dynamic_child_settles_and_merges_its_owned_write() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, frames) = drive_dynamic(&rig, execution, |stage| match stage {
        "fan" => DynamicAnswer::Complete(
            r#"{"child_invocation_requests": [{"role": "w", "name": "a", "prompt": "do a", "owned_paths": ["a"]}]}"#
                .to_owned(),
            None,
        ),
        "fan#child-w-a" => {
            DynamicAnswer::Complete("{\"ok\":1}".to_owned(), Some(("a/x.txt", b"x")))
        }
        _ => DynamicAnswer::Complete("after".to_owned(), None),
    })
    .await;
    let outputs = outcome.expect("the single-child fanout settles");
    assert!(outputs.contains_key(&SmolStr::new("after")), "`after` ran");
    assert_eq!(
        frames
            .iter()
            .map(|(stage, _, _)| stage.as_str())
            .collect::<Vec<_>>(),
        ["fan", "fan#child-w-a", "after"],
        "one request mints exactly one child"
    );
    assert_eq!(
        head_file_bytes(&rig, execution, "a/x.txt").as_deref(),
        Some(b"x".as_slice()),
        "the child's owned write landed on the stage's head"
    );
}

/// The dynamic REVIEW arm: `fan` declares one OPTIONAL worker role and one REQUIRED
/// reviewer role behind `review_quorum(1)`, so a request for `w` that dies is
/// an advisory failure and a request for `r` is the quorum's only input.
const DYNAMIC_REVIEW_PACK: &str = r#"
fan = stage(
    id = "fan",
    agent = "shell",
    run = "printf 'plan\\n'",
    sandbox = sandbox_profile(workspace = "rw"),
    topology = topology(
        "root_with_parallel_workers",
        root = role("planner", agent = "shell"),
        workers = [
            role("w", agent = "shell", required = False),
        ],
        reviewers = [
            role("r", agent = "shell"),
        ],
        dynamic_fanout = True,
        mutation_policy = "owned_paths",
        review_quorum = review_quorum(1, block_on_any_finding = True),
        max_concurrency = 3,
        fanout_limit = 3,
    ),
)

after = stage(
    id = "after",
    agent = "shell",
    run = "printf 'after\\n'",
    depends_on = ["fan"],
)

workflow(
    "dynamic-review-smoke",
    description = "Model-free smoke: a dynamic fanout carrying a reviewer request.",
    root = [fan, after],
)
"#;

/// The dynamic fan-in's `child_invocation_summary` is not a bag of
/// frames: a reviewer-kinded REQUEST contributes its verdict to `review_votes`
/// and to the quorum evaluation (a worker's output never does), a dead
/// OPTIONAL child lands in `advisory_failures` (a required one would have
/// failed the stage), and both lists ride the summary only when non-empty.
///
/// **Watched red**: with the verdict arm inverted the reviewer contributes no
/// vote and `review_votes` is absent; with either non-empty guard deleted the
/// list is emitted backwards — present-empty here, absent-full under the same
/// shape — and with the quorum's reviewer filter inverted the approving
/// reviewer counts for nothing and `review_quorum.passed` reads `false`.
#[tokio::test(flavor = "current_thread")]
async fn a_dynamic_fanout_records_reviewer_votes_quorum_and_advisory_failures() {
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, _) = drive_dynamic_pack(
        &rig,
        execution,
        DYNAMIC_REVIEW_PACK,
        "dynamic-review.star",
        |stage| match stage {
            "fan" => DynamicAnswer::Complete(
                r#"{"child_invocation_requests": [{"role": "w", "name": "a", "prompt": "do a", "owned_paths": ["a"]}, {"role": "r", "name": "c", "prompt": "check"}]}"#
                    .to_owned(),
                None,
            ),
            "fan#child-r-c" => {
                DynamicAnswer::Complete(r#"{"verdict":"approve"}"#.to_owned(), None)
            }
            "fan#child-w-a" => DynamicAnswer::Die,
            _ => DynamicAnswer::Complete("{}".to_owned(), None),
        },
    )
    .await;
    let outputs = outcome.expect("one approving reviewer meets the quorum");
    let summary = &outputs["fan"]["child_invocation_summary"];
    assert_eq!(summary["total"], serde_json::json!(2));
    assert_eq!(summary["completed"], serde_json::json!(1));
    assert_eq!(summary["failed"], serde_json::json!(1));
    assert_eq!(
        summary["review_votes"],
        serde_json::json!([{
            "role": "r",
            "stage_name": "fan#child-r-c",
            "required": true,
            "verdict": "approve",
            "classification": "approve",
        }]),
        "the reviewer's verdict, and only a reviewer-kinded request's, is a vote"
    );
    assert_eq!(
        summary["advisory_failures"][0]["role"],
        serde_json::json!("w"),
        "the dead optional worker lands in advisory_failures"
    );
    assert_eq!(
        summary["advisory_failures"][0]["stage_name"],
        serde_json::json!("fan#child-w-a")
    );
    let quorum = &summary["review_quorum"];
    assert_eq!(quorum["required"], serde_json::json!(1));
    assert_eq!(
        quorum["approved"],
        serde_json::json!(1),
        "the quorum evaluated the reviewer request, not the worker's"
    );
    assert_eq!(quorum["passed"], serde_json::json!(true));
    assert_eq!(quorum["available_reviewers"], serde_json::json!(1));
}

/// The loop-topology pack: the loop body `implement` is a `root_with_parallel_workers`
/// topology, the gate `review` a `review_quorum(1, block_on_any_finding)`
/// topology with one REQUIRED and one optional reviewer, and `after` depends on
/// the gate. Every role is a shell role, so the stub scripts each verdict.
const LOOP_TOPOLOGY_PACK: &str = r#"
implement = stage(
    id = "implement",
    agent = "shell",
    run = "printf 'impl iter={{ review.iteration }} fb={{ review.feedback }}\\n'",
    sandbox = sandbox_profile(workspace = "rw"),
    topology = topology(
        "root_with_parallel_workers",
        root = role("impl_root", agent = "shell"),
        workers = [
            role("w1", agent = "shell"),
            role("w2", agent = "shell"),
        ],
        max_concurrency = 3,
    ),
)

review = stage(
    id = "review",
    agent = "shell",
    run = "printf '{\"verdict\":\"approve\",\"feedback\":\"ok\"}\\n'",
    outputs = {
        "verdict": "string",
        "feedback": "string",
    },
    depends_on = ["implement"],
    topology = topology(
        "review_quorum",
        root = role("review_root", agent = "shell"),
        reviewers = [
            role("r1", agent = "shell"),
            role("r2", agent = "shell", required = False),
        ],
        review_quorum = review_quorum(1, block_on_any_finding = True),
        max_concurrency = 3,
    ),
)

after = stage(
    id = "after",
    agent = "shell",
    run = "printf 'after\\n'",
    depends_on = ["review"],
)

loop(
    body = implement,
    gate = review,
    max_iterations = 2,
    on_exhaustion = "fail",
)

workflow(
    "loop-topology-smoke",
    description = "Model-free smoke: topologies as a loop's body and gate.",
    root = [implement, review, after],
)
"#;

/// The durable coordinate of `frame`'s occurrence.
fn frame_path(rig: &OciNodeRig, frame: &kata_transport::types::CapsuleAssignment) -> Vec<u32> {
    let bytes: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT operation_path FROM occurrences WHERE occurrence_id = ?1",
            [frame.occurrence_id.0.0.as_slice()],
            |row| row.get(0),
        )
        .expect("the frame's occurrence row");
    OperationPath::from_canonical_bytes(&bytes)
        .expect("the path decodes")
        .0
}

/// Drive [`LOOP_TOPOLOGY_PACK`] with `stdout(stage, iteration)` scripting every
/// member frame; returns the run outcome, every frame's `(stage, path)` in
/// dispatch order, and each `implement` ROOT frame's argv by iteration.
async fn drive_loop_topology(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
    stdout: impl Fn(&str, u32) -> Option<String>,
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, Vec<u32>)>,
    std::collections::BTreeMap<u32, String>,
) {
    drive_loop_topology_failing_with(rig, program, execution, stdout, None).await
}

/// [`drive_loop_topology`] whose FAILED frames report `fail_usage` — the usage a
/// performed-but-failed agent turn carries to the main — instead of none.
async fn drive_loop_topology_failing_with(
    rig: &OciNodeRig,
    program: &ExecutionProgram,
    execution: Ulid,
    stdout: impl Fn(&str, u32) -> Option<String>,
    fail_usage: Option<kata_types::metering::StageUsage>,
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, Vec<u32>)>,
    std::collections::BTreeMap<u32, String>,
) {
    let runner = rig.runner(program, execution);
    let reactor = reactor(rig);
    let mut frames = Vec::new();
    let mut root_argv = std::collections::BTreeMap::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let stage_id = frame_stage_id(rig, &frame);
                    let path = frame_path(rig, &frame);
                    let iteration = if path.len() == 4 { path[1] } else { 0 };
                    if stage_id == "implement" {
                        root_argv.insert(iteration, member_argv(rig, &frame).join(" "));
                    }
                    match stdout(&stage_id, iteration) {
                        Some(bytes) => complete_frame(rig, &reactor, &frame, bytes.as_bytes()),
                        None => {
                            reactor
                                .handle_message_for_test(
                                    kata_transport::types::WorkerMessage::Failed {
                                        assignment_id: frame.attempt_id,
                                        reason: format!("{stage_id} crashed"),
                                        verdict: kata_types::effect::DeliveryFailureProvenance::PerformedButFailed,
                                        provider_failure: None,
                                        usage: fail_usage.clone(),
                                        fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                                    },
                                )
                                .expect("the member failure is adjudicated");
                        }
                    }
                    frames.push((stage_id, path));
                }
            }
        }
    })
    .await
    .expect("the loop-topology drive reaches a terminal within the budget");
    (outcome, frames, root_argv)
}

/// LOOP SEMANTIC — a topology fans out EVERY iteration, body and gate alike, and
/// an unmet quorum on the GATE is the loop's refine. Iteration 0: the required
/// reviewer blocks, so the gate's quorum is unmet → the loop refines and the
/// quorum's own reason rides the next iteration's `{{ review.feedback }}` (read
/// off the iteration-1 root capsule's argv). Iteration 1: the reviewer approves
/// → the loop approves and `after` runs. Raw: every nested member occurrence
/// sits at `[loop, N, m, r]`, both iterations' nested `#op` attempts are
/// accepted, and the loop record's verdict rows carry the quorum cause.
///
/// **Watched red**: with the gate-quorum override removed from
/// `derive_topology` the iteration-0 gate FAILS and the loop aborts.
#[tokio::test(flavor = "current_thread")]
async fn a_loop_runs_its_topologies_every_iteration_and_refines_on_an_unmet_gate_quorum() {
    let program = topology_program(LOOP_TOPOLOGY_PACK, "loop-topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let loop_expansion = expansion(&program);
    let (outcome, frames, root_argv) =
        drive_loop_topology(&rig, &program, execution, |stage, iteration| {
            Some(
                match (stage, iteration) {
                    ("review", _) => "{\"verdict\":\"approve\",\"feedback\":\"root ok\"}",
                    ("review#child-r1", 0) => "{\"verdict\":\"block\"}",
                    ("review#child-r1" | "review#child-r2", _) => "{\"verdict\":\"approve\"}",
                    _ => "{\"note\":\"ok\"}",
                }
                .to_owned(),
            )
        })
        .await;
    let outputs = outcome.expect("the loop approves at iteration 1");
    assert!(outputs.contains_key(&SmolStr::new("after")), "`after` ran");

    let loop_path = loop_expansion.path.0[0];
    let nested: Vec<(String, Vec<u32>)> = frames
        .iter()
        .filter(|(stage, _)| stage != "after")
        .cloned()
        .collect();
    let mut expected = Vec::new();
    for iteration in 0..2u32 {
        for (member, base, children) in [
            (0u32, "implement", ["w1", "w2"]),
            (1, "review", ["r1", "r2"]),
        ] {
            expected.push((base.to_owned(), vec![loop_path, iteration, member, 0]));
            for (r, child) in children.iter().enumerate() {
                expected.push((
                    format!("{base}#child-{child}"),
                    vec![loop_path, iteration, member, u32::try_from(r + 1).unwrap()],
                ));
            }
        }
    }
    let mut got = nested.clone();
    got.sort();
    expected.sort();
    assert_eq!(
        got, expected,
        "both topologies fanned out at both iterations, one level below the loop member"
    );

    let refine_render = root_argv
        .get(&1)
        .expect("the iteration-1 implement root ran");
    assert!(
        refine_render.contains("iter=1")
            && refine_render.contains("review quorum not met")
            && refine_render.contains("root ok"),
        "the unmet quorum's reason rides the refine feedback after the root's own: {refine_render}"
    );

    let record = expansion_record(&rig, execution, &loop_expansion).expect("the loop's record");
    assert!(matches!(
        record.resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Approved { iteration: 1 }
    ));
    assert_eq!(record.verdicts.len(), 2);
    assert!(
        record.verdicts[0].quorum_unmet.is_some() && record.verdicts[1].quorum_unmet.is_none(),
        "iteration 0's verdict row carries the quorum cause, iteration 1's none: {:?}",
        record.verdicts
    );
    let accepted_nested: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts a JOIN occurrences o ON o.accepted_attempt_id = a.attempt_id
              WHERE a.execution_id = ?1 AND a.executor = 'main' AND a.stage_id LIKE '#op/%.%'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the nested #op count reads");
    assert_eq!(
        accepted_nested, 4,
        "two nested topologies per iteration, each accepted"
    );
}

/// LOOP BRANCHES — a loop BODY topology's writing members each map their own
/// `/work` branch of the loop member's head, and the nested settle merges them
/// onto it (`expansion_settle_head` for a `LoopMemberTopology`): the gate
/// approves at iteration 0 and all three writes are on the landed head, read
/// from the CAS manifest, before `after` runs.
#[tokio::test(flavor = "current_thread")]
async fn a_loop_body_topologys_writers_merge_onto_the_loop_members_head() {
    let program = topology_program(LOOP_TOPOLOGY_PACK, "loop-topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = reactor(&rig);
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let write = match stage_id.as_str() {
                        "implement" => Some(("root.txt", b"root".as_slice())),
                        "implement#child-w1" => Some(("w1.txt", b"w1".as_slice())),
                        "implement#child-w2" => Some(("w2.txt", b"w2".as_slice())),
                        _ => None,
                    };
                    let delta = match write {
                        Some((path, bytes)) => Some(named_work_delta(&rig, execution, &frame, path, bytes)),
                        None => kata_workflow::test_harness::stub_work_delta(&rig.db, &rig.cas, frame.occurrence_id),
                    };
                    let stdout = if stage_id == "review" {
                        "{\"verdict\":\"approve\",\"feedback\":\"root ok\"}"
                    } else if stage_id.starts_with("review#child-") {
                        "{\"verdict\":\"approve\"}"
                    } else {
                        "{\"note\":\"ok\"}"
                    };
                    complete_frame_with(&rig, &reactor, &frame, stdout.as_bytes(), delta);
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    let outputs = outcome.expect("the loop approves at iteration 0");
    assert!(outputs.contains_key(&SmolStr::new("after")), "`after` ran");
    for (path, bytes) in [
        ("root.txt", b"root".as_slice()),
        ("w1.txt", b"w1".as_slice()),
        ("w2.txt", b"w2".as_slice()),
    ] {
        assert_eq!(
            head_file_bytes(&rig, execution, path).as_deref(),
            Some(bytes),
            "{path} landed on the loop member's head"
        );
    }
}

/// LOOP DEATH — a REQUIRED reviewer's attempt DIES: the gate topology fails (a
/// crash is not a vote), which is the loop's member death, and the loop aborts
/// by name; `after` never dispatches.
#[tokio::test(flavor = "current_thread")]
async fn a_dead_required_reviewer_in_a_gate_topology_aborts_the_loop() {
    let program = topology_program(LOOP_TOPOLOGY_PACK, "loop-topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let (outcome, frames, _) =
        drive_loop_topology(&rig, &program, execution, |stage, _| match stage {
            "review#child-r1" => None,
            "review" => Some("{\"verdict\":\"approve\",\"feedback\":\"root ok\"}".to_owned()),
            _ => Some("{\"note\":\"ok\"}".to_owned()),
        })
        .await;
    let error = outcome.expect_err("a dead required reviewer aborts the loop");
    let text = error.to_string();
    assert!(
        text.contains("required child invocation \"r1\" failed"),
        "the abort names the dead required role: {text}"
    );
    assert!(
        frames.iter().all(|(stage, _)| stage != "after"),
        "`after` never dispatches"
    );
}

/// **A loop bound charges a FAILED attempt's turn** — here an advisory reviewer of the
/// gate's `review_quorum` topology, whose death the quorum outlives. The reviewer's
/// failed frame reports the usage its turn spent; the gate topology still settles
/// (the required reviewer approves), and the loop's bound trips on the gate member
/// before its verdict classifies — `Exhausted{1, fail}` read off the raw `#op`
/// terminal, both members folded, no verdict, the run failed naming the trip:
///
/// * `token_bound(100)` over the failed turn's 500 in + 40 out (540 tokens);
/// * `cost_bound(0.0005)` (500 micro-USD) over its authoritative 600 micro-USD;
/// * `token_bound(100)` over an `Unavailable` charge — CLOSED, naming the member;
/// * `cost_bound(0.0005)` over the same `Unavailable` charge — CLOSED, naming it too.
///
/// **Would red if:** the loop fold read only each member's accepted envelope (the
/// fan-in sums completed children's cost and no child's tokens, and drops a failed
/// child's charge: the loop approves at iteration 0 and `after` runs), or read the
/// failed turn's unknown token count or cost as `0`.
#[tokio::test(flavor = "current_thread")]
async fn a_loop_bound_charges_a_failed_advisory_reviewers_turn() {
    use kata_types::metering::{MeteredCost, StageUsage};
    let spent = |micro_usd| {
        StageUsage::metered(
            &kata_types::cache::TokenUsage {
                input: 500,
                output: 40,
                cache_read: 0,
                cache_write: 0,
            },
            MeteredCost::Authoritative { micro_usd },
            0,
        )
    };
    let mut wrong = Vec::new();
    for (bound, usage, trip) in [
        (
            "token_bound(100)",
            spent(1),
            "loop token bound exceeded: 540 > 100 tokens",
        ),
        (
            "cost_bound(0.0005)",
            spent(600),
            "loop cost bound exceeded: 600 > 500 micro-USD",
        ),
        (
            "token_bound(100)",
            StageUsage::unmetered("nanocode_openai", "gpt-declared"),
            "loop token bound unenforceable: member \"review\" recorded no token count \
             (token_metering_unavailable)",
        ),
        (
            "cost_bound(0.0005)",
            StageUsage::unmetered("nanocode_openai", "gpt-declared"),
            "loop cost bound unenforceable: member \"review\" recorded no measurable cost \
             (metering_unavailable)",
        ),
    ] {
        let source = LOOP_TOPOLOGY_PACK.replace(
            "    on_exhaustion = \"fail\",\n)",
            &format!("    on_exhaustion = \"fail\",\n    bounds = [{bound}],\n)"),
        );
        assert_ne!(
            source, LOOP_TOPOLOGY_PACK,
            "the bound is spliced into the loop"
        );
        let program = topology_program(&source, "loop-topology-bounded.star");
        let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
        rig.declare_bound_environment();
        let execution = Ulid::new();
        let loop_expansion = expansion(&program);
        let (outcome, _, _) = drive_loop_topology_failing_with(
            &rig,
            &program,
            execution,
            |stage, _| match stage {
                "review#child-r2" => None,
                "review" => Some("{\"verdict\":\"approve\",\"feedback\":\"root ok\"}".to_owned()),
                "review#child-r1" => Some("{\"verdict\":\"approve\"}".to_owned()),
                _ => Some("{\"note\":\"ok\"}".to_owned()),
            },
            Some(usage),
        )
        .await;
        let record = expansion_record(&rig, execution, &loop_expansion).expect("the loop's record");
        let tripped = matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 1,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Fail,
            }
        ) && record.members.len() == 2
            && record.verdicts.is_empty();
        let named = outcome
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains(trip));
        if !(tripped && named) {
            wrong.push(format!(
                "{bound}, expecting `{trip}`: record {:?} with {} member(s) and {} verdict(s); \
                 the run {}",
                record.resolution,
                record.members.len(),
                record.verdicts.len(),
                match &outcome {
                    Ok(_) => "completed".to_owned(),
                    Err(error) => format!("failed: {error}"),
                }
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// LOOP EXHAUSTION — the gate's quorum stays unmet through the LAST iteration:
/// an ordinary refine-at-max, so `on_exhaustion = "fail"` fails the loop.
#[tokio::test(flavor = "current_thread")]
async fn an_unmet_gate_quorum_at_the_last_iteration_exhausts_the_loop() {
    let program = topology_program(LOOP_TOPOLOGY_PACK, "loop-topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let loop_expansion = expansion(&program);
    let (outcome, _, _) = drive_loop_topology(&rig, &program, execution, |stage, _| {
        Some(
            match stage {
                "review" => "{\"verdict\":\"approve\",\"feedback\":\"root ok\"}",
                "review#child-r1" => "{\"verdict\":\"block\"}",
                _ => "{\"note\":\"ok\"}",
            }
            .to_owned(),
        )
    })
    .await;
    outcome.expect_err("a quorum unmet at max iterations fails under on_exhaustion = fail");
    let record = expansion_record(&rig, execution, &loop_expansion).expect("the loop's record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 2,
                ..
            }
        ),
        "the bound was spent on refines: {:?}",
        record.resolution
    );
    assert!(
        record
            .verdicts
            .iter()
            .all(|verdict| verdict.quorum_unmet.is_some())
    );
}

/// A NESTED topology root's structured-output retry sits
/// one level below its root seat: `[loop, N, m, 0, k]`, depth five where a
/// top-level root retry is depth three. The gate `review`'s root emits invalid
/// JSON on attempt 0; the retry mints at `[l, 0, 1, 0, 1]`, re-runs the root,
/// and its valid verdict lets iteration 0's quorum pass — `after` releases.
///
/// **Watched red**: with the root-retry arm of `expansion_member_path_of`
/// slicing or indexing at `len() / 2`, the depth-5 retry coordinate
/// classifies as no member — the frame never folds and the run fails rather
/// than approving at iteration 0.
#[tokio::test(flavor = "current_thread")]
async fn a_loop_member_topologys_root_retries_at_its_nested_root_seat() {
    let program = topology_program(LOOP_TOPOLOGY_PACK, "loop-topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let loop_expansion = expansion(&program);
    let review_roots = std::cell::Cell::new(0u32);
    let (outcome, frames, _) = drive_loop_topology(&rig, &program, execution, |stage, _| {
        Some(
            match stage {
                "review" if review_roots.get() == 0 => {
                    review_roots.set(1);
                    "{\"wrong\":true}"
                }
                "review" => "{\"verdict\":\"approve\",\"feedback\":\"root ok\"}",
                "review#child-r1" | "review#child-r2" => "{\"verdict\":\"approve\"}",
                _ => "{\"note\":\"ok\"}",
            }
            .to_owned(),
        )
    })
    .await;
    let outputs = outcome.expect("the retried nested root's loop approves");
    assert!(outputs.contains_key(&SmolStr::new("after")), "`after` ran");

    let loop_path = loop_expansion.path.0[0];
    let review_frames: Vec<&Vec<u32>> = frames
        .iter()
        .filter(|(stage, _)| stage == "review")
        .map(|(_, path)| path)
        .collect();
    let root_seat = vec![loop_path, 0, 1, 0];
    let mut retry_seat = root_seat.clone();
    retry_seat.push(1);
    assert_eq!(
        review_frames,
        vec![&root_seat, &retry_seat],
        "the nested root ran attempt 0 at its member seat and its retry at \
         the seat's child(1): {frames:?}"
    );
    let record = expansion_record(&rig, execution, &loop_expansion).expect("the loop's record");
    assert!(matches!(
        record.resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Approved { iteration: 0 }
    ));
}

/// REQUIRED-CHILD — a dead REQUIRED child fails the expansion with the
/// own `required child invocation "<role>" failed: …` reason, resolves the
/// `#op` attempt `failed`, and fails the STAGE: `successor` never dispatches.
#[tokio::test(flavor = "current_thread")]
async fn a_required_child_death_fails_the_topology_stage() {
    let program = topology_program(TOPOLOGY_PACK, "topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = topology_expansion(&program, "parent");
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    match stage_id.as_str() {
                        "parent#child-first_worker" => {
                            reactor
                                .handle_message_for_test(
                                    kata_transport::types::WorkerMessage::Failed {
                                        assignment_id: frame.attempt_id,
                                        reason: "the first worker crashed".to_owned(),
                                        verdict: kata_types::effect::DeliveryFailureProvenance::PerformedButFailed,
                                        provider_failure: None,
                                        usage: None,
                                        fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                                    },
                                )
                                .expect("the member failure is adjudicated");
                        }
                        "parent#child-second_worker" => {
                            // Its sibling's death resolves the expansion first;
                            // the live member may still be in flight — complete it
                            // if a frame already arrived, but never require one.
                            complete_frame(&rig, &reactor, &frame, b"{\"note\":\"second ok\"}");
                        }
                        stage => {
                            let stdout = match stage {
                                "parent" => "{\"note\":\"root ok\"}",
                                "successor" => panic!("a failed stage releases no successor"),
                                other => panic!("no frame is scripted for {other}"),
                            };
                            complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");

    let error = outcome.expect_err("a required child's death fails the run");
    assert!(
        error
            .to_string()
            .contains("required child invocation \"first_worker\" failed"),
        "the failure is the required-child phrasing: {error}"
    );
    assert!(
        error.to_string().contains("\"parent\" failed"),
        "the STAGE records a failure, not a skip — a skipped stage is no run \
         failure line at all: {error}"
    );
    assert_eq!(
        expansion_terminal_state(&rig, execution, &expansion),
        "failed",
        "the expansion's #op attempt resolved failed"
    );

    // The stage is failed — `successor` minted no occurrence and its stage is
    // cascade-skipped: the run's outputs carry no envelope for either member
    // spelling, only the durable member rows remain.
    let successor_attempts: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT COUNT(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'successor'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the successor attempt count reads");
    assert_eq!(
        successor_attempts, 0,
        "a failed stage's successor never dispatches"
    );
}

/// QUORUM — every member terminal, the declared quorum UNMET: the expansion
/// resolves `failed` on `review_quorum_failure_reason`'s own phrasing and the
/// stage fails with it. The advisory blockers and absent-optional arms ride
/// the static review-quorum evaluation.
#[tokio::test(flavor = "current_thread")]
async fn a_declared_review_quorum_blocks_the_topology_settlement() {
    let program = topology_program(QUORUM_PACK, "topology-quorum-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = topology_expansion(&program, "review_parent");
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let stdout = match stage_id.as_str() {
                        "review_parent" => "{\"note\":\"root ok\"}",
                        "review_parent#child-first_reviewer" | "review_parent#child-second_reviewer" => "{\"verdict\":\"block\"}",
                        other => panic!("no frame is scripted for {other}"),
                    };
                    complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");

    let error = outcome.expect_err("a blocked quorum fails the run");
    assert!(
        error
            .to_string()
            .contains("review quorum blocked by reviewer \"first_reviewer\" verdict \"block\""),
        "the failure is the quorum's own phrasing: {error}"
    );
    assert_eq!(
        expansion_terminal_state(&rig, execution, &expansion),
        "failed",
        "the quorum-blocked expansion resolved failed"
    );
}

/// The POSITIVE arm: the same quorum holds on approve verdicts and the record
/// settles — `child_invocation_summary.review_quorum` carries the declared
/// policy plus its evaluation.
#[tokio::test(flavor = "current_thread")]
async fn a_held_review_quorum_settles_the_topology() {
    let program = topology_program(QUORUM_PACK, "topology-quorum-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let expansion = topology_expansion(&program, "review_parent");
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome.expect("the quorum run completes"),
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let stdout = match stage_id.as_str() {
                        "review_parent" => "{\"note\":\"root ok\"}",
                        s if s.starts_with("review_parent#child-") => "{\"verdict\":\"approve\"}",
                        other => panic!("no frame is scripted for {other}"),
                    };
                    complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");

    let record = expansion_record(&rig, execution, &expansion)
        .expect("the expansion's accepted record resolves");
    assert!(matches!(
        record.resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Settled
    ));

    let parent = outputs
        .get(&SmolStr::new("review_parent"))
        .expect("the stage completes with its envelope");
    let quorum = &parent["child_invocation_summary"]["review_quorum"];
    assert_eq!(quorum["required"], 1);
    assert_eq!(quorum["approved"], 2);
    assert_eq!(quorum["passed"], true);
    assert_eq!(quorum["required_approved"], 2);
    let votes = parent["child_invocation_summary"]["review_votes"]
        .as_array()
        .expect("the review votes row");
    assert_eq!(votes.len(), 2);
    assert!(
        votes
            .iter()
            .all(|vote| vote["verdict"].as_str() == Some("approve")
                && vote["classification"].as_str() == Some("approve")),
        "every reviewer vote classifies approve: {votes:?}"
    );
}

/// RESTART — a crash after member 0 and the first child settled leaves the
/// second child and the successor live; the resumed runner derives the same
/// member state off durable occurrences and never re-dispatches what settled.
#[tokio::test(flavor = "current_thread")]
async fn a_crashed_topology_run_resumes_from_durable_member_state() {
    let program = topology_program(TOPOLOGY_PACK, "topology-smoke.star");
    let dir = tempfile::tempdir().unwrap().keep();
    let rig = OciNodeRig::open(&dir);
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let reactor = reactor(&rig);

    // Drive member 0 and the first child to accepted, then drop the run — the
    // crash — with member 2 still in flight (its frame was already delivered).
    let runner = rig.runner(&program, execution);
    let mut settled = 0usize;
    {
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    _ = &mut run => panic!("the first drive must not finish; it dies mid-fanout"),
                    frame = next_frame(&rig) => {
                        let stage_id = frame_stage_id(&rig, &frame);
                        let stdout = match stage_id.as_str() {
                            "parent" => "{\"note\":\"root ok\"}",
                            "parent#child-first_worker" => "{\"note\":\"first ok\"}",
                            _ => "{\"note\":\"other ok\"}",
                        };
                        complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
                        settled += 1;
                        if settled == 2 {
                            return;
                        }
                    }
                }
            }
        })
        .await
        .expect("the first two members settle within the budget");
    }
    drop(runner);

    // RESUME: a fresh runner over the same planes — the second child and the
    // successor re-dispatch; nothing that already accepted is re-run.
    let runner = rig.runner(&program, execution);
    let mut replayed: Vec<String> = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outputs = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome.expect("the resumed run completes"),
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    assert_ne!(
                        stage_id.as_str(), "parent",
                        "member 0 is durable; a resumed drive never re-runs it"
                    );
                    assert_ne!(
                        stage_id.as_str(), "parent#child-first_worker",
                        "the settled child is durable; a resumed drive never re-runs it"
                    );
                    complete_frame(&rig, &reactor, &frame, b"{\"note\":\"resumed ok\"}");
                    replayed.push(stage_id);
                }
            }
        }
    })
    .await
    .expect("the resumed drive reaches a terminal within the budget");

    assert_eq!(
        replayed,
        vec![
            "parent#child-second_worker".to_owned(),
            "successor".to_owned(),
        ],
        "the resumed drive picks up exactly the unsettled members"
    );
    let expansion = topology_expansion(&program, "parent");
    let record = expansion_record(&rig, execution, &expansion)
        .expect("the expansion's accepted record resolves");
    assert!(matches!(
        record.resolution,
        kata_program::execution_program::expansion::ExpansionResolution::Settled
    ));
    assert!(outputs.contains_key(&SmolStr::new("parent")));
    assert!(outputs.contains_key(&SmolStr::new("successor")));
}

/// RECORD/REPLAY — a tampered accepted record diverges from the recompute:
/// the boot fold refuses `expansion_decision_diverged` rather than applying a
/// `Settled` the durable member outcomes do not support.
#[tokio::test(flavor = "current_thread")]
async fn a_tampered_topology_record_diverges_from_the_recompute() {
    let program = topology_program(TOPOLOGY_PACK, "topology-smoke.star");
    let dir = tempfile::tempdir().unwrap().keep();
    let rig = OciNodeRig::open(&dir);
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let reactor = reactor(&rig);
    let runner = rig.runner(&program, execution);
    let expansion = topology_expansion(&program, "parent");

    {
        let run = runner.run();
        tokio::pin!(run);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                tokio::select! {
                    outcome = &mut run => break outcome.expect("the drive settles"),
                    frame = next_frame(&rig) => {
                        complete_frame(&rig, &reactor, &frame, b"{\"note\":\"ok\"}");
                    }
                }
            }
        })
        .await
        .expect("the drive reaches a terminal within the budget");
    }
    drop(runner);

    // TAMPER: member 1's durable record row now names member 9 — the member
    // outcomes still recompute member 1.
    let payload_bytes: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT t.payload_json FROM transitions t
               JOIN occurrences o ON o.accepted_attempt_id = t.attempt_id
               JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE o.execution_id = ?1 AND a.stage_id = ?2
                AND t.resulting_state = 'completed'",
            rusqlite::params![
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
            |row| row.get(0),
        )
        .expect("the expansion's accepting transition");
    let payload = String::from_utf8(payload_bytes).expect("the payload is UTF-8 JSON");
    assert!(
        payload.contains("\"member\":1"),
        "the record names member 1"
    );
    let payload = payload.replace("\"member\":1", "\"member\":9");
    {
        let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
        conn.execute(
            "UPDATE transitions SET payload_json = ?1
              WHERE attempt_id = (
                SELECT o.accepted_attempt_id FROM occurrences o
                  JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
                 WHERE o.execution_id = ?2 AND a.stage_id = ?3)
                AND resulting_state = 'completed'",
            rusqlite::params![
                payload.as_bytes(),
                execution.to_bytes().as_slice(),
                expansion.path.program_operation_stage_id().as_str(),
            ],
        )
        .expect("the tamper lands");
    }

    let runner = rig.runner(&program, execution);
    let error = runner
        .run()
        .await
        .expect_err("a tampered record diverges from the recompute");
    assert!(
        error.to_string().contains("expansion_decision_diverged"),
        "the refusal is named: {error}"
    );
}

/// Topology CHECK — a static `topology(..)` COMPILES under `oci`,
/// standalone AND as a `loop(..)` member, and so
/// does a standalone `dynamic_fanout`. What still refuses, each by name and
/// each against a twin that compiles so the refused set is exactly what it
/// claims: `dynamic_fanout` as a loop member
/// (`dynamic_fanout_in_loop_unsupported`, the loop-specific reason); and a
/// `review_quorum` topology on the GATE of a loop with a custom `gate_verdict`
/// vocabulary (`loop_gate_quorum_needs_default_verdicts`) — the same gate under
/// the default vocabulary compiles.
///
/// **Watched red**: with a nested-topology refusal added this cell
/// fails at the nested-compiles assertion; with either new refusal's predicate
/// forced false it fails at that refusal's `expect_err`.
#[test]
fn oci_admits_static_topologies_in_and_out_of_loops_and_refuses_by_name() {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(TOPOLOGY_PACK, "topology-smoke.star", &[])
        .unwrap_or_else(|error| panic!("a static topology pack must compile under oci: {error}"));

    // A dynamic fanout compiles under `oci` too.
    let dynamic = TOPOLOGY_PACK.replacen(
        "max_concurrency = 3,",
        "max_concurrency = 3,\n        dynamic_fanout = True,",
        1,
    );
    compile_starlark_execution_program(&dynamic, "topology-dynamic.star", &[])
        .unwrap_or_else(|error| panic!("a dynamic fanout compiles under oci: {error}"));

    let nested = r#"
nested = stage(
    id = "nested",
    agent = "shell",
    run = "printf 'x\\n'",
    topology = topology(
        "root_with_parallel_workers",
        root = role("the_root", agent = "shell"),
        workers = [
            role("a_worker", agent = "shell"),
        ],
        max_concurrency = 2,
    ),
)

gate = stage(
    id = "gate",
    agent = "shell",
    run = "printf '{\"decision\":\"promote\"}\\n'",
    outputs = {
        "decision": "string",
    },
    depends_on = ["nested"],
)

loop(
    body = nested,
    gate = gate,
    max_iterations = 1,
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["again"],
        "block": ["stop"],
    },
)

workflow(
    "nested-topology-smoke",
    description = "A topology stage inside a loop body — refused under oci.",
    root = [nested, gate],
)
"#;
    compile_starlark_execution_program(nested, "topology-nested.star", &[]).unwrap_or_else(
        |error| panic!("a topology stage inside a loop member set compiles under oci: {error}"),
    );

    let nested_dynamic = nested.replacen(
        "max_concurrency = 2,",
        "max_concurrency = 2,\n        dynamic_fanout = True,",
        1,
    );
    let error =
        compile_starlark_execution_program(&nested_dynamic, "topology-nested-dynamic.star", &[])
            .expect_err("a dynamic fanout inside a loop refuses under oci");
    assert!(
        error
            .to_string()
            .contains("dynamic_fanout_in_loop_unsupported"),
        "the in-loop dynamic refusal is named: {error}"
    );

    let quorum_gate = |gate_verdict: &str| {
        format!(
            r#"
worker = stage(
    id = "worker",
    agent = "shell",
    run = "printf 'x\\n'",
)

gate = stage(
    id = "gate",
    agent = "shell",
    run = "printf '{{\"decision\":\"promote\"}}\\n'",
    outputs = {{
        "decision": "string",
    }},
    depends_on = ["worker"],
    topology = topology(
        "review_quorum",
        root = role("the_root", agent = "shell"),
        reviewers = [
            role("a_reviewer", agent = "shell"),
        ],
        review_quorum = review_quorum(1),
        max_concurrency = 2,
    ),
)

loop(
    body = worker,
    gate = gate,
    max_iterations = 2,
{gate_verdict})

workflow(
    "quorum-gate-smoke",
    description = "A review-quorum topology on a loop gate.",
    root = [worker, gate],
)
"#
        )
    };
    let custom = quorum_gate(
        r#"    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["again"],
        "block": ["stop"],
    },
"#,
    );
    let error = compile_starlark_execution_program(&custom, "quorum-gate-custom.star", &[])
        .expect_err("a quorum gate under a custom vocabulary refuses under oci");
    assert!(
        error
            .to_string()
            .contains("loop_gate_quorum_needs_default_verdicts"),
        "the custom-vocabulary quorum-gate refusal is named: {error}"
    );
    // The default vocabulary reads `parsed.verdict`: the twin declares that
    // output instead of `decision` — a CHECK-only twin, its `run` never runs.
    let default = quorum_gate("").replace("\"decision\": \"string\"", "\"verdict\": \"string\"");
    compile_starlark_execution_program(&default, "quorum-gate-default.star", &[]).unwrap_or_else(
        |error| panic!("the same quorum gate under the default vocabulary compiles: {error}"),
    );
}

// ---------------------------------------------------------------------------
// MAIN-RESOLVED LOOP MEMBERS: `memory_snapshot` and `workspace_effect`
// ---------------------------------------------------------------------------

/// A `memory_snapshot` body member ahead of a shell member — member classes
/// the `oci` door now resolves at the main, at the member seat.
const MEMBER_SNAP_PACK: &str = r#"
snap = memory_snapshot(id = "snap", kind = "task", status = "active")
w = stage(
    id = "w",
    agent = "shell",
    run = "printf w",
    sandbox = sandbox_profile(workspace = "ro"),
    depends_on = ["snap"],
    outputs = {"stage": "string", "marker": "number"},
)
g = stage(
    id = "g",
    agent = "shell",
    run = "printf g",
    depends_on = ["w"],
    outputs = {"decision": "string", "feedback": "string"},
)
loop(
    body = sequence(snap, w),
    gate = g,
    max_iterations = 2,
    on_exhaustion = "fail",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)
workflow("mem-member-loop", root = [snap, w, g])
"#;

/// A shell body member ahead of a `workspace_effect` commit member — the
/// effect acts on the head the member's `/work` apply landed, every
/// iteration.
const MEMBER_EFFECT_PACK: &str = r#"
w = stage(
    id = "w",
    agent = "shell",
    run = "printf w",
    sandbox = sandbox_profile(workspace = "rw"),
    outputs = {"stage": "string", "marker": "number"},
)
rec = stage(
    id = "rec",
    agent = "workspace_effect",
    op = "commit",
    depends_on = ["w"],
)
g = stage(
    id = "g",
    agent = "shell",
    run = "printf g",
    depends_on = ["rec"],
    outputs = {"decision": "string", "feedback": "string"},
)
loop(
    body = sequence(w, rec),
    gate = g,
    max_iterations = 2,
    on_exhaustion = "fail",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)
workflow("effect-member-loop", root = [w, rec, g], worktree_isolated = True)
"#;

/// The memory store the snapshot member answers — two ACTIVE tasks (the
/// queried set), nothing else.
fn seed_two_task_store() -> Arc<kata_core::store::SqliteNativeMemoryStore> {
    use kata_types::memory::{
        MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus, MemoryProposal, MemoryProvenance,
        MemorySourceKind,
    };
    let store = Arc::new(
        kata_core::store::SqliteNativeMemoryStore::open_in_memory()
            .expect("the memory store opens"),
    );
    for id in ["task-1", "task-2"] {
        store
            .apply_proposal(MemoryProposal {
                proposal_id: None,
                expected_revision: None,
                object: MemoryObjectDraft {
                    id: Some(id.to_owned()),
                    kind: MemoryObjectKind::Task,
                    status: MemoryObjectStatus::Active,
                    scope: kata_types::memory::MemoryScope::Global,
                    title: Some(id.to_owned()),
                    body: serde_json::json!({ "note": id }),
                    tags: Vec::new(),
                    links: Vec::new(),
                    provenance: MemoryProvenance {
                        source_kind: MemorySourceKind::Workflow,
                        source_id: Some("member-snapshot-cell".to_owned()),
                        execution_id: None,
                        agent_id: None,
                        path: None,
                    },
                },
                source_file: None,
            })
            .expect("the draft applies");
    }
    store
}

/// Drive `runner` to its terminal, stub-answering member capsules: the gate
/// reports `verdict_for(<ordinal>)`; a body member named in `file_for` lands
/// its own iteration's `/work` delta (the file the effect member commits).
/// Returns the run outcome and `(stage_id, (iteration, member))` per frame.
async fn drive_member_loop(
    rig: &OciNodeRig,
    runner: &kata_workflow::runner::WorkflowRunner,
    execution: Ulid,
    file_for: impl Fn(u32) -> Option<(String, Vec<u8>)>,
    verdict_for: impl Fn(u32) -> &'static str,
) -> (
    kata_types::error::KataResult<std::collections::BTreeMap<SmolStr, serde_json::Value>>,
    Vec<(String, (u32, u32))>,
) {
    let reactor = reactor(rig);
    let mut frames: Vec<(String, (u32, u32))> = Vec::new();
    let mut gate_seen = 0_u32;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(rig) => {
                    let stage_id = frame_stage_id(rig, &frame);
                    let (iteration, member) = member_coordinate(rig, &frame);
                    if stage_id == "g" {
                        let verdict = verdict_for(gate_seen);
                        gate_seen += 1;
                        complete_frame(
                            rig,
                            &reactor,
                            &frame,
                            format!("{{\"decision\":\"{verdict}\",\"feedback\":\"fb\"}}")
                                .as_bytes(),
                        );
                    } else {
                        let delta = file_for(iteration)
                            .map(|(name, bytes)| {
                                named_work_delta(rig, execution, &frame, &name, &bytes)
                            })
                            .or_else(|| {
                                kata_workflow::test_harness::stub_work_delta(
                                    &rig.db,
                                    &rig.cas,
                                    frame.occurrence_id,
                                )
                            });
                        complete_frame_with(
                            rig,
                            &reactor,
                            &frame,
                            b"{\"stage\":\"w\",\"marker\":0}",
                            delta,
                        );
                    }
                    frames.push((stage_id, (iteration, member)));
                }
            }
        }
    })
    .await
    .expect("the member loop drive reaches a terminal within the budget");
    (outcome, frames)
}

/// The `rec` member seat's raw row set, read off a second handle: one
/// `executor = 'main'` attempt at `expand.child(iteration).child(member)`
/// carrying an accepted resolution, and the attempt's effect spec.
fn member_effect_rows(
    rig: &OciNodeRig,
    execution: Ulid,
    seat: &kata_types::execution_contract::OperationPath,
) -> Vec<(String, bool)> {
    raw(&rig.op_path)
        .prepare(
            "SELECT a.executor, (o.accepted_attempt_id = a.attempt_id)
               FROM attempts a
               JOIN occurrences o ON o.occurrence_id = a.occurrence_id
              WHERE o.execution_id = ?1 AND o.operation_path = ?2
              ORDER BY a.attempt_id",
        )
        .expect("the seat's attempt query prepares")
        .query_map(
            rusqlite::params![
                execution.to_bytes().as_slice(),
                seat.canonical_bytes().as_slice()
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
        )
        .expect("the seat's attempts read")
        .collect::<Result<Vec<_>, _>>()
        .expect("the rows decode")
}

/// A `memory_snapshot()` BODY MEMBER runs at the main, at its member seat:
/// each iteration mints ONE `executor = 'main'` attempt at
/// `expand.child(iteration).child(0)` resolving `completed` with the snapshot
/// envelope `{"content": …}` — and the following shell member's capsule frame
/// arrives only after that acceptance (the derive's member-order rule).
/// Nothing about the member reaches a worker.
///
/// **Watched red:** with the `MemorySnapshot` arm removed from
/// `dispatch_expansion_member`'s routing, the member hits the invariant
/// refusal (`has no dispatch answer inside an iteration`) and the run fails
/// with no member occurrence minted.
#[tokio::test(flavor = "current_thread")]
async fn a_memory_snapshot_member_resolves_at_its_member_seat_each_iteration() {
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(MEMBER_SNAP_PACK, "mem-member.star", &[])
        .expect("a loop with a memory_snapshot member compiles under oci");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig
        .runner(&program, execution)
        .with_memory_store(seed_two_task_store());
    let expansion = expansion(&program);

    let (outcome, frames) = drive_member_loop(
        &rig,
        &runner,
        execution,
        |_| None,
        |gate| {
            if gate == 0 { "continue" } else { "promote" }
        },
    )
    .await;
    outcome.expect("the snapshot-member loop completes");

    assert_eq!(
        frames
            .iter()
            .map(|(stage, seat)| (stage.as_str(), *seat))
            .collect::<Vec<_>>(),
        vec![("w", (0, 1)), ("g", (0, 2)), ("w", (1, 1)), ("g", (1, 2))],
        "only the capsule members ever reach a worker — snap resolves main-side"
    );
    for iteration in 0..2_u32 {
        let seat = expansion.path.child(iteration).child(0);
        let rows = member_effect_rows(&rig, execution, &seat);
        assert_eq!(
            rows,
            vec![("main".to_owned(), true)],
            "iteration {iteration}'s snapshot member is ONE accepted main attempt"
        );
        let payload: Vec<u8> = raw(&rig.op_path)
            .query_row(
                "SELECT t.payload_json FROM occurrences o
                   JOIN transitions t ON t.attempt_id = o.accepted_attempt_id
                  WHERE o.execution_id = ?1 AND o.operation_path = ?2
                    AND t.resulting_state = 'completed'",
                rusqlite::params![
                    execution.to_bytes().as_slice(),
                    seat.canonical_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .expect("the member's accepting transition reads");
        let payload: serde_json::Value =
            serde_json::from_slice(&payload).expect("the payload decodes");
        let content = payload["output"]["content"]
            .as_str()
            .unwrap_or_else(|| panic!("the snapshot envelope carries content: {payload}"));
        let snapshot: serde_json::Value =
            serde_json::from_str(content).expect("the content is the snapshot JSON");
        assert_eq!(
            snapshot["object_count"],
            serde_json::json!(2),
            "iteration {iteration}'s member snapshot counted the seeded tasks"
        );
    }
}

/// The `workspace_effect` member fixture — a real git repo with a jj backend,
/// the execution workspace created and the committed base head published
/// BEFORE the runner builds (its `seed_scratch_head` reads a recorded head as
/// a resume and leaves the real one). Returns the rig, the backend, and the
/// repo path.
fn effect_member_fixture(
    dir: &Path,
    execution: Ulid,
    program: &kata_program::execution_program::ExecutionProgram,
) -> (
    OciNodeRig,
    Arc<kata_vcs::JjBackend>,
    kata_workflow::runner::WorkflowRunner,
) {
    let repo = dir.join("repo");
    if !repo.exists() {
        std::fs::create_dir_all(&repo).expect("the fixture repo dir");
        init_git_repo_at(&repo);
        std::fs::write(repo.join("a.txt"), "committed\n").expect("the base file");
        run_git(&repo, &["add", "-A"]);
        run_git(&repo, &["commit", "-q", "-m", "the committed base"]);
    }
    let rig = OciNodeRig::open(&dir.join("data"));
    rig.declare_bound_environment();
    let backend: Arc<kata_vcs::JjBackend> =
        Arc::new(kata_vcs::JjBackend::open(&repo).expect("the colocated jj backend opens"));
    let key = kata_effects_contract::ExecutionWorkspaceKey::execution(execution);
    let target = kata_vcs::test_support::resolve_trunk_target(backend.as_ref(), &key)
        .expect("resolve the trunk target");
    let workspace =
        kata_effects_contract::ExecutionWorkspaceProvider::lookup_workspace(backend.as_ref(), &key)
            .expect("the workspace lookup reads")
            .unwrap_or_else(|| {
                kata_effects_contract::ExecutionWorkspaceProvider::create_workspace(
                    backend.as_ref(),
                    &key,
                    &target,
                )
                .expect("the workspace creates")
            });
    // The head's `cas_roots` row foreign-keys `programs` — the program must be
    // retained BEFORE the head publishes, and `seed_scratch_head` must find the
    // real head already recorded (it reads a recorded head as a resume).
    rig.dispatcher
        .execution_lifecycle()
        .put_current_program_with_target(execution, program, target)
        .expect("the program is retained");
    if rig
        .db
        .execution_work_tree_head(execution)
        .expect("the head row reads")
        .is_none()
    {
        kata_core::work_tree::publish_base_tree_head(&rig.db, &rig.cas, execution, |put| {
            kata_effects_contract::ExecutionWorkspaceProvider::committed_base_tree(
                backend.as_ref(),
                &workspace,
                kata_types::tree_artifact::WorkTreeInputBounds::default(),
                put,
            )
        })
        .expect("the committed base head publishes");
    }
    let runner = kata_workflow::runner::WorkflowRunner::new_from_program(
        program.clone(),
        Arc::clone(&rig.dispatcher),
        execution,
    )
    .expect("the runner builds")
    .with_cache_store(Arc::clone(&rig.store))
    .with_workspace_provider(
        Arc::clone(&backend) as Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>
    );
    (rig, backend, runner)
}

/// The commits `exec-<execution>` accumulated past `main`, oldest first — read
/// out of the fixture repo's git, never out of kata's own record.
fn exec_branch_commits(repo: &Path, execution: Ulid) -> Vec<String> {
    let reference = format!("refs/heads/exec-{execution}");
    let out = hermetic_git_in(repo)
        .args(["rev-list", "--reverse", &format!("main..{reference}")])
        .output()
        .expect("git rev-list runs");
    assert!(
        out.status.success(),
        "the exec branch reads: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// `path`'s content at `commit` in `repo`, or None.
fn git_show_file(repo: &Path, commit: &str, path: &str) -> Option<String> {
    let out = hermetic_git_in(repo)
        .args(["show", &format!("{commit}:{path}")])
        .output()
        .expect("git show runs");
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A `workspace_effect` BODY MEMBER commits the head its iteration built —
/// the member dispatch drained every earlier member's pending `/work` apply,
/// so iteration N's `commit` lands N's file. Two iterations, two commits,
/// each read out of the fixture repo's own git: the first carries
/// `iter-0.txt` and NOT `iter-1.txt`, the second both. The effect member
/// itself never reaches a worker (no capsule frame, `executor = 'main'`).
///
/// **Watched red:** with the `Execute { Effect }` arm removed from
/// `dispatch_expansion_member`'s routing, the member dies on the invariant
/// refusal (`has no dispatch answer inside an iteration`); no `exec-<id>`
/// branch exists.
#[tokio::test(flavor = "current_thread")]
async fn a_workspace_effect_member_commits_each_iterations_head() {
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(MEMBER_EFFECT_PACK, "effect-member.star", &[])
        .expect("a loop with a workspace_effect member compiles under oci");
    let dir = tempfile::tempdir().unwrap().keep();
    let execution = Ulid::new();
    let (rig, _backend, runner) = effect_member_fixture(&dir, execution, &program);
    let expansion = expansion(&program);

    let (outcome, frames) = drive_member_loop(
        &rig,
        &runner,
        execution,
        |iteration| {
            Some((
                format!("iter-{iteration}.txt"),
                format!("iteration {iteration}\n").into_bytes(),
            ))
        },
        |gate| if gate == 0 { "continue" } else { "promote" },
    )
    .await;
    outcome.expect("the effect-member loop completes");

    assert_eq!(
        frames
            .iter()
            .map(|(stage, seat)| (stage.as_str(), *seat))
            .collect::<Vec<_>>(),
        vec![("w", (0, 0)), ("g", (0, 2)), ("w", (1, 0)), ("g", (1, 2))],
        "only the capsule members ever reach a worker — rec resolves main-side"
    );
    for iteration in 0..2_u32 {
        let seat = expansion.path.child(iteration).child(1);
        let rows = member_effect_rows(&rig, execution, &seat);
        assert_eq!(
            rows,
            vec![("main".to_owned(), true)],
            "iteration {iteration}'s effect member is ONE accepted main attempt"
        );
        let spec_bytes: Vec<u8> = raw(&rig.op_path)
            .query_row(
                "SELECT a.assignment_json FROM attempts a
                   JOIN occurrences o ON o.occurrence_id = a.occurrence_id
                  WHERE o.execution_id = ?1 AND o.operation_path = ?2",
                rusqlite::params![
                    execution.to_bytes().as_slice(),
                    seat.canonical_bytes().as_slice()
                ],
                |row| row.get(0),
            )
            .expect("the member attempt's spec reads");
        let spec = kata_core::operational::workspace_effect_spec(&spec_bytes)
            .expect("the spec decodes")
            .expect("the member attempt IS a workspace_effect");
        assert_eq!(
            spec.op,
            kata_types::workflow::WorkspaceEffectOp::Commit,
            "iteration {iteration}'s effect member committed"
        );
    }

    // THE LANDED ANSWER, out of the repo itself: two commits past `main`,
    // each iteration's commit carrying exactly the files its own iteration's
    // applies landed.
    let repo = dir.join("repo");
    let commits = exec_branch_commits(&repo, execution);
    assert_eq!(commits.len(), 2, "one commit per iteration: {commits:?}");
    assert_eq!(
        git_show_file(&repo, &commits[0], "iter-0.txt").as_deref(),
        Some("iteration 0\n"),
        "iteration 0's commit carries its member's file"
    );
    assert!(
        git_show_file(&repo, &commits[0], "iter-1.txt").is_none(),
        "iteration 0's commit cannot carry a file iteration 1 has not run"
    );
    assert_eq!(
        git_show_file(&repo, &commits[1], "iter-0.txt").as_deref(),
        Some("iteration 0\n")
    );
    assert_eq!(
        git_show_file(&repo, &commits[1], "iter-1.txt").as_deref(),
        Some("iteration 1\n"),
        "iteration 1's commit carries its member's file over iteration 0's head"
    );
}

/// A `writing + reporting` LOOP MEMBER: `w` writes `iter-<N>.txt` to `/work`
/// and reports the `wrote` criterion in the same breath. The capsule arm binds
/// a report to the RECORDED candidate — stamped before the member's deferred
/// `#apply` lands, that is the PRE-write tree. The deferred persist
/// (`evidence.rs`) + the re-persist at the apply's completed fold
/// (`runner/work_apply.rs`) must land each iteration's report bound to THAT
/// iteration's post-write tree.
///
/// Read off raw evidence rows and the repo's own git object store: iteration
/// 0's bound tree contains `iter-0.txt` and cannot contain `iter-1.txt`
/// (iteration 1 has not run); iteration 1's contains both.
///
/// **Watched red:** without the re-persist, no report records at all — the
/// promote-class gates then read `validation_criterion:w:missing`; binding at
/// inject instead of at the apply fold stamps the pre-write tree and the
/// `iter-0.txt` membership read fails.
#[tokio::test(flavor = "current_thread")]
async fn a_writing_loop_members_report_binds_its_own_iterations_landed_tree() {
    const PACK: &str = r#"
w = stage(
    id = "w",
    agent = "shell",
    run = "printf w",
    sandbox = sandbox_profile(workspace = "rw"),
    outputs = {"criteria": "array"},
)
g = stage(
    id = "g",
    agent = "shell",
    run = "printf g",
    depends_on = ["w"],
    outputs = {"decision": "string", "feedback": "string"},
)
loop(
    body = w,
    gate = g,
    max_iterations = 2,
    on_exhaustion = "fail",
    gate_verdict = {
        "field": "decision",
        "approve": ["promote"],
        "refine": ["continue"],
        "block": ["stop"],
    },
)
workflow(
    "loop-member-report",
    root = [w, g],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            "wrote",
            description = "the member wrote its iteration's marker",
            stage = "w",
            required = True,
        ),
    ],
)
"#;
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(PACK, "loop-member-report.star", &[])
        .expect("a writing+reporting loop member compiles under oci");
    let dir = tempfile::tempdir().unwrap().keep();
    let execution = Ulid::new();
    let (rig, _backend, runner) = effect_member_fixture(&dir, execution, &program);

    let reactor = reactor(&rig);
    let mut gate_seen = 0_u32;
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    let stage_id = frame_stage_id(&rig, &frame);
                    let (iteration, _member) = member_coordinate(&rig, &frame);
                    if stage_id == "g" {
                        let verdict = if gate_seen == 0 { "continue" } else { "promote" };
                        gate_seen += 1;
                        complete_frame(
                            &rig,
                            &reactor,
                            &frame,
                            format!("{{\"decision\":\"{verdict}\",\"feedback\":\"fb\"}}")
                                .as_bytes(),
                        );
                    } else {
                        let delta = named_work_delta(
                            &rig,
                            execution,
                            &frame,
                            &format!("iter-{iteration}.txt"),
                            format!("iteration {iteration}\n").as_bytes(),
                        );
                        complete_frame_with(
                            &rig,
                            &reactor,
                            &frame,
                            b"{\"criteria\":[{\"criterion_id\":\"wrote\",\"status\":\"passed\"}]}",
                            Some(delta),
                        );
                    }
                }
            }
        }
    })
    .await
    .expect("the member loop drive reaches a terminal within the budget");
    outcome.expect("the loop completes");

    // One report per iteration, in claim order — the member's durable
    // `stage_id` is its AUTHORED name at every iteration (the iteration lives
    // on the member's occurrence coordinate `[loop, iter, member]`, not on the
    // name), so both rows land under `w`; what the raw rows must prove is that
    // each bound ITS OWN iteration's post-apply tree.
    let reports: Vec<kata_types::execution::ExecutionValidationEvidence> = rig
        .db
        .execution_evidence_for(execution)
        .expect("the evidence rows read")
        .into_iter()
        .flat_map(|record| record.evidence.validation_reports)
        .filter(|report| report.stage_name == "w")
        .collect();
    assert_eq!(
        reports.len(),
        2,
        "one report per iteration — the deferred record re-persisted at each apply's fold"
    );

    let repo = dir.join("repo");
    let bound_tree = |report: &kata_types::execution::ExecutionValidationEvidence,
                      iteration: u32| {
        report
            .criteria
            .iter()
            .find(|criterion| criterion.criterion_id == "wrote")
            .unwrap_or_else(|| panic!("iteration {iteration}'s report carries the criterion"))
            .candidate
            .as_ref()
            .unwrap_or_else(|| panic!("iteration {iteration}'s report binds a candidate"))
            .tree_id
            .clone()
            .unwrap_or_else(|| panic!("iteration {iteration}'s candidate carries a tree id"))
    };
    let tree0 = bound_tree(&reports[0], 0);
    let tree1 = bound_tree(&reports[1], 1);
    assert_ne!(tree0, tree1, "each iteration binds its own post-write tree");

    // The trees are read out of the repo's git object store — jj candidate
    // tree ids ARE git tree ids on the colocated repo.
    assert_eq!(
        git_show_file(&repo, &tree0, "iter-0.txt").as_deref(),
        Some("iteration 0\n"),
        "iteration 0's bound tree carries its own write"
    );
    assert_eq!(
        git_show_file(&repo, &tree0, "iter-1.txt"),
        None,
        "iteration 0's bound tree predates iteration 1's write"
    );
    assert_eq!(
        git_show_file(&repo, &tree1, "iter-0.txt").as_deref(),
        Some("iteration 0\n"),
        "iteration 1's bound tree carries iteration 0's write"
    );
    assert_eq!(
        git_show_file(&repo, &tree1, "iter-1.txt").as_deref(),
        Some("iteration 1\n"),
        "iteration 1's bound tree carries its own write"
    );
}

/// The armed child's whole drive for the member crash cell — reopen the rig
/// and backend off `CHILD_DIR` and run the member loop until the armed
/// boundary aborts the process mid-claim.
const EFFECT_MEMBER_CHILD: &str = "KATA_EFFECT_MEMBER_CHILD";
const EFFECT_MEMBER_DIR: &str = "KATA_EFFECT_MEMBER_DIR";

async fn effect_member_child_entry() {
    if std::env::var(EFFECT_MEMBER_CHILD).is_err() {
        return;
    }
    let dir = std::path::PathBuf::from(std::env::var(EFFECT_MEMBER_DIR).expect("CHILD_DIR"));
    let execution: Ulid = std::fs::read_to_string(dir.join("execution_id"))
        .unwrap()
        .parse()
        .unwrap();
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(MEMBER_EFFECT_PACK, "effect-member.star", &[])
        .expect("the member pack compiles");
    let (rig, _backend, runner) = effect_member_fixture(&dir, execution, &program);
    let (outcome, _frames) = drive_member_loop(
        &rig,
        &runner,
        execution,
        |iteration| {
            Some((
                format!("iter-{iteration}.txt"),
                format!("iteration {iteration}\n").into_bytes(),
            ))
        },
        |gate| if gate == 0 { "continue" } else { "promote" },
    )
    .await;
    outcome.expect("the child's drive");
    panic!("the armed fault point was never reached — the cell proves nothing");
}

/// CRASH between the effect member's claim and its jj publish: iteration 0's
/// `rec` attempt sits `pending` when the process dies; the restarted drive's
/// pending-effect sweep (`drive_pending_workspace_effects`, run before the
/// first fold) classifies it `NotPerformed`, performs the verb ONCE, and the
/// loop runs its second iteration clean — exactly one commit per iteration,
/// one member attempt per seat. The sweep resolves the member before any
/// derive reads it, so the derive never judges it pending here.
///
/// **Watched red:** with the sweep's `NotPerformed` arm returning without
/// performing the verb, the pending member never resolves and the resumed
/// drive never reaches iteration 0's gate (`a capsule frame reaches the
/// worker: Elapsed(())`).
#[tokio::test(flavor = "current_thread")]
async fn a_crashed_workspace_effect_member_resumes_with_exactly_one_commit() {
    if std::env::var(EFFECT_MEMBER_CHILD).is_ok() {
        effect_member_child_entry().await;
        return;
    }
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(MEMBER_EFFECT_PACK, "effect-member.star", &[])
        .expect("the member pack compiles");
    let dir = tempfile::tempdir().unwrap().keep();
    let execution = Ulid::new();
    let (rig, _backend, runner) = effect_member_fixture(&dir, execution, &program);
    drop(runner);
    drop(rig);
    std::fs::write(dir.join("execution_id"), execution.to_string()).unwrap();

    // The armed child drives iteration 0: `w`'s apply lands, `rec` claims its
    // main attempt — and the process aborts before the jj publish.
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg("a_crashed_workspace_effect_member_resumes_with_exactly_one_commit")
        .arg("--exact")
        .arg("--nocapture")
        .env(EFFECT_MEMBER_CHILD, "1")
        .env(EFFECT_MEMBER_DIR, &dir)
        .env(
            "KATA_FAULT_INJECT",
            "operational.after_workspace_effect_claimed_before_jj_publish",
        );
    let output = command.output().expect("spawn the crash child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the armed child must abort at the claim boundary, not exit cleanly — {stderr}"
    );
    assert!(
        stderr.contains(
            "crash point reached: operational.after_workspace_effect_claimed_before_jj_publish"
        ),
        "the child died AT the claim boundary: {stderr}"
    );

    // The RESUMED drive: a fresh rig over the same data dir, the same
    // workspace provider, the same drive — the pending member attempt is the
    // sweep's input, the derive waits on it, and the loop completes.
    let rig = OciNodeRig::open(&dir.join("data"));
    rig.declare_bound_environment();
    let backend: Arc<kata_vcs::JjBackend> =
        Arc::new(kata_vcs::JjBackend::open(&dir.join("repo")).expect("the backend reopens"));
    // Trunk did not move across the crash, so the re-resolved target is the one
    // the first admission froze, and the re-admission converges.
    let target = kata_vcs::test_support::resolve_trunk_target(
        backend.as_ref(),
        &kata_effects_contract::ExecutionWorkspaceKey::execution(execution),
    )
    .expect("resolve the trunk target");
    let runner = rig
        .runner_with_target(&program, execution, target)
        .with_workspace_provider(
            Arc::clone(&backend) as Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>
        );
    let expansion = expansion(&program);
    let (outcome, frames) = drive_member_loop(
        &rig,
        &runner,
        execution,
        |iteration| {
            Some((
                format!("iter-{iteration}.txt"),
                format!("iteration {iteration}\n").into_bytes(),
            ))
        },
        |gate| if gate == 0 { "continue" } else { "promote" },
    )
    .await;
    outcome.expect("the resumed drive completes the loop");

    // The pending claim was performed exactly once: ONE main attempt per
    // member seat, both accepted, and the exec branch holds exactly one
    // commit per iteration.
    for iteration in 0..2_u32 {
        let seat = expansion.path.child(iteration).child(1);
        let rows = member_effect_rows(&rig, execution, &seat);
        assert_eq!(
            rows,
            vec![("main".to_owned(), true)],
            "iteration {iteration}'s effect member claimed exactly once"
        );
    }
    let commits = exec_branch_commits(&dir.join("repo"), execution);
    assert_eq!(
        commits.len(),
        2,
        "the resume landed no second commit: {commits:?}"
    );
    assert_eq!(
        git_show_file(&dir.join("repo"), &commits[0], "iter-0.txt").as_deref(),
        Some("iteration 0\n")
    );
    assert_eq!(
        git_show_file(&dir.join("repo"), &commits[1], "iter-1.txt").as_deref(),
        Some("iteration 1\n")
    );
    let stage_frames: Vec<&str> = frames.iter().map(|(stage, _)| stage.as_str()).collect();
    assert_eq!(
        stage_frames,
        vec!["g", "w", "g"],
        "the resume replays no member work — iteration 0's gate frames next"
    );
}

/// THE OCI PROMOTE'S VALIDATION GATE — a `promote` whose required validation
/// criterion's proof recorded a `failed` report is refused BEFORE the effect
/// claims: `submit_workspace_effect` runs the same conjuncts the operator
/// route's `authorize_promote_directive` runs. Computing only the pin would
/// let the promote LAND — trunk moving despite the failed criterion. The cell's trunk read is the
/// fixture repo's own `git`, never kata's record.
///
/// **Watched red:** before the gate was wired, this run completed and trunk
/// fast-forwarded past `before`.
#[tokio::test(flavor = "current_thread")]
async fn a_promote_whose_required_criterion_failed_is_refused_and_the_trunk_never_moves() {
    const PROMOTE_GATE_PACK: &str = r#"
proof = stage(
    id = "proof",
    agent = "shell",
    run = "printf 'proof\\n'",
)
ship = stage(
    id = "ship",
    agent = "workspace_effect",
    op = "promote",
    depends_on = ["proof"],
)
workflow(
    "promote-gate-cell",
    root = [proof, ship],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            "proof",
            description = "the proof stage",
            stage = "proof",
            required = True,
        ),
    ],
)
"#;
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(PROMOTE_GATE_PACK, "promote-gate.star", &[])
        .expect("the promote-gate pack compiles under oci");
    let dir = tempfile::tempdir().unwrap().keep();
    let execution = Ulid::new();
    let (rig, _backend, runner) = effect_member_fixture(&dir, execution, &program);
    let reactor = reactor(&rig);
    let trunk_before = {
        let out = hermetic_git_in(&dir.join("repo"))
            .args(["rev-parse", "main"])
            .output()
            .expect("git rev-parse runs");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };

    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    // `proof` reports a FAILED criterion on stdout; `ship` is
                    // main-resolved — it must never reach a worker.
                    complete_frame(
                        &rig, &reactor, &frame,
                        b"{\"criteria\":[{\"criterion_id\":\"proof\",\"status\":\"failed\"}]}",
                    );
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    let error = outcome.expect_err("a failed criterion refuses the promote");
    assert!(
        error.to_string().contains("REFUSED before dispatch")
            || error.to_string().contains("failed stage"),
        "the refusal is the promotion gate's, propagated by the runner: {error}"
    );
    let trunk_after = {
        let out = hermetic_git_in(&dir.join("repo"))
            .args(["rev-parse", "main"])
            .output()
            .expect("git rev-parse runs");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    assert_eq!(
        trunk_after, trunk_before,
        "the trunk never moved — the promote was refused before dispatch"
    );
}

/// A `forge_export` claimed AFTER `promote` binds the LANDED candidate — the
/// head row's commit and the tree git reports for it — because a landed
/// promote legitimately tears the execution workspace down and the claim's
/// live-workspace reads have no answer there. A dispatch that asked for the
/// workspace anyway would die `the execution workspace is gone`.
///
/// The claim is exercised through `runner.run()` →
/// `WorkflowRunner::submit_workspace_effect` itself — the door that binds it,
/// and the door the promotion gate guards: `proof` reports a PASSING
/// criterion, which the capsule arm binds to the recorded candidate
/// (`attach_validation_candidate_binding`), satisfying both conjuncts — the
/// promote dispatches because the evidence is there, not because the door
/// skipped the check.
///
/// **Watched red twice:** drop the passing report and the promote is refused
/// by the gate (trunk never moves); re-break the original fix — the claim
/// reading the live workspace — and the export dies `the execution workspace
/// is gone`.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_forge_export_after_promote_binds_the_landed_candidate() {
    const PACK: &str = r#"
proof = stage(
    id = "proof",
    agent = "shell",
    run = "printf 'proof\\n'",
)
ship = stage(
    id = "ship",
    agent = "workspace_effect",
    op = "promote",
    depends_on = ["proof"],
)
export = stage(
    id = "export",
    agent = "workspace_effect",
    op = "forge_export",
    depends_on = ["ship"],
)
workflow(
    "promote-export-cell",
    root = [proof, ship, export],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            "proof",
            description = "the proof stage",
            stage = "proof",
            required = True,
        ),
    ],
)
"#;
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(PACK, "promote-export.star", &[])
        .expect("the promote+export pack compiles under oci");
    let dir = tempfile::tempdir().unwrap().keep();
    let execution = Ulid::new();
    let (rig, backend, runner) = effect_member_fixture(&dir, execution, &program);
    // The bare `origin` the export pushes to — the fixture's repo exists after
    // `effect_member_fixture` builds it — plus a recording forge so the PR is
    // provable without a network.
    let repo = dir.join("repo");
    let origin = dir.join("origin.git");
    run_git(&dir, &["init", "--bare", "-q", origin.to_str().unwrap()]);
    kata_test_utils::git::add_forge_remote(&repo, "origin", &origin, "forge.test/o/r");
    let forge = Arc::new(kata_effects_contract::RecordingForge::succeeding_with_url(
        "https://forge.test/pull/1",
    ));
    let runner = runner.with_forge(Some(
        Arc::clone(&forge) as Arc<dyn kata_effects_contract::Forge>
    ));
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    // `proof` reports a PASSING criterion; `ship` and `export`
                    // are main-resolved — they must never reach a worker.
                    complete_frame(
                        &rig, &reactor, &frame,
                        b"{\"criteria\":[{\"criterion_id\":\"proof\",\"status\":\"passed\"}]}",
                    );
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");
    outcome.expect("the promote passes the gate on the passing evidence, and the export performs");

    // THE PROMOTE'S TEARDOWN — the live workspace is gone; the claim could not
    // have read it.
    let key = kata_effects_contract::ExecutionWorkspaceKey::execution(execution);
    assert!(
        kata_effects_contract::ExecutionWorkspaceProvider::workspace_status(backend.as_ref(), &key)
            .expect("the workspace status reads")
            .is_none(),
        "a landed promote tears the execution workspace down"
    );
    let landed = rig
        .db
        .execution_work_tree_head(execution)
        .expect("the head row reads")
        .expect("the head row exists")
        .candidate_commit_id;
    let landed_tree = {
        let out = hermetic_git_in(&repo)
            .args(["rev-parse", &format!("{landed}^{{tree}}")])
            .output()
            .expect("git rev-parse runs");
        assert!(out.status.success(), "git rev-parse failed");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };

    // THE EXPORT'S CLAIM, read back out of the raw attempt row — not the
    // return value: the spec binds the LANDED commit and its tree.
    let blob: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT assignment_json FROM attempts WHERE execution_id = ?1 AND stage_id = 'export'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the export attempt row reads");
    let spec = kata_core::operational::workspace_effect_spec(&blob)
        .expect("the attempt's spec decodes")
        .expect("the attempt IS a workspace_effect");
    assert_eq!(
        spec.candidate_commit, landed,
        "the export's claim binds the head row's LANDED commit"
    );
    assert_eq!(
        spec.candidate_tree_id, landed_tree,
        "the claim's tree is the tree git reports for the landed commit"
    );

    // And the effect itself: one `kata/<exec>` branch on the remote at the
    // landed commit, one PR.
    let branch = format!("kata/{execution}");
    let out = hermetic_git_in(&origin)
        .args(["rev-parse", &format!("refs/heads/{branch}")])
        .output()
        .expect("git rev-parse runs");
    assert!(out.status.success(), "the remote holds {branch}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), landed);
    assert_eq!(forge.calls().len(), 1, "exactly one PR opened");
}

/// **The promote claim names the FROZEN branch.** The execution froze trunk
/// `main`; before the promote claims, the host's trunk answer moves to
/// `master` (a remote whose `HEAD` names `master`). The claim's recorded
/// `target` — what the approval gate shows the operator — is the branch the
/// perform lands on or refuses: `main`, never the live `master`. The perform
/// then refuses `target_trunk_renamed` (the landing ladder's live check), so
/// nothing lands on either branch.
///
/// From outside the runner: the claim's spec read out of the raw attempt row
/// through a second read-only handle, and both branches read out of git.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_promote_claim_records_the_frozen_branch_when_the_host_trunk_moved() {
    const PACK: &str = r#"
proof = stage(
    id = "proof",
    agent = "shell",
    run = "printf 'proof\\n'",
)
ship = stage(
    id = "ship",
    agent = "workspace_effect",
    op = "promote",
    depends_on = ["proof"],
)
workflow(
    "promote-frozen-target-cell",
    root = [proof, ship],
    worktree_isolated = True,
    validation_criteria = [
        validation_criterion(
            "proof",
            description = "the proof stage",
            stage = "proof",
            required = True,
        ),
    ],
)
"#;
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(PACK, "promote-frozen.star", &[])
        .expect("the promote pack compiles under oci");
    let dir = tempfile::tempdir().unwrap().keep();
    let execution = Ulid::new();
    let (rig, backend, runner) = effect_member_fixture(&dir, execution, &program);
    let repo = dir.join("repo");
    let seed = {
        let out = hermetic_git_in(&repo)
            .args(["rev-parse", "refs/heads/main"])
            .output()
            .expect("git rev-parse runs");
        assert!(out.status.success(), "the fixture's trunk is main");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    // THE HOST'S TRUNK ANSWER MOVES: `master` at the seed, on a remote whose
    // `HEAD` names it — after admission froze `main`.
    let origin = dir.join("origin.git");
    run_git(&dir, &["init", "--bare", "-q", origin.to_str().unwrap()]);
    kata_test_utils::git::add_forge_remote(&repo, "origin", &origin, "forge.test/o/r");
    run_git(&repo, &["branch", "master", &seed]);
    run_git(&repo, &["push", "-q", "origin", "main", "master"]);
    run_git(&repo, &["fetch", "-q", "origin"]);
    run_git(&repo, &["remote", "set-head", "origin", "master"]);
    let answer = kata_vcs::test_support::resolve_trunk_target(
        backend.as_ref(),
        &kata_effects_contract::ExecutionWorkspaceKey::execution(Ulid::new()),
    )
    .expect("another run resolves the host's trunk now");
    assert_eq!(
        answer.branch.as_deref(),
        Some("master"),
        "the host's trunk answer moved to master"
    );
    let reactor = reactor(&rig);

    let run = runner.run();
    tokio::pin!(run);
    // The perform refuses (`target_trunk_renamed`); the outcome's shape is not
    // the oracle — the raw claim row and git are.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                frame = next_frame(&rig) => {
                    complete_frame(
                        &rig, &reactor, &frame,
                        b"{\"criteria\":[{\"criterion_id\":\"proof\",\"status\":\"passed\"}]}",
                    );
                }
            }
        }
    })
    .await
    .expect("the drive reaches a terminal within the budget");

    let blob: Vec<u8> = raw(&rig.op_path)
        .query_row(
            "SELECT assignment_json FROM attempts WHERE execution_id = ?1 AND stage_id = 'ship'",
            [execution.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the promote attempt row reads");
    let spec = kata_core::operational::workspace_effect_spec(&blob)
        .expect("the attempt's spec decodes")
        .expect("the attempt IS a workspace_effect");
    assert_eq!(
        spec.target, "main",
        "the promote's claim records the frozen branch, not the host's live answer"
    );
    for branch in ["main", "master"] {
        let out = hermetic_git_in(&repo)
            .args(["rev-parse", &format!("refs/heads/{branch}")])
            .output()
            .expect("git rev-parse runs");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            seed,
            "nothing landed on {branch}"
        );
    }
}

/// A LEAF stage's `/work` delta is owed its apply before the run reports
/// finished: the derived obligation carries no chain row until the drive
/// claims it, so a finish check that asks only `is_finished` exits with the
/// last stage's write missing from the recorded head — the tree
/// promote/forge/operator readers consume. The cell commits EVERY capsule
/// completion through [`interleave_before_the_pass_fold`] — between the pass's
/// apply drive and its last fold, the exact window a real interleave can hit —
/// and reads the head manifest off the CAS, never kata's own summary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finished_run_has_applied_its_leaf_stages_work_delta() {
    kata_types::node_profile::mark_node_installed();
    const LEAF_WRITER_PACK: &str = r#"
probe = stage(
    id = "probe",
    agent = "shell",
    run = "printf 'probe\\n'",
    sandbox = sandbox_profile(workspace = "rw"),
)

after = stage(
    id = "after",
    agent = "shell",
    run = "printf 'after\\n'",
    depends_on = ["probe"],
    sandbox = sandbox_profile(workspace = "rw"),
)

workflow("leaf-writer", root = [probe, after])
"#;
    let program = compile_starlark_execution_program(LEAF_WRITER_PACK, "leaf-writer.star", &[])
        .expect("the leaf-writer pack compiles under oci");
    let rig = std::sync::Arc::new(OciNodeRig::open(&tempfile::tempdir().unwrap().keep()));
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = std::sync::Arc::new(reactor(&rig));

    // A pump task forwards every dispatched capsule frame into the mover's
    // channel; the mover — running inside the runner's own pass at the seam —
    // completes them there, so EVERY completion commits in the
    // drive→last-fold window. The leaf's delta writes a real file.
    let (deposit_tx, deposit_rx) =
        std::sync::mpsc::channel::<kata_transport::types::CapsuleAssignment>();
    let deposit_rx = std::sync::Mutex::new(deposit_rx);
    let pump = tokio::spawn({
        let worker_side = std::sync::Arc::clone(&rig.worker_side);
        async move {
            while let Ok(DispatchFrame::Capsule(capsule)) = worker_side.recv_frame().await {
                if deposit_tx.send(*capsule).is_err() {
                    break;
                }
            }
        }
    });

    kata_workflow::test_harness::interleave_before_the_pass_fold({
        let rig = std::sync::Arc::clone(&rig);
        let reactor = std::sync::Arc::clone(&reactor);
        std::sync::Arc::new(move |_: Ulid| {
            let deposit_rx = deposit_rx.lock().unwrap();
            while let Ok(frame) = deposit_rx.try_recv() {
                let stage = frame_stage_id(&rig, &frame);
                let delta = if stage == "after" {
                    Some(named_work_delta(
                        &rig, execution, &frame, "leaf.txt", b"leaf\n",
                    ))
                } else {
                    Some(named_work_delta(
                        &rig,
                        execution,
                        &frame,
                        "probe.txt",
                        b"probe\n",
                    ))
                };
                complete_frame_with(&rig, &reactor, &frame, b"done", delta);
            }
        })
    });

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), runner.run())
        .await
        .expect("the leaf-writer drive settles within the budget");
    outcome.expect("the run completes");
    pump.abort();

    let paths = head_manifest_paths(&rig, execution);
    assert!(
        paths.iter().any(|path| path == "probe.txt"),
        "the recorded head must carry `probe`'s write; head paths: {paths:?}"
    );
    assert!(
        paths.iter().any(|path| path == "leaf.txt"),
        "the recorded head must carry the leaf's write before the run reports finished; head paths: {paths:?}"
    );
}

/// The single-stage degenerate of the leaf-apply gate: the ONLY stage's write
/// is owed its apply before `run` reports finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finished_single_stage_run_has_applied_its_work_delta() {
    kata_types::node_profile::mark_node_installed();
    const SINGLE_WRITER_PACK: &str = r#"
only = stage(
    id = "only",
    agent = "shell",
    run = "printf 'only\\n'",
    sandbox = sandbox_profile(workspace = "rw"),
)

workflow("single-writer", root = [only])
"#;
    let program = compile_starlark_execution_program(SINGLE_WRITER_PACK, "single-writer.star", &[])
        .expect("the single-writer pack compiles under oci");
    let rig = std::sync::Arc::new(OciNodeRig::open(&tempfile::tempdir().unwrap().keep()));
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = std::sync::Arc::new(reactor(&rig));

    let (deposit_tx, deposit_rx) =
        std::sync::mpsc::channel::<kata_transport::types::CapsuleAssignment>();
    let deposit_rx = std::sync::Mutex::new(deposit_rx);
    let pump = tokio::spawn({
        let worker_side = std::sync::Arc::clone(&rig.worker_side);
        async move {
            while let Ok(DispatchFrame::Capsule(capsule)) = worker_side.recv_frame().await {
                if deposit_tx.send(*capsule).is_err() {
                    break;
                }
            }
        }
    });

    kata_workflow::test_harness::interleave_before_the_pass_fold({
        let rig = std::sync::Arc::clone(&rig);
        let reactor = std::sync::Arc::clone(&reactor);
        std::sync::Arc::new(move |_: Ulid| {
            let deposit_rx = deposit_rx.lock().unwrap();
            // Drain whatever the pump deposited, then — while the leaf's
            // attempt is dispatched — wait for its frame: completing it here
            // lands the leaf's `completed` inside the drive→fold window.
            while let Ok(frame) = deposit_rx.try_recv() {
                complete_frame_with(
                    &rig,
                    &reactor,
                    &frame,
                    b"done",
                    Some(named_work_delta(
                        &rig, execution, &frame, "only.txt", b"only\n",
                    )),
                );
            }
            let leaf_dispatched = rig
                .db
                .attempts_for_execution(execution)
                .unwrap()
                .iter()
                .any(|attempt| {
                    attempt.row.stage_id == "only" && attempt.state.as_deref() == Some("dispatched")
                });
            if leaf_dispatched {
                let frame = deposit_rx
                    .recv_timeout(std::time::Duration::from_secs(30))
                    .expect("the pump delivers the leaf's frame");
                complete_frame_with(
                    &rig,
                    &reactor,
                    &frame,
                    b"done",
                    Some(named_work_delta(
                        &rig, execution, &frame, "only.txt", b"only\n",
                    )),
                );
            }
        })
    });

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), runner.run())
        .await
        .expect("the single-writer drive settles within the budget");
    outcome.expect("the run completes");
    pump.abort();

    let paths = head_manifest_paths(&rig, execution);
    assert!(
        paths.iter().any(|path| path == "only.txt"),
        "the recorded head must carry the leaf's write before the run reports finished; head paths: {paths:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// A MEMBER'S LIVENESS IS JUDGED FROM ONE SNAPSHOT. An expansion drive reads a
// member's occurrence and then judges the member live or dead. A completion
// that commits between the read of the occurrence (unaccepted) and the read of
// its attempts (`completed`) must never make a finished member look dead —
// that is "review loop aborted … resolved `completed` without a recorded
// reason" on a run whose every member succeeded. Each cell commits the
// completion inside that window, deterministically, through
// `interleave_after_a_member_read`, and reads the outcome off the raw handle.
// ═══════════════════════════════════════════════════════════════════════════

/// The frames a member-read mover completes, keyed by occurrence. The pump
/// deposits every frame it does not complete itself; [`Self::take`] blocks
/// until the frame bound at `occurrence` has arrived.
struct DepositedFrames {
    rx: std::sync::Mutex<std::sync::mpsc::Receiver<kata_transport::types::CapsuleAssignment>>,
    held: std::sync::Mutex<
        std::collections::HashMap<[u8; 32], kata_transport::types::CapsuleAssignment>,
    >,
}

impl DepositedFrames {
    fn take(&self, occurrence: [u8; 32]) -> kata_transport::types::CapsuleAssignment {
        let mut held = self.held.lock().unwrap();
        loop {
            if let Some(frame) = held.remove(&occurrence) {
                return frame;
            }
            let frame = self
                .rx
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the pump delivers the member's frame");
            held.insert(frame.occurrence_id.0.0, frame);
        }
    }
}

/// Spawn the pump: every capsule frame the worker side receives is completed
/// on the spot when `direct(stage)` scripts it (a stage no expansion reads as
/// a member), and deposited for the mover otherwise.
fn spawn_member_pump(
    rig: &Arc<OciNodeRig>,
    reactor: &Arc<kata_workflow::reactor::ResultReactor>,
    direct: impl Fn(&str) -> Option<String> + Send + 'static,
) -> (tokio::task::JoinHandle<()>, Arc<DepositedFrames>) {
    let (tx, rx) = std::sync::mpsc::channel::<kata_transport::types::CapsuleAssignment>();
    let frames = Arc::new(DepositedFrames {
        rx: std::sync::Mutex::new(rx),
        held: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    let pump = tokio::spawn({
        let rig = Arc::clone(rig);
        let reactor = Arc::clone(reactor);
        async move {
            while let Ok(DispatchFrame::Capsule(capsule)) = rig.worker_side.recv_frame().await {
                let stage = frame_stage_id(&rig, &capsule);
                if let Some(stdout) = direct(&stage) {
                    complete_frame(&rig, &reactor, &capsule, stdout.as_bytes());
                } else if tx.send(*capsule).is_err() {
                    break;
                }
            }
        }
    });
    (pump, frames)
}

/// The executors of the attempts bound at `occurrence`, off the raw handle.
fn occurrence_executors(rig: &OciNodeRig, occurrence: [u8; 32]) -> Vec<String> {
    let conn = raw(&rig.op_path);
    let mut statement = conn
        .prepare("SELECT executor FROM attempts WHERE occurrence_id = ?1")
        .unwrap();
    statement
        .query_map([occurrence.as_slice()], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// A mover that completes the WORKER member the drive just read unaccepted —
/// inside the read window — with `stdout(stage)`, counting each completion.
fn complete_worker_members_in_the_read_window(
    rig: &Arc<OciNodeRig>,
    reactor: &Arc<kata_workflow::reactor::ResultReactor>,
    frames: &Arc<DepositedFrames>,
    stdout: impl Fn(&str) -> String + Send + Sync + 'static,
    completed: &Arc<std::sync::atomic::AtomicUsize>,
) -> kata_workflow::test_harness::MemberReadMover {
    let rig = Arc::clone(rig);
    let reactor = Arc::clone(reactor);
    let frames = Arc::clone(frames);
    let completed = Arc::clone(completed);
    Arc::new(move |_: Ulid, occurrence: [u8; 32]| {
        if !occurrence_executors(&rig, occurrence)
            .iter()
            .any(|executor| executor == "worker")
        {
            return;
        }
        let frame = frames.take(occurrence);
        let stage = frame_stage_id(&rig, &frame);
        complete_frame(&rig, &reactor, &frame, stdout(&stage).as_bytes());
        completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    })
}

/// LOOP MEMBER: every member of the three-iteration loop completes INSIDE its
/// read window. The run approves at iteration 2 with nine accepted members —
/// no member is judged dead off a read that missed its completion.
///
/// **Watched red**: with the loop arm reading the occurrence and its attempts in
/// two snapshots, the first member dies `resolved \`completed\` without a
/// recorded reason` and the loop aborts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loop_member_completing_inside_its_read_window_is_never_judged_dead() {
    let program = program();
    let rig = Arc::new(OciNodeRig::open(&tempfile::tempdir().unwrap().keep()));
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = Arc::new(reactor(&rig));
    let (pump, frames) = spawn_member_pump(&rig, &reactor, |_| None);
    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let controller_seen = std::sync::atomic::AtomicU32::new(0);
    kata_workflow::test_harness::interleave_after_a_member_read(
        complete_worker_members_in_the_read_window(
            &rig,
            &reactor,
            &frames,
            move |stage| {
                let seen = if stage == "controller" {
                    controller_seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                } else {
                    controller_seen.load(std::sync::atomic::Ordering::SeqCst)
                };
                member_stdout(stage, seen)
            },
            &completed,
        ),
    );

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), runner.run())
        .await
        .expect("the drive settles within the budget");
    pump.abort();
    outcome.expect("a member that completes inside its read window is never judged dead");

    assert_eq!(
        completed.load(std::sync::atomic::Ordering::SeqCst),
        9,
        "every member completion committed inside its read window"
    );
    let record = expansion_record(&rig, execution, &expansion(&program))
        .expect("the loop's accepted record resolves");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Approved {
                iteration: 2
            }
        ),
        "the loop approves at iteration 2, got {:?}",
        record.resolution
    );
    assert_eq!(record.members.len(), 9, "the record names every member run");
}

/// TOPOLOGY MEMBER: the root and both children of a static topology complete
/// INSIDE their read windows. The topology settles with both children
/// `completed` and releases `successor`.
///
/// **Watched red**: with `read_topology_member` reading the occurrence and its
/// attempts in two snapshots, the root reads dead and the stage fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_topology_member_completing_inside_its_read_window_is_never_judged_dead() {
    let program = topology_program(TOPOLOGY_PACK, "topology-smoke.star");
    let rig = Arc::new(OciNodeRig::open(&tempfile::tempdir().unwrap().keep()));
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let reactor = Arc::new(reactor(&rig));
    let (pump, frames) = spawn_member_pump(&rig, &reactor, |stage| {
        (stage == "successor").then(|| "{\"note\":\"successor ok\"}".to_owned())
    });
    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    kata_workflow::test_harness::interleave_after_a_member_read(
        complete_worker_members_in_the_read_window(
            &rig,
            &reactor,
            &frames,
            |stage| match stage {
                "parent" => "{\"note\":\"root ok\"}".to_owned(),
                "parent#child-first_worker" => "{\"note\":\"first ok\"}".to_owned(),
                "parent#child-second_worker" => "{\"note\":\"second ok\"}".to_owned(),
                other => panic!("no member frame is scripted for {other}"),
            },
            &completed,
        ),
    );

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), runner.run())
        .await
        .expect("the drive settles within the budget");
    pump.abort();
    let outputs =
        outcome.expect("a member that completes inside its read window is never judged dead");

    assert_eq!(
        completed.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "the root and both children committed inside their read windows"
    );
    let record = expansion_record(&rig, execution, &topology_expansion(&program, "parent"))
        .expect("the topology's accepted record resolves");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Settled
        ),
        "the topology settles, got {:?}",
        record.resolution
    );
    assert_eq!(
        outputs[&SmolStr::new("parent")]["child_invocation_summary"]["completed"],
        2,
        "both children are completed in the fan-in"
    );
    assert!(
        outputs.contains_key(&SmolStr::new("successor")),
        "the settled topology released the successor"
    );
}

/// The unaccepted and accepted member occurrences one coordinate below
/// `parent`'s path, off the raw handle.
fn member_occurrences_below(
    rig: &OciNodeRig,
    execution: Ulid,
    parent: [u8; 32],
) -> (Vec<[u8; 32]>, usize) {
    let conn = raw(&rig.op_path);
    let parent_path: Vec<u8> = conn
        .query_row(
            "SELECT operation_path FROM occurrences WHERE occurrence_id = ?1",
            [parent.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let parent_path = OperationPath::from_canonical_bytes(&parent_path).unwrap();
    let mut statement = conn
        .prepare(
            "SELECT occurrence_id, operation_path, accepted_attempt_id IS NOT NULL
               FROM occurrences WHERE execution_id = ?1",
        )
        .unwrap();
    let rows: Vec<(Vec<u8>, Vec<u8>, bool)> = statement
        .query_map([execution.to_bytes().as_slice()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut unaccepted = Vec::new();
    let mut accepted = 0;
    for (id, path, is_accepted) in rows {
        let path = OperationPath::from_canonical_bytes(&path).unwrap();
        if path.0.len() != parent_path.0.len() + 1 || !path.0.starts_with(&parent_path.0) {
            continue;
        }
        if is_accepted {
            accepted += 1;
        } else {
            unaccepted.push(id.try_into().unwrap());
        }
    }
    (unaccepted, accepted)
}

/// NESTED TOPOLOGY: the loop body `implement` is a topology. Its members are
/// completed while the loop reads its nested `#op` occurrence unaccepted, and
/// the moment all three are accepted a SECOND driver of the same execution
/// resolves the nested topology — inside the loop's read window. The loop
/// approves at iteration 0 and `after` runs.
///
/// **Watched red**: with `nested_topology_member` reading the occurrence and its
/// main attempts in two snapshots, the nested topology reads dead `resolved
/// \`completed\` without a recorded reason` and the loop aborts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nested_topology_resolving_inside_its_read_window_is_never_judged_dead() {
    let program = topology_program(LOOP_TOPOLOGY_PACK, "loop-topology-smoke.star");
    let rig = Arc::new(OciNodeRig::open(&tempfile::tempdir().unwrap().keep()));
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution);
    let second_driver = Arc::new(rig.runner(&program, execution));
    let reactor = Arc::new(reactor(&rig));
    let (pump, frames) = spawn_member_pump(&rig, &reactor, |stage| {
        (stage == "after").then(|| "{\"note\":\"after ok\"}".to_owned())
    });
    let resolved_in_window = Arc::new(std::sync::atomic::AtomicBool::new(false));
    kata_workflow::test_harness::interleave_after_a_member_read({
        let rig = Arc::clone(&rig);
        let reactor = Arc::clone(&reactor);
        let resolved_in_window = Arc::clone(&resolved_in_window);
        Arc::new(move |execution: Ulid, occurrence: [u8; 32]| {
            // Only the nested `#op` read: its members complete here, never in
            // their own read windows, so this cell isolates the nested arm.
            if !occurrence_executors(&rig, occurrence)
                .iter()
                .all(|executor| executor == "main")
            {
                return;
            }
            let (unaccepted, _) = member_occurrences_below(&rig, execution, occurrence);
            for member in unaccepted {
                let frame = frames.take(member);
                let stdout = match frame_stage_id(&rig, &frame).as_str() {
                    "review" => "{\"verdict\":\"approve\",\"feedback\":\"root ok\"}",
                    "review#child-r1" | "review#child-r2" => "{\"verdict\":\"approve\"}",
                    _ => "{\"note\":\"ok\"}",
                };
                complete_frame(&rig, &reactor, &frame, stdout.as_bytes());
            }
            let (_, accepted) = member_occurrences_below(&rig, execution, occurrence);
            if accepted < 3 || resolved_in_window.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let second_driver = Arc::clone(&second_driver);
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current()
                    .block_on(second_driver.drive_pending_expansions_for_test())
            })
            .expect("the second driver resolves the nested topology");
            let accepted: bool = raw(&rig.op_path)
                .query_row(
                    "SELECT accepted_attempt_id IS NOT NULL FROM occurrences
                      WHERE occurrence_id = ?1",
                    [occurrence.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                accepted,
                "the nested topology's resolution committed inside the read window"
            );
        })
    });

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(120), runner.run())
        .await
        .expect("the drive settles within the budget");
    pump.abort();
    let outputs = outcome.expect("a nested topology resolved inside its read window is not dead");

    assert!(
        resolved_in_window.load(std::sync::atomic::Ordering::SeqCst),
        "the nested topology resolved inside the loop's read window"
    );
    let record = expansion_record(&rig, execution, &expansion(&program))
        .expect("the loop's accepted record resolves");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Approved {
                iteration: 0
            }
        ),
        "the loop approves at iteration 0, got {:?}",
        record.resolution
    );
    assert!(outputs.contains_key(&SmolStr::new("after")), "`after` ran");
}

/// `LOOP_TOPOLOGY_PACK` under `on_exhaustion = "accept"` with a typed gate
/// verdict and two routes on the quorum gate: a `branch()` on the loop's
/// verdict field (`approve`/`refine`/`block` arms) and a `branch()` on the
/// report's `lane` field (`ship`/`hold` arms).
fn unmet_quorum_accept_pack() -> String {
    let pack = LOOP_TOPOLOGY_PACK
        .replacen(
            "    outputs = {\n        \"verdict\": \"string\",\n        \"feedback\": \"string\",\n    },\n    depends_on = [\"implement\"],",
            "    produces = contract(\"Rv\", {\n        \"verdict\": field(enum(\"approve\", \"refine\", \"block\")),\n        \"lane\": field(enum(\"ship\", \"hold\")),\n        \"feedback\": field(\"string\"),\n    }),\n    depends_on = [\"implement\"],",
            1,
        )
        .replacen("on_exhaustion = \"fail\",", "on_exhaustion = \"accept\",", 1)
        .replacen(
            "workflow(\n    \"loop-topology-smoke\",",
            "promote_arm = stage(id = \"promote_arm\", agent = \"shell\", run = \"printf 'p\\\\n'\")\n\
             refine_arm = stage(id = \"refine_arm\", agent = \"shell\", run = \"printf 'r\\\\n'\")\n\
             block_arm = stage(id = \"block_arm\", agent = \"shell\", run = \"printf 'b\\\\n'\")\n\
             ship_arm = stage(id = \"ship_arm\", agent = \"shell\", run = \"printf 's\\\\n'\")\n\
             hold_arm = stage(id = \"hold_arm\", agent = \"shell\", run = \"printf 'h\\\\n'\")\n\
             branch(on = review, verdict_field = \"verdict\", arms = {\"approve\": [promote_arm], \"refine\": [refine_arm], \"block\": [block_arm]})\n\
             branch(on = review, verdict_field = \"lane\", arms = {\"ship\": [ship_arm], \"hold\": [hold_arm]})\n\n\
             workflow(\n    \"loop-topology-smoke\",",
            1,
        )
        .replacen(
            "root = [implement, review, after],",
            "root = [implement, review, after, promote_arm, refine_arm, block_arm, ship_arm, hold_arm],",
            1,
        );
    for spliced in [
        "produces = contract(\"Rv\"",
        "on_exhaustion = \"accept\"",
        "verdict_field = \"verdict\"",
        "verdict_field = \"lane\"",
        "hold_arm],",
    ] {
        assert!(pack.contains(spliced), "the pack splices {spliced:?}");
    }
    pack
}

/// An accepted exhaustion whose LAST gate verdict had its `review_quorum`
/// UNMET routes what the loop classified, not what the root said: the root
/// reports `approve` (and `lane = ship`) every iteration while the required
/// reviewer `r1` blocks, so every verdict's action is `refine`. The route on
/// the loop's verdict field takes its `refine` arm — never `approve` — and
/// the route on `lane`, a value the quorum refused, skips every arm. Arm
/// attempts are read from the raw `attempts` table through a read-only handle.
#[tokio::test(flavor = "current_thread")]
async fn an_accepted_exhaustion_on_an_unmet_quorum_routes_the_refine_arm() {
    let program = topology_program(&unmet_quorum_accept_pack(), "loop-topology-smoke.star");
    let rig = OciNodeRig::open(&tempfile::tempdir().unwrap().keep());
    rig.declare_bound_environment();
    let execution = Ulid::new();
    let loop_expansion = expansion(&program);
    let (outcome, _frames, _) = drive_loop_topology(&rig, &program, execution, |stage, _| {
        Some(
            match stage {
                "review" => "{\"verdict\":\"approve\",\"lane\":\"ship\",\"feedback\":\"root ok\"}",
                "review#child-r1" => "{\"verdict\":\"block\"}",
                "promote_arm" | "refine_arm" | "block_arm" | "ship_arm" | "hold_arm" => "{}",
                _ => "{\"note\":\"ok\"}",
            }
            .to_owned(),
        )
    })
    .await;
    outcome.expect("an accepted exhaustion completes the run");
    let record = expansion_record(&rig, execution, &loop_expansion).expect("the loop's record");
    assert!(
        matches!(
            record.resolution,
            kata_program::execution_program::expansion::ExpansionResolution::Exhausted {
                iterations: 2,
                on_max: kata_program::execution_program::expansion::ExpansionOnMax::Accept,
            }
        ),
        "the loop exhausts under accept, got {:?}",
        record.resolution
    );
    let verdicts: Vec<(String, bool)> = record
        .verdicts
        .iter()
        .map(|verdict| (verdict.verdict.clone(), verdict.quorum_unmet.is_some()))
        .collect();
    assert_eq!(
        verdicts,
        vec![("approve".to_owned(), true), ("approve".to_owned(), true)],
        "every root said approve and every quorum was unmet"
    );
    let attempts: Vec<(&str, i64)> = [
        "promote_arm",
        "refine_arm",
        "block_arm",
        "ship_arm",
        "hold_arm",
    ]
    .into_iter()
    .map(|arm| (arm, arm_attempt_count(&rig, execution, arm)))
    .collect();
    assert_eq!(
        attempts,
        vec![
            ("promote_arm", 0),
            ("refine_arm", 1),
            ("block_arm", 0),
            ("ship_arm", 0),
            ("hold_arm", 0),
        ],
        "a quorum-refused candidate takes the refine arm and no arm its root's report selects"
    );
}

/// [`unmet_quorum_accept_pack`] with the loop's verdict field narrowed to
/// `enum("approve", "block")` and its verdict route's `refine` arm dropped:
/// the route on the verdict field is exhaustive over the field's tags, and
/// `refine`, the tag an unmet quorum's accepted exhaustion routes, is not
/// among them.
fn refineless_quorum_accept_pack() -> String {
    let pack = unmet_quorum_accept_pack()
        .replacen(
            "field(enum(\"approve\", \"refine\", \"block\"))",
            "field(enum(\"approve\", \"block\"))",
            1,
        )
        .replacen(
            "arms = {\"approve\": [promote_arm], \"refine\": [refine_arm], \"block\": [block_arm]}",
            "arms = {\"approve\": [promote_arm], \"block\": [block_arm]}",
            1,
        );
    for spliced in [
        "field(enum(\"approve\", \"block\"))",
        "arms = {\"approve\": [promote_arm], \"block\": [block_arm]}",
    ] {
        assert!(pack.contains(spliced), "the pack splices {spliced:?}");
    }
    pack
}

/// CHECK — `loop_accept_quorum_route_needs_refine_tag`. A review-quorum gate
/// of an `on_exhaustion = "accept"` loop whose `branch()` routes the loop's
/// verdict field without the loop's refine tag among its arms is refused by
/// name: an accepted exhaustion whose last quorum was unmet routes `refine`,
/// which that route cannot take, so the run would fail
/// `select_verdict_unmatched` (`runner/select.rs`'s "unreachable from a
/// checked pack" depends on this refusal). Each twin is admitted, so the
/// refused set is no wider than it claims: the same pack under
/// `on_exhaustion = "fail"`, and [`unmet_quorum_accept_pack`], whose verdict
/// field carries `refine` — the pack
/// `an_accepted_exhaustion_on_an_unmet_quorum_routes_the_refine_arm` drives,
/// which still routes the refine arm.
///
/// **Watched red**: before the refusal the refineless pack compiled, and
/// driving it with the root approving and the required reviewer blocking
/// failed the run `select_verdict_unmatched`.
#[test]
fn an_accept_quorum_gate_routing_its_verdict_without_the_refine_tag_is_refused_by_name() {
    kata_types::node_profile::mark_node_installed();
    let error = compile_starlark_execution_program(
        &refineless_quorum_accept_pack(),
        "loop-topology-smoke.star",
        &[],
    )
    .expect_err("a refineless verdict route on an accept quorum gate refuses at CHECK");
    let message = error.to_string();
    assert!(
        message.contains("loop_accept_quorum_route_needs_refine_tag")
            && message.contains("\"review\""),
        "the refusal is named and names the gate: {message}"
    );

    let under_fail = refineless_quorum_accept_pack().replacen(
        "on_exhaustion = \"accept\",",
        "on_exhaustion = \"fail\",",
        1,
    );
    assert!(under_fail.contains("on_exhaustion = \"fail\","));
    compile_starlark_execution_program(&under_fail, "loop-topology-smoke.star", &[])
        .unwrap_or_else(|error| panic!("the same pack under `fail` compiles: {error}"));
    compile_starlark_execution_program(
        &unmet_quorum_accept_pack(),
        "loop-topology-smoke.star",
        &[],
    )
    .unwrap_or_else(|error| panic!("a verdict field that carries `refine` compiles: {error}"));
}
