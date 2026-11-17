//! The typed `memory_snapshot()` stage: a MAIN-RESOLVED read of the
//! node's native memory store on EVERY profile, never a host shell stage
//! calling back into the loopback API.
//!
//! # Invariant
//!
//! Every durable assertion reads `operational.db` through a read-only
//! connection this file opens itself; the snapshot's objects are seeded into a
//! real `SqliteNativeMemoryStore` and counted there; "nothing ran" is read off
//! the WORKER end of the rig's `InProcessTransport`. The run goes through
//! `WorkflowRunner::run` — the production drive — on both profiles.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kata_program::execution_program::{compile_starlark_execution_program, lower_stage_operation};
use kata_transport::types::{DispatchFrame, WorkerMessage};
use kata_types::execution_contract::RuntimeOperation;
use kata_types::memory::{
    MemoryObjectDraft, MemoryObjectKind, MemoryObjectStatus, MemoryProposal, MemoryProvenance,
    MemorySourceKind,
};
use kata_types::workflow::{MemorySnapshotSpec, StageId};
use kata_workflow::reactor::ResultReactor;
use kata_workflow::test_harness::{OCI_RIG_WORKER, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

fn raw(path: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a second raw handle")
}

/// A snapshot stage between two shell stages, the downstream rendering the
/// injected `parsed`.
const SNAP_PACK: &str = r#"
a = stage(id = "a", agent = "shell", run = "true")
snap = memory_snapshot(id = "snap", kind = "task", status = "active", depends_on = [a])
tail = stage(id = "tail", agent = "shell",
    run = "echo '{\"seen\": {{ stages.snap.parsed.object_count }} }'",
    depends_on = [snap])
workflow("snap-pack", root = [a])
"#;

fn seed_store() -> Arc<kata_core::store::SqliteNativeMemoryStore> {
    seeded(
        kata_core::store::SqliteNativeMemoryStore::open_in_memory()
            .expect("the memory store opens"),
    )
}

fn seeded(
    store: kata_core::store::SqliteNativeMemoryStore,
) -> Arc<kata_core::store::SqliteNativeMemoryStore> {
    let store = Arc::new(store);
    let draft = |id: &str, kind: MemoryObjectKind, status: MemoryObjectStatus| MemoryProposal {
        proposal_id: None,
        expected_revision: None,
        object: MemoryObjectDraft {
            id: Some(id.to_owned()),
            kind,
            status,
            scope: kata_types::memory::MemoryScope::Global,
            title: Some(id.to_owned()),
            body: serde_json::json!({ "note": id }),
            tags: Vec::new(),
            links: Vec::new(),
            provenance: MemoryProvenance {
                source_kind: MemorySourceKind::Workflow,
                source_id: Some("snapshot-cell".to_owned()),
                execution_id: None,
                agent_id: None,
                path: None,
            },
        },
        source_file: None,
    };
    // Two ACTIVE tasks (the queried set), one ACTIVE finding and one RESOLVED
    // task (the excluded set) — the filter, not the store size, is asserted.
    store
        .apply_proposal(draft(
            "task-1",
            MemoryObjectKind::Task,
            MemoryObjectStatus::Active,
        ))
        .unwrap();
    store
        .apply_proposal(draft(
            "task-2",
            MemoryObjectKind::Task,
            MemoryObjectStatus::Active,
        ))
        .unwrap();
    store
        .apply_proposal(draft(
            "finding-1",
            MemoryObjectKind::Finding,
            MemoryObjectStatus::Active,
        ))
        .unwrap();
    store
        .apply_proposal(draft(
            "task-3",
            MemoryObjectKind::Task,
            MemoryObjectStatus::Resolved,
        ))
        .unwrap();
    store
}

// ---------------------------------------------------------------------------
// DSL → marker → typed operation
// ---------------------------------------------------------------------------

/// The builtin lowers its authored filter onto the checked-IR marker and the
/// marker lowers to `RuntimeOperation::MemorySnapshot` — the routing fact the
/// runner diverts on.
#[test]
fn snapshot_builtin_lowers_the_marker_and_the_main_resolved_operation() {
    let program = compile_starlark_execution_program(SNAP_PACK, "snap.star", &[])
        .expect("the snapshot pack compiles");
    let stage = program
        .stages
        .get(&StageId(SmolStr::new("snap")))
        .expect("snap is a stage of the program");
    assert_eq!(
        stage.memory_snapshot,
        Some(MemorySnapshotSpec {
            kind: Some(MemoryObjectKind::Task),
            status: Some(MemoryObjectStatus::Active),
        }),
        "the authored filter rides the checked-IR marker"
    );
    // The declared envelope is the snapshot's five fields, and the stage is
    // never content-cached.
    let output_names: Vec<&str> = stage.outputs.iter().map(|o| o.name.as_str()).collect();
    for field in [
        "schema_version",
        "generated_at_ms",
        "revision_head",
        "object_count",
        "objects",
    ] {
        assert!(output_names.contains(&field), "outputs: {output_names:?}");
    }
    assert_eq!(
        stage.policies.cache_policy,
        kata_types::cache::CachePolicy::Disabled
    );

    let lowered = lower_stage_operation(&program, &StageId(SmolStr::new("snap")))
        .expect("the marker stage lowers");
    match &lowered.contract.operation {
        RuntimeOperation::MemorySnapshot { query } => {
            assert_eq!(query.kind, Some(MemoryObjectKind::Task));
            assert_eq!(query.status, Some(MemoryObjectStatus::Active));
        }
        operation => panic!(
            "snap lowers to `{}`, not memory_snapshot",
            operation.as_tag()
        ),
    }
    assert_eq!(lowered.contract.operation.as_tag(), "memory_snapshot");

    // An unfiltered builtin carries both fields absent.
    let bare = compile_starlark_execution_program(
        "s = memory_snapshot(id = \"s\")\nworkflow(\"w\", root = [s])\n",
        "bare.star",
        &[],
    )
    .expect("a bare memory_snapshot compiles");
    match &lower_stage_operation(&bare, &StageId(SmolStr::new("s")))
        .unwrap()
        .contract
        .operation
    {
        RuntimeOperation::MemorySnapshot { query } => {
            assert_eq!(
                query,
                &MemorySnapshotSpec {
                    kind: None,
                    status: None
                }
            );
        }
        operation => panic!("{operation:?}"),
    }
}

/// `kind`/`status` are closed sets at the builtin: an unknown spelling is a
/// load-time error naming the accepted set — not a parse failure deep in the
/// engine.
#[test]
fn snapshot_builtin_validates_the_closed_kind_and_status_sets() {
    let err = |line: &str| {
        compile_starlark_execution_program(
            &format!("s = memory_snapshot({line})\nworkflow(\"w\", root = [s])\n"),
            "snap-err.star",
            &[],
        )
        .expect_err("the bad filter is refused at load")
        .to_string()
    };
    let bad_kind = err("kind = \"bug\"");
    assert!(
        bad_kind.contains("memory_snapshot() kind must be one of") && bad_kind.contains("\"bug\""),
        "the refusal names the set and the bad value: {bad_kind}"
    );
    let bad_status = err("status = \"on-fire\"");
    assert!(
        bad_status.contains("memory_snapshot() status must be one of")
            && bad_status.contains("\"on-fire\""),
        "{bad_status}"
    );
    // Every advertised spelling parses — the catalog domain and the parse set
    // are one list.
    for kind in MemoryObjectKind::all() {
        compile_starlark_execution_program(
            &format!(
                "s = memory_snapshot(kind = \"{}\")\nworkflow(\"w\", root = [s])\n",
                kind.label()
            ),
            "k.star",
            &[],
        )
        .unwrap_or_else(|e| panic!("kind {:?} must be admitted: {e}", kind.label()));
    }
    for status in MemoryObjectStatus::all() {
        compile_starlark_execution_program(
            &format!(
                "s = memory_snapshot(status = \"{}\")\nworkflow(\"w\", root = [s])\n",
                status.label()
            ),
            "s.star",
            &[],
        )
        .unwrap_or_else(|e| panic!("status {:?} must be admitted: {e}", status.label()));
    }
}

// ---------------------------------------------------------------------------
// CHECK admission
// ---------------------------------------------------------------------------

/// The marker stage is ADMITTED under `oci` (it maps no `/work`, asks for no
/// capsule bound, and opts out of nothing) — while the `host` opt-out on a
/// plain stage is still refused BY NAME, and the refusal names only that stage.
#[test]
fn the_marker_stage_is_admitted_under_oci_and_the_host_door_still_fires_elsewhere() {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(SNAP_PACK, "snap.star", &[])
        .expect("the snapshot pack is admitted under oci");
    // A pack whose OTHER stage runs host-unconfined refuses that stage only.
    let mixed = r#"
hot = stage(id = "hot", agent = "shell", run = "id", sandbox = "host")
snap = memory_snapshot(id = "snap", depends_on = [hot])
workflow("mixed", root = [hot])
"#;
    let refusal = compile_starlark_execution_program(mixed, "mixed.star", &[])
        .expect_err("the host stage is refused under oci")
        .to_string();
    assert!(
        refusal.contains("host_sandbox_unsupported_under_oci") && refusal.contains("\"hot\""),
        "the refusal names the host stage by name: {refusal}"
    );
    assert!(
        !refusal.contains("\"snap\""),
        "the marker stage is outside the refused set: {refusal}"
    );
}

// ---------------------------------------------------------------------------
// Operation identity
// ---------------------------------------------------------------------------

/// The authored filter rides the operation identity PRESENCE-SENSITIVELY: an
/// absent filter, a `task` filter and a `finding` filter are three different
/// operations — a widened read cannot adopt a narrower one's acceptance.
#[test]
fn the_authored_filter_rotates_operation_identity() {
    use kata_types::execution_contract::OperationContract;
    let contract = |kind, status| {
        OperationContract::new(
            StageId(SmolStr::new("snap")),
            RuntimeOperation::MemorySnapshot {
                query: MemorySnapshotSpec { kind, status },
            },
        )
    };
    let bare = contract(None, None);
    let task = contract(Some(MemoryObjectKind::Task), None);
    let task_active = contract(
        Some(MemoryObjectKind::Task),
        Some(MemoryObjectStatus::Active),
    );
    let finding = contract(Some(MemoryObjectKind::Finding), None);
    let task_again = contract(Some(MemoryObjectKind::Task), None);
    assert_ne!(bare.id(), task.id());
    assert_ne!(task.id(), task_active.id());
    assert_ne!(task.id(), finding.id());
    assert_eq!(task.id(), task_again.id());
}

// ---------------------------------------------------------------------------
// Main-side resolution — oci
// ---------------------------------------------------------------------------

/// Publish `bytes` as a capture blob in the rig's CAS.
fn publish_capture(rig: &OciNodeRig, bytes: &[u8]) -> kata_types::execution_contract::ArtifactRef {
    let receipt = rig.cas.put_durable(bytes).unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    )
}

fn empty_tree_result() -> kata_types::execution_contract::ArtifactRef {
    let manifest = kata_types::tree_artifact::TreeManifest::new(Vec::new())
        .unwrap()
        .manifest_bytes()
        .unwrap();
    kata_types::execution_contract::ArtifactRef::new(
        kata_types::cache::object_id_for_canonical_bytes(&manifest),
        u64::try_from(manifest.len()).unwrap(),
        kata_types::execution_contract::ArtifactPrivacy::Public,
    )
}

fn reactor(rig: &OciNodeRig) -> ResultReactor {
    ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.worker_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    )
}

/// The stub worker's one step: take the next delivered capsule, run its argv
/// with the host's `sh`, report the completion. Answers the argv.
async fn run_next_capsule(rig: &OciNodeRig, reactor: &ResultReactor) -> Vec<String> {
    let frame = match rig
        .worker_side
        .recv_frame()
        .await
        .expect("the transport delivers a frame")
    {
        DispatchFrame::Capsule(capsule) => *capsule,
    };
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
            panic!("the fixture stage is a Command capsule")
        }
    };
    let ran = std::process::Command::new("sh")
        .args(&argv[1..])
        .output()
        .expect("the host shell runs the capsule's command");
    reactor
        .handle_message_for_test(WorkerMessage::CompletedCapsule {
            attempt_id: frame.attempt_id,
            fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
            result: empty_tree_result(),
            work_delta: kata_workflow::test_harness::stub_work_delta(
                &rig.db,
                &rig.cas,
                frame.occurrence_id,
            ),
            exit_code: ran.status.code(),
            stdout: publish_capture(rig, &ran.stdout),
            stderr: publish_capture(rig, &ran.stderr),
            capture_exceeded: false,
            agent: None,
            provenance: kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                "memory snapshot cell",
            ),
            egress_refusals: vec![],
        })
        .expect("the completion is adopted and accepted");
    argv
}

/// THE MAIN-SIDE READ, under `oci`: the `memory_snapshot` marker stage never
/// reaches a worker — it claims and resolves one `executor = 'main'` attempt
/// in one transaction with the snapshot envelope `{"content": <snapshot JSON>}`,
/// the fold validates the declared fields and injects `parsed`, and the
/// downstream stage's capsule argv literally renders the live `object_count`.
/// The read runs inside the resolution transaction, not in a process.
///
/// **Watched red:** with the `RuntimeOperation::MemorySnapshot` arm deleted
/// from `divert_under_capsule_profile`, the stage hits the catch-all refusal
/// (`stage_operation_unsupported`) and no attempt or output
/// exists.
#[tokio::test]
async fn the_snapshot_resolves_main_side_under_oci() {
    kata_types::node_profile::mark_node_installed();
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();
    let store = seed_store();
    let program = compile_starlark_execution_program(SNAP_PACK, "snap.star", &[])
        .expect("the pack compiles under oci");
    let execution = Ulid::new();
    let runner = rig
        .runner(&program, execution)
        .with_memory_store(Arc::clone(&store));
    let reactor = reactor(&rig);
    let mut argvs = Vec::new();
    let run = runner.run();
    tokio::pin!(run);
    let outcome = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            tokio::select! {
                outcome = &mut run => break outcome,
                argv = run_next_capsule(&rig, &reactor) => argvs.push(argv),
            }
        }
    })
    .await
    .expect("the run ends within its budget");
    let outputs = outcome.expect("the pack completes");

    // The accepted output: the envelope the fold's `inject_parsed_if_declared`
    // augmented — `content` is the snapshot JSON as a string, `parsed` its
    // decoded form.
    let envelope = &outputs["snap"];
    let content = envelope["content"].as_str().expect("content is a string");
    let snapshot: serde_json::Value =
        serde_json::from_str(content).expect("content decodes as the snapshot JSON");
    assert_eq!(snapshot["object_count"], 2, "{snapshot}");
    assert_eq!(snapshot["objects"].as_array().unwrap().len(), 2);
    assert!(snapshot["revision_head"].is_number() && snapshot["schema_version"].is_number());
    assert_eq!(envelope["parsed"]["object_count"], 2, "{envelope:?}");

    // The downstream capsule rendered the injected parsed value.
    assert_eq!(
        argvs.len(),
        2,
        "a and tail ran as capsules; snap ran nothing: {argvs:?}"
    );
    let tail_command = argvs[1].join(" ");
    assert!(
        tail_command.contains("\"seen\": 2"),
        "tail's argv renders the live snapshot count: {tail_command}"
    );

    // Raw durable assertions, through a second read-only handle: ONE attempt
    // for snap, `executor = 'main'`, accepted; no worker attempt exists for it.
    let (executor, accepted): (String, i64) = raw(&rig.op_path)
        .query_row(
            "SELECT a.executor, (o.accepted_attempt_id IS NOT NULL) FROM attempts a
               JOIN occurrences o ON o.occurrence_id = a.occurrence_id
              WHERE a.stage_id = 'snap'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("snap's attempt row");
    assert_eq!(executor, "main");
    assert_eq!(accepted, 1);
    let worker_attempts: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = 'snap' AND executor = 'worker'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(worker_attempts, 0, "no process ever held snap");
}

/// A RE-PRESENTED snapshot converges and writes nothing: the occurrence keeps
/// its one accepted attempt, no second resolution lands, and the store is NOT
/// read again — between the presentations a second handle renames the store's
/// event table, so a re-read would fail the divert.
///
/// **Watched red:** before `resolve_memory_snapshot` decided convergence ahead
/// of the store read, the re-presentation answered
/// `Storage("native_memory_store select revision head: no such table: memory_events")`.
#[tokio::test]
async fn a_re_presented_snapshot_converges_on_its_accepted_resolution() {
    kata_types::node_profile::mark_node_installed();
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    let store_path = dir.path().join("memory.db");
    let store = seeded(
        kata_core::store::SqliteNativeMemoryStore::open(&store_path)
            .expect("the file-backed memory store opens"),
    );
    let program = compile_starlark_execution_program(SNAP_PACK, "snap.star", &[])
        .expect("the pack compiles under oci");
    let execution = Ulid::new();
    let runner = rig
        .runner(&program, execution)
        .with_memory_store(Arc::clone(&store));
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new("snap"))
            .expect("the first presentation resolves"),
        "a snapshot is a main-resolved route"
    );
    let attempts: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = 'snap'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempts, 1);
    rusqlite::Connection::open(&store_path)
        .expect("a second handle on the memory store")
        .execute_batch("ALTER TABLE memory_events RENAME TO memory_events_gone;")
        .expect("the store's event table is renamed away");
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new("snap"))
            .expect("the re-presentation converges without reading the store"),
        "a snapshot converges as resolved"
    );
    let attempts_after: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts WHERE stage_id = 'snap'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempts_after, 1, "the re-presentation wrote nothing");
    let live: i64 = raw(&rig.op_path)
        .query_row(
            "SELECT count(*) FROM attempts a JOIN attempt_projection p
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
               AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.stage_id = 'snap' AND p.state NOT IN ('completed','failed','cancelled')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(live, 0, "nothing is left live");
}

/// THE STORE-ABSENT VERDICT: on a node whose runner carries no memory store the
/// stage claims and resolves `failed` with `memory_snapshot_store_unavailable`
/// — a recorded verdict, not a poisoned dispatch. The verdict does not settle
/// the occurrence: a re-presentation mints one further attempt, which resolves
/// the same verdict while the node still has no store. Each presentation
/// returns `Ok`: the claim answers `Resolved` for the failed resolution, and
/// the runner refuses `ResolvedFailed`, which only a join answers.
#[tokio::test]
async fn a_snapshot_on_a_node_without_a_store_resolves_failed() {
    kata_types::node_profile::mark_node_installed();
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    let program = compile_starlark_execution_program(SNAP_PACK, "snap.star", &[])
        .expect("the pack compiles under oci");
    let execution = Ulid::new();
    let runner = rig.runner(&program, execution); // no memory store attached
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new("snap"))
            .expect("the failed resolution is still a resolution")
    );
    let (state, detail): (String, String) = raw(&rig.op_path)
        .query_row(
            "SELECT p.state, t.payload_json FROM attempts a
               JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
               JOIN transitions t ON t.attempt_id = a.attempt_id
              WHERE a.stage_id = 'snap' AND t.resulting_state = 'failed'",
            [],
            |row| {
                let state: String = row.get(0)?;
                let payload: Vec<u8> = row.get(1)?;
                Ok((state, String::from_utf8_lossy(&payload).into_owned()))
            },
        )
        .expect("snap's recorded failed resolution");
    assert_eq!(state, "failed");
    assert!(
        detail.contains("memory_snapshot_store_unavailable"),
        "the verdict is recorded by name: {detail}"
    );
    // A re-presentation after a FAILED resolution is a retry, not a no-op:
    // `converge_in_tx` folds only live and accepted attempts, so the plane
    // mints a second attempt — which must deterministically replay the SAME
    // verdict, never a divergent one.
    assert!(
        runner
            .divert_under_capsule_profile_for_test(&SmolStr::new("snap"))
            .expect("the re-presentation retries the recorded verdict")
    );
    let (attempts, failed): (i64, i64) = raw(&rig.op_path)
        .query_row(
            "SELECT count(*), sum(p.state = 'failed') FROM attempts a
               JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.stage_id = 'snap'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        attempts, 2,
        "the retry minted one more attempt, nothing else"
    );
    assert_eq!(failed, 2, "both presentations resolve the same verdict");
}

/// THE SNAPSHOT'S LOG LINE NAMES ITS VERDICT: the runner's own trace output is what an
/// operator reads, so a store-less node's `failed` resolution is a WARN line naming
/// `memory_snapshot_store_unavailable` and never the success line, and a store-backed
/// node's accepted resolution is the INFO success line and never the failure one. Read off
/// the test thread's fmt subscriber, which formats the line the runner emitted.
///
/// **Would red if:** the store-less resolution were logged with the accepted one's line
/// (`runner: resolved a memory snapshot main-side`) — the L3 C-65 defect.
#[tokio::test]
async fn a_failed_snapshot_is_logged_as_a_failure_and_an_accepted_one_as_resolved() {
    const SUCCESS: &str = "runner: resolved a memory snapshot main-side";
    const FAILURE: &str = "runner: a memory snapshot resolved FAILED main-side";
    kata_types::node_profile::mark_node_installed();
    let program = compile_starlark_execution_program(SNAP_PACK, "snap.star", &[])
        .expect("the pack compiles under oci");

    let logs = CapturedLogs::default();
    {
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_writer(logs.clone())
                .finish(),
        );
        let dir = tempfile::tempdir().unwrap();
        let rig = OciNodeRig::open(dir.path());
        let runner = rig.runner(&program, Ulid::new()); // no memory store attached
        assert!(
            runner
                .divert_under_capsule_profile_for_test(&SmolStr::new("snap"))
                .expect("the failed resolution is still a resolution")
        );
    }
    let text = logs.text();
    let line = text
        .lines()
        .find(|line| line.contains("stage=snap") && line.contains("memory snapshot"))
        .unwrap_or_else(|| panic!("the store-less snapshot logs one line: {text}"));
    assert!(
        line.contains("WARN")
            && line.contains(FAILURE)
            && line.contains("memory_snapshot_store_unavailable")
            && !text.contains(SUCCESS),
        "a failed snapshot is logged as a failure, never as resolved: {text}"
    );

    let logs = CapturedLogs::default();
    {
        let _subscriber = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_writer(logs.clone())
                .finish(),
        );
        let dir = tempfile::tempdir().unwrap();
        let rig = OciNodeRig::open(dir.path());
        let runner = rig
            .runner(&program, Ulid::new())
            .with_memory_store(seed_store());
        assert!(
            runner
                .divert_under_capsule_profile_for_test(&SmolStr::new("snap"))
                .expect("the accepted resolution")
        );
    }
    let text = logs.text();
    let line = text
        .lines()
        .find(|line| line.contains("stage=snap") && line.contains("memory snapshot"))
        .unwrap_or_else(|| panic!("the accepted snapshot logs one line: {text}"));
    assert!(
        line.contains("INFO") && line.contains(SUCCESS) && !text.contains(FAILURE),
        "an accepted snapshot is logged as resolved: {text}"
    );
}

/// The fmt output of the test thread's tracing, captured.
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
