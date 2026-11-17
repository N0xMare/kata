//! A subworkflow `Invoke` under the `oci` profile, driven through
//! the REAL executor (`WorkflowExecutor`, child spawning installed): the parent's runner
//! reaches the stage, the divert's `Invoke` arm starts the child through the executor's
//! `ChildInvoker`, the child runs as its own execution, and its terminal publication
//! resolves the parent.
//!
//! The same executor rig also carries the CANCEL-OUTCOME cells: a cancelled `oci`
//! execution publishes `cancelled` whichever executor held its cancelled stage (a parked
//! main timer, a running capsule, a parent's `Invoke`).
//!
//! A stub worker on the WORKER end of the node's `InProcessTransport` runs each delivered
//! capsule's argv with the host's own `sh` and reports the completion through the result
//! reactor. Every outcome is read through a SECOND raw read-only rusqlite handle on
//! `operational.db` — never through the executor's answer about itself.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::WorkflowExecutor;
use kata_program::execution_program::{
    ExecutionProgram, compile_starlark_execution_program, lower_stage_operation, occurrence_for,
};
use kata_program::library::WorkflowLibrary;
use kata_transport::types::DispatchFrame;
use kata_types::workflow::{ExecutionId, StageId};
use kata_workflow::execution_program_store::ExecutionInvocation;
use kata_workflow::test_harness::{OCI_RIG_WORKER, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

const SHIPPED_PARENT: &str = include_str!("../../../workflows/smoke/subworkflow-parent-smoke.star");
const INVOKE_STAGE: &str = "sub";

/// A pack whose middle stage is a ten-minute durable sleep — a child that is still running
/// whenever a cell acts on it, and whose parked timer a cancel ends main-side.
const LONG_CHILD: &str = "pre = stage(id = \"pre\", agent = \"shell\", run = \"true\")\n\
                          nap = sleep(id = \"nap\", for_ms = 600000, depends_on = [pre])\n\
                          post = stage(id = \"post\", agent = \"shell\", run = \"true\", \
                          depends_on = [nap])\n\
                          workflow(\"long-child\", root = [pre])\n";
/// A pack whose one stage FAILS: it declares a structured output and prints no JSON, so
/// its schema validation refuses the completion. (A non-zero exit would fail it the same
/// way under `oci` — the main judges a capsule's exit status against the stage's exit
/// policy at acceptance — and `crates/workflow/tests/oci_check_and_dispatch.rs` pins
/// that; this child fails on the other failure class.)
const FAILING_CHILD: &str = "bad = stage(id = \"bad\", agent = \"shell\", run = \"echo not-json\", \
                             outputs = {\"value\": \"string\"})\n\
                             workflow(\"failing-child\", root = [bad])\n";

fn smoke_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workflows/smoke")
}

fn raw(rig: &OciNodeRig) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        &rig.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// A node on `oci` over `path` with an executor whose child spawning is installed, and a
/// stub worker answering every capsule. `hold` names a stage whose answer waits until a
/// durable timer is parked somewhere on the node — so a sibling's failure lands while a
/// child waits.
struct Node {
    rig: OciNodeRig,
    executor: Arc<WorkflowExecutor>,
    worker: tokio::task::JoinHandle<()>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

fn node(node_dir: &Arc<tempfile::TempDir>, hold: Option<&'static str>) -> Node {
    node_with(node_dir, |rig, dir| spawn_stub_worker(rig, dir, hold))
}

/// [`node`] with `worker` as its stub worker. `node_dir` reaches the worker
/// factory as an `Arc`: `Node::drop` only aborts the task, and an abort lands
/// at the task's next poll — the directory the worker's CAS/db handles root
/// at must live in the task, not just in the caller.
fn node_with(
    node_dir: &Arc<tempfile::TempDir>,
    worker: impl FnOnce(&OciNodeRig, Arc<tempfile::TempDir>) -> tokio::task::JoinHandle<()>,
) -> Node {
    kata_types::node_profile::mark_node_installed();
    let rig = OciNodeRig::open(node_dir.path());
    rig.declare_bound_environment();
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle())
        // The node's content store, which the capsule route publishes a capsule into.
        .with_cache_store(Arc::clone(&rig.store)),
    );
    executor.install_child_spawning();
    let worker = worker(&rig, Arc::clone(node_dir));
    Node {
        rig,
        executor,
        worker,
    }
}

/// THE STUB WORKER: take each delivered capsule frame, read its argv out of the node's CAS
/// (the bytes a container would `execve`), RUN it with the host's own `sh`, and report the
/// completion — stdout and exit code — through the result reactor.
fn spawn_stub_worker(
    rig: &OciNodeRig,
    node_dir: Arc<tempfile::TempDir>,
    hold: Option<&'static str>,
) -> tokio::task::JoinHandle<()> {
    let worker_side = Arc::clone(&rig.worker_side);
    let cas = Arc::new(
        kata_core::store::cas::CasStore::open(
            node_dir.path().join("cas.db"),
            node_dir.path().join("cas"),
        )
        .expect("the content store opens"),
    );
    let op_path = rig.op_path.clone();
    let db = Arc::clone(&rig.db);
    let reactor = Arc::new(kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.worker_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    ));
    // Each frame is answered on its own task, so a HELD answer never blocks the next
    // delivery (a child's capsule behind a held sibling's).
    tokio::spawn(async move {
        while let Ok(frame) = worker_side.recv_frame().await {
            let DispatchFrame::Capsule(frame) = frame;
            let (cas, reactor, op_path, db, frame_dir) = (
                Arc::clone(&cas),
                Arc::clone(&reactor),
                op_path.clone(),
                Arc::clone(&db),
                Arc::clone(&node_dir),
            );
            tokio::spawn(async move {
                let _node_dir = frame_dir;
                let stage: String = rusqlite::Connection::open_with_flags(
                    &op_path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .unwrap()
                .query_row(
                    "SELECT stage_id FROM attempts WHERE attempt_id = ?1",
                    [frame.attempt_id.to_bytes().as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
                if hold == Some(stage.as_str()) {
                    wait_until(&op_path, "a durable timer parks", |conn| {
                    count(
                        conn,
                        "SELECT count(*) FROM attempt_projection WHERE state = 'awaiting_timer'",
                    ) > 0
                })
                .await;
                }
                let bytes = cas
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
                .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
                    attempt_id: frame.attempt_id,
                    fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                    result: empty_tree_result(),
                    work_delta: stub_work_delta(&db, &cas, &capsule),
                    exit_code: ran.status.code(),
                    stdout: {
                        let receipt = cas.put_durable(&ran.stdout).unwrap();
                        kata_types::execution_contract::ArtifactRef::new(
                            receipt.object_id(),
                            receipt.size(),
                            kata_types::execution_contract::ArtifactPrivacy::Private,
                        )
                    },
                    stderr: {
                        let receipt = cas.put_durable(&ran.stderr).unwrap();
                        kata_types::execution_contract::ArtifactRef::new(
                            receipt.object_id(),
                            receipt.size(),
                            kata_types::execution_contract::ArtifactPrivacy::Private,
                        )
                    },
                    capture_exceeded: false,
                    agent: None,
                    provenance:
                        kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                            "subworkflow invoke cell",
                        ),
                    egress_refusals: vec![],
                })
                .expect("the completion is adopted");
            });
        }
    })
}

/// A STUB WORKER THAT ONLY STOPS: every delivered capsule is HELD — never run — until the
/// node sends its attempt a `Stop`, which it answers the way the worker's capsule route
/// answers a container it stopped (`kata_worker::capsule_execution`, a drive refusal):
/// `Failed`, PROVEN AMBIGUOUS, echoing the held frame's fence.
fn spawn_stopping_worker(
    rig: &OciNodeRig,
    node_dir: Arc<tempfile::TempDir>,
) -> tokio::task::JoinHandle<()> {
    let worker_side = Arc::clone(&rig.worker_side);
    let reactor = kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.worker_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    );
    tokio::spawn(async move {
        let _node_dir = node_dir;
        let mut held = std::collections::HashMap::new();
        loop {
            tokio::select! {
                frame = worker_side.recv_frame() => {
                    let Ok(DispatchFrame::Capsule(frame)) = frame else { return };
                    held.insert(frame.attempt_id, *frame);
                }
                control = worker_side.recv_control() => {
                    let Ok(kata_transport::types::WorkerControl::Stop { assignment_id, reason, .. }) =
                        control
                    else {
                        continue;
                    };
                    let frame = held.remove(&assignment_id).expect("a stop names a held capsule");
                    reactor
                        .handle_message_for_test(kata_transport::types::WorkerMessage::Failed {
                            assignment_id,
                            reason: format!("operator stop: {reason}"),
                            verdict: kata_types::effect::DeliveryFailureProvenance::ProvenAmbiguous,
                            provider_failure: None,
                            fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                            usage: None,
                        })
                        .expect("the stopped attempt's failure is adjudicated");
                }
            }
        }
    })
}

/// The canonical EMPTY tree — what a shell stage that writes no `/out` file reports.
/// Publish `bytes` as a capture blob in the rig's CAS — the shape a v6 frame's
/// `stdout`/`stderr` carry (the provider spools, the worker publishes).
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

/// The stub's `/work` answer: the argv ran against no tree at all, so the
/// truthful delta is EMPTY over the mapped base — the same object a real worker
/// publishes for an untouched `/work`. `None` only for a capsule that maps no
/// `/work`, the one arm the adoption accepts a `None` for.
fn stub_work_delta(
    db: &kata_core::OperationalDb,
    cas: &kata_core::store::cas::CasStore,
    capsule: &kata_types::execution_contract::Capsule,
) -> Option<kata_types::execution_contract::ArtifactRef> {
    let mapping = capsule
        .inputs()
        .iter()
        .find(|mapping| mapping.guest_path.as_str() == "/work")?;
    let base_row = db
        .artifact(mapping.artifact.0.0)
        .expect("the artifact read succeeds")
        .expect("the capsule's /work base is a declared artifact");
    let base_ref = kata_types::execution_contract::ArtifactRef::new(
        kata_types::primitives::ObjectId::from(base_row.object_id),
        base_row.size_bytes,
        base_row.privacy,
    );
    assert_eq!(
        base_ref.id().0.0,
        base_row.artifact_id,
        "the artifact row reconstructs the mapping's base id"
    );
    let base: kata_types::tree_artifact::TreeManifest = serde_json::from_slice(
        &cas.get(&base_ref.object_id())
            .expect("the CAS reads")
            .expect("the base manifest object is published"),
    )
    .expect("the /work base decodes as a tree manifest");
    let delta = kata_types::tree_delta::TreeDelta::between(base_ref.clone(), &base, &base)
        .expect("an untouched /work diffs to an empty delta")
        .delta_bytes()
        .expect("an empty delta encodes");
    let receipt = cas.put_durable(&delta).expect("the delta bytes publish");
    Some(kata_types::execution_contract::ArtifactRef::new(
        receipt.object_id(),
        receipt.size(),
        kata_types::execution_contract::ArtifactPrivacy::Private,
    ))
}

fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

/// Poll the raw plane at `op_path` until `ready`, for at most 30 s.
async fn wait_until(op_path: &Path, what: &str, ready: impl Fn(&rusqlite::Connection) -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let conn = rusqlite::Connection::open_with_flags(
            op_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        if ready(&conn) {
            return;
        }
        drop(conn);
        if std::time::Instant::now() >= deadline {
            let dump = std::process::Command::new("sqlite3")
                .arg(op_path)
                .arg(
                    "SELECT substr(hex(execution_id),1,8), kind, coalesce(stage_id,''), \
                     coalesce(resulting_state,'') FROM transitions ORDER BY seq",
                )
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
                .unwrap_or_default();
            panic!("never happened: {what}\n{dump}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn lifecycle(conn: &rusqlite::Connection, execution: Ulid) -> String {
    conn.query_row(
        "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
        [execution.to_bytes().as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

const TERMINAL: [&str; 4] = ["completed", "failed", "cancelled", "timed_out"];

async fn until_terminal(rig: &OciNodeRig, execution: Ulid) -> String {
    wait_until(&rig.op_path, &format!("{execution} is terminal"), |conn| {
        TERMINAL.contains(&lifecycle(conn, execution).as_str())
    })
    .await;
    let state = lifecycle(&raw(rig), execution);
    if state != "completed" {
        eprintln!("{execution} ended {state}:\n{}", diagnose(rig));
    }
    state
}

/// Every execution's lifecycle and terminal reason, and every transition's `(execution,
/// kind, stage, state, reason)` — a failing cell's diagnosis, read raw.
fn diagnose(rig: &OciNodeRig) -> String {
    let conn = raw(rig);
    let mut out = String::new();
    let mut statement = conn
        .prepare(
            "SELECT hex(execution_id), state, coalesce(CAST(terminal_reason_json AS TEXT), '') \
               FROM execution_lifecycle",
        )
        .unwrap();
    for row in statement
        .query_map([], |row| {
            Ok(format!(
                "exec {}: {} {}\n",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?
            ))
        })
        .unwrap()
    {
        out.push_str(&row.unwrap());
    }
    let mut statement = conn
        .prepare(
            "SELECT substr(hex(execution_id), 1, 8), kind, coalesce(stage_id, ''), \
                    coalesce(resulting_state, ''), \
                    CASE WHEN json_valid(CAST(payload_json AS TEXT)) \
                    THEN coalesce(json_extract(CAST(payload_json AS TEXT), '$.reason'), '') \
                    ELSE '' END \
               FROM transitions ORDER BY seq",
        )
        .unwrap();
    for row in statement
        .query_map([], |row| {
            Ok(format!(
                "  {} {} {} {} {}\n",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4).unwrap_or_default()
            ))
        })
        .unwrap()
    {
        out.push_str(&row.unwrap());
    }
    out
}

/// Every execution OTHER than `parent` on the node — the children — read raw.
fn children_of(rig: &OciNodeRig, parent: Ulid) -> Vec<Ulid> {
    let conn = raw(rig);
    let mut statement = conn
        .prepare("SELECT execution_id FROM execution_lifecycle WHERE execution_id != ?1")
        .unwrap();
    statement
        .query_map([parent.to_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .unwrap()
        .map(|id| Ulid::from_bytes(id.unwrap().try_into().unwrap()))
        .collect()
}

/// The parent's `Invoke` attempt: `(executor, child id, folded state, last transition's
/// output, last transition's reason)`, read raw.
fn invoke_attempt(
    rig: &OciNodeRig,
    parent: Ulid,
) -> (
    String,
    Option<Ulid>,
    String,
    Option<serde_json::Value>,
    Option<String>,
) {
    raw(rig)
        .query_row(
            "SELECT a.executor, a.child_execution_id, p.state,
                    (SELECT json_extract(t.payload_json, '$.output') FROM transitions t
                      WHERE t.attempt_id = a.attempt_id ORDER BY t.seq DESC LIMIT 1),
                    (SELECT json_extract(t.payload_json, '$.reason') FROM transitions t
                      WHERE t.attempt_id = a.attempt_id ORDER BY t.seq DESC LIMIT 1)
               FROM attempts a JOIN attempt_projection p
                 ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
                AND p.attempt_ordinal = a.attempt_ordinal
              WHERE a.execution_id = ?1 AND a.stage_id = ?2",
            rusqlite::params![parent.to_bytes().as_slice(), INVOKE_STAGE],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?
                        .map(|id| Ulid::from_bytes(id.try_into().unwrap())),
                    row.get(2)?,
                    row.get::<_, Option<String>>(3)?
                        .map(|output| serde_json::from_str(&output).unwrap()),
                    row.get(4)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("the parent has exactly one Invoke attempt: {error}"))
}

/// A stage's accepted output, read raw off its accepting transition.
fn accepted_output(rig: &OciNodeRig, execution: Ulid, stage: &str) -> serde_json::Value {
    let output: String = raw(rig)
        .query_row(
            "SELECT coalesce(
                (SELECT json_extract(t.payload_json, '$.output') FROM transitions t
                  WHERE t.attempt_id = o.accepted_attempt_id AND t.kind = 'outcome_amended'
                  ORDER BY t.seq DESC LIMIT 1),
                (SELECT json_extract(t.payload_json, '$.output') FROM transitions t
                  WHERE t.attempt_id = o.accepted_attempt_id AND t.resulting_state = 'completed'))
               FROM occurrences o JOIN attempts a ON a.attempt_id = o.accepted_attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = ?2",
            rusqlite::params![execution.to_bytes().as_slice(), stage],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| panic!("{stage} of {execution} is accepted: {error}"));
    serde_json::from_str(&output).unwrap()
}

fn compile(pack: &str, roots: &[PathBuf]) -> ExecutionProgram {
    kata_types::node_profile::mark_node_installed();
    compile_starlark_execution_program(pack, "parent.star", roots)
        .expect("the parent compiles under oci")
}

/// A library root holding `(name, source)` packs.
fn library(packs: &[(&str, &str)]) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for (name, source) in packs {
        std::fs::write(root.path().join(format!("{name}.star")), source).unwrap();
    }
    root
}

fn submit(node: &Node, program: ExecutionProgram) -> Ulid {
    Ulid::from_string(
        &node
            .executor
            .submit_execution_program(program)
            .expect("the parent is admitted"),
    )
    .unwrap()
}

/// THE WHOLE DRIVE through the executor: under `oci` the shipped
/// `subworkflow-parent-smoke` completes, and its `sub` stage ran NO process — its
/// occurrence is accepted by an `executor = 'main'` attempt with no capsule — while its
/// child ran as a SEPARATE execution: exactly one other execution exists, admitted with
/// the program the parent's check BOUND (`programs.program_hash` = the lowering's
/// `Invoke` program), named by the attempt's `child_execution_id` and by the
/// `dynamic_child_spawned` record, and `completed`. The parent's accepted envelope names
/// that child and carries its outputs, and `after` rendered the child's value.
///
/// The parent was completed by the child's publication through the main-resolved door,
/// so no stage-scope transition for `sub` exists.
///
/// **Watched red:** with the divert's `Invoke` arm refused, the parent fails at `sub` and no
/// child exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_shipped_subworkflow_smoke_runs_its_child_as_a_linked_execution_under_oci() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let node = node(&dir, None);
    let program = compile(SHIPPED_PARENT, &[smoke_root()]);
    let bound = program.stages[&StageId(SmolStr::new(INVOKE_STAGE))]
        .subworkflow
        .as_ref()
        .expect("sub is a subworkflow")
        .bound
        .program_hash();
    let parent = submit(&node, program);
    assert_eq!(until_terminal(&node.rig, parent).await, "completed");

    let children = children_of(&node.rig, parent);
    assert_eq!(children.len(), 1, "one child execution: {children:?}");
    let child = children[0];
    let conn = raw(&node.rig);
    assert_eq!(lifecycle(&conn, child), "completed");
    let child_program: Vec<u8> = conn
        .query_row(
            "SELECT program_hash FROM programs WHERE execution_id = ?1",
            [child.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        child_program,
        bound.as_bytes().to_vec(),
        "the BOUND program ran"
    );
    let spawned: Vec<u8> = conn
        .query_row(
            "SELECT payload_json FROM transitions WHERE execution_id = ?1 \
               AND kind = 'dynamic_child_spawned'",
            [parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(spawned, child.to_string().into_bytes());

    let (executor, linked, state, output, _) = invoke_attempt(&node.rig, parent);
    assert_eq!(
        (executor.as_str(), linked, state.as_str()),
        ("main", Some(child), "completed")
    );
    let output = output.expect("the resolution carries the envelope");
    assert_eq!(output["child_execution_id"], child.to_string());
    assert_eq!(
        output["outputs"]["second"]["parsed"]["echoed"],
        "child-value-echoed"
    );
    assert_eq!(
        output["child_invocation_summary"]["token_usage"]["cost_micro_usd"], 0,
        "shell stages carry no token cost"
    );
    assert_eq!(
        count(
            &conn,
            &format!(
                "SELECT count(*) FROM capsules WHERE occurrence_id IN (SELECT occurrence_id \
                   FROM attempts WHERE stage_id = '{INVOKE_STAGE}')"
            )
        ),
        0,
        "the Invoke ran no capsule"
    );
    let stage_scope: i64 = conn
        .query_row(
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 AND scope = 'stage' \
               AND stage_id = ?2",
            rusqlite::params![parent.to_bytes().as_slice(), INVOKE_STAGE],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        stage_scope, 0,
        "the assignment-plane subworkflow completion wrote nothing"
    );
    let after = accepted_output(&node.rig, parent, "after");
    assert_eq!(
        after["parsed"],
        serde_json::json!({"relayed": "child-value-echoed", "carried": "before-value"}),
        "{after}"
    );
}

/// PARENT CANCEL CANCELS THE CHILD: with the child parked on its ten-minute timer, a
/// cancel of the PARENT reaches the child (`child_executions_cancelled: 1`, the child's
/// timer counted in `main_side_settled`) and ends its timer `cancelled` with the operator's
/// reason; the child terminalizes `cancelled`, its publication resolves the parent's
/// `Invoke` `cancelled` naming the child, and the parent terminalizes `cancelled`. Read raw.
///
/// **Watched red:** without the cancel's propagation to invoked children, the cancel
/// settles nothing (the parent's own `Invoke` is no timer or gate), and the child stays
/// `running` with its timer parked. With `terminal_lifecycle_for_run` reading the
/// assignment population (which holds neither a main nor a capsule attempt), the child
/// and the parent both terminalize `failed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parent_cancel_cancels_the_child() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let node = node(&dir, None);
    let root = library(&[("long-child", LONG_CHILD)]);
    let program = compile(
        "sub = subworkflow(id = \"sub\", pack = \"long-child\")\n\
         workflow(\"cancel-parent\", root = [sub])\n",
        &[root.path().to_path_buf()],
    );
    let parent = submit(&node, program);
    wait_until(&node.rig.op_path, "the child's timer parks", |conn| {
        count(
            conn,
            "SELECT count(*) FROM attempt_projection WHERE state = 'awaiting_timer'",
        ) == 1
    })
    .await;
    let child = children_of(&node.rig, parent)[0];

    let outcome = node
        .executor
        .cancel(parent, "operator cancel".to_string())
        .await
        .expect("the cancel succeeds");
    assert_eq!(outcome.child_executions_cancelled, 1, "{outcome:?}");
    assert_eq!(
        outcome.main_side_settled, 1,
        "the child's timer: {outcome:?}"
    );

    // The child's only cancelled stage is its MAIN timer, so its terminal is `cancelled`
    // only because the executor's outcome derivation (`terminal_lifecycle_for_run`) reads
    // every executor's stages; the parent's only cancelled stage is its MAIN `Invoke`,
    // ended `cancelled` by the child's publication, so the same holds one level up.
    let child_outcome = until_terminal(&node.rig, child).await;
    assert_eq!(child_outcome, "cancelled", "{}", diagnose(&node.rig));
    let timer: (String, Option<String>) = raw(&node.rig)
        .query_row(
            "SELECT t.resulting_state, json_extract(t.payload_json, '$.reason')
               FROM transitions t JOIN attempts a ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = 'nap' ORDER BY t.seq DESC LIMIT 1",
            [child.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        timer,
        ("cancelled".to_string(), Some("operator cancel".to_string()))
    );
    assert_eq!(
        until_terminal(&node.rig, parent).await,
        "cancelled",
        "{}",
        diagnose(&node.rig)
    );
    let (_, linked, state, _, reason) = invoke_attempt(&node.rig, parent);
    assert_eq!(linked, Some(child));
    assert_eq!(state, "cancelled", "the Invoke ends by its child's outcome");
    assert!(
        reason.unwrap_or_default().contains(&child.to_string()),
        "the parent's Invoke names the child that ended it"
    );
}

/// A SIBLING FAILURE CANCELS THE CHILD AND THE PARENT TERMINALIZES: `boom` fails (its
/// structured output is not JSON) while
/// `sub`'s child is parked on its timer (the stub worker holds `boom`'s answer until the
/// timer parks). The parent latches `failed`, its terminal-intent path cancels the child,
/// and every row settles: the parent `failed`, the child terminal with its timer
/// `cancelled`, the `Invoke` attempt terminal, and no main wait left parked anywhere. Read
/// raw.
///
/// **Watched red:** without the terminal-intent propagation, the child stays `running`
/// with its timer parked after its parent has failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sibling_failure_cancels_the_child_and_the_parent_terminalizes() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let node = node(&dir, Some("boom"));
    let root = library(&[("long-child", LONG_CHILD)]);
    let program = compile(
        "sub = subworkflow(id = \"sub\", pack = \"long-child\")\n\
         boom = stage(id = \"boom\", agent = \"shell\", run = \"echo not-json\", \
         outputs = {\"value\": \"string\"})\n\
         workflow(\"sibling-parent\", root = [sub, boom])\n",
        &[root.path().to_path_buf()],
    );
    let parent = submit(&node, program);
    assert_eq!(until_terminal(&node.rig, parent).await, "failed");
    let child = children_of(&node.rig, parent)[0];
    until_terminal(&node.rig, child).await;
    let timer: String = raw(&node.rig)
        .query_row(
            "SELECT t.resulting_state FROM transitions t JOIN attempts a
                ON a.attempt_id = t.attempt_id
              WHERE a.execution_id = ?1 AND a.stage_id = 'nap' ORDER BY t.seq DESC LIMIT 1",
            [child.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(timer, "cancelled", "the child's parked timer was cancelled");
    let (_, linked, state, _, _) = invoke_attempt(&node.rig, parent);
    assert_eq!(linked, Some(child));
    assert!(
        ["cancelled", "failed"].contains(&state.as_str()),
        "the Invoke attempt is terminal: {state}"
    );
    assert_eq!(
        count(
            &raw(&node.rig),
            "SELECT count(*) FROM attempt_projection WHERE state IN \
               ('awaiting_timer', 'awaiting_input', 'awaiting_child_completion')"
        ),
        0,
        "no main wait is left parked"
    );
}

/// CHILD FAILURE FAILS THE PARENT STAGE: a child whose stage fails terminalizes
/// `failed`, its publication resolves the parent's `Invoke` `failed` naming the child, the
/// parent fails, and the stage after `sub` never runs. Read raw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn child_failure_fails_the_parent_stage() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let node = node(&dir, None);
    let root = library(&[("failing-child", FAILING_CHILD)]);
    let program = compile(
        "sub = subworkflow(id = \"sub\", pack = \"failing-child\")\n\
         after = stage(id = \"after\", agent = \"shell\", run = \"true\", depends_on = [sub])\n\
         workflow(\"failing-parent\", root = [sub])\n",
        &[root.path().to_path_buf()],
    );
    let parent = submit(&node, program);
    let ended = until_terminal(&node.rig, parent).await;
    assert_eq!(ended, "failed", "{}", diagnose(&node.rig));
    let child = children_of(&node.rig, parent)[0];
    assert_eq!(lifecycle(&raw(&node.rig), child), "failed");
    let (_, linked, state, output, reason) = invoke_attempt(&node.rig, parent);
    assert_eq!(
        (linked, state.as_str(), output),
        (Some(child), "failed", None)
    );
    assert!(reason.unwrap_or_default().contains(&child.to_string()));
    assert_eq!(
        count(
            &raw(&node.rig),
            "SELECT count(*) FROM attempts WHERE stage_id = 'after'"
        ),
        0,
        "the successor never ran"
    );
}

/// A CHILD LEFT `admitting` AT BOOT RESUMES: the invocation's transaction committed (the
/// parent's `Invoke` parked, the child admitted) and the main died before it spawned the
/// child's runner — K4, reproduced here by committing that transaction through the
/// execution-lifecycle face and nothing else. A RESTARTED node's recovery resumes both:
/// the child is authorized from `admitting` and runs, the parent's resumed runner
/// re-presents `sub` and CONVERGES on its parked attempt (no second child), the child's
/// publication resolves it, and the parent completes with `after` rendering the child's
/// value. Read raw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_child_admitting_at_boot_resumes() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let program = compile(SHIPPED_PARENT, &[smoke_root()]);
    let parent = Ulid::new();
    let child = Ulid::new();
    {
        kata_types::node_profile::mark_node_installed();
        let rig = OciNodeRig::open(dir.path());
        let face = rig.dispatcher.execution_lifecycle();
        face.put_current_program(parent, &program).unwrap();
        rig.seed_scratch_head(parent);
        face.mark_running_after_admission(parent).unwrap();
        let bound = program.stages[&StageId(SmolStr::new(INVOKE_STAGE))]
            .subworkflow
            .as_ref()
            .unwrap()
            .bound
            .program()
            .clone();
        let lowered = lower_stage_operation(&program, &StageId(SmolStr::new(INVOKE_STAGE)))
            .expect("sub lowers");
        let params =
            kata_types::params::resolve_and_validate_params(&bound.params, &serde_json::Map::new())
                .unwrap();
        face.invoke_child_execution(
            Ulid::new(),
            &kata_core::operational::MainAttemptSpec {
                stage_id: INVOKE_STAGE.to_string(),
                occurrence: kata_core::operational::OccurrenceBinding::new(
                    occurrence_for(&program, ExecutionId(parent), &lowered),
                    None,
                    None,
                ),
            },
            child,
            &bound,
            &ExecutionInvocation::workflow_with_params(Vec::new(), params),
        )
        .expect("the invocation commits");
        assert_eq!(lifecycle(&raw(&rig), child), "admitting");
    }

    // THE RESTARTED NODE.
    let node = node(&dir, None);
    let resumed = node
        .executor
        .resume_in_flight_runs()
        .expect("recovery prepares");
    assert!(
        resumed.contains(&parent) && resumed.contains(&child),
        "both are recovered: {resumed:?}"
    );
    assert_eq!(until_terminal(&node.rig, parent).await, "completed");
    assert_eq!(lifecycle(&raw(&node.rig), child), "completed");
    assert_eq!(
        children_of(&node.rig, parent),
        vec![child],
        "no second child"
    );
    let (_, linked, state, _, _) = invoke_attempt(&node.rig, parent);
    assert_eq!((linked, state.as_str()), (Some(child), "completed"));
    assert_eq!(
        accepted_output(&node.rig, parent, "after")["parsed"]["relayed"],
        "child-value-echoed"
    );
}

/// A PARENT CANCEL STOPS A CHILD WITH NO WORK PLACED: the invocation
/// committed (the child `admitting`, nothing of it placed — K4 of the invocation), and the
/// parent is cancelled BEFORE recovery resumes anything, so the cancel's asks reach
/// nothing live in the child. The cancel LATCHES the child's `cancelled` intent all the
/// same; recovery then closes the child out `cancelled` without running it — its
/// publication resolving the parent's `Invoke` `cancelled` — and the resumed parent
/// publishes `cancelled`. Read raw.
///
/// **Watched red:** without the latch in `WorkflowExecutor::cancel`, the cancel reports
/// `child_executions_cancelled: 1` and the child is resumed and completes, and so does the
/// parent (the review measured parent=`completed`, child=`completed`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parent_cancel_stops_a_child_with_no_work_placed() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let program = compile(SHIPPED_PARENT, &[smoke_root()]);
    let parent = Ulid::new();
    let child = Ulid::new();
    {
        kata_types::node_profile::mark_node_installed();
        let rig = OciNodeRig::open(dir.path());
        let face = rig.dispatcher.execution_lifecycle();
        face.put_current_program(parent, &program).unwrap();
        rig.seed_scratch_head(parent);
        face.mark_running_after_admission(parent).unwrap();
        let bound = program.stages[&StageId(SmolStr::new(INVOKE_STAGE))]
            .subworkflow
            .as_ref()
            .unwrap()
            .bound
            .program()
            .clone();
        let lowered = lower_stage_operation(&program, &StageId(SmolStr::new(INVOKE_STAGE)))
            .expect("sub lowers");
        let params =
            kata_types::params::resolve_and_validate_params(&bound.params, &serde_json::Map::new())
                .unwrap();
        face.invoke_child_execution(
            Ulid::new(),
            &kata_core::operational::MainAttemptSpec {
                stage_id: INVOKE_STAGE.to_string(),
                occurrence: kata_core::operational::OccurrenceBinding::new(
                    occurrence_for(&program, ExecutionId(parent), &lowered),
                    None,
                    None,
                ),
            },
            child,
            &bound,
            &ExecutionInvocation::workflow_with_params(Vec::new(), params),
        )
        .expect("the invocation commits");
    }

    let node = node(&dir, None);
    let outcome = node
        .executor
        .cancel(parent, "operator cancel".to_string())
        .await
        .expect("the cancel succeeds");
    assert_eq!(outcome.child_executions_cancelled, 1, "{outcome:?}");
    assert_eq!(
        lifecycle(&raw(&node.rig), child),
        "terminalizing",
        "the child's cancel is latched by the cancel itself"
    );
    node.executor
        .resume_in_flight_runs()
        .expect("recovery prepares");
    assert_eq!(
        until_terminal(&node.rig, child).await,
        "cancelled",
        "{}",
        diagnose(&node.rig)
    );
    assert_eq!(
        until_terminal(&node.rig, parent).await,
        "cancelled",
        "{}",
        diagnose(&node.rig)
    );
    assert_eq!(
        count(
            &raw(&node.rig),
            &format!(
                "SELECT count(*) FROM attempts WHERE execution_id = x'{}'",
                hex::encode(child.to_bytes())
            )
        ),
        0,
        "the child ran nothing"
    );
    let (_, linked, state, _, reason) = invoke_attempt(&node.rig, parent);
    assert_eq!((linked, state.as_str()), (Some(child), "cancelled"));
    assert!(reason.unwrap_or_default().contains(&child.to_string()));
}

// -- A CANCELLED EXECUTION PUBLISHES `cancelled`, WHICHEVER EXECUTOR HELD ITS WORK --------
//
// A `terminal_lifecycle_for_run` that decided `cancelled` off the assignment population —
// which holds no main-resolved attempt and no capsule attempt — would publish `failed` for an
// `oci` execution whose only cancelled stage was a timer or a capsule.

/// `pre` exits 0, `nap` parks for ten minutes, `post` would follow.
const LONG_NAP: &str = "pre = stage(id = \"pre\", agent = \"shell\", run = \"true\")\n\
                        nap = sleep(id = \"nap\", for_ms = 600000, depends_on = [pre])\n\
                        post = stage(id = \"post\", agent = \"shell\", run = \"true\", \
                        depends_on = [nap])\n\
                        workflow(\"long-nap\", root = [pre])\n";

/// A CANCEL DURING A PARKED TIMER PUBLISHES `cancelled`: the timer is the execution's
/// only open work, the cancel resolves it `cancelled` main-side, and the execution's
/// lifecycle row reads `cancelled`, with `post` never submitted. Read raw.
///
/// **Watched red:** with `terminal_lifecycle_for_run` reading the assignment
/// population, the execution terminalizes `failed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancel_during_a_parked_timer_publishes_cancelled() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let node = node(&dir, None);
    let execution = submit(&node, compile(LONG_NAP, &[]));
    wait_until(&node.rig.op_path, "the timer parks", |conn| {
        count(
            conn,
            "SELECT count(*) FROM attempt_projection WHERE state = 'awaiting_timer'",
        ) == 1
    })
    .await;
    let outcome = node
        .executor
        .cancel(execution, "operator cancel".to_string())
        .await
        .expect("the cancel succeeds");
    assert_eq!(outcome.main_side_settled, 1, "{outcome:?}");
    assert_eq!(
        until_terminal(&node.rig, execution).await,
        "cancelled",
        "{}",
        diagnose(&node.rig)
    );
    assert_eq!(
        count(
            &raw(&node.rig),
            "SELECT count(*) FROM attempts WHERE stage_id = 'post'"
        ),
        0,
        "the successor was never submitted"
    );
}

/// A CANCEL OF A RUNNING CAPSULE PUBLISHES `cancelled`: the capsule is delivered and held
/// by a worker that answers only a stop; the cancel asks it (`assignments_asked_to_stop:
/// 1`), the worker reports the stopped container, the attempt is adjudicated `cancelled`
/// under the standing stop, and the execution's lifecycle row reads `cancelled`. Read raw.
///
/// **Watched red:** with `terminal_lifecycle_for_run` reading the assignment
/// population, the execution terminalizes `failed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancel_of_a_running_capsule_publishes_cancelled() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let node = node_with(&dir, spawn_stopping_worker);
    let execution = submit(
        &node,
        compile(
            "long = stage(id = \"long\", agent = \"shell\", run = \"sleep 600\")\n\
             workflow(\"long-capsule\", root = [long])\n",
            &[],
        ),
    );
    wait_until(&node.rig.op_path, "the capsule is dispatched", |conn| {
        count(
            conn,
            "SELECT count(*) FROM attempts WHERE stage_id = 'long' \
               AND dispatched_at_ms IS NOT NULL",
        ) == 1
    })
    .await;
    let outcome = node
        .executor
        .cancel(execution, "operator cancel".to_string())
        .await
        .expect("the cancel succeeds");
    assert_eq!(outcome.assignments_asked_to_stop, 1, "{outcome:?}");
    assert_eq!(
        until_terminal(&node.rig, execution).await,
        "cancelled",
        "{}",
        diagnose(&node.rig)
    );
    let state: String = raw(&node.rig)
        .query_row(
            "SELECT t.resulting_state FROM transitions t JOIN attempts a
                ON a.attempt_id = t.attempt_id
              WHERE a.stage_id = 'long' ORDER BY t.seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "cancelled", "the capsule attempt ended cancelled");
}

/// A `loop(..)` over one shell member, gated by a shell controller that approves.
const SHELL_LOOP: &str = r#"worker = stage(
    id = "worker",
    agent = "shell",
    run = "printf '{\"stage\":\"w\",\"marker\":1}\n'",
    outputs = {"stage": "string", "marker": "number"},
)

controller = stage(
    id = "controller",
    agent = "shell",
    run = "printf '{\"decision\":\"promote\",\"feedback\":\"ship\"}\n'",
    depends_on = ["worker"],
    outputs = {"decision": "string", "feedback": "string"},
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

workflow("shell-loop", root = [worker, controller])
"#;

/// A CANCEL OF A RUN WHOSE `loop(..)` MEMBER IS RUNNING PUBLISHES `cancelled`: the member
/// capsule is held by a worker that answers only a stop; the cancel asks it, the member
/// ends `cancelled`, the loop's own pending main attempt is driven to its end by the loop's
/// walk under the latch, and the execution's lifecycle row reads `cancelled`. Read raw.
///
/// **Watched red:** with the expansion enumeration reading only `admitting`/`running`
/// executions, the run stayed `terminalizing` with the loop's main attempt `pending`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancel_of_a_running_loop_member_publishes_cancelled() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let node = node_with(&dir, spawn_stopping_worker);
    let execution = submit(&node, compile(SHELL_LOOP, &[]));
    wait_until(&node.rig.op_path, "the loop member is dispatched", |conn| {
        count(
            conn,
            "SELECT count(*) FROM attempts WHERE stage_id = 'worker' \
               AND dispatched_at_ms IS NOT NULL",
        ) == 1
    })
    .await;
    let outcome = node
        .executor
        .cancel(execution, "operator cancel".to_string())
        .await
        .expect("the cancel succeeds");
    assert_eq!(outcome.assignments_asked_to_stop, 1, "{outcome:?}");
    assert_eq!(
        until_terminal(&node.rig, execution).await,
        "cancelled",
        "{}",
        diagnose(&node.rig)
    );
    let open = execution_count(
        &node.rig,
        "SELECT count(*) FROM attempts a JOIN attempt_projection p \
            ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
           AND p.attempt_ordinal = a.attempt_ordinal \
         WHERE a.execution_id = ?1 \
           AND p.state NOT IN ('completed', 'failed', 'cancelled', 'orphaned')",
        execution,
    );
    assert_eq!(open, 0, "no attempt is left open: {}", diagnose(&node.rig));
    let state: String = raw(&node.rig)
        .query_row(
            "SELECT t.resulting_state FROM transitions t JOIN attempts a
                ON a.attempt_id = t.attempt_id
              WHERE a.stage_id = 'worker' ORDER BY t.seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "cancelled", "the member attempt ended cancelled");
}

// -- AN OPERATOR CANCEL OF A ROOT IS DURABLE -----------------------------------------------
//
// `WorkflowExecutor::cancel` latched a durable cancel only on the CHILD executions it
// walked; for the root it asked the work live at that instant. A root cancelled between two
// stages — its previous stage accepted, its next not yet claimed, nothing live — ran on.

/// `first` then `second`, both shell no-ops.
const TWO_STAGES: &str = "first = stage(id = \"first\", agent = \"shell\", run = \"true\")\n\
                          second = stage(id = \"second\", agent = \"shell\", run = \"true\", \
                          depends_on = [first])\n\
                          workflow(\"two-stages\", root = [first])\n";

/// Hold every runner at the submission of `stage` (`interleave_before_a_stage_submit`)
/// until the returned sender releases it; the receiver answers the execution held.
fn hold_before_submitting(
    stage: &'static str,
) -> (std::sync::mpsc::Receiver<Ulid>, std::sync::mpsc::Sender<()>) {
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    kata_workflow::test_harness::interleave_before_a_stage_submit(Arc::new(
        move |execution, submitted| {
            if submitted == stage {
                let _ = reached_tx.send(execution);
                let _ = release_rx.lock().unwrap().recv();
            }
        },
    ));
    (reached_rx, release_tx)
}

async fn held(reached: std::sync::mpsc::Receiver<Ulid>) -> Ulid {
    tokio::task::spawn_blocking(move || reached.recv_timeout(Duration::from_secs(30)))
        .await
        .unwrap()
        .expect("the runner reaches the held submission")
}

fn execution_count(rig: &OciNodeRig, sql: &str, execution: Ulid) -> i64 {
    raw(rig)
        .query_row(sql, [execution.to_bytes().as_slice()], |row| row.get(0))
        .unwrap()
}

/// `(terminal_outcome, terminal_reason_json)` off the raw lifecycle row.
fn terminal_intent(rig: &OciNodeRig, execution: Ulid) -> (Option<String>, String) {
    raw(rig)
        .query_row(
            "SELECT terminal_outcome, coalesce(CAST(terminal_reason_json AS TEXT), '') \
               FROM execution_lifecycle WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

const TERMINAL_WRITES: &str = "SELECT count(*) FROM transitions WHERE execution_id = ?1 \
                                 AND kind IN ('terminal_intent', 'terminalized')";

/// A ROOT CANCELLED BETWEEN TWO STAGES NEVER RUNS THE SECOND, under `oci`, through the
/// production drive: `first` is accepted, the runner is held at `second`'s submission with
/// nothing live, the operator cancels (asking and settling nothing — nothing is live), the
/// runner is released, and `second` is never claimed: its claim is refused
/// (`claim_after_terminal_intent`), the run ends, and the task adopts the latched
/// `cancelled`, publishing the operator's reason. One terminal intent, one publication.
///
/// **Watched red:** with `cancel` latching only children again, `second` is claimed and
/// run and the lifecycle publishes `completed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_root_cancelled_between_two_stages_never_runs_the_second_under_oci() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let (reached, release) = hold_before_submitting("second");
    let node = node(&dir, None);
    let execution = submit(&node, compile(TWO_STAGES, &[]));
    assert_eq!(held(reached).await, execution);
    assert_eq!(
        execution_count(
            &node.rig,
            "SELECT count(*) FROM attempts a JOIN attempt_projection p \
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
               AND p.attempt_ordinal = a.attempt_ordinal \
             WHERE a.execution_id = ?1 AND a.stage_id = 'first' AND p.state = 'completed'",
            execution
        ),
        1,
        "the premise: `first` is accepted, and it is the only attempt"
    );

    let outcome = node
        .executor
        .cancel(execution, "operator cancel between stages".to_string())
        .await
        .expect("the cancel succeeds");
    assert_eq!(
        outcome,
        kata_api::executor::CancelOutcome::default(),
        "nothing was live"
    );
    release.send(()).unwrap();

    assert_eq!(
        until_terminal(&node.rig, execution).await,
        "cancelled",
        "{}",
        diagnose(&node.rig)
    );
    assert!(
        terminal_intent(&node.rig, execution)
            .1
            .contains("operator cancel between stages"),
        "{:?}",
        terminal_intent(&node.rig, execution)
    );
    assert_eq!(
        execution_count(
            &node.rig,
            "SELECT count(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'second'",
            execution
        ),
        0,
        "`second` was never claimed"
    );
    assert_eq!(execution_count(&node.rig, TERMINAL_WRITES, execution), 2);
}

/// A SECOND CANCEL IS IDEMPOTENT: the root is cancelled twice between its stages, with two
/// reasons; the second writes nothing, the execution publishes `cancelled` once, and the
/// reason that stands is the FIRST.
///
/// **Watched red:** with the latch's `admitting | running` guard removed
/// (`child_invocation::latch_cancel_in_tx`), the second cancel is refused as a conflicting
/// terminalization.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_cancel_of_a_root_is_idempotent() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let (reached, release) = hold_before_submitting("second");
    let node = node(&dir, None);
    let execution = submit(&node, compile(TWO_STAGES, &[]));
    assert_eq!(held(reached).await, execution);
    for reason in ["the first cancel", "the second cancel"] {
        node.executor
            .cancel(execution, reason.to_string())
            .await
            .unwrap_or_else(|error| panic!("{reason} succeeds: {error}"));
    }
    release.send(()).unwrap();
    assert_eq!(
        until_terminal(&node.rig, execution).await,
        "cancelled",
        "{}",
        diagnose(&node.rig)
    );
    let (_, reason) = terminal_intent(&node.rig, execution);
    assert!(
        reason.contains("the first cancel") && !reason.contains("the second cancel"),
        "{reason}"
    );
    assert_eq!(execution_count(&node.rig, TERMINAL_WRITES, execution), 2);
    // And a cancel of the now-terminal execution is a no-op.
    assert_eq!(
        node.executor
            .cancel(execution, "after the end".to_string())
            .await
            .expect("a cancel of a terminal execution succeeds"),
        kata_api::executor::CancelOutcome::default()
    );
    assert_eq!(execution_count(&node.rig, TERMINAL_WRITES, execution), 2);
}

/// A CANCEL THAT LOSES THE RACE TO THE ROOT'S OWN OUTCOME WRITES NOTHING: the root's runner
/// latched `completed` (the intent is `terminalizing`, not yet published) before the
/// operator's cancel arrived; the cancel succeeds, latches nothing, and the one intent
/// stands — whichever latches first wins, and there is one terminal.
///
/// **Watched red:** with the latch's `admitting | running` guard removed
/// (`child_invocation::latch_cancel_in_tx`), the cancel is refused as a conflicting
/// terminalization.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancel_after_the_root_latched_its_own_outcome_writes_nothing() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let execution = Ulid::new();
    {
        kata_types::node_profile::mark_node_installed();
        let rig = OciNodeRig::open(dir.path());
        let face = rig.dispatcher.execution_lifecycle();
        face.put_current_program(execution, &compile(TWO_STAGES, &[]))
            .unwrap();
        rig.seed_scratch_head(execution);
        face.mark_running_after_admission(execution).unwrap();
        face.begin_terminalization(
            execution,
            kata_workflow::execution_program_store::ExecutionLifecycleState::Completed,
            &kata_workflow::execution_program_store::ExecutionTerminalReason::new(
                "completed",
                "the run completed first",
            ),
        )
        .unwrap();
    }
    let node = node(&dir, None);
    assert_eq!(
        node.executor
            .cancel(execution, "operator cancel".to_string())
            .await
            .expect("a cancel that lost the race succeeds"),
        kata_api::executor::CancelOutcome::default()
    );
    let (outcome, reason) = terminal_intent(&node.rig, execution);
    assert_eq!(outcome.as_deref(), Some("completed"), "{reason}");
    assert!(reason.contains("the run completed first"), "{reason}");
    assert_eq!(
        execution_count(
            &node.rig,
            "SELECT count(*) FROM transitions WHERE execution_id = ?1 \
               AND kind = 'terminal_intent'",
            execution
        ),
        1
    );
}

/// CANCEL RACING THE ROOT'S NATURAL COMPLETION, through the production drive: a one-stage
/// root is cancelled at sixteen instants — 0, 3, 6 … 21 ms after its submission (the latch
/// lands before or during the stage) and then the moment its stage is seen accepted (the
/// latch races the runner task's own) — and whichever latches first wins: `cancelled` with
/// the operator's reason, or `completed` with the cancel having written nothing. Every run
/// publishes exactly one terminal intent and one publication. (Each order is also pinned
/// deterministically: the cancel first by `a_second_cancel_of_a_root_is_idempotent`, the
/// runner first by `a_cancel_after_the_root_latched_its_own_outcome_writes_nothing`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancel_racing_the_roots_completion_publishes_exactly_one_terminal() {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let node = node(&dir, None);
    let program = compile(
        "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
         workflow(\"one-stage\", root = [only])\n",
        &[],
    );
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for round in 0..16_u64 {
        let execution = submit(&node, program.clone());
        if round < 8 {
            tokio::time::sleep(Duration::from_millis(round * 3)).await;
        } else {
            wait_until(&node.rig.op_path, "the stage is accepted", |conn| {
                conn.query_row(
                    "SELECT count(*) FROM attempts a JOIN attempt_projection p \
                        ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
                       AND p.attempt_ordinal = a.attempt_ordinal \
                     WHERE a.execution_id = ?1 AND a.stage_id = 'only' \
                       AND p.state = 'completed'",
                    [execution.to_bytes().as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
                    == 1
            })
            .await;
        }
        node.executor
            .cancel(execution, "operator cancel racing completion".to_string())
            .await
            .expect("the cancel succeeds, whichever order it lands in");
        let state = until_terminal(&node.rig, execution).await;
        let (_, reason) = terminal_intent(&node.rig, execution);
        match state.as_str() {
            "cancelled" => assert!(
                reason.contains("operator cancel racing completion"),
                "{reason}"
            ),
            "completed" => assert!(!reason.contains("operator cancel"), "{reason}"),
            other => panic!("{other}: {reason}\n{}", diagnose(&node.rig)),
        }
        assert_eq!(execution_count(&node.rig, TERMINAL_WRITES, execution), 2);
        *outcomes.entry(state).or_default() += 1;
    }
    eprintln!("race outcomes: {outcomes:?}");
}

/// A WORKER THAT FINISHES AS THE STOP ARRIVES: every delivered capsule is held until the
/// node sends its attempt a `Stop`, which it answers with the container's SUCCESSFUL
/// completion — the run that ended just as the operator cancelled.
fn spawn_completing_on_stop_worker(
    rig: &OciNodeRig,
    node_dir: Arc<tempfile::TempDir>,
) -> tokio::task::JoinHandle<()> {
    let empty_stdout = publish_capture(rig, b"");
    let empty_stderr = publish_capture(rig, b"");
    let node_path = rig
        .op_path
        .parent()
        .expect("operational.db lives in the node dir")
        .to_owned();
    let db = Arc::clone(&rig.db);
    let worker_side = Arc::clone(&rig.worker_side);
    let reactor = kata_workflow::reactor::ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.worker_side) as Arc<dyn kata_transport::WorkerResultTransport>,
        Arc::clone(&rig.dispatcher),
        Arc::new(kata_transport::heartbeat::HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(30),
        )),
    );
    tokio::spawn(async move {
        let _node_dir = node_dir;
        let mut held = std::collections::HashMap::new();
        loop {
            tokio::select! {
                frame = worker_side.recv_frame() => {
                    let Ok(DispatchFrame::Capsule(frame)) = frame else { return };
                    held.insert(frame.attempt_id, *frame);
                }
                control = worker_side.recv_control() => {
                    let Ok(kata_transport::types::WorkerControl::Stop { assignment_id, .. }) =
                        control
                    else {
                        continue;
                    };
                    let frame = held.remove(&assignment_id).expect("a stop names a held capsule");
                    let cas = kata_core::store::cas::CasStore::open(
                        node_path.join("cas.db"),
                        node_path.join("cas"),
                    )
                    .expect("the content store opens");
                    let capsule: kata_types::execution_contract::Capsule = serde_json::from_slice(
                        &cas.get(&frame.capsule.object)
                            .expect("the CAS reads")
                            .expect("the capsule object is published"),
                    )
                    .expect("the capsule decodes");
                    reactor
                        .handle_message_for_test(kata_transport::types::WorkerMessage::CompletedCapsule {
                            attempt_id: frame.attempt_id,
                            fence: kata_transport::types::AttemptFence::echoing_capsule(&frame),
                            result: empty_tree_result(),
                            work_delta: stub_work_delta(&db, &cas, &capsule),
                            exit_code: Some(0),
                            stdout: empty_stdout.clone(),
                            stderr: empty_stderr.clone(),
                            capture_exceeded: false,
                            provenance:
                                kata_types::execution_provenance::ExecutionProvenance::local_oci_runtime(
                                    "root cancel cell",
                                ),
                            agent: None,
                            egress_refusals: vec![],
                        })
                        .expect("the completion is adjudicated");
                }
            }
        }
    })
}

/// AN IN-FLIGHT COMPLETION AFTER THE LATCH IS RECORDED, AND THE ROOT STILL ENDS CANCELLED:
/// `first` is running when the operator cancels; the root is latched and `first`'s worker
/// asked to stop, and the worker answers with `first`'s successful completion. That
/// completion is adjudicated and recorded on `first`'s attempt — not lost to the latch —
/// the execution publishes `cancelled`, and `second` is never claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_completion_landing_after_the_roots_cancel_latch_is_recorded_and_the_root_ends_cancelled()
{
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let node = node_with(&dir, spawn_completing_on_stop_worker);
    let execution = submit(&node, compile(TWO_STAGES, &[]));
    wait_until(&node.rig.op_path, "`first` is dispatched", |conn| {
        count(
            conn,
            "SELECT count(*) FROM attempts WHERE stage_id = 'first' \
               AND dispatched_at_ms IS NOT NULL",
        ) == 1
    })
    .await;
    let outcome = node
        .executor
        .cancel(execution, "operator cancel mid-stage".to_string())
        .await
        .expect("the cancel succeeds");
    assert_eq!(outcome.assignments_asked_to_stop, 1, "{outcome:?}");
    assert_eq!(
        until_terminal(&node.rig, execution).await,
        "cancelled",
        "{}",
        diagnose(&node.rig)
    );
    let (state, kind): (String, String) = raw(&node.rig)
        .query_row(
            "SELECT t.resulting_state, t.kind FROM transitions t JOIN attempts a
                ON a.attempt_id = t.attempt_id
              WHERE a.stage_id = 'first' ORDER BY t.seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    eprintln!("`first` ended {state} ({kind})");
    assert!(
        ["completed", "cancelled"].contains(&state.as_str()),
        "the worker's answer was adjudicated: {state} ({kind})\n{}",
        diagnose(&node.rig)
    );
    assert_eq!(
        execution_count(
            &node.rig,
            "SELECT count(*) FROM attempts WHERE execution_id = ?1 AND stage_id = 'second'",
            execution
        ),
        0,
        "`second` was never claimed"
    );
    assert_eq!(execution_count(&node.rig, TERMINAL_WRITES, execution), 2);
}
