//! The declared-writeback scans on the capsule arm.
//!
//! `persist_workflow_memory_writebacks` and the per-iteration hook scan the
//! completed attempt rows — capsule attempts, and the `executor = 'main'`
//! attempt that accepts a REUSED capsule stage — not the assignment population.
//! A scan of `execution_assignment_states` would make a declared
//! `memory_writeback` under `oci` match nothing and silently write no memory
//! objects at all. This cell runs a workflow that DECLARES a
//! writeback on the oci rig and reads the memory store from outside — the proof
//! that the completed capsule attempts' outputs reach the machinery.

use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::WorkflowExecutor;
use kata_core::store::SqliteNativeMemoryStore;
use kata_program::execution_program::compile_starlark_execution_program;
use kata_program::library::WorkflowLibrary;
use kata_program::test_harness::install_rig_agents;
use kata_test_utils::MockResponse;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_types::memory::{MemoryObjectKind, MemoryObjectStatus};
use kata_workflow::reactor::ResultReactor;
use kata_workflow::test_harness::OciNodeRig;
use smol_str::SmolStr;

/// A two-iteration review loop whose worker declares a memory writeback —
/// iteration 0's implement writes `finding-iter-0`, iteration 1's writes
/// `finding-iter-1` — so the close-the-loop hook AND the terminal pass each
/// have a distinct durable row to produce.
const PACK: &str = r#"
implement = stage(
    id = "implement",
    agent = "default",
    prompt = "write code",
    outputs = {"memory_writebacks": "array"},
)
review = stage(
    id = "review",
    agent = "default",
    depends_on = ["implement"],
    prompt = "review",
    outputs = {"verdict": "string"},
)
loop(body = implement, gate = review, max_iterations = 2, on_exhaustion = "fail")
workflow(
    "oci-memory-writeback",
    root = [implement],
    memory_writebacks = [
        memory_writeback(
            "loop-findings",
            stage = "implement",
            field = "memory_writebacks",
            kinds = ["finding"],
            statuses = ["active"],
            max_objects = 8,
        ),
    ],
)
"#;

fn writeback_output(id: &str) -> serde_json::Value {
    serde_json::json!({
        "memory_writebacks": [{
            "id": id,
            "kind": "finding",
            "status": "active",
            "title": format!("{id} title"),
            "body": {"summary": "from the capsule"},
            "tags": ["oci"],
        }]
    })
}

/// The oci rig the cells run on: a scripted capsule worker, the bookkeeper, the
/// result reactor and the delivery service, and an executor carrying a memory store.
struct Node {
    _dir: Arc<tempfile::TempDir>,
    rig: OciNodeRig,
    mock: kata_workflow::test_harness::ScriptedWorkerHandle,
    executor: Arc<WorkflowExecutor>,
    store: Arc<SqliteNativeMemoryStore>,
}

fn boot() -> Node {
    kata_types::node_profile::mark_node_installed();
    install_rig_agents(["default".to_owned()]);
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig_labels = ["default".to_owned()];
    let rig = OciNodeRig::open_with_caps(
        dir.path(),
        &kata_workflow::test_harness::rig_program_names(&rig_labels),
        kata_workflow::test_harness::rig_worker_caps(&rig_labels, &[]),
    );
    rig.declare_bound_environment();
    let (mock, _pump) = rig.scripted_worker(Arc::clone(&dir));

    let bookkeeper = Arc::clone(&rig.dispatcher);
    {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            bookkeeper.run_bookkeeper().await;
        });
    }
    // The reactor must answer AS the rig's registered worker id: the ingress
    // fence refuses a capsule result attributed to any other id, quietly —
    // `handle_message` records the refusal and returns Ok, so a rig that names
    // its reactor anything else watches `delivered` grow while nothing folds.
    let reactor = ResultReactor::new(
        SmolStr::new(kata_workflow::test_harness::OCI_RIG_WORKER),
        Arc::clone(&rig.main_side),
        Arc::clone(&rig.dispatcher),
        Arc::new(HeartbeatMonitor::new(
            Duration::from_millis(500),
            Duration::from_millis(500),
        )),
    );
    {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            reactor.run().await;
        });
    }

    let store = Arc::new(SqliteNativeMemoryStore::open_in_memory().expect("memory store"));
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle())
        .with_cache_store(Arc::clone(&rig.store))
        .with_memory_store(Arc::clone(&store)),
    );

    let delivery = kata_workflow::delivery_service::DeliveryService::new(
        Arc::clone(executor.execution_lifecycle().db()),
        Arc::clone(rig.dispatcher.ledger()),
    );
    delivery.catch_up().expect("initial delivery");
    {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            delivery.run().await;
        });
    }

    Node {
        _dir: dir,
        rig,
        mock,
        executor,
        store,
    }
}

/// Poll the execution's durable lifecycle row — read raw — until it is terminal,
/// and answer it.
async fn terminal_lifecycle(rig: &OciNodeRig, submitted: &str) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let exec_bytes = ulid::Ulid::from_string(submitted)
        .expect("submission id parses")
        .to_bytes()
        .to_vec();
    loop {
        let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
        let state: Option<String> = conn
            .query_row(
                "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
                [&exec_bytes[..]],
                |row| row.get(0),
            )
            .ok();
        if let Some(state) = state
            && matches!(state.as_str(), "completed" | "failed" | "aborted")
        {
            return state;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the oci writeback run never reached terminal"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The writeback machinery sees the capsule arm's completed attempts: every
/// iteration's declared writeback lands in the memory store.
///
/// **Would red if:** the deciding scan read `execution_assignment_states`
/// (empty under `oci`) instead of the attempt/occurrence plane — the run would
/// complete and the memory store would hold ZERO of the objects the two
/// iterations produced.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn oci_declared_memory_writebacks_land_per_iteration_and_terminally() {
    let Node {
        _dir,
        rig,
        mock,
        executor,
        store,
    } = boot();

    // The four frames the loop produces, in dispatch order.
    mock.push(MockResponse::Json(writeback_output("finding-iter-0")));
    mock.push(MockResponse::Json(serde_json::json!({"verdict": "refine"})));
    mock.push(MockResponse::Json(writeback_output("finding-iter-1")));
    mock.push(MockResponse::Json(
        serde_json::json!({"verdict": "approve"}),
    ));

    let program = compile_starlark_execution_program(PACK, "oci-memory-writeback.star", &[])
        .expect("the pack compiles under oci");
    let submitted = executor
        .submit_execution_program(program.clone())
        .expect("the workflow submits under the oci rig");

    // The writebacks land through the run task's per-iteration hook and the
    // terminal pass — neither is a read this test holds, so the terminal row is
    // the observable that means both ran.
    assert_eq!(
        terminal_lifecycle(&rig, &submitted).await,
        "completed",
        "the writeback-declaring run must complete, not fail"
    );

    let snapshot = store
        .snapshot(
            Some(MemoryObjectKind::Finding),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot the finding objects");
    let mut ids: Vec<String> = snapshot
        .objects
        .iter()
        .map(|object| object.id.clone())
        .collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        vec!["finding-iter-0".to_string(), "finding-iter-1".to_string()],
        "both iterations' declared writebacks must land under oci — the \
         per-iteration hook AND the terminal pass read the capsule arm's facts"
    );
}

/// A content-cached shell stage whose output declares a REQUIRED memory writeback.
const REUSED_PACK: &str = r#"
finding = stage(
    id = "finding",
    agent = "shell",
    sandbox = "read-work",
    cache_policy = "content_cache",
    prompt = "true",
    outputs = {"memory_writebacks": "array"},
)
workflow(
    "oci-reused-memory-writeback",
    root = [finding],
    sandbox_profiles = {
        "read-work": sandbox_profile(workspace = "ro", net = "offline"),
    },
    memory_writebacks = [
        memory_writeback(
            "reused-findings",
            stage = "finding",
            field = "memory_writebacks",
            kinds = ["finding"],
            statuses = ["active"],
            max_objects = 8,
            required = True,
        ),
    ],
)
"#;

/// A stage the content cache REUSES still produces its declared memory
/// writebacks. A reuse runs no container: its occurrence is claimed and accepted by
/// an `executor = 'main'` attempt (`MainOperation::CapsuleReuse`), and the
/// writeback scan must count that attempt as the stage's completion.
///
/// The second, equal run adopts the first's result; its declared writeback is
/// `required`, so a scan that skips the reusing attempt finds no completed stage and
/// FAILS the execution. Both the reuse and the outcome are read raw.
///
/// **Watched red:** with `completed_stage_facts` keeping only `Capsule`-arm
/// attempts, the second run ended `failed` (its premise — one completed main
/// attempt — held).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_reused_stage_still_lands_its_required_memory_writeback() {
    let Node {
        _dir,
        rig,
        mock,
        executor,
        store,
    } = boot();
    let program =
        compile_starlark_execution_program(REUSED_PACK, "oci-reused-memory-writeback.star", &[])
            .expect("the pack compiles under oci");

    mock.push(MockResponse::Json(writeback_output("finding-reused")));
    let first = executor
        .submit_execution_program(program.clone())
        .expect("the first run submits");
    assert_eq!(terminal_lifecycle(&rig, &first).await, "completed");
    // No second frame is scripted: the second run must adopt, not run.
    let second = executor
        .submit_execution_program(program)
        .expect("the second run submits");
    let second_outcome = terminal_lifecycle(&rig, &second).await;

    let conn = rusqlite::Connection::open_with_flags(
        &rig.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    let executors: Vec<(String, String)> = conn
        .prepare(
            "SELECT a.executor, p.state FROM attempts a JOIN attempt_projection p \
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
              AND p.attempt_ordinal = a.attempt_ordinal \
             WHERE a.execution_id = ?1 AND a.stage_id = 'finding'",
        )
        .unwrap()
        .query_map(
            [ulid::Ulid::from_string(&second)
                .unwrap()
                .to_bytes()
                .as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        executors,
        vec![("main".to_owned(), "completed".to_owned())],
        "premise: the second run's stage was REUSED — one main attempt, no container"
    );
    assert_eq!(
        second_outcome, "completed",
        "the reused stage's required writeback must be found, not fail the run"
    );
    let objects = store
        .snapshot(
            Some(MemoryObjectKind::Finding),
            Some(MemoryObjectStatus::Active),
        )
        .expect("snapshot the finding objects")
        .objects;
    let ids: Vec<&str> = objects.iter().map(|object| object.id.as_str()).collect();
    assert_eq!(ids, vec!["finding-reused"]);
    // The id alone cannot tell the runs apart: the FIRST run wrote `finding-reused`
    // too. A writeback links the object to the execution that wrote it, so the
    // object naming the SECOND run is what proves the reused stage's writeback
    // landed rather than the first run's surviving.
    let written_by: Vec<Option<&str>> = objects[0]
        .links
        .iter()
        .filter(|link| link.relation == "execution")
        .map(|link| link.execution_id.as_deref())
        .collect();
    assert_eq!(
        written_by,
        vec![Some(second.as_str())],
        "the object must have been rewritten BY the reusing run (first run was {first})"
    );
}

/// The writeback scan FAILS on a completed attempt whose at-rest blob names no arm,
/// rather than skipping it (the scan is an authority consultation — see
/// `completed_stage_facts`). The first run's completed capsule attempt has its blob
/// rewritten raw to name neither `capsule` nor `main`; the terminal pass must refuse
/// with the arm classifier's own refusal.
///
/// **Watched red:** with `Err` from `arm()` skipped (`_ => continue`), the row was
/// silently dropped and the `required` writeback failed as "no completed stage
/// matched" — a refusal about a stage that DID complete.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn the_writeback_scan_refuses_a_completed_attempt_it_cannot_classify() {
    let Node {
        _dir,
        rig,
        mock,
        executor,
        store,
    } = boot();
    let program =
        compile_starlark_execution_program(REUSED_PACK, "oci-reused-memory-writeback.star", &[])
            .expect("the pack compiles under oci");
    mock.push(MockResponse::Json(writeback_output("finding-unclassified")));
    let submitted = executor
        .submit_execution_program(program.clone())
        .expect("the run submits");
    assert_eq!(terminal_lifecycle(&rig, &submitted).await, "completed");
    let execution_id = ulid::Ulid::from_string(&submitted).unwrap();

    let rewritten = rusqlite::Connection::open(&rig.op_path)
        .unwrap()
        .execute(
            "UPDATE attempts SET assignment_json = ?1 \
              WHERE execution_id = ?2 AND executor = 'worker'",
            rusqlite::params![
                br#"{"neither":{}}"#.as_slice(),
                execution_id.to_bytes().as_slice()
            ],
        )
        .unwrap();
    assert_eq!(rewritten, 1, "premise: the run's one capsule attempt");

    let error = kata_api::executor::testing::persist_workflow_memory_writebacks(
        &store,
        execution_id,
        &program,
        &rig.dispatcher,
    )
    .expect_err("an unclassifiable completed attempt must fail the scan");
    let message = error.to_string();
    assert!(
        message.contains("names NEITHER of the arms"),
        "the refusal must be the arm classifier's, not a missing-stage verdict: {message}"
    );
}

/// The writeback scan FAILS on a completed MAIN attempt whose operation this build
/// does not know, rather than skipping it — the other half of the scan's refused
/// set (`completed_stage_facts`'s `# Failure`). The reusing run's one main attempt
/// (`MainOperation::CapsuleReuse`) has its blob's operation rewritten raw to a name
/// no build knows; the arm still classifies as main, so the refusal can only be
/// `main_operation`'s.
///
/// **Watched red:** with `main_operation()`'s `Err` read as "not a reuse"
/// (`.ok().flatten()`), the row was skipped and the `required` writeback failed as
/// "no completed stage matched" — about a stage that DID complete.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn the_writeback_scan_refuses_a_main_attempt_whose_operation_it_does_not_know() {
    let Node {
        _dir,
        rig,
        mock,
        executor,
        store,
    } = boot();
    let program =
        compile_starlark_execution_program(REUSED_PACK, "oci-reused-memory-writeback.star", &[])
            .expect("the pack compiles under oci");
    mock.push(MockResponse::Json(writeback_output("finding-unknown-op")));
    let first = executor
        .submit_execution_program(program.clone())
        .expect("the first run submits");
    assert_eq!(terminal_lifecycle(&rig, &first).await, "completed");
    let second = executor
        .submit_execution_program(program.clone())
        .expect("the second run submits");
    assert_eq!(terminal_lifecycle(&rig, &second).await, "completed");
    let execution_id = ulid::Ulid::from_string(&second).unwrap();

    let conn = rusqlite::Connection::open(&rig.op_path).unwrap();
    let (attempt_id, blob): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT attempt_id, assignment_json FROM attempts \
              WHERE execution_id = ?1 AND executor = 'main' AND stage_id = 'finding'",
            [execution_id.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("premise: the reusing run's one main attempt");
    let mut frame: serde_json::Value = serde_json::from_slice(&blob).unwrap();
    assert!(
        frame["main"].get("operation").is_some(),
        "premise: the blob names its main operation: {frame}"
    );
    frame["main"]["operation"] = serde_json::json!("no_such_operation");
    let rewritten = conn
        .execute(
            "UPDATE attempts SET assignment_json = ?1 WHERE attempt_id = ?2",
            rusqlite::params![serde_json::to_vec(&frame).unwrap(), attempt_id],
        )
        .unwrap();
    assert_eq!(rewritten, 1);

    let error = kata_api::executor::testing::persist_workflow_memory_writebacks(
        &store,
        execution_id,
        &program,
        &rig.dispatcher,
    )
    .expect_err("a main attempt with an unknown operation must fail the scan");
    let message = error.to_string();
    assert!(
        message.contains("names an operation this build does not know"),
        "the refusal must be main_operation's, not a missing-stage verdict: {message}"
    );
}
