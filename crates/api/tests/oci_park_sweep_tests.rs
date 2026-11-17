//! The park sweep's in-flight guard on the capsule arm.
//!
//! `require_terminal_lifecycle_for_parking` refuses to park a Cancelled or
//! TimedOut execution while any attempt is still in flight — a worker may still
//! be writing the workspace the parking reclaims. A guard reading
//! `execution_assignment_states`, which excludes capsule attempts, would be
//! vacuous under `oci`. This cell parks a cancelled execution
//! while its capsule attempt is still in flight and watches the refusal.

use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::{ExecutorError, WorkflowExecutor};
use kata_program::execution_program::compile_starlark_execution_program;
use kata_program::library::WorkflowLibrary;
use kata_program::test_harness::install_rig_agents;
use kata_test_utils::MockResponse;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_workflow::reactor::ResultReactor;
use kata_workflow::test_harness::OciNodeRig;
use smol_str::SmolStr;
use ulid::Ulid;

const PACK: &str = r#"
work = stage(id = "work", agent = "default", prompt = "hold")
workflow("oci-park-sweep", root = [work])
"#;

/// A cancelled execution whose capsule attempt never settled must refuse
/// `park_candidate`: the worker can still be writing the workspace.
///
/// **Would red if:** the in-flight sweep read `execution_assignment_states`
/// (empty under `oci`) — the cancelled run would park with its capsule still
/// in flight, which is exactly the teardown-under-a-writer the conjunct
/// exists to refuse.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn cancelled_execution_with_in_flight_capsule_attempt_refuses_to_park() {
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
    // The capsule frame is parked on a rendezvous barrier the test never
    // releases — the attempt stays started-and-answered-never, the honest
    // "still in flight" (Hang would ANSWER the frame as a failed run).
    let (mock, pump) = rig.scripted_worker(Arc::clone(&dir));
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    mock.push(MockResponse::Rendezvous(Arc::clone(&barrier)));

    let bookkeeper = Arc::clone(&rig.dispatcher);
    {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            bookkeeper.run_bookkeeper().await;
        });
    }
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

    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle())
        .with_cache_store(Arc::clone(&rig.store)),
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

    let program = compile_starlark_execution_program(PACK, "oci-park-sweep.star", &[])
        .expect("the pack compiles under oci");
    let submitted = executor
        .submit_execution_program(program)
        .expect("the workflow submits under the oci rig");
    let execution_id = Ulid::from_string(&submitted).expect("the submission id is a ulid");
    let exec_bytes = execution_id.to_bytes().to_vec();

    // Wait for the WORKER to hold the attempt — `running` with `started_at_ms`,
    // folded from the start checkpoint the scripted pump sends only after it
    // received the frame. A claim alone is not in flight: a dispatch that
    // commits after the cancel below latches is refused
    // (`dispatch_after_terminal_intent`) and settles the claim PROVEN NOT
    // PERFORMED in the same transaction, and the park then rightly passes this
    // conjunct. A wait that broke on the `pending` claim raced that dispatch.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let attempt_held_by_the_worker = |conn: &rusqlite::Connection| -> i64 {
        conn.query_row(
            "SELECT count(*) FROM attempts a JOIN attempt_projection p \
               ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id \
              AND p.attempt_ordinal = a.attempt_ordinal \
             WHERE a.execution_id = ?1 AND p.state = 'running' \
               AND a.started_at_ms IS NOT NULL AND a.finished_at_ms IS NULL",
            [&exec_bytes[..]],
            |row| row.get(0),
        )
        .unwrap()
    };
    loop {
        let held = attempt_held_by_the_worker(&rusqlite::Connection::open(&rig.op_path).unwrap());
        if held >= 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the worker never reported the capsule attempt started"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Latch the cancelled intent the way `cancel` does, then publish the
    // terminal through the same doors the run task's closeout calls — WITHOUT
    // `cancel`'s stop-ask arm, so the park refusal can only come from the
    // in-flight conjunct (a stop-ask would fire the unacknowledged-stop
    // conjunct first and prove nothing about the attempts read).
    executor
        .execution_lifecycle()
        .begin_terminalization(
            execution_id,
            kata_workflow::execution_program_store::ExecutionLifecycleState::Cancelled,
            &kata_workflow::execution_program_store::ExecutionTerminalReason::new(
                "cancelled",
                "operator asked for a stop",
            ),
        )
        .expect("the cancelled intent latches");
    // `finish_terminalization` does not wait for live worker work — the
    // capsule attempt stays `running` under a terminal lifecycle, exactly
    // the "terminal lifecycle while an attempt still writes" window the
    // in-flight conjunct exists to refuse.
    executor
        .execution_lifecycle()
        .complete_cleanup(execution_id)
        .expect("the cancelled execution's cleanup closes");
    executor
        .execution_lifecycle()
        .finish_terminalization(execution_id)
        .expect("the cancelled terminal publishes over the in-flight attempt");
    let lifecycle = executor
        .execution_lifecycle()
        .lifecycle(execution_id)
        .expect("the lifecycle reads")
        .expect("the execution has a lifecycle");
    assert_eq!(
        lifecycle.state,
        kata_workflow::execution_program_store::ExecutionLifecycleState::Cancelled,
        "the cancelled terminal published with the capsule attempt still running"
    );

    let refusal = executor.park_candidate(execution_id, None).expect_err(
        "a cancelled execution whose capsule attempt is still in flight must refuse to park",
    );
    assert!(
        matches!(refusal, ExecutorError::PolicyDenied(_)),
        "the refusal is PolicyDenied — the in-flight attempt blocks parking: {refusal:?}"
    );
    let message = refusal.to_string();
    assert!(
        message.contains("not settled"),
        "the refusal names the un-settled attempts: {message}"
    );
    // The premise, read out of the database rather than out of the refusal: the
    // worker still holds the attempt the park was refused over.
    assert_eq!(
        attempt_held_by_the_worker(&rusqlite::Connection::open(&rig.op_path).unwrap()),
        1,
        "the attempt is still running, unsettled, when the park is refused"
    );
    // Release the parked answer so the pump is not left mid-frame, then stop
    // its receive loop — `pump` runs until aborted, not until its queue drains.
    let _ = barrier.wait().await;
    pump.abort();
}
