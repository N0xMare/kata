//! Blocking human requests on the capsule arm, verified end-to-end.
//!
//! Under `oci` a blocking `human_request` is a main-side `awaiting_input` wait:
//! the request's answer (or its `default_assumption` once `timeout_ms` elapses)
//! is accepted ONCE as the wait's outcome, and the held stage resumes with the
//! effective answer rendered into its capsule. `execution_assignment_states` is
//! a plane capsule attempts never land on, so these cells watch the whole chain
//! rather than any one read: submit → parked wait → resolve → dispatched
//! capsule argv carrying the answer.

use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::WorkflowExecutor;
use kata_program::library::WorkflowLibrary;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_transport::types::DispatchFrame;
use kata_types::approval::ApprovalPrincipal;
use kata_types::execution::ExecutionHumanRequestAnswerRequest;
use kata_workflow::delivery_service::DeliveryService;
use kata_workflow::reactor::ResultReactor;
use kata_workflow::test_harness::{OCI_RIG_WORKER, OciNodeRig};
use smol_str::SmolStr;
use ulid::Ulid;

const PACK: &str = include_str!("../../../workflows/examples/durable-wait-signal.star");

struct Boot {
    // `Arc`-shared with the spawned tasks below — a detached task can outlive
    // this guard, and the directory must die after its last poll, not at it.
    _dir: Arc<tempfile::TempDir>,
    rig: OciNodeRig,
    executor: Arc<WorkflowExecutor>,
}

fn boot() -> Boot {
    kata_types::node_profile::mark_node_installed();
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let rig = OciNodeRig::open(dir.path());
    rig.declare_bound_environment();

    let bookkeeper = Arc::clone(&rig.dispatcher);
    {
        let node_dir = Arc::clone(&dir);
        tokio::spawn(async move {
            let _node_dir = node_dir;
            bookkeeper.run_bookkeeper().await;
        });
    }
    let reactor = ResultReactor::new(
        SmolStr::new(OCI_RIG_WORKER),
        Arc::clone(&rig.worker_side) as Arc<dyn kata_transport::WorkerResultTransport>,
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

    let delivery = DeliveryService::new(
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

    Boot {
        _dir: dir,
        rig,
        executor,
    }
}

fn submit(boot: &Boot) -> String {
    let program = kata_program::execution_program::compile_starlark_execution_program(
        PACK,
        "durable-wait-signal.star",
        &[],
    )
    .expect("the pack compiles under oci");
    boot.executor
        .submit_execution_program(program)
        .expect("the submission is accepted")
}

/// Raw read of the parked input-wait count — rows the assignment fold never
/// carries.
fn parked_input_waits(boot: &Boot, execution: Ulid) -> i64 {
    rusqlite::Connection::open(&boot.rig.op_path)
        .unwrap()
        .query_row(
            "SELECT count(*) FROM attempt_projection p JOIN attempts a \
               ON a.execution_id = p.execution_id AND a.stage_id = p.stage_id \
              AND a.attempt_ordinal = p.attempt_ordinal \
             WHERE p.execution_id = ?1 AND p.state = 'awaiting_input'",
            [execution.to_bytes().to_vec()],
            |row| row.get(0),
        )
        .unwrap()
}

/// The next capsule frame's argv — the rendered command the `decide` stage
/// dispatches with its effective answer spliced in.
async fn next_capsule_argv(boot: &Boot) -> Vec<String> {
    let frame = tokio::time::timeout(Duration::from_secs(60), async {
        let DispatchFrame::Capsule(capsule) = boot
            .rig
            .worker_side
            .recv_frame()
            .await
            .expect("the transport delivers a frame");
        *capsule
    })
    .await
    .expect("the held stage's capsule dispatches after the wait resolves");
    let body = boot
        .rig
        .cas
        .get(&frame.capsule.object)
        .expect("the CAS reads")
        .expect("the capsule object is published");
    let capsule: kata_types::execution_contract::Capsule =
        serde_json::from_slice(&body).expect("the capsule decodes");
    match capsule.process() {
        kata_types::execution_contract::CapsuleProcess::Command { argv } => {
            argv.iter().map(ToString::to_string).collect()
        }
        kata_types::execution_contract::CapsuleProcess::Agent(..) => {
            panic!("the held stage is a Command capsule")
        }
    }
}

async fn wait_parked(boot: &Boot, execution: Ulid) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if parked_input_waits(boot, execution) == 1 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the blocking request never parked `decide` in awaiting_input"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// (a) THE OPERATOR ANSWER: while `decide` is parked on the blocking request,
/// `answer_human_request` resolves the input wait through the capsule arm
/// (`answer_input_wait`) and the stage dispatches with the answer rendered
/// into its argv.
///
/// **Watched red:** an answer path scanning `execution_assignment_states` — an
/// oci park is an `awaiting_input` main
/// wait, so no parked assignment exists to approve and the stage would stay
/// held forever.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_answer_resumes_the_held_stage_with_the_answer_in_its_argv() {
    let boot = boot();
    let execution_id = submit(&boot);
    let execution = Ulid::from_string(&execution_id).unwrap();
    wait_parked(&boot, execution).await;

    boot.executor
        .answer_human_request(
            execution,
            ExecutionHumanRequestAnswerRequest {
                request_id: "proceed_q".to_string(),
                answer_summary: "ship-it".to_string(),
                answered_by_steering_id: None,
            },
            Some(&ApprovalPrincipal::UnauthenticatedLoopback),
        )
        .expect("the answer resolves the wait");

    let argv = next_capsule_argv(&boot).await;
    assert!(
        argv.iter().any(|arg| arg.contains("ship-it")),
        "the resumed stage's rendered command carries the operator's answer: {argv:?}"
    );
}

/// (b)+(c) THE TIMEOUT SELF-HEAL: with the request unanswered, the due-wait
/// sweep accepts `default_assumption` as the wait's outcome (`timeout_default`)
/// and the stage resumes with the default in its argv. The parked input wait is
/// not an approval gate: no approval-gate sweep heals it.
///
/// **Watched red:** no capsule-arm self-heal at all — the wait would park
/// `decide` past its deadline with the frame never arriving.
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn a_timed_out_blocking_request_self_heals_on_the_due_wait_sweep() {
    let boot = boot();
    let execution_id = submit(&boot);
    let execution = Ulid::from_string(&execution_id).unwrap();
    wait_parked(&boot, execution).await;

    // (b): the deadline tick past the request's 600s timeout accepts the
    // authored default.
    boot.rig
        .dispatcher
        .run_deadline_sweep_tick_for_test(kata_types::time::now_ms() + 700_000)
        .await;

    let argv = next_capsule_argv(&boot).await;
    assert!(
        argv.iter().any(|arg| arg.contains("proceed")),
        "the resumed stage's rendered command carries the authored default: {argv:?}"
    );
}
