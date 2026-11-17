//! What `WorkflowExecutor::cancel` REACHES: a parked MAIN-RESOLVED wait (which no worker
//! holds, so the cancel must end it itself) and a running CAPSULE attempt (which the
//! assignment population excludes, so a cancel reading it would ask it nothing).
//!
//! Every durable outcome is read through a second raw read-only rusqlite handle; the stop
//! is read off the WORKER side of a real `InProcessTransport`.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::WorkflowExecutor;
use kata_core::operational::{MainAttemptSpec, MainWait, OccurrenceBinding};
use kata_program::execution_program::{ExecutionProgram, compile_starlark_execution_program};
use kata_transport::types::{AttemptFence, WorkerControl};
use kata_types::execution_contract::{OccurrenceRef, OperationContractId, OperationPath};
use kata_types::primitives::ContentHash;
use kata_types::wait::WaitDeadline;
use kata_types::workflow::ExecutionId;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use smol_str::SmolStr;
use ulid::Ulid;

/// How long a cell waits for a frame/event it EXPECTS (every wait ends on its match, so the
/// window only bounds a failure): sized for the commit tier's full parallel load, where the
/// oci rig's capsule round trips can take longer than 5 s.
const EVENT_DEADLINE: Duration = Duration::from_secs(30);

const PACK: &str = "only = stage(id = \"only\", agent = \"shell\", run = \"true\")\n\
                    workflow(\"cancel-reach\", root = [only])\n";
/// The shared rig's registered worker name — the cancel's fenced `Stop`
/// targets it.
const WORKER: &str = "test-worker";

/// A booted `oci` rig: the scripted worker holds the worker side of the
/// transport, `db`/`op_path`/`store.cas()` are the durable readouts.
struct Rig {
    stack: common::ExecutorStack,
    face: ExecutionLifecycleFace,
    executor: Arc<WorkflowExecutor>,
    program: ExecutionProgram,
    execution: Ulid,
}

fn rig() -> Rig {
    let stack = common::boot_executor();
    let face = stack.executor.execution_lifecycle().clone();
    let program = compile_starlark_execution_program(PACK, "cancel-reach.star", &[])
        .expect("the pack compiles");
    let execution = Ulid::new();
    face.put_current_program(execution, &program)
        .expect("the execution is admitted and running");
    Rig {
        executor: Arc::clone(&stack.executor),
        stack,
        face,
        program,
        execution,
    }
}

fn op_path(rig: &Rig) -> &Path {
    rig.stack
        .op_path
        .as_ref()
        .expect("the rig's operational face is file-backed")
}

fn raw(dir: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        dir,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

fn last_state(dir: &Path, attempt: Ulid) -> (String, String) {
    raw(dir)
        .query_row(
            "SELECT resulting_state, coalesce(json_extract(payload_json, '$.reason'), '') \
               FROM transitions WHERE attempt_id = ?1 ORDER BY seq DESC LIMIT 1",
            [attempt.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

/// THE CANCEL'S MAIN-SIDE ARM: a parked durable timer is resolved `cancelled` by the
/// cancel itself — `main_side_settled: 1`, nothing asked of any worker — and its deadline
/// is cleared, so no later tick can accept it. A repeat cancel settles nothing more.
///
/// **Watched red:** with `cancel`'s main-side arm removed (today's cancel, which reads
/// only placed attempts), `main_side_settled` is 0 and the timer stays `awaiting_timer`.
#[tokio::test]
async fn cancel_settles_a_parked_main_timer_cancelled() {
    let rig = rig();
    let timer = Ulid::new();
    rig.face
        .db()
        .claim_main_attempt(
            timer,
            &MainAttemptSpec {
                stage_id: "only".to_string(),
                occurrence: OccurrenceBinding::new(
                    OccurrenceRef::new(
                        ExecutionId(rig.execution),
                        rig.program.program_hash,
                        OperationContractId(ContentHash::new([0x7C; 32])),
                        OperationPath(vec![0]),
                    ),
                    None,
                    None,
                ),
            },
            MainWait::Timer(WaitDeadline::AfterClaim { delay_ms: 600_000 }),
        )
        .expect("the timer parks");

    let outcome = rig
        .executor
        .cancel(rig.execution, "operator cancel".to_string())
        .await
        .expect("the cancel succeeds");
    assert_eq!(outcome.main_side_settled, 1, "{outcome:?}");
    assert_eq!(outcome.assignments_asked_to_stop, 0, "{outcome:?}");
    let (state, reason) = last_state(op_path(&rig), timer);
    assert_eq!(
        (state.as_str(), reason.as_str()),
        ("cancelled", "operator cancel")
    );
    let deadline: Option<i64> = raw(op_path(&rig))
        .query_row(
            "SELECT wait_deadline_ms FROM attempts WHERE attempt_id = ?1",
            [timer.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(deadline, None, "no tick can find it due any more");

    let again = rig
        .executor
        .cancel(rig.execution, "operator cancel".to_string())
        .await
        .expect("a repeat cancel succeeds");
    assert_eq!(
        (again.main_side_settled, again.assignments_asked_to_stop),
        (0, 0)
    );
}

/// THE CANCEL REACHES A RUNNING CAPSULE: a capsule attempt dispatched to a worker and
/// started is ASKED to stop — a durable stop request written for its generation, then a
/// fenced `Stop` for exactly that attempt, epoch and worker delivered to the worker's side
/// of the transport.
///
/// **Watched red:** with the worker arm reading the assignment population
/// (`Dispatcher::execution_assignment_states`, which excludes the capsule arm), the cancel
/// asks nothing and no control frame reaches the worker.
#[tokio::test]
async fn cancel_asks_a_running_capsule_attempt_to_stop_fenced() {
    let rig = rig();
    let attempt = kata_workflow::test_harness::seed_dispatched_capsule_attempt(
        rig.face.db(),
        rig.stack.store.cas(),
        rig.execution,
        rig.program.program_hash,
        "only",
        WORKER,
        Some(kata_types::time::now_ms().try_into().unwrap()),
    );

    let outcome = rig
        .executor
        .cancel(rig.execution, "operator cancel".to_string())
        .await
        .expect("the cancel reaches the worker");
    assert_eq!(outcome.assignments_asked_to_stop, 1, "{outcome:?}");
    assert_eq!(outcome.main_side_settled, 0, "{outcome:?}");

    let control = tokio::time::timeout(EVENT_DEADLINE, rig.stack.worker_side.recv_control())
        .await
        .expect("a control frame reaches the worker")
        .expect("the transport delivers it");
    let conn = raw(op_path(&rig));
    let lease_epoch: i64 = conn
        .query_row(
            "SELECT lease_epoch FROM attempts WHERE attempt_id = ?1",
            [attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    match control {
        WorkerControl::Stop {
            assignment_id,
            fence,
            reason,
        } => {
            assert_eq!(assignment_id, attempt);
            assert_eq!(
                fence,
                AttemptFence::commanding(lease_epoch, SmolStr::new(WORKER))
            );
            assert_eq!(reason, "operator cancel");
        }
        other => panic!("expected a fenced stop, got {other:?}"),
    }
    let requests: i64 = conn
        .query_row(
            "SELECT count(*) FROM attempt_stop_requests WHERE attempt_id = ?1",
            [attempt.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(requests, 1, "the ask is durable");
}
