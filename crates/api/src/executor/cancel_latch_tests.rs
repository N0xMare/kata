//! The CANCEL LATCH's executor seams that no public face reaches alone: the
//! terminal-intent arm of cancel propagation (`WorkflowExecutor::cancel_invoked_children`)
//! and a task's adoption of a latched cancel (`adopt_a_latched_cancel`).
//!
//! Durable outcomes are read through a SECOND raw read-only rusqlite handle on
//! `operational.db`, never through the executor's answer about itself.

use std::path::Path;
use std::sync::Arc;

use kata_core::LifecycleState;
use kata_core::operational::{MainAttemptSpec, OccurrenceBinding};
use kata_program::execution_program::{
    compile_starlark_execution_program, lower_stage_operation, occurrence_for,
};
use kata_program::library::WorkflowLibrary;
use kata_types::error::{KataError, KataResult};
use kata_types::workflow::{ExecutionId, StageId};
use kata_workflow::execution_program_store::{
    ExecutionInvocation, ExecutionLifecycleState, ExecutionTerminalReason,
};
use kata_workflow::test_harness::OciNodeRig;
use smol_str::SmolStr;
use ulid::Ulid;

use super::{WorkflowExecutor, adopt_a_latched_cancel};

const SHIPPED_PARENT: &str =
    include_str!("../../../../workflows/smoke/subworkflow-parent-smoke.star");

fn raw(rig: &OciNodeRig) -> rusqlite::Connection {
    rusqlite::Connection::open_with_flags(
        &rig.op_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap()
}

/// `(state, terminal_outcome)` of `execution`'s lifecycle row, read raw.
fn lifecycle(rig: &OciNodeRig, execution: Ulid) -> (String, Option<String>) {
    raw(rig)
        .query_row(
            "SELECT state, terminal_outcome FROM execution_lifecycle WHERE execution_id = ?1",
            [execution.to_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

/// A PARENT'S TERMINAL INTENT LATCHES ITS DIRECT CHILD AT ONCE: a running
/// parent whose `Invoke` is parked on a RUNNING child latches its own outcome (a sibling
/// failed), and the terminal-intent arm (`cancel_invoked_children`) runs. The child is
/// `terminalizing` with intent `cancelled` straight after that call — before the parent's
/// publication (whose transaction also latches it) and before any deadline tick — while the
/// parent's `Invoke` is still parked, which is what shows the latch came from this arm.
/// Read raw.
///
/// **Watched red:** with `WorkflowExecutor::cancel` latching only the executions BELOW the
/// root of its walk (`execution != execution_id`), the direct child — the root of the
/// `cancel` this arm calls — reads `running` after the call: it is asked to stop, and free
/// to claim and start a new stage until the parent publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_parents_terminal_intent_latches_its_direct_child_at_once() {
    kata_types::node_profile::mark_node_installed();
    let dir = tempfile::tempdir().unwrap();
    let rig = OciNodeRig::open(dir.path());
    let smoke_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../workflows/smoke");
    let program = compile_starlark_execution_program(
        SHIPPED_PARENT,
        "subworkflow-parent-smoke.star",
        &[smoke_root],
    )
    .expect("the shipped parent compiles under oci");
    let face = rig.dispatcher.execution_lifecycle();
    let (parent, child) = (Ulid::new(), Ulid::new());
    face.put_current_program(parent, &program).unwrap();
    face.mark_running_after_admission(parent).unwrap();
    let sub = StageId(SmolStr::new("sub"));
    let bound = program.stages[&sub]
        .subworkflow
        .as_ref()
        .unwrap()
        .bound
        .program()
        .clone();
    let lowered = lower_stage_operation(&program, &sub).expect("sub lowers");
    let params =
        kata_types::params::resolve_and_validate_params(&bound.params, &serde_json::Map::new())
            .unwrap();
    face.invoke_child_execution(
        Ulid::new(),
        &MainAttemptSpec {
            stage_id: "sub".to_string(),
            occurrence: OccurrenceBinding::new(
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
    face.mark_running_after_admission(child).unwrap();
    rig.db
        .begin_terminalization(
            parent,
            LifecycleState::Failed,
            b"{\"code\":\"failed\",\"message\":\"a sibling stage failed\"}",
        )
        .unwrap();
    let executor = Arc::new(
        WorkflowExecutor::new(
            Arc::clone(&rig.dispatcher),
            Arc::clone(&rig.supervisor),
            Arc::new(WorkflowLibrary::new(vec![])),
        )
        .with_execution_lifecycle(rig.dispatcher.execution_lifecycle()),
    );

    let asked = executor
        .cancel_invoked_children(parent, "the parent latched its outcome")
        .await
        .expect("the arm runs");
    assert_eq!(asked, 1);
    assert_eq!(
        lifecycle(&rig, child),
        ("terminalizing".to_string(), Some("cancelled".to_string())),
        "the direct child is latched by the arm itself"
    );
    let invoke: String = raw(&rig)
        .query_row(
            "SELECT p.state FROM attempts a JOIN attempt_projection p
                ON p.execution_id = a.execution_id AND p.stage_id = a.stage_id
               AND p.attempt_ordinal = a.attempt_ordinal
             WHERE a.execution_id = ?1 AND a.stage_id = 'sub'",
            [parent.to_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        invoke, "awaiting_child_completion",
        "the parent has not published: its Invoke is still parked"
    );
    assert_eq!(
        lifecycle(&rig, parent),
        ("terminalizing".to_string(), Some("failed".to_string()))
    );
}

/// A RUN THAT RETURNED `Ok` UNDER A LATCHED CANCEL CLOSES OUT AS CANCELLED: when the
/// standing intent is another party's cancel, `adopt_a_latched_cancel` turns an `Ok` run
/// into an `Err` naming the latched reason, so the task takes the failure arm (which parks
/// the candidate the latch's disposition names) rather than the completion arm. When the
/// standing intent IS the task's own, the result is left alone, `Ok` or `Err`.
///
/// **Watched red:** with the `Ok` → `Err` rewrite removed, the adopted run stays `Ok(())`.
#[test]
fn a_latched_cancel_turns_an_ok_run_into_the_cancelled_failure() {
    let execution = Ulid::new();
    let own = ExecutionTerminalReason::new("completed", "the run completed");
    let latched = (
        ExecutionLifecycleState::Cancelled,
        ExecutionTerminalReason::new("cancelled", "operator cancel"),
    );
    let mut run: KataResult<()> = Ok(());
    adopt_a_latched_cancel(execution, &own, &latched, &mut run);
    let error = run.expect_err("an adopted cancel is not a completion");
    assert!(
        matches!(&error, KataError::Validation(message)
            if message.contains(&execution.to_string())
                && message.contains("was cancelled while it ran")
                && message.contains("operator cancel")),
        "{error:?}"
    );

    let mut failed: KataResult<()> = Err(KataError::Internal("the stage failed".to_string()));
    adopt_a_latched_cancel(execution, &own, &latched, &mut failed);
    assert!(
        matches!(&failed, Err(KataError::Internal(message)) if message == "the stage failed"),
        "a failed run keeps its own error: {failed:?}"
    );

    let mine = (ExecutionLifecycleState::Completed, own.clone());
    let mut completed: KataResult<()> = Ok(());
    adopt_a_latched_cancel(execution, &own, &mine, &mut completed);
    assert!(completed.is_ok(), "its own intent is no adoption");
}
