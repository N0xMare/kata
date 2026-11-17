use std::sync::Arc;
use std::time::Duration;

use kata_core::InFlightLedger;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_transport::supervisor::WorkerPoolSupervisor;
use ulid::Ulid;

use super::Dispatcher;
use crate::execution_lifecycle::ExecutionLifecycleFace;
use crate::execution_program_store::ExecutionLifecycleState;
use crate::execution_program_store::{ExecutionInvocation, ExecutionTerminalReason};
use crate::runner::WorkflowRunner;
use kata_program::execution_program::ExecutionProgram;

fn rig() -> (Arc<Dispatcher>, ExecutionLifecycleFace, ExecutionProgram) {
    rig_on(ExecutionLifecycleFace::in_memory().unwrap())
}

fn rig_on(
    face: ExecutionLifecycleFace,
) -> (Arc<Dispatcher>, ExecutionLifecycleFace, ExecutionProgram) {
    let program = kata_program::execution_program::compile_execution_program_from_parts_for_tests(
        kata_test_utils::simple_two_stage_workflow(),
        kata_program::policy::WorkflowExtensions::empty(),
        kata_program::execution_program::ExecutionProgramCompileOptions::empty(),
    )
    .unwrap();
    let dispatcher = Arc::new(
        Dispatcher::new(
            Arc::new(WorkerPoolSupervisor::new()),
            Arc::new(HeartbeatMonitor::new(
                Duration::from_secs(1),
                Duration::from_secs(1),
            )),
            InFlightLedger::in_memory(),
        )
        .with_execution_lifecycle(face.clone()),
    );
    (dispatcher, face, program)
}

#[test]
fn execution_hot_state_releases_rejected_admission_after_runner_drop() {
    let (dispatcher, face, program) = rig();
    let id = Ulid::new();
    let runner = WorkflowRunner::new_from_program(program, Arc::clone(&dispatcher), id).unwrap();
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.checked_program_authority.len(), 1);
    assert!(face.lifecycle(id).unwrap().is_none());
    drop(runner);
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.checked_program_authority.len(), 0);
}

#[test]
fn execution_hot_state_releases_terminal_only_after_runner_drop() {
    let (dispatcher, face, program) = rig();
    let id = Ulid::new();
    face.put_current_program(id, &program).unwrap();
    let runner = WorkflowRunner::new_from_program(program, Arc::clone(&dispatcher), id).unwrap();
    face.mark_terminal(id, ExecutionLifecycleState::Completed)
        .unwrap();
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.checked_program_authority.len(), 1);
    drop(runner);
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.checked_program_authority.len(), 0);
    assert!(
        face.program_json(id).unwrap().is_some(),
        "hot retirement preserves durable checked program"
    );
    assert_eq!(
        face.lifecycle(id).unwrap().unwrap().state,
        ExecutionLifecycleState::Completed
    );
}

#[test]
fn execution_hot_state_retains_running_and_failed_closeout() {
    let (dispatcher, face, program) = rig();
    let id = Ulid::new();
    face.put_current_program(id, &program).unwrap();
    let runner = WorkflowRunner::new_from_program(program, Arc::clone(&dispatcher), id).unwrap();
    drop(runner);
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 1);
    face.begin_terminalization(
        id,
        ExecutionLifecycleState::Failed,
        &ExecutionTerminalReason::new("fixture_failure", "cleanup still pending"),
    )
    .unwrap();
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 1);
    face.complete_cleanup(id).unwrap();
    face.finish_terminalization(id).unwrap();
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 0);
}

#[test]
fn execution_hot_state_retains_unreadable_authority() {
    let (dispatcher, face, program) = rig();
    let id = Ulid::new();
    face.put_current_program(id, &program).unwrap();
    let runner = WorkflowRunner::new_from_program(program, Arc::clone(&dispatcher), id).unwrap();
    face.drop_lifecycle_table_for_test().unwrap();
    drop(runner);
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 1);
}

#[test]
fn execution_hot_state_reclaims_after_authority_read_recovers() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let (dispatcher, face, program) = rig_on(ExecutionLifecycleFace::open(&path).unwrap());
    let id = Ulid::new();
    face.put_current_program(id, &program).unwrap();
    let runner = WorkflowRunner::new_from_program(program, Arc::clone(&dispatcher), id).unwrap();
    face.mark_terminal(id, ExecutionLifecycleState::Completed)
        .unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("ALTER TABLE execution_lifecycle RENAME TO unavailable_lifecycle;")
        .unwrap();
    drop(runner);
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 1);
    raw.execute_batch("ALTER TABLE unavailable_lifecycle RENAME TO execution_lifecycle;")
        .unwrap();
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 0);
    let state: String = raw
        .query_row(
            "SELECT state FROM execution_lifecycle WHERE execution_id = ?1",
            [id.to_bytes().as_ref()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "completed");
}

/// Lifecycle/runner fixtures, not actual stage executions, RSS measurements or
/// a full production workload. The raw database and reopen are independent oracles
/// for retained durable history while every process-local execution root retires.
///
/// The writer skips commit fsync: the population is ~5000 commits, and no assertion
/// here can tell a flushed commit from an unflushed one (the reopen is clean, not a
/// power cut). At FULL the cell's runtime was those commits times the host disk's
/// fsync latency, which a concurrent gate drives past any timeout.
#[test]
fn execution_hot_state_fixture_population_retires_with_durable_history_and_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operational.db");
    let mut completed = 0;
    let mut last = None;
    for checkpoint in [0, 1, 10, 100, 1000] {
        let (dispatcher, face, program) = rig_on(ExecutionLifecycleFace::open(&path).unwrap());
        face.db().debug_skip_commit_fsync().unwrap();
        assert_eq!(dispatcher.execution_hot_state_count_for_test(), 0);
        while completed < checkpoint {
            let id = Ulid::new();
            let runner =
                WorkflowRunner::new_from_program(program.clone(), Arc::clone(&dispatcher), id)
                    .unwrap();
            face.put_current_program(id, &program).unwrap();
            face.mark_terminal(id, ExecutionLifecycleState::Completed)
                .unwrap();
            assert_eq!(dispatcher.execution_hot_state_count_for_test(), 1);
            drop(runner);
            assert_eq!(dispatcher.execution_hot_state_count_for_test(), 0);
            completed += 1;
            last = Some(id);
        }
        let raw = rusqlite::Connection::open(&path).unwrap();
        let programs: i64 = raw
            .query_row("SELECT COUNT(*) FROM programs", [], |row| row.get(0))
            .unwrap();
        let terminals: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM execution_lifecycle WHERE state = 'completed'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let invocations: i64 = raw
            .query_row("SELECT COUNT(*) FROM invocations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            (programs, terminals, invocations),
            (checkpoint, checkpoint, checkpoint)
        );
        drop(raw);
        drop(dispatcher);
        drop(face);
        let reopened = ExecutionLifecycleFace::open(&path).unwrap();
        if let Some(id) = last {
            assert_eq!(
                reopened.program_json(id).unwrap().unwrap(),
                serde_json::to_vec(&program).unwrap()
            );
        }
        assert!(reopened.recoverable_execution_ids().unwrap().is_empty());
    }
}

#[test]
fn execution_hot_state_retains_child_admitted_before_parent_parks() {
    let (dispatcher, face, program) = rig();
    let parent = Ulid::new();
    let child = Ulid::new();
    face.put_current_program(parent, &program).unwrap();
    let runner =
        WorkflowRunner::new_from_program(program.clone(), Arc::clone(&dispatcher), parent).unwrap();
    let checked =
        crate::admission::checked_admission(&program, &ExecutionInvocation::workflow(Vec::new()))
            .unwrap();
    face.db()
        .dynamic_child(
            parent,
            child,
            checked.program(),
            checked.invocation(),
            b"child-before-park",
        )
        .unwrap();
    face.mark_terminal(parent, ExecutionLifecycleState::Cancelled)
        .unwrap();
    drop(runner);
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 1);
    face.mark_terminal(child, ExecutionLifecycleState::Cancelled)
        .unwrap();
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 0);
}

#[test]
fn execution_hot_state_rejects_replacing_a_live_program() {
    let (dispatcher, _face, program) = rig();
    let id = Ulid::new();
    let runner =
        WorkflowRunner::new_from_program(program.clone(), Arc::clone(&dispatcher), id).unwrap();
    let mut different = program;
    different.program_hash = [42; 32].into();
    assert!(WorkflowRunner::new_from_program(different, Arc::clone(&dispatcher), id).is_err());
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 1);
    drop(runner);
    assert_eq!(dispatcher.execution_hot_state_count_for_test(), 0);
}

/// A main-resolved attempt at `path` in `execution`'s program.
fn main_spec(
    execution: Ulid,
    program: &ExecutionProgram,
    path: Vec<u32>,
) -> kata_core::operational::MainAttemptSpec {
    kata_core::operational::MainAttemptSpec {
        stage_id: "wait".to_string(),
        occurrence: kata_core::operational::OccurrenceBinding::new(
            kata_types::execution_contract::OccurrenceRef::new(
                kata_types::workflow::ExecutionId(execution),
                program.program_hash,
                kata_types::execution_contract::OperationContractId(
                    kata_types::primitives::ContentHash::new([0x6B; 32]),
                ),
                kata_types::execution_contract::OperationPath(path),
            ),
            None,
            None,
        ),
    }
}

/// Schema 24 — a PARKED main-resolved wait is live stage authority: an execution whose
/// lifecycle is terminal while a wait of its is still parked keeps its hot state, exactly
/// as it would for a parked worker attempt. The retire decision reads
/// `execution_stage_states`, which must therefore carry the main attempt.
///
/// No production writer leaves a parked main wait under a terminal lifecycle any more:
/// the terminal publication ends every one in its own transaction. So the terminal
/// lifecycle is FORGED (`debug_forge_lifecycle_terminal`) over a
/// parked child wait — what this cell pins is the READER, which must still count a live
/// main attempt as stage authority should one ever be found there.
#[test]
fn execution_hot_state_retains_a_parked_main_resolved_wait() {
    let (dispatcher, face, program) = rig();
    let id = Ulid::new();
    face.put_current_program(id, &program).unwrap();
    let runner =
        WorkflowRunner::new_from_program(program.clone(), Arc::clone(&dispatcher), id).unwrap();
    face.db()
        .claim_main_attempt(
            Ulid::new(),
            &main_spec(id, &program, vec![1]),
            kata_core::operational::MainWait::ChildCompletion {
                child_execution_id: Ulid::new(),
            },
        )
        .unwrap();
    face.db()
        .debug_forge_lifecycle_terminal(id, "cancelled")
        .unwrap();
    drop(runner);
    dispatcher.reconcile_dispatch_charges_for_test();
    assert_eq!(
        dispatcher.execution_hot_state_count_for_test(),
        1,
        "a parked main-resolved wait keeps its execution's hot state"
    );
}
