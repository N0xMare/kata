//! Workflow-level-failure / parking / controller-application / finalize tests for
//! `kata_api::executor`.
//!
//! Shared boot / mock / build / seed helpers live in `common`.

#![allow(clippy::large_futures)]

mod common;
use common::*;

use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::testing::{
    persist_controller_application_evidence, persist_parked_candidate_evidence,
    persist_workflow_level_failure_for_program,
};
use kata_api::executor::{ExecutionStatus, ExecutorError, WORKFLOW_LEVEL_STAGE_NAME};
use kata_core::InFlightLedger;

use kata_effects_contract::{ExecutionWorkspaceKey, ExecutionWorkspaceProvider};
use kata_program::execution_program::ExecutionProgram;
use kata_types::execution::ExecutionControllerApplyFinalizeRequest;
use kata_types::workflow::{AgentSelector, StageId};
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::execution_program_store::ExecutionLifecycleState;
use smol_str::SmolStr;
use tokio_stream::StreamExt as _;
use ulid::Ulid;

// This family's local admission helpers declare the controller and validation
// stages its fixtures actually complete; common's tiny program declares only `only`.
fn controller_fixture_definition(name: &str) -> kata_types::workflow::WorkflowDefinition {
    let mut definition = tiny_definition(name);
    let template = definition.stages.values().next().unwrap().clone();
    for name in ["controller", "validate"] {
        let mut stage = template.clone();
        stage.id = StageId(SmolStr::new(name));
        definition.stages.insert(stage.id.clone(), stage);
    }
    definition
}

fn seed_checked_previous_execution_for_test(
    executor: &Arc<kata_api::executor::WorkflowExecutor>,
    execution: Ulid,
    name: &str,
) -> String {
    common::seed_execution_program_for_test(
        executor,
        execution,
        compile_definition(controller_fixture_definition(name)),
    )
}

fn catch_up_fixture_delivery(executor: &kata_api::executor::WorkflowExecutor) {
    kata_workflow::delivery_service::DeliveryService::new(
        Arc::clone(executor.execution_lifecycle().db()),
        Arc::clone(executor.dispatcher_for_test().ledger()),
    )
    .catch_up()
    .expect("project current fixture authority");
}

fn terminalize_completed_fixture(
    executor: &kata_api::executor::WorkflowExecutor,
    execution_id: Ulid,
) {
    executor
        .execution_lifecycle()
        .mark_terminal(execution_id, ExecutionLifecycleState::Completed)
        .expect("terminalize controller application fixture");
}

// ----- Workflow-level failures persisted into the ledger -----
//
// Pre-dispatch errors are written into the durable ledger, so operators
// see `status: failed` instead of `status: pending` forever, as a
// synthetic `Failed` assignment under the
// [`WORKFLOW_LEVEL_STAGE_NAME`] sentinel — same surface behaviour,
// and the error survives a home-node restart over the durable nucleus.

fn workflow_level_failure_assignment_id_for_test(
    execution_id: Ulid,
    _program: &ExecutionProgram,
) -> Ulid {
    let mut bytes = execution_id.to_bytes();
    const ROTATIONS: [u32; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
    for (index, byte) in b"kata.api.workflow_level_failure.assignment.v1\0"
        .iter()
        .enumerate()
    {
        bytes[index % bytes.len()] ^= byte.rotate_left(ROTATIONS[index % ROTATIONS.len()]);
    }
    Ulid::from_bytes(bytes)
}

/// Admit `execution_id` into the nucleus, which EVERY production caller of
/// `persist_workflow_level_failure_for_program` has done by the time it records:
/// all eight call statements run after `begin_terminalization` (or, for the
/// recovery repair, inside the lifecycle scan). The paired door fails
/// CLOSED on an execution the nucleus does not hold, so the fixtures route through
/// the real admission seam rather than the guard being relaxed.
fn admit_workflow_level_failure_fixture(
    executor: &kata_api::executor::WorkflowExecutor,
    execution_id: Ulid,
    program: &ExecutionProgram,
) {
    executor
        .execution_lifecycle()
        .put_current_program(execution_id, program)
        .expect("admit the workflow-level failure fixture into the nucleus");
}

/// When `submit`'s background task writes a synthetic Failed
/// assignment under the workflow-level sentinel, the standard
/// `execution_record_from_assignments_with_program_and_evidence` aggregator must
/// produce `status: Failed` with the captured error string in
/// `error`. No side-registry consultation needed — this is the
/// core workflow-level-failure contract.
///
/// # What proves what
///
/// The fixture carries a terminal Failed LIFECYCLE, because the production
/// writer's paired door requires the execution to be in the nucleus. Any lifecycle
/// row overrides `record.status` (`try_get_execution_by_ulid`), so `status` here is
/// the lifecycle's and is NOT a proof of row aggregation — said plainly rather
/// than left to read as one. What the synthetic row still proves is everything the
/// `Failed` arm does NOT overwrite: `error` (the arm resets it only for
/// Admitting/Running/Completed) and `started_at_ms`. Missing-admission refusal is
/// covered by [`a_workflow_level_failure_cannot_create_an_execution_without_admission`].
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn synthetic_workflow_level_failure_aggregates_to_failed() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("ghost"));
    admit_workflow_level_failure_fixture(&executor, execution_id, &program);
    persist_workflow_level_failure_for_program(
        executor.dispatcher_for_test(),
        execution_id,
        &program,
        "sandbox rejected: no WorkspaceManager",
    )
    .expect("synthetic ledger write must succeed");
    executor
        .execution_lifecycle()
        .mark_terminal(execution_id, ExecutionLifecycleState::Failed)
        .expect("latch the terminal Failed lifecycle production reaches");

    let rec = executor
        .get_execution(&execution_id.to_string())
        .expect("record must exist once the synthetic assignment is in the ledger");
    assert_eq!(rec.status, ExecutionStatus::Failed);
    assert_eq!(rec.workflow_name, "ghost");
    assert!(rec.outputs.is_none());
    let err = rec.error.expect("error must be populated on aggregation");
    assert!(
        err.contains("no WorkspaceManager"),
        "error must surface the synthetic assignment's reason, got: {err}"
    );
    assert!(
        err.contains(WORKFLOW_LEVEL_STAGE_NAME),
        "error must surface the sentinel stage name so operators can \
         tell workflow-level failures from real stage failures, got: {err}"
    );
    assert!(
        rec.finished_at_ms.is_some(),
        "synthetic Failed assignment must stamp finished_at_ms"
    );
    assert!(
        rec.started_at_ms.is_none(),
        "synthetic assignment never ran — started_at_ms must stay None"
    );
}

/// A `Completed` LIFECYCLE MUST NOT ERASE a failure the durable rows
/// already prove.
///
/// # The property, stated as the two planes disagreeing
///
/// `try_get_execution_by_ulid` reassigns `record.status` from the lifecycle. If
/// its `Completed` arm also cleared `record.error`, then whenever the lifecycle
/// INFERRED success while the durable rows HELD a `Failed` row, the record would
/// report `"status":"completed"` with `"error":null` and the evidence would be
/// gone from the surface — not merely outranked, erased.
///
/// A tripped `time_bound` is one producer of that shape: it records a synthetic
/// `<stage>#bound-halt-time` row that is deliberately NOT a DAG stage, so a
/// runner that enumerated only DAG stages (`WorkflowRunner::collect_failures`)
/// would return `Ok` and the lifecycle would latch `Completed` while
/// `aggregate_status` derives `Failed` from that very row.
///
/// # COUNTERFACTUAL
///
/// Delete the `ExecutionLifecycleState::Completed if record.status ==
/// ExecutionStatus::Failed` arm from `try_get_execution_by_ulid` and this test
/// fails on the first assertion with `status=Completed`, `error=None`.
///
/// # Why this test is separate from the runner's
///
/// The runner (`WorkflowRunner::finalize_run` folding in
/// `collect_durable_walkaway_halts`) stops PRODUCING the divergence; this pins
/// that the divergence is not INVISIBLE if any other path ever produces it. It
/// seeds the two planes directly and never runs a workflow, so it holds even if
/// the runner's terminal decision regresses.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_completed_lifecycle_does_not_erase_a_durable_failed_row() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("walkaway"));
    admit_workflow_level_failure_fixture(&executor, execution_id, &program);
    persist_workflow_level_failure_for_program(
        executor.dispatcher_for_test(),
        execution_id,
        &program,
        "bound_exceeded: workflow time bound reached 3006 ms (limit: 1000 ms)",
    )
    .expect("synthetic ledger write must succeed");

    // The plane that was WRONG, latched exactly as production latched it.
    terminalize_completed_fixture(&executor, execution_id);

    let rec = executor
        .get_execution(&execution_id.to_string())
        .expect("record must exist");
    assert_eq!(
        rec.status,
        ExecutionStatus::Failed,
        "the ledger holds a Failed row; a Completed lifecycle must not outrank it. \
         record was: status={:?} error={:?}",
        rec.status,
        rec.error
    );
    let err = rec
        .error
        .expect("the Completed arm must no longer clear the aggregate's error");
    assert!(
        err.contains("bound_exceeded"),
        "the walk-away reason must survive the lifecycle read; got: {err}"
    );
    assert!(
        rec.outputs.is_none(),
        "a run reported Failed must not also hand back a success output map"
    );
}

/// The other direction, so the refusal above cannot be satisfied by never
/// reporting `Completed` at all: a `Completed` lifecycle over a ledger holding NO
/// failed row still reads `Completed`, with `error` cleared as before.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_completed_lifecycle_over_a_clean_ledger_still_reads_completed() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let id = executor
        .submit_execution_program(compile_definition(tiny_definition("clean")))
        .expect("submit should succeed with a live worker");
    let rec = wait_terminal(&executor, &id).await;
    assert_eq!(
        rec.status,
        ExecutionStatus::Completed,
        "error={:?} outputs={:?}",
        rec.error,
        rec.outputs
    );
    assert!(rec.error.is_none(), "a clean run carries no error");
}

/// Failure evidence cannot invent an execution with no lifecycle admission —
/// and on the current plane it cannot even be WRITTEN under one: the
/// dispatcher's stage door fails closed on an execution the nucleus does not
/// hold, and one level down the schema's `transitions.execution_id` foreign
/// key refuses the raw row itself. The API-visible absence this test always
/// measured is therefore enforced at the door, not only at the read.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_workflow_level_failure_cannot_create_an_execution_without_admission() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("ghost"));
    let assignment_id = workflow_level_failure_assignment_id_for_test(execution_id, &program);
    assert!(
        executor
            .execution_lifecycle()
            .lifecycle(execution_id)
            .expect("lifecycle read")
            .is_none(),
        "POSITIVE CONTROL: this fixture is the NO-lifecycle shape, so the aggregation \
         below cannot be the lifecycle answering for the ledger"
    );
    let dispatcher = executor.dispatcher_for_test();
    let dispatcher_refusal = dispatcher
        .admit_undispatched_stage(
            execution_id,
            assignment_id,
            WORKFLOW_LEVEL_STAGE_NAME,
            WORKFLOW_LEVEL_STAGE_NAME,
        )
        .expect_err("the dispatcher door refuses an execution the nucleus does not hold");
    assert!(
        dispatcher_refusal
            .to_string()
            .contains("operational nucleus does not hold"),
        "{dispatcher_refusal}"
    );
    // The raw operational door has no dispatcher gate of its own — the SCHEMA
    // is what refuses it: `transitions.execution_id` is a foreign key into
    // `execution_lifecycle`, so an unadmitted execution cannot hold a chain row
    // at all.
    let schema_refusal = executor
        .execution_lifecycle()
        .db()
        .admit_undispatched_stage(
            execution_id,
            assignment_id,
            WORKFLOW_LEVEL_STAGE_NAME,
            WORKFLOW_LEVEL_STAGE_NAME,
        )
        .expect_err("the chain cannot hold a row under an execution it never admitted");
    assert!(
        schema_refusal
            .to_string()
            .contains("FOREIGN KEY constraint failed"),
        "{schema_refusal}"
    );

    assert!(
        executor
            .try_get_execution(&execution_id.to_string())
            .expect("an unadmitted identity is an ordinary absence")
            .is_none(),
        "refused evidence and cached names cannot introduce an admitted execution"
    );
    assert!(
        executor
            .try_list_executions()
            .unwrap()
            .iter()
            .all(|record| record.id != execution_id.to_string())
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn synthetic_workflow_level_failure_persistence_is_idempotent() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("ghost"));
    admit_workflow_level_failure_fixture(&executor, execution_id, &program);
    let dispatcher = executor.dispatcher_for_test();

    persist_workflow_level_failure_for_program(dispatcher, execution_id, &program, "first failure")
        .expect("first synthetic ledger write must succeed");
    persist_workflow_level_failure_for_program(dispatcher, execution_id, &program, "retry failure")
        .expect("retry synthetic ledger write must be idempotent");

    let dispatcher = executor.dispatcher_for_test();
    let assignments = dispatcher
        .execution_assignment_states(execution_id)
        .expect("the chain answers");
    let failures = assignments
        .iter()
        .filter(|state| state.stage_name.as_str() == WORKFLOW_LEVEL_STAGE_NAME)
        .collect::<Vec<_>>();
    assert_eq!(
        failures.len(),
        1,
        "duplicate workflow-level failure persistence must not create duplicate sentinel rows"
    );
    assert_eq!(
        failures[0].assignment_id,
        workflow_level_failure_assignment_id_for_test(execution_id, &program)
    );
    assert!(matches!(
        failures[0].status,
        kata_core::AssignmentStatus::Failed { .. }
    ));
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn synthetic_workflow_level_failure_persistence_repairs_pending_sentinel() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("ghost"));
    admit_workflow_level_failure_fixture(&executor, execution_id, &program);
    let assignment_id = workflow_level_failure_assignment_id_for_test(execution_id, &program);

    executor
        .dispatcher_for_test()
        .admit_undispatched_stage(
            execution_id,
            assignment_id,
            WORKFLOW_LEVEL_STAGE_NAME,
            WORKFLOW_LEVEL_STAGE_NAME,
        )
        .expect("seed crash-window pending sentinel");

    persist_workflow_level_failure_for_program(
        executor.dispatcher_for_test(),
        execution_id,
        &program,
        "repaired failure",
    )
    .expect("retry should repair pending synthetic sentinel");

    let dispatcher = executor.dispatcher_for_test();
    let assignments = dispatcher
        .execution_assignment_states(execution_id)
        .expect("the chain answers");
    assert_eq!(assignments.len(), 1);
    let failure = &assignments[0];
    assert_eq!(failure.assignment_id, assignment_id);
    assert_eq!(failure.stage_name.as_str(), WORKFLOW_LEVEL_STAGE_NAME);
    match &failure.status {
        kata_core::AssignmentStatus::Failed { reason, .. } => {
            assert!(reason.contains("repaired failure"), "{reason}");
        }
        other => panic!("pending sentinel should be repaired to Failed, got {other:?}"),
    }
    // The current admission committed before the crash; repair completes that
    // admitted sentinel without adopting a presentation-only row.
    catch_up_fixture_delivery(&executor);
    let chain_states = executor
        .execution_lifecycle()
        .db()
        .read_transitions_for_execution(execution_id, 1, 10_000)
        .expect("the authority chain reads")
        .frames
        .iter()
        .filter(|frame| {
            frame.scope == kata_core::operational::ChainScope::Stage
                && frame.kind.starts_with("undispatched_stage_")
        })
        .map(|frame| frame.resulting_state.clone())
        .collect::<Vec<_>>();
    assert!(
        chain_states == ["pending", "failed"],
        "the repair leaves the admission and its completed failure on the chain, got {chain_states:?}"
    );
    executor
        .execution_lifecycle()
        .mark_terminal(execution_id, ExecutionLifecycleState::Failed)
        .expect("latch the terminal Failed lifecycle production reaches");
    let rec = executor
        .get_execution(&execution_id.to_string())
        .expect("repaired synthetic failure should aggregate");
    assert_eq!(rec.status, ExecutionStatus::Failed);
    assert!(
        rec.error
            .as_deref()
            .is_some_and(|error| error.contains("repaired failure")),
        "repaired error should project through execution record: {:?}",
        rec.error
    );
}

/// THE `__workflow__` ROW REACHES THE AUTHORITY CHAIN.
///
/// The last raw ledger insert with no operational counterpart, measured at the
/// exact observation point a repointed reader consults. `apply_event` IGNORES this
/// row (it is reserved execution metadata), so the authority chain is the only
/// durable record of the workflow-level failure, and it must carry the
/// sentinel's whole ledger history.
///
/// Compared against the ledger read rather than a literal, so a chain that went
/// empty again fails here instead of agreeing with a hardcoded expectation, and
/// both lists are asserted non-empty first so two empty vectors cannot masquerade
/// as agreement.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_workflow_level_failure_row_reaches_the_authority_chain() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("ghost"));
    executor
        .execution_lifecycle()
        .put_current_program(execution_id, &program)
        .expect("admit the fixture execution into the nucleus");

    persist_workflow_level_failure_for_program(
        executor.dispatcher_for_test(),
        execution_id,
        &program,
        "sandbox rejected: no WorkspaceManager",
    )
    .expect("the workflow-level failure records");

    catch_up_fixture_delivery(&executor);
    // Read the delivery plane through the SSE relay a client is served by, until
    // it goes quiet.
    let mut relay = executor
        .dispatcher_for_test()
        .ledger()
        .subscribe_ledger_reliable(None);
    let mut ledger_states = Vec::new();
    while let Ok(Some((_, event))) =
        tokio::time::timeout(Duration::from_millis(500), relay.next()).await
    {
        if event.execution_id == execution_id {
            ledger_states.push(event.new_status.tag());
        }
    }
    assert_eq!(
        ledger_states,
        vec!["pending", "failed"],
        "POSITIVE CONTROL: the ledger plane recorded the sentinel's whole history"
    );

    let frames = executor
        .execution_lifecycle()
        .db()
        .read_transitions_for_execution(execution_id, 1, 10_000)
        .expect("the authority chain reads")
        .frames;
    let stage_frames = frames
        .iter()
        .filter(|frame| {
            frame.scope == kata_core::operational::ChainScope::Stage
                && frame.kind.starts_with("undispatched_stage_")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        stage_frames
            .iter()
            .map(|frame| frame.resulting_state.clone())
            .collect::<Vec<_>>(),
        ledger_states,
        "the chain must carry the sentinel's whole ledger history at STAGE scope"
    );
    // The sentinel is NOT an attempt, and claiming one would strand it: nothing
    // dispatches `__workflow__`, so no terminal writer could ever release it from
    // the bounded live registry.
    assert!(
        !frames
            .iter()
            .any(|frame| frame.scope == kata_core::operational::ChainScope::Attempt),
        "a workflow-level failure dispatches nothing, so it claims no attempt"
    );
    // The deciding reader keys on the ledger stage name, so it rides the frame.
    let terminal: serde_json::Value = serde_json::from_slice(
        &stage_frames
            .last()
            .expect("a terminal stage-scope frame")
            .payload_json,
    )
    .expect("a stage-scope frame carries a JSON payload");
    assert_eq!(
        terminal
            .get("stage_name")
            .and_then(serde_json::Value::as_str),
        Some(WORKFLOW_LEVEL_STAGE_NAME)
    );
    assert!(
        terminal
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reason| reason.contains("no WorkspaceManager")),
        "the operator-facing reason rides the frame, where the delivery mapping reads \
         it from: {terminal:?}"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn resume_repairs_pending_workflow_level_failure_for_running_lifecycle() {
    let ledger = InFlightLedger::in_memory();
    let program_store = ExecutionLifecycleFace::in_memory().expect("program store");
    let stack = boot_executor_with_custom_ledger(ledger, None, Some(program_store));
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("ghost"));
    executor.insert_execution_program_for_test(execution_id, program.clone());
    let assignment_id = workflow_level_failure_assignment_id_for_test(execution_id, &program);
    executor
        .dispatcher_for_test()
        .admit_undispatched_stage(
            execution_id,
            assignment_id,
            WORKFLOW_LEVEL_STAGE_NAME,
            WORKFLOW_LEVEL_STAGE_NAME,
        )
        .expect("seed interrupted pending sentinel");

    let resumed = executor.resume_in_flight_runs().unwrap();
    assert_eq!(
        resumed,
        vec![execution_id],
        "the durable Running lifecycle remains authoritative even when its only ledger row is a synthetic failure sentinel"
    );
    let dispatcher = executor.dispatcher_for_test();
    let assignments = dispatcher
        .execution_assignment_states(execution_id)
        .expect("the chain answers");
    let repaired = assignments
        .iter()
        .find(|state| state.assignment_id == assignment_id)
        .expect("repaired synthetic failure sentinel");
    assert_eq!(repaired.assignment_id, assignment_id);
    assert!(matches!(
        repaired.status,
        kata_core::AssignmentStatus::Failed { .. }
    ));
    let rec = wait_terminal(&executor, &execution_id.to_string()).await;
    assert_eq!(rec.status, ExecutionStatus::Failed);
    assert_eq!(
        executor
            .execution_lifecycle()
            .lifecycle(execution_id)
            .expect("read recovered lifecycle")
            .expect("recovered lifecycle exists")
            .state,
        kata_workflow::execution_program_store::ExecutionLifecycleState::Failed,
        "a repaired durable workflow-level failure must terminalize Failed"
    );
    assert!(
        dispatcher
            .execution_assignment_states(execution_id)
            .expect("the chain answers")
            .iter()
            .all(|state| state.stage_name.as_str() == WORKFLOW_LEVEL_STAGE_NAME),
        "recovery must not execute any real checked stage after finding a durable workflow-level failure sentinel"
    );
    assert!(
        rec.error.as_deref().is_some_and(|error| {
            error.contains("main restart repaired incomplete workflow-level failure sentinel")
        }),
        "repaired sentinel error should project: {:?}",
        rec.error
    );
}

/// End-to-end: `WorkflowExecutor::submit_execution_program` with a stage the
/// capsule route cannot lower (an unbound `AgentSelector::Any` — no adapter label
/// exists to bind on an `oci` node) must persist a synthetic
/// workflow-level Failed assignment so `get_execution` reports
/// `status=failed`. Operator-facing regression test for the durable
/// workflow-level failure.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn submit_errors_before_dispatch_persists_failure_into_ledger() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);

    // Build a one-stage workflow whose stage's agent selector is `Any` —
    // the check admits it (the compiled contract is binding-agnostic), and
    // capsule LOWERING refuses it at dispatch, before any worker is picked.
    let mut def = tiny_definition("unbound-selector");
    let stage_id = StageId(SmolStr::new("only"));
    let stage = def.stages.get_mut(&stage_id).unwrap();
    stage.agent = AgentSelector::Any;

    let id = executor
        .submit_execution_program(compile_definition(def))
        .expect("submit must succeed — the failure is runtime, not validation");

    // Generous on purpose, on the shared ≥30 s poll contract
    // (`common::wait_terminal`): pre-dispatch failures land fast on a quiet host,
    // but the FULL-sync terminal commit stalls under load; no latency is tested.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let rec = loop {
        if let Some(rec) = executor.get_execution(&id)
            && matches!(rec.status, ExecutionStatus::Failed)
        {
            break rec;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "execution did not reach Failed within 30s — synthetic \
             workflow-level failure may not be wired"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    assert_eq!(rec.workflow_name, "unbound-selector");
    let err = rec.error.expect("failed record must carry an error");
    assert!(
        err.contains("agent_selector_unbound") || err.contains("AgentSelectorUnbound"),
        "error must surface the capsule lowering refusal, got: {err}"
    );
    assert!(rec.outputs.is_none());
    assert!(rec.finished_at_ms.is_some());

    // Explicit ledger inspection: the synthetic failure remains an assignment
    // because it drives lifecycle status, while execution-program identity and
    // checked dispatch guard evidence live in the typed metadata plane.
    let execution_id = Ulid::from_string(&id).unwrap();
    let dispatcher = executor.dispatcher_for_test();
    let assignments = dispatcher
        .execution_assignment_states(execution_id)
        .expect("the chain answers");
    assert_eq!(
        assignments.len(),
        1,
        "only the workflow failure should be an assignment, got {assignments:?}"
    );
    let workflow_failure = assignments
        .iter()
        .find(|assignment| assignment.stage_name.as_str() == WORKFLOW_LEVEL_STAGE_NAME)
        .expect("workflow-level failure assignment must be present");
    assert_eq!(
        workflow_failure.stage_name.as_str(),
        WORKFLOW_LEVEL_STAGE_NAME,
        "synthetic assignment must use the sentinel stage name"
    );
    assert!(matches!(
        &workflow_failure.status,
        kata_core::AssignmentStatus::Failed { .. }
    ));
    let evidence_rows = executor
        .dispatcher_for_test()
        .ledger()
        .execution_evidence_records(execution_id);
    assert_eq!(
        evidence_rows.len(),
        2,
        "execution evidence rows should include identity and checked dispatch guard evidence"
    );
    let evidence = evidence_rows
        .iter()
        .map(|record| &record.evidence)
        .find(|evidence| evidence.execution_program.is_some())
        .expect("execution-program identity evidence must be present");
    let _execution_program = evidence
        .execution_program
        .as_ref()
        .expect("execution-program identity evidence must be present");
    assert_eq!(
        workflow_failure.stage_name.as_str(),
        WORKFLOW_LEVEL_STAGE_NAME,
        "workflow-level failure row must be marked as non-worker synthetic metadata"
    );
}

/// `list_executions` must surface the failed record after the
/// synthetic workflow-level assignment lands. Without ledger
/// persistence, `GET /executions` would have hidden
/// these runs entirely once the process-local registry was gone.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn list_executions_includes_synthetic_workflow_level_failures() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    let program = compile_definition(tiny_definition("ghost"));
    admit_workflow_level_failure_fixture(&executor, execution_id, &program);
    persist_workflow_level_failure_for_program(
        executor.dispatcher_for_test(),
        execution_id,
        &program,
        "boom",
    )
    .expect("synthetic ledger write must succeed");
    executor
        .execution_lifecycle()
        .mark_terminal(execution_id, ExecutionLifecycleState::Failed)
        .expect("latch the terminal Failed lifecycle production reaches");

    let list = executor.list_executions();
    let found = list
        .iter()
        .find(|r| r.id == execution_id.to_string())
        .expect("list_executions must surface synthetic workflow-level failures");
    assert_eq!(found.status, ExecutionStatus::Failed);
    assert_eq!(found.workflow_name, "ghost");
    let err = found.error.as_deref().expect("error must be present");
    assert!(
        err.contains("boom") && err.contains(WORKFLOW_LEVEL_STAGE_NAME),
        "list entry must surface the synthetic failure, got: {err}"
    );
    let assignment = executor
        .dispatcher_for_test()
        .execution_assignment_states(execution_id)
        .expect("the chain answers")
        .into_iter()
        .find(|assignment| assignment.stage_name.as_str() == WORKFLOW_LEVEL_STAGE_NAME)
        .expect("workflow-level failure assignment must be present");
    assert_eq!(assignment.stage_name.as_str(), WORKFLOW_LEVEL_STAGE_NAME);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn parked_candidate_evidence_is_durable_ledger_state() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    executor
        .execution_lifecycle()
        .admit_current_execution(
            execution_id,
            &compile_definition(tiny_definition("parked-run")),
            &kata_workflow::execution_program_store::ExecutionInvocation::workflow(Vec::new()),
        )
        .unwrap();
    let candidate = kata_effects_contract::ParkedWorkspace {
        ref_name: "parked/manual-review".to_string(),
        commit_sha: "abc123".to_string(),
        identity: Some(workspace_identity(
            execution_id,
            "jj",
            Some("exec-test"),
            Some("abc123"),
            Some("main"),
            Some("base123"),
            Some("parked/manual-review"),
            Some("abc123"),
        )),
    };

    persist_parked_candidate_evidence(
        executor.dispatcher_for_test().ledger(),
        execution_id,
        &candidate,
        true,
    )
    .expect("synthetic evidence write must succeed");

    let rec = executor
        .get_execution(&execution_id.to_string())
        .expect("record must exist once evidence is in the ledger");
    assert_eq!(rec.workflow_name, "parked-run");
    assert_eq!(
        rec.status,
        ExecutionStatus::Pending,
        "metadata-only evidence must not complete the execution lifecycle"
    );
    assert!(
        rec.outputs.is_none(),
        "evidence-only rows are not stage outputs"
    );
    assert!(rec.evidence.auto_parked);
    let parked = rec
        .evidence
        .parked_candidate
        .expect("parked candidate evidence must be available on the record");
    assert_eq!(parked.parked_ref, candidate.ref_name);
    assert_eq!(parked.commit_sha, candidate.commit_sha);
    let identity = parked
        .identity
        .as_ref()
        .expect("parked candidate identity must be durable evidence");
    assert_eq!(identity.backend, "jj");
    assert_eq!(identity.execution_id, execution_id.to_string());
    assert_eq!(identity.target_ref.as_deref(), Some("parked/manual-review"));
    assert_eq!(identity.target_commit_sha.as_deref(), Some("abc123"));

    let assignments = executor
        .dispatcher_for_test()
        .execution_assignment_states(execution_id)
        .expect("the chain answers");
    assert!(
        assignments.is_empty(),
        "typed evidence must not create synthetic assignment rows"
    );
    let evidence_rows = executor
        .dispatcher_for_test()
        .ledger()
        .execution_evidence_records(execution_id);
    assert_eq!(evidence_rows.len(), 1);
    assert!(evidence_rows[0].evidence.auto_parked);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn missing_auto_parked_candidate_evidence_backfills_from_visible_ref() {
    let (_tmp, backend) = jj_fixture();
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let store = Arc::new(FailingUnclaimedEvidenceStore::new(false));
    let ledger = store.open_ledger();
    let executor = build_executor_with_workspace_provider_and_ledger(Arc::clone(&provider), ledger);
    let execution_id = Ulid::new();
    seed_checked_previous_execution_for_test(&executor, execution_id, "auto-park-recovery");
    let key = ExecutionWorkspaceKey::execution(execution_id);
    let worktree = kata_vcs::test_support::create_trunk_workspace(&*provider, &key)
        .expect("create execution workspace")
        .path;
    std::fs::write(worktree.join("candidate.txt"), "candidate\n").expect("write candidate");

    let attempt_id =
        seed_dispatched_capsule_attempt_on_authority(&executor, execution_id, "validate")
            .expect("seed the attempt");
    executor
        .dispatcher_for_test()
        .mark_failed_and_fold_attempt(attempt_id, "validation failed")
        .expect("fail seeded execution");
    executor
        .execution_lifecycle()
        .mark_terminal(execution_id, ExecutionLifecycleState::Failed)
        .expect("terminalize historical failed execution fixture");

    let parked = provider
        .park_workspace(&key, None)
        .expect("park failed candidate");
    assert_eq!(parked.ref_name, format!("parked/{execution_id}"));
    assert!(!parked.commit_sha.is_empty());
    assert!(
        !worktree.exists(),
        "parking should remove the execution workspace"
    );
    store.set_fail_parked_candidate_evidence(true);
    let parked_workspace = kata_effects_contract::ParkedWorkspace {
        ref_name: parked.ref_name.clone(),
        commit_sha: parked.commit_sha.clone(),
        identity: None,
    };
    persist_parked_candidate_evidence(
        executor.dispatcher_for_test().ledger(),
        execution_id,
        &parked_workspace,
        true,
    )
    .expect_err("injected parked evidence failure should leave only the VCS ref");

    let before_recovery_rows = executor
        .dispatcher_for_test()
        .ledger()
        .execution_evidence_records(execution_id);
    assert!(
        before_recovery_rows
            .iter()
            .all(|row| row.evidence.parked_candidate.is_none()),
        "the ledger must not already contain parked-candidate evidence"
    );

    let recovered_while_store_failing = executor
        .get_execution(&execution_id.to_string())
        .expect("execution record should surface visible parked ref");
    assert_eq!(
        recovered_while_store_failing.status,
        ExecutionStatus::Failed
    );
    assert!(recovered_while_store_failing.evidence.auto_parked);
    let recovered_candidate = recovered_while_store_failing
        .evidence
        .parked_candidate
        .expect("auto-park evidence should be visible from VCS even before durable backfill");
    assert_eq!(recovered_candidate.parked_ref, parked.ref_name);
    assert_eq!(recovered_candidate.commit_sha, parked.commit_sha);
    let still_missing_rows = executor
        .dispatcher_for_test()
        .ledger()
        .execution_evidence_records(execution_id);
    assert!(
        still_missing_rows
            .iter()
            .all(|row| row.evidence.parked_candidate.is_none()),
        "failed backfill must not create partial parked-candidate evidence"
    );
    let snapshot = executor
        .execution_workspace_snapshot(execution_id)
        .expect("workspace snapshot should surface visible parked ref");
    assert!(snapshot.parking.parked);
    assert!(snapshot.parking.auto_parked);
    let snapshot_candidate = snapshot
        .parking
        .candidate
        .expect("workspace snapshot should include recovered parked candidate");
    assert_eq!(snapshot_candidate.parked_ref, parked.ref_name);
    assert_eq!(snapshot_candidate.commit_sha, parked.commit_sha);

    store.set_fail_parked_candidate_evidence(false);
    let recovered_after_store_heals = executor
        .get_execution(&execution_id.to_string())
        .expect("execution record should backfill after store recovers");
    assert!(recovered_after_store_heals.evidence.auto_parked);
    assert_eq!(
        recovered_after_store_heals
            .evidence
            .parked_candidate
            .as_ref()
            .expect("backfilled parked candidate")
            .parked_ref,
        parked.ref_name
    );

    let after_recovery_rows = executor
        .dispatcher_for_test()
        .ledger()
        .execution_evidence_records(execution_id);
    assert!(
        after_recovery_rows
            .iter()
            .any(|row| row.evidence.parked_candidate.is_some()),
        "backfill should persist parked-candidate evidence into the ledger"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn controller_application_evidence_is_durable_ledger_state() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();
    seed_checked_previous_execution_for_test(&executor, execution_id, "factory-application");
    let application = controller_application(
        "advance:decision-wave-1",
        "decision-wave-1",
        "repair",
        "advance",
        true,
    );

    persist_controller_application_evidence(
        executor.dispatcher_for_test().ledger(),
        execution_id,
        application.clone(),
    )
    .expect("synthetic controller application evidence write must succeed");

    let rec = executor
        .get_execution(&execution_id.to_string())
        .expect("record must exist once evidence is in the ledger");
    assert_eq!(rec.workflow_name, "factory-application");
    assert_eq!(
        rec.status,
        ExecutionStatus::Running,
        "metadata-only evidence must not override the durable Running lifecycle"
    );
    assert!(rec.outputs.is_none());
    assert_eq!(rec.evidence.controller_applications, vec![application]);
    // DELIBERATELY on the ledger projection. The subject writer is
    // `persist_controller_application_evidence`, so an evidence writer that began
    // creating assignment rows would trip this — unlike the dispatch-refusal
    // assertions, which read the authority chain.
    assert!(
        executor
            .dispatcher_for_test()
            .execution_assignment_states(execution_id)
            .expect("the chain answers")
            .is_empty(),
        "typed evidence must not create synthetic assignment rows"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn direct_custom_park_ref_refuses_foreign_execution_binding() {
    let (_tmp, backend) = jj_fixture();
    let provider: Arc<dyn ExecutionWorkspaceProvider> = backend.clone();
    let source_execution = Ulid::new();
    let source_key = ExecutionWorkspaceKey::execution(source_execution);
    let source_worktree = kata_vcs::test_support::create_trunk_workspace(&*provider, &source_key)
        .expect("create source execution workspace")
        .path;
    std::fs::write(source_worktree.join("source.txt"), "source\n").expect("write source candidate");
    let source_parked = provider
        .park_workspace(&source_key, Some("shared-review"))
        .expect("park source candidate under custom ref");

    let executor = build_executor_with_workspace_provider(Arc::clone(&provider));
    let target_execution = Ulid::new();
    let target_worktree = kata_vcs::test_support::create_trunk_workspace(
        &*provider,
        &ExecutionWorkspaceKey::execution(target_execution),
    )
    .expect("create target execution workspace")
    .path;
    std::fs::write(target_worktree.join("target.txt"), "target\n").expect("write target candidate");
    seed_checked_previous_execution_for_test(
        &executor,
        target_execution,
        "foreign-custom-park-ref",
    );
    terminalize_completed_fixture(&executor, target_execution);

    let error = executor
        .park_candidate(target_execution, Some("shared-review"))
        .expect_err("foreign custom ref must not be adopted or replaced");
    assert!(
        matches!(&error, ExecutorError::PolicyDenied(message)
            if message.contains("already exists without durable evidence")
                && message.contains(&target_execution.to_string())),
        "{error:?}"
    );
    assert!(
        target_worktree.exists(),
        "refused custom park removed target execution workspace"
    );
    let record = executor
        .get_execution(&target_execution.to_string())
        .expect("target execution remains visible");
    assert!(
        record.evidence.parked_candidate.is_none(),
        "foreign custom ref was persisted as target evidence"
    );
    let after = provider
        .lookup_parked_workspace(&source_key, &source_parked.ref_name)
        .expect("lookup source parked ref")
        .expect("source parked ref remains");
    assert_eq!(after.commit_sha, source_parked.commit_sha);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn finalize_controller_application_claim_requires_confirmation_reason_and_evidence() {
    let stack = boot_executor();
    let executor = Arc::clone(&stack.executor);
    let execution_id = Ulid::new();

    let err = executor
        .finalize_controller_application_claim(
            execution_id,
            ExecutionControllerApplyFinalizeRequest {
                decision_id: "decision-park".to_string(),
                reason: Some("operator verified side effect".to_string()),
                evidence: vec!["proof".to_string()],
                confirm_side_effect: false,
                ..ExecutionControllerApplyFinalizeRequest::default()
            },
        )
        .expect_err("confirmation is required");
    assert!(
        matches!(err, ExecutorError::InvalidDefinition(message) if message.contains("confirm_side_effect"))
    );

    let err = executor
        .finalize_controller_application_claim(
            execution_id,
            ExecutionControllerApplyFinalizeRequest {
                decision_id: "decision-park".to_string(),
                confirm_side_effect: true,
                evidence: vec!["proof".to_string()],
                ..ExecutionControllerApplyFinalizeRequest::default()
            },
        )
        .expect_err("reason is required");
    assert!(matches!(err, ExecutorError::InvalidDefinition(message) if message.contains("reason")));

    let err = executor
        .finalize_controller_application_claim(
            execution_id,
            ExecutionControllerApplyFinalizeRequest {
                decision_id: "decision-park".to_string(),
                reason: Some("operator verified side effect".to_string()),
                confirm_side_effect: true,
                ..ExecutionControllerApplyFinalizeRequest::default()
            },
        )
        .expect_err("evidence is required");
    assert!(
        matches!(err, ExecutorError::InvalidDefinition(message) if message.contains("evidence"))
    );
}
