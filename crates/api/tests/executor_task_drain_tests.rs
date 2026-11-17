//! Regression for the completed-run teardown-vs-shutdown race.
//!
//! A submitted workflow runs to its terminal on a detached `tokio::spawn`
//! (`WorkflowExecutor::run_submitted_workflow_task`); the run's terminal
//! handling — including its execution-workspace park/teardown — executes INSIDE
//! that task. If nothing awaited those tasks at shutdown, dropping the tokio
//! runtime would abort the in-flight task mid-teardown and the completed run
//! would leak its workspace.
//!
//! `WorkflowExecutor::drain_in_flight_workflow_tasks` closes the race by
//! awaiting the tracked task handles before the runtime tears down. This test
//! models the exact race with a task whose "teardown" removes a sentinel dir:
//! dropping the runtime WITHOUT draining aborts it (sentinel survives — the
//! leak); draining first lets it finish (sentinel removed).

mod common;

use std::sync::Arc;
use std::time::Duration;

use kata_api::executor::WorkflowExecutor;
use kata_program::library::WorkflowLibrary;
use kata_transport::transport::WorkerTransport;
use kata_transport::{InProcessTransport, WorkerPoolSupervisor};
use smol_str::SmolStr;

fn executor() -> Arc<WorkflowExecutor> {
    common::build_executor(
        Arc::new(WorkerPoolSupervisor::new()),
        Arc::new(WorkflowLibrary::new(vec![])),
    )
}

/// RED (counterfactual: no `drain_in_flight_workflow_tasks` call) — a tracked
/// in-flight teardown task is aborted when the runtime is dropped, leaking the
/// workspace. GREEN — draining before the runtime drops lets the teardown
/// complete. Both halves run the SAME registration path production uses
/// (`track_workflow_task`, called directly — it is the public method `boot` uses).
#[test]
fn drain_awaits_in_flight_teardown_across_runtime_shutdown() {
    let tmp = tempfile::tempdir().unwrap();

    // ── RED: shutdown WITHOUT draining aborts teardown ──
    let leaked = tmp.path().join("workspace-leaked");
    std::fs::create_dir(&leaked).unwrap();
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let sentinel = leaked.clone();
        rt.block_on(async {
            // The shared rig spawns its bookkeeper/delivery tasks — build it
            // inside the runtime.
            let exec = executor();
            let handle = tokio::spawn(async move {
                // A teardown that has not finished by the time shutdown fires.
                tokio::time::sleep(Duration::from_secs(30)).await;
                let _ = std::fs::remove_dir_all(&sentinel);
            });
            exec.track_workflow_task(handle);
            // Simulate a shutdown that returns without awaiting the task.
        });
        drop(rt); // aborts the in-flight teardown
    }
    assert!(
        leaked.exists(),
        "RED: teardown aborted by runtime shutdown, workspace leaked"
    );

    // ── GREEN: draining before shutdown completes teardown ──
    let torn_down = tmp.path().join("workspace-reclaimed");
    std::fs::create_dir(&torn_down).unwrap();
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let sentinel = torn_down.clone();
        rt.block_on(async {
            let exec = executor();
            let handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = std::fs::remove_dir_all(&sentinel);
            });
            exec.track_workflow_task(handle);
            // The fix: await in-flight teardown before returning from the block.
            let (drained, completed) = exec
                .drain_in_flight_workflow_tasks(Duration::from_secs(10))
                .await;
            assert_eq!(drained, 1, "the one in-flight teardown task was drained");
            assert!(
                completed,
                "the tracked teardown completed inside its budget"
            );
        });
        drop(rt);
    }
    assert!(
        !torn_down.exists(),
        "GREEN: drain awaited teardown, workspace reclaimed before shutdown"
    );
}

/// The PRODUCTION `submit() -> track_workflow_task` wiring is
/// covered, not only a direct `track_workflow_task` call. A real
/// `submit_execution_program` spawns its detached run task through
/// `track_workflow_task`, so `drain_in_flight_workflow_tasks` observes and would
/// await it at shutdown.
///
/// The run is pinned in-flight by a black-hole worker that accepts the
/// dispatched assignment and never replies, so the drain deterministically finds
/// exactly the one tracked, still-running task the real submit path registered
/// (a fast worker would let the run finish and hide the wiring). RED
/// counterfactual: had `submit` not called `track_workflow_task`, the drain
/// would report 0 despite a live in-flight run.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn drain_reports_task_registered_by_real_submit() {
    use common::{compile_definition, tiny_definition};

    // Black-hole worker: receives the dispatched assignment but never sends a
    // result, so the submitted run stays Running (its detached task alive).
    let (home, worker) = InProcessTransport::pair(64);
    let home = Arc::new(home);
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let fixture_lifecycle =
        kata_workflow::execution_lifecycle::ExecutionLifecycleFace::in_memory().unwrap();
    supervisor.register_worker_with_effect_domain(
        SmolStr::new("black-hole"),
        Arc::clone(&home) as Arc<dyn WorkerTransport>,
        // The capsule frame must actually deliver — a capless worker would
        // never be offered the stage, hiding the wiring under "no dispatch".
        // `tiny_definition`'s stage binds `agent = "default"` → `agent:default`.
        vec!["agent:default".to_string()],
        kata_workflow::test_harness::rig_worker_containment(),
        *kata_workflow::test_harness::oci_rig_executor_term().digest(),
        common::fake_worker_domain(&fixture_lifecycle),
    );
    tokio::spawn(async move {
        // Drain capsule frames off the wire but never reply — keep the run
        // in-flight.
        while worker.recv_frame().await.is_ok() {}
    });

    let library = Arc::new(WorkflowLibrary::new(vec![]));
    let executor = common::build_executor_with_execution_lifecycle(
        Arc::clone(&supervisor),
        library,
        Some(fixture_lifecycle),
    );

    // Real production path: submit -> track_workflow_task (executor/mod.rs).
    executor
        .submit_execution_program(compile_definition(tiny_definition("drain-real-submit")))
        .expect("submit should succeed with a live worker");

    // Short budget: the black-hole run cannot finish, so the drain reports the
    // one still-in-flight task the REAL submit path registered.
    let (drained, completed) = executor
        .drain_in_flight_workflow_tasks(Duration::from_millis(250))
        .await;
    assert_eq!(
        drained, 1,
        "real submit() must register its run task on the drainable set"
    );
    assert!(
        !completed,
        "the black-hole task must exceed the short drain budget"
    );
}
