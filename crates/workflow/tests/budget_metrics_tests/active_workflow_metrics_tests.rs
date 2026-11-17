//! End-to-end wiring proof for the `kata_workflow_active_count`
//! gauge.
//!
//! A real `WorkflowRunner::run()` that fails (no workers registered)
//! must leave the gauge balanced at 0 — proving the `ActiveWorkflowGuard`
//! is actually held inside `run()` and decrements on the error path, not
//! only on the happy path. The guard's pure balance contract (drop on
//! panic / error / completion) is unit-tested in
//! `src/runner/mod.rs::active_workflow_gauge_tests`.

use std::sync::Arc;
use std::time::Duration;

use kata_core::InFlightLedger;
use kata_program::preflight::build_starlark_workflow_compiled_artifact;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_transport::supervisor::WorkerPoolSupervisor;
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::runner::WorkflowRunner;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use ulid::Ulid;

const GAUGE: &str = "kata_workflow_active_count";

fn gauge_value(snapshotter: &Snapshotter) -> Option<f64> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .find(|(key, _, _, _)| key.key().name() == GAUGE)
        .and_then(|(_, _, _, value)| match value {
            DebugValue::Gauge(g) => Some(g.into_inner()),
            _ => None,
        })
}

#[test]
fn active_count_balances_to_zero_after_failed_run() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime builds");

    let artifact = build_starlark_workflow_compiled_artifact(
        r#"
only = stage(id = "only", agent = "default", prompt = "do it")
workflow("active-count", root = [only])
"#,
        "active-count.star",
        &[],
    )
    .expect("compiled artifact builds");

    // No workers registered → the run fails fast instead of hanging.
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(50),
        Duration::from_millis(50),
    ));
    let ledger = InFlightLedger::in_memory();
    let dispatcher = Arc::new(Dispatcher::new(
        Arc::clone(&supervisor),
        heartbeat,
        Arc::clone(&ledger),
    ));
    let runner = WorkflowRunner::new_from_program(
        artifact.execution_program,
        Arc::clone(&dispatcher),
        Ulid::new(),
    )
    .expect("runner builds");

    // `with_local_recorder` installs the recorder for the calling thread;
    // the current-thread runtime drives `run()` on that same thread, so the
    // gauge emits land in `recorder`.
    let timed = metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            Box::pin(tokio::time::timeout(Duration::from_secs(30), runner.run())).await
        })
    });

    let result = timed.expect("run must finish within the 30s bound");
    assert!(
        result.is_err(),
        "a run with no registered workers must fail, got {result:?}"
    );
    assert_eq!(
        gauge_value(&snapshotter),
        Some(0.0),
        "kata_workflow_active_count must balance to 0 after a failed run \
         (an increment-only leak would leave it at 1.0)"
    );
}
