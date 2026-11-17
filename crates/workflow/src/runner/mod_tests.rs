//! Tests for runner/mod.rs. Extracted from the inline #[cfg(test)] module.

//! `kata_workflow_active_count` leak-freedom. These tests pin the
//! RAII balance contract of [`ActiveWorkflowGuard`] directly — the
//! mechanism `WorkflowRunner::run` relies on — so the gauge cannot
//! drift even when a run errors, panics, or is cancelled. The
//! end-to-end wiring (guard actually held inside `run()`) is exercised
//! in `tests/budget_metrics_tests/active_workflow_metrics_tests.rs`.

use super::ActiveWorkflowGuard;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

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
fn guard_increments_on_new_and_decrements_on_drop() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    metrics::with_local_recorder(&recorder, || {
        let guard = ActiveWorkflowGuard::new();
        assert_eq!(
            gauge_value(&snapshotter),
            Some(1.0),
            "gauge must read 1 while a run is active"
        );
        drop(guard);
        assert_eq!(
            gauge_value(&snapshotter),
            Some(0.0),
            "gauge must return to 0 once the guard drops"
        );
    });
}

#[test]
fn gauge_balances_to_zero_across_two_completed_runs() {
    // A leak (increment-only) would leave the gauge at 2.0 after two
    // runs; a balanced guard returns it to 0.0 every time.
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    metrics::with_local_recorder(&recorder, || {
        for _ in 0..2 {
            let _g = ActiveWorkflowGuard::new();
        }
    });

    assert_eq!(
        gauge_value(&snapshotter),
        Some(0.0),
        "two balanced runs must leave active_count at 0, not 2"
    );
}

#[test]
fn gauge_balances_when_a_run_fails() {
    // Model the runner's `?`-error path: the guard is held by a body
    // that returns Err. Drop still fires, so the gauge balances.
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let outcome: Result<(), &str> = metrics::with_local_recorder(&recorder, || {
        let _g = ActiveWorkflowGuard::new();
        Err("stage failed")
    });

    assert!(outcome.is_err());
    assert_eq!(
        gauge_value(&snapshotter),
        Some(0.0),
        "active_count must return to 0 after a failed run"
    );
}

#[test]
fn gauge_balances_on_panic_unwind() {
    // The strongest leak test: even when the run future panics, the
    // guard's Drop runs during unwind and the gauge balances.
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    metrics::with_local_recorder(&recorder, || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = ActiveWorkflowGuard::new();
            panic!("simulated run panic");
        }));
        assert!(result.is_err(), "the inner closure must have panicked");
    });

    assert_eq!(
        gauge_value(&snapshotter),
        Some(0.0),
        "active_count must return to 0 even when a run panics"
    );
}
