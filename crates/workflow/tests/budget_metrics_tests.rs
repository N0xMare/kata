//! `kata_workflow_budget_micro_usd` gauge emission tests.
//!
//! Verifies that `BudgetTracker::record_completion` emits the gauge on
//! every call, produces separate time-series per scope, and tracks a
//! monotonically-increasing running total. Uses
//! `metrics_util::debugging::DebuggingRecorder` so no Prometheus
//! exporter is needed. The recorder stores the **current** value per
//! composite key (metric name + label set); tests take two snapshots
//! to compare before/after states.

use kata_types::BudgetPolicy;
use kata_types::workflow::StageId;
use kata_workflow::runner::testing::BudgetTracker;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
use smol_str::SmolStr;
use ulid::Ulid;

const GAUGE: &str = "kata_workflow_budget_micro_usd";

fn stage(id: &str) -> StageId {
    StageId(SmolStr::new(id))
}

/// Read the current gauge value for the given `execution_id` + `scope`
/// label pair. Returns `None` if no entry exists yet. Filters by label
/// rather than position because snapshot ordering across distinct keys
/// is non-deterministic.
fn gauge_value(snapshotter: &Snapshotter, execution_id: &str, scope: &str) -> Option<f64> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .find(|(key, _, _, _)| {
            key.key().name() == GAUGE
                && key
                    .key()
                    .labels()
                    .any(|l| l.key() == "execution_id" && l.value() == execution_id)
                && key
                    .key()
                    .labels()
                    .any(|l| l.key() == "scope" && l.value() == scope)
        })
        .and_then(|(_, _, _, value)| match value {
            DebugValue::Gauge(g) => Some(g.into_inner()),
            _ => None,
        })
}

/// `kata_workflow_budget_micro_usd` must update on **every** call to
/// `record_completion`. After the first call the gauge is present;
/// after the second call its value is strictly larger (the running
/// total increased).
#[test]
fn gauge_fires_on_every_record_completion() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let execution_id = Ulid::new();
    let eid = execution_id.to_string();
    let tracker = BudgetTracker::new(execution_id);
    let s1 = stage("s1");

    metrics::with_local_recorder(&recorder, || {
        let _ = tracker.record_completion(
            &s1,
            1_000_000,
            BudgetPolicy::Unlimited,
            BudgetPolicy::Unlimited,
            |_, _, _| {},
        );
    });
    let first = gauge_value(&snapshotter, &eid, "workflow")
        .expect("workflow gauge must be present after first completion");

    metrics::with_local_recorder(&recorder, || {
        let _ = tracker.record_completion(
            &s1,
            500_000,
            BudgetPolicy::Unlimited,
            BudgetPolicy::Unlimited,
            |_, _, _| {},
        );
    });
    let second = gauge_value(&snapshotter, &eid, "workflow")
        .expect("workflow gauge must be present after second completion");

    assert!(
        second > first,
        "gauge must update on every record_completion; after-first={first}, after-second={second}",
    );
}

/// A single `record_completion` must emit **two distinct time-series**:
/// one for `scope=workflow` and one for `scope=stage:<name>`. The two
/// series must be independently selectable by their `scope` label.
#[test]
fn separate_series_per_scope() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let execution_id = Ulid::new();
    let eid = execution_id.to_string();
    let tracker = BudgetTracker::new(execution_id);

    metrics::with_local_recorder(&recorder, || {
        let _ = tracker.record_completion(
            &stage("draft"),
            2_000_000,
            BudgetPolicy::Unlimited,
            BudgetPolicy::Unlimited,
            |_, _, _| {},
        );
    });

    let workflow_val = gauge_value(&snapshotter, &eid, "workflow")
        .expect("scope=workflow time-series must be present");
    let stage_val = gauge_value(&snapshotter, &eid, "stage:draft")
        .expect("scope=stage:draft time-series must be present");

    assert!(
        (workflow_val - 2_000_000.0).abs() < 1.0,
        "workflow gauge must equal cumulative cost 2M; got {workflow_val}",
    );
    assert!(
        (stage_val - 2_000_000.0).abs() < 1.0,
        "stage:draft gauge must equal cumulative cost 2M; got {stage_val}",
    );
}

/// The workflow-scope gauge value must increase monotonically: the
/// value after the second completion must equal the cumulative running
/// total (first + second), not just the second stage's cost.
#[test]
fn gauge_is_monotonic_across_two_completions() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let execution_id = Ulid::new();
    let eid = execution_id.to_string();
    let tracker = BudgetTracker::new(execution_id);
    let s1 = stage("s1");

    metrics::with_local_recorder(&recorder, || {
        let _ = tracker.record_completion(
            &s1,
            1_000_000,
            BudgetPolicy::Unlimited,
            BudgetPolicy::Unlimited,
            |_, _, _| {},
        );
    });
    let after_first = gauge_value(&snapshotter, &eid, "workflow")
        .expect("gauge must be present after first completion");

    metrics::with_local_recorder(&recorder, || {
        let _ = tracker.record_completion(
            &s1,
            500_000,
            BudgetPolicy::Unlimited,
            BudgetPolicy::Unlimited,
            |_, _, _| {},
        );
    });
    let after_second = gauge_value(&snapshotter, &eid, "workflow")
        .expect("gauge must be present after second completion");

    assert!(
        (after_first - 1_000_000.0).abs() < 1.0,
        "after first completion gauge must be 1M; got {after_first}",
    );
    assert!(
        (after_second - 1_500_000.0).abs() < 1.0,
        "after second completion gauge must be cumulative 1.5M; got {after_second}",
    );
    assert!(
        after_second > after_first,
        "running cost must be monotonically increasing; first={after_first}, second={after_second}",
    );
}

// Small suites folded into this binary so each costs no link of its own. Each
// keeps its module, so its tests are named `<module>::<test>` here.
#[path = "budget_metrics_tests/active_workflow_metrics_tests.rs"]
mod active_workflow_metrics_tests;
