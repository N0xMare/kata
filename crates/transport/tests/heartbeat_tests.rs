//! Tests for `HeartbeatMonitor` (`crates/transport/src/heartbeat.rs`).

use std::time::Duration;

use kata_transport::HeartbeatMonitor;
use kata_transport::heartbeat::LivenessState;

/// Advance paused time by `span` one sweep per `step` (the interval), as a main
/// sweeps, and return the ids every sweep marked dead.
async fn sweep_through(
    monitor: &HeartbeatMonitor,
    span: Duration,
    step: Duration,
) -> Vec<smol_str::SmolStr> {
    let mut dead = Vec::new();
    let mut elapsed = Duration::ZERO;
    while elapsed < span {
        let next = step.min(span.saturating_sub(elapsed));
        tokio::time::advance(next).await;
        elapsed += next;
        dead.extend(
            monitor
                .sweep()
                .dead
                .into_iter()
                .map(|silent| silent.worker_id),
        );
    }
    dead
}

#[test]
fn record_and_check_alive() {
    kata_test_seeded::run_seeded("record_and_check_alive", |_ctx| async move {
        let monitor = HeartbeatMonitor::new(Duration::from_millis(100), Duration::from_millis(50));

        // A worker the monitor has never heard from is Unknown, not Dead.
        assert_eq!(monitor.liveness("w1"), LivenessState::Unknown);

        monitor.record_heartbeat("w1");
        assert_eq!(monitor.liveness("w1"), LivenessState::Alive);

        // No time has passed, so a sweep finds no dead workers.
        assert!(monitor.sweep().dead.is_empty());
    });
}

#[test]
fn lag_seconds_reports_each_tracked_worker() {
    // Backing data for kata_worker_heartbeat_lag_seconds{worker_id}.
    kata_test_seeded::run_seeded(
        "lag_seconds_reports_each_tracked_worker",
        |_ctx| async move {
            let monitor =
                HeartbeatMonitor::new(Duration::from_millis(100), Duration::from_millis(50));
            assert!(
                monitor.lag_seconds().is_empty(),
                "no tracked workers → no lag entries"
            );

            monitor.record_heartbeat("w1");
            monitor.record_heartbeat("w2");

            let lag: std::collections::BTreeMap<_, _> = monitor.lag_seconds().into_iter().collect();
            assert_eq!(lag.len(), 2, "one lag entry per tracked worker");
            assert!(lag.contains_key("w1"), "w1 must have a lag entry");
            assert!(lag.contains_key("w2"), "w2 must have a lag entry");
            // Read-only: lag_seconds must not declare any worker dead.
            assert_eq!(monitor.liveness("w1"), LivenessState::Alive);
            for value in lag.values() {
                assert!(
                    *value >= 0.0,
                    "lag must be a non-negative elapsed duration, got {value}"
                );
            }
        },
    );
}

// NOTE: detect_dead_after_grace_window, a_heartbeat_resets_the_observed_silence,
// and revive_dead_worker remain #[tokio::test] because they use
// tokio::time::pause() and tokio::time::advance() for controlled time.

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn detect_dead_after_grace_window() {
    // Use tokio::time::pause to control time without real sleeps.
    tokio::time::pause();

    let interval = Duration::from_millis(100);
    let grace = Duration::from_millis(50);
    let monitor = HeartbeatMonitor::new(interval, grace);

    monitor.record_heartbeat("w1");
    assert_eq!(monitor.liveness("w1"), LivenessState::Alive);

    // Sweep past interval + grace_window of observed silence.
    let dead = sweep_through(&monitor, Duration::from_millis(160), interval).await;
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0], "w1");
    assert_eq!(monitor.liveness("w1"), LivenessState::Dead);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_heartbeat_resets_the_observed_silence() {
    tokio::time::pause();

    let interval = Duration::from_millis(100);
    let grace = Duration::from_millis(50);
    let monitor = HeartbeatMonitor::new(interval, grace);

    monitor.record_heartbeat("w1");

    // Sweep to just under the deadline.
    assert!(
        sweep_through(&monitor, Duration::from_millis(140), interval)
            .await
            .is_empty()
    );

    // Re-heartbeat resets the observed silence.
    monitor.record_heartbeat("w1");

    assert!(
        sweep_through(&monitor, Duration::from_millis(140), interval)
            .await
            .is_empty()
    );
    assert_eq!(monitor.liveness("w1"), LivenessState::Alive);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn revive_dead_worker() {
    tokio::time::pause();

    let interval = Duration::from_millis(50);
    let monitor = HeartbeatMonitor::new(interval, Duration::from_millis(10));

    monitor.record_heartbeat("w1");
    sweep_through(&monitor, Duration::from_millis(70), interval).await;
    assert_eq!(monitor.liveness("w1"), LivenessState::Dead);

    // A new heartbeat revives the worker.
    monitor.record_heartbeat("w1");
    assert_eq!(monitor.liveness("w1"), LivenessState::Alive);
}

// -- LivenessState tri-state tests --------------------------------------
//
// `liveness()` must distinguish Unknown (never registered) from Dead
// (known but grace window exceeded): the scheduler falls back to the
// transport's own liveness for Unknown and never routes to Dead, so a
// monitor that answered the same for both would route to dead workers.

#[test]
fn unknown_worker_is_unknown_not_dead() {
    kata_test_seeded::run_seeded("unknown_worker_is_unknown_not_dead", |_ctx| async move {
        let monitor = HeartbeatMonitor::new(Duration::from_millis(100), Duration::from_millis(50));
        assert_eq!(monitor.liveness("never-seen"), LivenessState::Unknown);
        assert!(!monitor.is_registered("never-seen"));
    });
}

#[test]
fn registered_worker_is_alive() {
    kata_test_seeded::run_seeded("registered_worker_is_alive", |_ctx| async move {
        let monitor = HeartbeatMonitor::new(Duration::from_millis(100), Duration::from_millis(50));
        monitor.record_heartbeat("w1");
        assert_eq!(monitor.liveness("w1"), LivenessState::Alive);
        assert!(monitor.is_registered("w1"));
    });
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn dead_worker_is_dead_not_unknown() {
    tokio::time::pause();

    let interval = Duration::from_millis(50);
    let monitor = HeartbeatMonitor::new(interval, Duration::from_millis(10));

    monitor.record_heartbeat("w1");
    assert_eq!(monitor.liveness("w1"), LivenessState::Alive);

    let dead = sweep_through(&monitor, Duration::from_millis(80), interval).await;
    assert_eq!(dead.len(), 1);

    // Critical: the dead worker must be `Dead`, not `Unknown`. If this
    // ever flips to `Unknown`, the scheduler's transport-fallback path
    // will route requests to explicitly-dead workers again.
    assert_eq!(monitor.liveness("w1"), LivenessState::Dead);
    assert!(monitor.is_registered("w1"));
}
