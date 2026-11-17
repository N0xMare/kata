//! Integration test: `HeartbeatMonitor` liveness detection.
//!
//! Exercises the heartbeat monitor with controlled time (via
//! `tokio::time::pause`) to verify that workers are correctly detected as
//! dead when they stop sending heartbeats past the grace window — judged on
//! the silence the main OBSERVED, one sweep per interval as production sweeps.

use std::time::Duration;

use kata_transport::HeartbeatMonitor;
use kata_transport::heartbeat::{HeartbeatSweep, LivenessState, SilentWorker};
use smol_str::SmolStr;

/// Advance paused time by `span` the way a main does: one sweep per `step` (its
/// heartbeat interval), collecting every worker a sweep marked dead.
async fn sweep_through(monitor: &HeartbeatMonitor, span: Duration, step: Duration) -> Vec<SmolStr> {
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

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn heartbeat_detects_dead_worker() {
    // Use paused time for deterministic tests.
    tokio::time::pause();

    // 1. Create heartbeat monitor with short interval (100ms) and grace (200ms).
    let interval = Duration::from_millis(100);
    let grace = Duration::from_millis(200);
    let monitor = HeartbeatMonitor::new(interval, grace);

    // 2. Register worker, record heartbeat.
    monitor.record_heartbeat("worker-1");
    assert_eq!(monitor.liveness("worker-1"), LivenessState::Alive);

    // Before deadline: no dead workers.
    assert!(monitor.sweep().dead.is_empty());

    // 3. Sweep past the deadline (interval + grace = 300ms of observed silence).
    let dead = sweep_through(&monitor, Duration::from_millis(310), interval).await;

    // 4. The sweep past it returns the dead worker.
    assert_eq!(dead, vec![SmolStr::new("worker-1")]);
    assert_eq!(monitor.liveness("worker-1"), LivenessState::Dead);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn heartbeat_alive_within_window() {
    tokio::time::pause();

    let interval = Duration::from_millis(100);
    let grace = Duration::from_millis(200);
    let monitor = HeartbeatMonitor::new(interval, grace);

    monitor.record_heartbeat("worker-1");

    // Sweep to just under the deadline (interval + grace = 300ms).
    let dead = sweep_through(&monitor, Duration::from_millis(290), interval).await;
    assert!(dead.is_empty());
    assert_eq!(monitor.liveness("worker-1"), LivenessState::Alive);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn heartbeat_refresh_keeps_alive() {
    tokio::time::pause();

    let interval = Duration::from_millis(100);
    let grace = Duration::from_millis(200);
    let monitor = HeartbeatMonitor::new(interval, grace);

    monitor.record_heartbeat("worker-1");

    // 250ms of silence (under the 300ms deadline).
    assert!(
        sweep_through(&monitor, Duration::from_millis(250), interval)
            .await
            .is_empty()
    );

    // Re-heartbeat resets the observed silence.
    monitor.record_heartbeat("worker-1");

    // Another 250ms (500ms from start, but only 250ms since the last heartbeat).
    assert!(
        sweep_through(&monitor, Duration::from_millis(250), interval)
            .await
            .is_empty()
    );
    assert_eq!(monitor.liveness("worker-1"), LivenessState::Alive);

    // Now past the deadline from the last heartbeat.
    let dead = sweep_through(&monitor, Duration::from_millis(60), interval).await;
    assert_eq!(dead, vec![SmolStr::new("worker-1")]);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn heartbeat_multiple_workers_mixed_liveness() {
    tokio::time::pause();

    let interval = Duration::from_millis(100);
    let grace = Duration::from_millis(100);
    let monitor = HeartbeatMonitor::new(interval, grace);

    // Register both workers at time 0.
    monitor.record_heartbeat("alive-worker");
    monitor.record_heartbeat("dead-worker");

    // 150ms of sweeps.
    assert!(
        sweep_through(&monitor, Duration::from_millis(150), interval)
            .await
            .is_empty()
    );

    // Only alive-worker gets a heartbeat refresh.
    monitor.record_heartbeat("alive-worker");

    // 60ms more (210ms total; alive-worker silent 60ms, dead-worker 210ms,
    // deadline 200ms).
    let dead = sweep_through(&monitor, Duration::from_millis(60), interval).await;
    assert_eq!(dead, vec![SmolStr::new("dead-worker")]);

    assert_eq!(monitor.liveness("alive-worker"), LivenessState::Alive);
    assert_eq!(monitor.liveness("dead-worker"), LivenessState::Dead);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn heartbeat_revive_dead_worker() {
    tokio::time::pause();

    let interval = Duration::from_millis(50);
    let monitor = HeartbeatMonitor::new(interval, Duration::from_millis(50));

    monitor.record_heartbeat("worker-1");

    // Kill it.
    sweep_through(&monitor, Duration::from_millis(110), interval).await;
    assert_eq!(monitor.liveness("worker-1"), LivenessState::Dead);

    // Revive by heartbeating again.
    monitor.record_heartbeat("worker-1");
    assert_eq!(monitor.liveness("worker-1"), LivenessState::Alive);
    assert!(monitor.sweep().dead.is_empty());
}

/// **A WORKER THAT HEARTBEATED SINCE ITS VERDICT IS NEVER FORGOTTEN.**
/// `HeartbeatMonitor::forget_dead` removes a worker only while it is still
/// marked dead: a beat that revived it between the sweep's verdict and the
/// call is kept, so the worker stays tracked, alive, and named by the lag
/// gauge. An id the monitor does not hold is a no-op; a still-dead worker is
/// removed and reads `Unknown`.
///
/// **Watched red:** with `forget_dead` removing unconditionally
/// (`.remove(worker_id)`), the revived worker is forgotten.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn forget_dead_keeps_a_worker_revived_since_its_verdict() {
    tokio::time::pause();

    let interval = Duration::from_millis(50);
    let monitor = HeartbeatMonitor::new(interval, Duration::from_millis(50));

    monitor.record_heartbeat("revived");
    monitor.record_heartbeat("silent");
    let dead = sweep_through(&monitor, Duration::from_millis(110), interval).await;
    assert_eq!(
        dead.len(),
        2,
        "both workers must be judged dead first: {dead:?}"
    );

    // The racing beat lands after the verdict, before the forget.
    monitor.record_heartbeat("revived");
    assert!(
        !monitor.forget_dead("revived"),
        "a revived worker must be kept"
    );
    assert_eq!(monitor.liveness("revived"), LivenessState::Alive);
    assert!(
        monitor.lag_seconds().iter().any(|(id, _)| id == "revived"),
        "the kept worker must still be named by the lag gauge"
    );

    assert!(!monitor.forget_dead("never-registered"));

    assert!(
        monitor.forget_dead("silent"),
        "a still-dead worker is removed"
    );
    assert_eq!(monitor.liveness("silent"), LivenessState::Unknown);
    assert!(!monitor.lag_seconds().iter().any(|(id, _)| id == "silent"));
}

/// **THE MAIN'S OWN STALL IS NOT ITS WORKER'S SILENCE.** At the live rigs'
/// 1 s / 5 s, a worker beating every 0.5 s is recorded at 4.5 s; then the main
/// stalls 10 s — no sweep runs and nothing is read, the worker's beats wait in
/// its socket — and on resume the overdue sweep runs before the waiting beat is
/// recorded, as measured live (a 2 s stop of the main settled its live worker
/// on 3 of 3 tries, the sweep deciding 1 ms before the beat was read). That
/// sweep charges the stall as one interval: 1 s of observed silence, not 10 s,
/// so the worker is not dead, and the beat recorded next resets it. The
/// wall-time lag gauge still reports the whole 10 s.
///
/// **Watched red:** with `HeartbeatMonitor::sweep` charging the whole gap since
/// the previous sweep (no one-interval cap), the stalled main's first sweep
/// marks the live worker dead.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_main_stall_is_charged_to_its_worker_as_at_most_one_interval() {
    tokio::time::pause();

    let interval = Duration::from_secs(1);
    let monitor = HeartbeatMonitor::new(interval, Duration::from_secs(5));
    monitor.record_heartbeat("w1");
    for _ in 0..9 {
        assert!(
            sweep_through(&monitor, Duration::from_millis(500), interval)
                .await
                .is_empty()
        );
        monitor.record_heartbeat("w1");
    }

    // The main stalls for 10 s: no sweep, no read.
    tokio::time::advance(Duration::from_secs(10)).await;
    let verdict = monitor.sweep();
    assert!(
        verdict.dead.is_empty(),
        "the main's 10 s stall was charged to its live worker: {verdict:?}"
    );
    assert_eq!(monitor.liveness("w1"), LivenessState::Alive);
    let (_, lag) = monitor.lag_seconds().pop().expect("w1 is tracked");
    assert!(
        lag >= 10.0,
        "the lag gauge reports wall time since the last beat, got {lag}"
    );

    // The beat that waited in the socket is read; the worker is current again.
    monitor.record_heartbeat("w1");
    assert!(
        sweep_through(&monitor, Duration::from_secs(3), interval)
            .await
            .is_empty()
    );
}

/// **A WORKER THAT STOPS BEATING IS STILL SETTLED, WITHIN ITS BOUND.** The cap
/// delays the verdict by a stall of the main, never cancels it: a worker silent
/// from its last beat is dead at the first on-time sweep past `interval + grace`
/// of observed silence (6 s here: the 7th sweep, 1 s apart), and a 10 s stall
/// of the main in the middle of that silence delays the verdict by the 9 s of
/// the stall beyond one interval. The verdict carries what its settlement
/// records: 7 s observed, 16 s since the beat, against the 6 s deadline.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_silent_worker_is_settled_within_its_bound() {
    tokio::time::pause();

    let interval = Duration::from_secs(1);
    let grace = Duration::from_secs(5);

    // On-time sweeps: dead at the 7th sweep after the beat (7 s > 6 s).
    let monitor = HeartbeatMonitor::new(interval, grace);
    monitor.record_heartbeat("w1");
    assert!(
        sweep_through(&monitor, Duration::from_secs(6), interval)
            .await
            .is_empty()
    );
    assert_eq!(
        sweep_through(&monitor, Duration::from_secs(1), interval).await,
        vec![SmolStr::new("w1")]
    );

    // A 10 s stall of the main 2 s into the silence: dead 9 s later.
    let monitor = HeartbeatMonitor::new(interval, grace);
    monitor.record_heartbeat("w1");
    assert!(
        sweep_through(&monitor, Duration::from_secs(2), interval)
            .await
            .is_empty()
    );
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(monitor.sweep().dead.is_empty(), "3 s observed");
    assert!(
        sweep_through(&monitor, Duration::from_secs(3), interval)
            .await
            .is_empty(),
        "6 s observed is not past the deadline"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        monitor.sweep().dead,
        vec![SilentWorker {
            worker_id: SmolStr::new("w1"),
            observed_silence: Duration::from_secs(7),
            last_heartbeat_age: Duration::from_secs(16),
            deadline: Duration::from_secs(6),
        }],
        "7 s observed, 16 s of wall time after the beat"
    );
}

/// **A DEAD WORKER IS REPORTED AT EVERY SWEEP UNTIL IT HEARTBEATS.** The sweep
/// that finds a worker dead reports it in `dead`; every later sweep reports it in
/// `still_dead`, its silence still accruing, so the main settles again whatever
/// the worker holds by then. A heartbeat revives it and the reports stop.
///
/// **Watched red:** with `HeartbeatMonitor::sweep` skipping a worker already
/// marked dead, the next sweep reported nothing.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_dead_worker_is_reported_at_every_sweep_until_it_heartbeats() {
    tokio::time::pause();

    let interval = Duration::from_secs(1);
    let monitor = HeartbeatMonitor::new(interval, Duration::from_secs(5));
    monitor.record_heartbeat("w1");
    assert_eq!(
        sweep_through(&monitor, Duration::from_secs(7), interval).await,
        vec![SmolStr::new("w1")]
    );

    for seconds in [8, 9] {
        tokio::time::advance(interval).await;
        let verdict = monitor.sweep();
        assert_eq!(
            verdict,
            HeartbeatSweep {
                stale: Vec::new(),
                dead: Vec::new(),
                still_dead: vec![SilentWorker {
                    worker_id: SmolStr::new("w1"),
                    observed_silence: Duration::from_secs(seconds),
                    last_heartbeat_age: Duration::from_secs(seconds),
                    deadline: Duration::from_secs(6),
                }],
            },
            "{seconds} s after its last beat the dead worker was not reported again"
        );
    }

    monitor.record_heartbeat("w1");
    tokio::time::advance(interval).await;
    assert_eq!(monitor.sweep(), HeartbeatSweep::default());
}
