//! Integration test: `DispatchScheduler` capability-aware routing.
//!
//! Exercises the scheduler's `select_worker` method to verify that workers
//! are routed by capability, that liveness is respected, and that
//! least-loaded selection works across the supervisor and heartbeat monitor.

use kata_test_utils::sample_capsule_assignment;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kata_test_seeded::run_seeded;
use kata_transport::heartbeat::LivenessState;
use kata_transport::scheduler::PlacementContainment;
use kata_transport::types::{StageCheckpoint, WorkerMessage};
use kata_transport::{
    DispatchScheduler, HeartbeatMonitor, InProcessTransport, WorkerPoolSupervisor, WorkerTransport,
};
use smol_str::SmolStr;

#[test]
fn scheduler_routes_by_capability() {
    run_seeded("scheduler_routes_by_capability", |_ctx| async move {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(10),
        ));

        // 1. Register worker A with capability "gpu".
        let (home_a, _worker_a) = InProcessTransport::pair(8);
        supervisor.register_worker_with_caps(
            SmolStr::new("worker-gpu"),
            Arc::new(home_a),
            vec!["gpu".to_string()],
        );

        // 2. Register worker B with capability "cpu".
        let (home_b, _worker_b) = InProcessTransport::pair(8);
        supervisor.register_worker_with_caps(
            SmolStr::new("worker-cpu"),
            Arc::new(home_b),
            vec!["cpu".to_string()],
        );

        let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));

        // 3. Select worker with requirement "gpu" -- should get worker-gpu.
        let selected = scheduler.select_worker(&["gpu".to_string()]).unwrap();
        assert_eq!(selected, "worker-gpu");

        // 4. Select worker with requirement "cpu" -- should get worker-cpu.
        let selected = scheduler.select_worker(&["cpu".to_string()]).unwrap();
        assert_eq!(selected, "worker-cpu");
    });
}

#[test]
fn scheduler_no_match_returns_error() {
    run_seeded("scheduler_no_match_returns_error", |_ctx| async move {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(10),
        ));

        let (home, _worker) = InProcessTransport::pair(8);
        supervisor.register_worker_with_caps(
            SmolStr::new("worker-cpu"),
            Arc::new(home),
            vec!["cpu".to_string()],
        );

        let scheduler = DispatchScheduler::new(supervisor, heartbeat);

        // No worker has "gpu" capability.
        let result = scheduler.select_worker(&["gpu".to_string()]);
        assert!(result.is_err());
    });
}

#[test]
fn scheduler_picks_least_loaded() {
    run_seeded("scheduler_picks_least_loaded", |_ctx| async move {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(10),
        ));

        let (home_a, _worker_a) = InProcessTransport::pair(8);
        let (home_b, _worker_b) = InProcessTransport::pair(8);

        // Both workers have the same capability set (empty = matches all).
        supervisor.register_worker_with_caps(SmolStr::new("heavy"), Arc::new(home_a), vec![]);
        supervisor.register_worker_with_caps(SmolStr::new("light"), Arc::new(home_b), vec![]);

        // Simulate heavy having 10 active assignments, light having 2.
        if let Some(info) = supervisor.get_worker("heavy") {
            info.active_assignments.store(10, Ordering::Relaxed);
        }
        if let Some(info) = supervisor.get_worker("light") {
            info.active_assignments.store(2, Ordering::Relaxed);
        }

        let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));

        let selected = scheduler.select_worker(&[]).unwrap();
        assert_eq!(selected, "light");
    });
}

#[test]
fn scheduler_skips_dead_transport() {
    run_seeded("scheduler_skips_dead_transport", |_ctx| async move {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(10),
        ));

        // Dead worker (transport shut down, heartbeat monitor has not seen it).
        let (dead_home, _dead_worker) = InProcessTransport::pair(8);
        dead_home.shutdown().await.unwrap();
        supervisor.register_worker_with_caps(SmolStr::new("dead"), Arc::new(dead_home), vec![]);

        // Live worker.
        let (live_home, _live_worker) = InProcessTransport::pair(8);
        supervisor.register_worker_with_caps(SmolStr::new("live"), Arc::new(live_home), vec![]);

        let scheduler = DispatchScheduler::new(supervisor, heartbeat);
        let selected = scheduler.select_worker(&[]).unwrap();
        assert_eq!(selected, "live");
    });
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn scheduler_excludes_dead_heartbeat_even_when_worker_is_least_loaded() {
    tokio::time::pause();

    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(50),
        Duration::from_millis(10),
    ));

    let (dead_home, _dead_worker) = InProcessTransport::pair(8);
    let (live_home, _live_worker) = InProcessTransport::pair(8);
    supervisor.register_worker_with_caps(SmolStr::new("stale-low"), Arc::new(dead_home), vec![]);
    supervisor.register_worker_with_caps(SmolStr::new("live-busy"), Arc::new(live_home), vec![]);

    heartbeat.record_heartbeat("stale-low");
    // Two sweeps one interval apart: 80 ms of observed silence > 50 + 10.
    tokio::time::advance(Duration::from_millis(40)).await;
    assert!(heartbeat.sweep().dead.is_empty());
    tokio::time::advance(Duration::from_millis(40)).await;
    assert_eq!(
        heartbeat
            .sweep()
            .dead
            .into_iter()
            .map(|silent| silent.worker_id)
            .collect::<Vec<_>>(),
        vec![SmolStr::new("stale-low")]
    );
    assert_eq!(heartbeat.liveness("stale-low"), LivenessState::Dead);
    heartbeat.record_heartbeat("live-busy");

    supervisor
        .get_worker("live-busy")
        .unwrap()
        .active_assignments
        .store(9, Ordering::Relaxed);

    let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));

    assert_eq!(
        scheduler.eligible_worker_count(&[], PlacementContainment::Unconstrained),
        1
    );
    assert_eq!(scheduler.select_worker(&[]).unwrap(), "live-busy");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn scheduler_selection_then_supervisor_dispatch_delivers() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_secs(30),
        Duration::from_secs(10),
    ));

    let (home, worker) = InProcessTransport::pair(8);
    supervisor.register_worker_with_caps(SmolStr::new("w1"), Arc::new(home), vec![]);

    let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));

    let assignment = sample_capsule_assignment();
    let expected_id = assignment.attempt_id;

    let selected = scheduler.select_worker(&[]).unwrap();
    assert_eq!(selected, "w1");
    supervisor
        .dispatch_to(
            &dispatch_authority,
            &selected,
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    // The worker should receive the assignment.
    let received = capsule_frame(worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, expected_id);
}

#[test]
fn scheduler_multi_capability_requirement() {
    run_seeded(
        "scheduler_multi_capability_requirement",
        |_ctx| async move {
            let supervisor = Arc::new(WorkerPoolSupervisor::new());
            let heartbeat = Arc::new(HeartbeatMonitor::new(
                Duration::from_secs(30),
                Duration::from_secs(10),
            ));

            // Worker A has both gpu and cuda.
            let (home_a, _wa) = InProcessTransport::pair(8);
            supervisor.register_worker_with_caps(
                SmolStr::new("full"),
                Arc::new(home_a),
                vec!["gpu".to_string(), "cuda".to_string()],
            );

            // Worker B has only gpu.
            let (home_b, _wb) = InProcessTransport::pair(8);
            supervisor.register_worker_with_caps(
                SmolStr::new("partial"),
                Arc::new(home_b),
                vec!["gpu".to_string()],
            );

            let scheduler = DispatchScheduler::new(supervisor, heartbeat);

            // Requiring both gpu+cuda should select "full".
            let selected = scheduler
                .select_worker(&["gpu".to_string(), "cuda".to_string()])
                .unwrap();
            assert_eq!(selected, "full");

            // Requiring only gpu could select either, but both are eligible.
            let selected = scheduler.select_worker(&["gpu".to_string()]).unwrap();
            assert!(selected == "full" || selected == "partial");
        },
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn scheduler_dispatch_then_receive_result() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_secs(30),
        Duration::from_secs(10),
    ));

    let (home, worker) = InProcessTransport::pair(16);
    let home: Arc<dyn WorkerTransport> = Arc::new(home);
    supervisor.register_worker_with_caps(SmolStr::new("w1"), Arc::clone(&home), vec![]);

    let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));

    let assignment = sample_capsule_assignment();
    let assignment_id = assignment.attempt_id;

    // Spawn worker that processes the assignment.
    let worker_handle = tokio::spawn(async move {
        let received = capsule_frame(worker.recv_frame().await.unwrap());
        worker
            .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id: received.attempt_id,
                output: serde_json::json!({"deployed": true}),
                stage_name: "fixture".into(),
                sequence: 1,
                fence: kata_transport::AttemptFence::default(),
            }))
            .await
            .unwrap();
    });

    let selected = scheduler.select_worker(&[]).unwrap();
    assert_eq!(selected, "w1");
    supervisor
        .dispatch_to(
            &dispatch_authority,
            &selected,
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    // Home receives the result via the transport directly.
    let msg = home.recv().await.unwrap();
    match msg {
        WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: id,
            output,
            ..
        }) => {
            assert_eq!(id, assignment_id);
            assert!(output["deployed"].as_bool().unwrap());
        }
        other => panic!("expected Checkpoint, got {other:?}"),
    }

    worker_handle.await.unwrap();
}

/// Unwrap the capsule arm of a received dispatch frame — the only arm left.
#[track_caller]
fn capsule_frame(
    frame: kata_transport::types::DispatchFrame,
) -> kata_transport::types::CapsuleAssignment {
    let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
    *capsule
}
