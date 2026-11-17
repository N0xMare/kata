//! Tests for crates/transport/src/scheduler.rs. Extracted from the inline #[cfg(test)] module.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kata_transport::heartbeat::LivenessState;
use kata_transport::scheduler::PlacementContainment;
use kata_transport::{
    DispatchScheduler, HeartbeatMonitor, InProcessTransport, WorkerPoolSupervisor, WorkerTransport,
};
use smol_str::SmolStr;
use ulid::Ulid;

fn test_assignment() -> kata_transport::types::CapsuleAssignment {
    let mut capsule = kata_test_utils::sample_capsule_assignment();
    capsule.attempt_id = Ulid::new();
    capsule.execution_id = Ulid::new();
    capsule
}

#[test]
fn select_worker_by_capability() {
    kata_test_seeded::run_seeded("select_worker_by_capability", |_ctx| async move {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(10),
        ));

        let (home_a, _worker_a) = InProcessTransport::pair(8);
        let (home_b, _worker_b) = InProcessTransport::pair(8);

        supervisor.register_worker_with_caps(
            SmolStr::new("w-gpu"),
            Arc::new(home_a),
            vec!["gpu".to_string()],
        );
        supervisor.register_worker_with_caps(
            SmolStr::new("w-cpu"),
            Arc::new(home_b),
            vec!["cpu".to_string()],
        );

        // Both workers report alive via transport; heartbeat monitor
        // hasn't seen them but the fallback transport check passes.
        let selected = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat))
            .select_worker(&["gpu".to_string()])
            .unwrap();

        assert_eq!(selected, "w-gpu");
    });
}

#[test]
fn multi_worker_selects_least_loaded_worker() {
    kata_test_seeded::run_seeded(
        "multi_worker_selects_least_loaded_worker",
        |_ctx| async move {
            let supervisor = Arc::new(WorkerPoolSupervisor::new());
            let heartbeat = Arc::new(HeartbeatMonitor::new(
                Duration::from_secs(30),
                Duration::from_secs(10),
            ));

            let (home_a, _worker_a) = InProcessTransport::pair(8);
            let (home_b, _worker_b) = InProcessTransport::pair(8);

            supervisor.register_worker_with_caps(SmolStr::new("w1"), Arc::new(home_a), vec![]);
            supervisor.register_worker_with_caps(SmolStr::new("w2"), Arc::new(home_b), vec![]);

            // Simulate w1 having more active assignments.
            if let Some(info) = supervisor.get_worker("w1") {
                info.active_assignments.store(5, Ordering::Relaxed);
            }
            if let Some(info) = supervisor.get_worker("w2") {
                info.active_assignments.store(1, Ordering::Relaxed);
            }

            let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));

            let selected = scheduler.select_worker(&[]).unwrap();
            assert_eq!(selected, "w2");
        },
    );
}

#[test]
fn placement_candidates_are_dispatch_eligible_and_load_ordered() {
    kata_test_seeded::run_seeded(
        "placement_candidates_are_dispatch_eligible_and_load_ordered",
        |_ctx| async move {
            let supervisor = Arc::new(WorkerPoolSupervisor::new());
            let heartbeat = Arc::new(HeartbeatMonitor::new(
                Duration::from_secs(30),
                Duration::from_secs(10),
            ));

            let (busy_home, _busy_worker) = InProcessTransport::pair(8);
            let (idle_home, _idle_worker) = InProcessTransport::pair(8);
            let (cpu_home, _cpu_worker) = InProcessTransport::pair(8);

            supervisor.register_worker_with_caps(
                SmolStr::new("busy-gpu"),
                Arc::new(busy_home),
                vec!["gpu".to_string()],
            );
            supervisor.register_worker_with_caps(
                SmolStr::new("idle-gpu"),
                Arc::new(idle_home),
                vec!["gpu".to_string()],
            );
            supervisor.register_worker_with_caps(
                SmolStr::new("cpu-only"),
                Arc::new(cpu_home),
                vec!["cpu".to_string()],
            );
            if let Some(info) = supervisor.get_worker("busy-gpu") {
                info.active_assignments.store(3, Ordering::Relaxed);
            }

            let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));
            let candidates = scheduler
                .placement_candidates(&["gpu".to_string()], PlacementContainment::Unconstrained);
            let candidate_ids = candidates
                .iter()
                .map(|candidate| candidate.worker_id.as_str())
                .collect::<Vec<_>>();

            assert_eq!(candidate_ids, vec!["idle-gpu", "busy-gpu"]);
            assert_eq!(candidates[0].active_assignment_count, 0);
            assert_eq!(candidates[1].active_assignment_count, 3);
            assert_eq!(
                scheduler.select_worker(&["gpu".to_string()]).unwrap(),
                "idle-gpu"
            );
        },
    );
}

#[test]
fn preferred_worker_is_used_only_when_still_eligible() {
    kata_test_seeded::run_seeded(
        "preferred_worker_is_used_only_when_still_eligible",
        |_ctx| async move {
            let supervisor = Arc::new(WorkerPoolSupervisor::new());
            let heartbeat = Arc::new(HeartbeatMonitor::new(
                Duration::from_secs(30),
                Duration::from_secs(10),
            ));

            let (busy_home, _busy_worker) = InProcessTransport::pair(8);
            let (idle_home, _idle_worker) = InProcessTransport::pair(8);
            let (cpu_home, _cpu_worker) = InProcessTransport::pair(8);

            supervisor.register_worker_with_caps(
                SmolStr::new("busy-gpu"),
                Arc::new(busy_home),
                vec!["gpu".to_string()],
            );
            supervisor.register_worker_with_caps(
                SmolStr::new("idle-gpu"),
                Arc::new(idle_home),
                vec!["gpu".to_string()],
            );
            supervisor.register_worker_with_caps(
                SmolStr::new("cpu-only"),
                Arc::new(cpu_home),
                vec!["cpu".to_string()],
            );
            if let Some(info) = supervisor.get_worker("busy-gpu") {
                info.active_assignments.store(3, Ordering::Relaxed);
            }

            let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));
            assert_eq!(
                scheduler
                    .select_worker_with_preference(
                        &["gpu".to_string()],
                        Some(&SmolStr::new("busy-gpu"))
                    )
                    .unwrap(),
                "busy-gpu"
            );
            assert_eq!(
                scheduler
                    .select_worker_with_preference(
                        &["gpu".to_string()],
                        Some(&SmolStr::new("cpu-only"))
                    )
                    .unwrap(),
                "idle-gpu"
            );
            assert_eq!(
                scheduler
                    .select_worker_excluding_with_preference(
                        &["gpu".to_string()],
                        &[SmolStr::new("busy-gpu")],
                        Some(&SmolStr::new("busy-gpu")),
                        PlacementContainment::Unconstrained,
                    )
                    .unwrap(),
                "idle-gpu"
            );
        },
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn preferred_worker_falls_back_when_missing_disconnected_or_heartbeat_dead() {
    tokio::time::pause();

    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(50),
        Duration::from_millis(10),
    ));

    let (planned_home, _planned_worker) = InProcessTransport::pair(8);
    let planned_home = Arc::new(planned_home);
    let (idle_home, _idle_worker) = InProcessTransport::pair(8);
    let idle_home = Arc::new(idle_home);

    supervisor.register_worker_with_caps(
        SmolStr::new("planned-gpu"),
        Arc::clone(&planned_home) as Arc<dyn WorkerTransport>,
        vec!["gpu".to_string()],
    );
    supervisor.register_worker_with_caps(
        SmolStr::new("idle-gpu"),
        Arc::clone(&idle_home) as Arc<dyn WorkerTransport>,
        vec!["gpu".to_string()],
    );
    if let Some(info) = supervisor.get_worker("idle-gpu") {
        info.active_assignments.store(9, Ordering::Relaxed);
    }

    let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));
    assert_eq!(
        scheduler
            .select_worker_with_preference(&["gpu".to_string()], Some(&SmolStr::new("planned-gpu")))
            .unwrap(),
        "planned-gpu"
    );

    supervisor.unregister_worker("planned-gpu");
    assert_eq!(
        scheduler
            .select_worker_with_preference(&["gpu".to_string()], Some(&SmolStr::new("planned-gpu")))
            .unwrap(),
        "idle-gpu"
    );

    let (shut_home, _shut_worker) = InProcessTransport::pair(8);
    let shut_home = Arc::new(shut_home);
    supervisor.register_worker_with_caps(
        SmolStr::new("planned-gpu"),
        Arc::clone(&shut_home) as Arc<dyn WorkerTransport>,
        vec!["gpu".to_string()],
    );
    shut_home.shutdown().await.unwrap();
    assert_eq!(
        scheduler
            .select_worker_with_preference(&["gpu".to_string()], Some(&SmolStr::new("planned-gpu")))
            .unwrap(),
        "idle-gpu"
    );

    let (dead_home, _dead_worker) = InProcessTransport::pair(8);
    supervisor.register_worker_with_caps(
        SmolStr::new("planned-gpu"),
        Arc::new(dead_home),
        vec!["gpu".to_string()],
    );
    heartbeat.record_heartbeat("planned-gpu");
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
        vec![SmolStr::new("planned-gpu")]
    );
    heartbeat.record_heartbeat("idle-gpu");
    assert_eq!(
        scheduler
            .select_worker_with_preference(&["gpu".to_string()], Some(&SmolStr::new("planned-gpu")))
            .unwrap(),
        "idle-gpu"
    );
}

#[test]
fn select_no_eligible_worker() {
    kata_test_seeded::run_seeded("select_no_eligible_worker", |_ctx| async move {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_secs(30),
            Duration::from_secs(10),
        ));

        let (home, _worker) = InProcessTransport::pair(8);
        supervisor.register_worker_with_caps(
            SmolStr::new("w1"),
            Arc::new(home),
            vec!["cpu".to_string()],
        );

        let scheduler = DispatchScheduler::new(supervisor, heartbeat);
        let result = scheduler.select_worker(&["gpu".to_string()]);
        assert!(result.is_err());
    });
}

/// The scheduler must skip a worker the heartbeat monitor has marked
/// [`LivenessState::Dead`] **even if** the transport reports
/// `is_alive() == true`. A selection loop that read heartbeat liveness as a
/// bool would collapse `Dead` and `Unknown` into `false`, and then fall back to
/// `transport.is_alive()` — routing work straight to explicitly-dead workers.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn multi_worker_dead_heartbeat_worker_is_never_selected() {
    tokio::time::pause();

    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(50),
        Duration::from_millis(10),
    ));

    // Register a single worker with a healthy transport. The
    // heartbeat monitor will mark it dead, but the transport still
    // reports alive — exactly the state a transport-fallback would slip through.
    let (home, _worker) = InProcessTransport::pair(8);
    supervisor.register_worker_with_caps(SmolStr::new("w1"), Arc::new(home), vec![]);

    // Heartbeat once then let it expire.
    heartbeat.record_heartbeat("w1");
    // Two sweeps one interval apart: 80 ms of observed silence > 50 + 10.
    tokio::time::advance(Duration::from_millis(40)).await;
    assert!(heartbeat.sweep().dead.is_empty());
    tokio::time::advance(Duration::from_millis(40)).await;
    let dead = heartbeat.sweep().dead;
    assert_eq!(dead.len(), 1);
    assert_eq!(heartbeat.liveness("w1"), LivenessState::Dead);

    // The transport itself is still alive — the condition under which a
    // scheduler that consulted only the transport would route to a dead worker.
    let info = supervisor.get_worker("w1").unwrap();
    assert!(info.is_alive());
    drop(info);

    let scheduler = DispatchScheduler::new(supervisor, heartbeat);
    assert_eq!(
        scheduler.eligible_worker_count(&[], PlacementContainment::Unconstrained),
        0
    );
    let result = scheduler.select_worker(&[]);
    assert!(
        result.is_err(),
        "scheduler must not route to a heartbeat-dead worker, \
         even if the transport still reports alive"
    );
}

/// Conversely, an `Unknown` heartbeat state must still allow the
/// transport-fallback path — otherwise in-process tests that never
/// wire a heartbeat source become unroutable.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn unknown_heartbeat_falls_back_to_transport() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_secs(30),
        Duration::from_secs(10),
    ));

    let (home, _worker) = InProcessTransport::pair(8);
    supervisor.register_worker_with_caps(SmolStr::new("w1"), Arc::new(home), vec![]);

    // No heartbeat has ever been recorded — `liveness("w1")` is Unknown.
    assert_eq!(heartbeat.liveness("w1"), LivenessState::Unknown);

    let scheduler = DispatchScheduler::new(supervisor, heartbeat);
    assert_eq!(
        scheduler.eligible_worker_count(&[], PlacementContainment::Unconstrained),
        1
    );
    let selected = scheduler.select_worker(&[]).unwrap();
    assert_eq!(selected, "w1");
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

    let assignment = test_assignment();
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

    let received = capsule_frame(worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, expected_id);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn scheduler_selection_excludes_dead_transport_before_dispatch() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_secs(30),
        Duration::from_secs(10),
    ));

    // Register a dead worker (will time out) and a live one.
    let (dead_home, _dead_worker) = InProcessTransport::pair(8);
    dead_home.shutdown().await.unwrap();

    let (live_home, live_worker) = InProcessTransport::pair(8);

    supervisor.register_worker_with_caps(SmolStr::new("dead"), Arc::new(dead_home), vec![]);
    supervisor.register_worker_with_caps(SmolStr::new("live"), Arc::new(live_home), vec![]);

    let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));

    let assignment = test_assignment();
    let expected_id = assignment.attempt_id;

    let selected = scheduler.select_worker(&[]).unwrap();
    assert_eq!(selected, "live");
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

    let received = capsule_frame(live_worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, expected_id);
}

/// Regression pin: scheduler placement must honor heartbeat and transport
/// liveness before any raw transport send happens.
///
/// Setup: two workers.
///
/// - `dead-hb`: transport reports `is_alive() == true`, but the
///   heartbeat monitor has marked it [`LivenessState::Dead`] (it
///   recorded one heartbeat and then let the grace window expire).
/// - `fail-send`: transport has been shut down so any dispatch fails
///   immediately, even though its heartbeat is recorded as alive.
///
/// No worker should be selected. The checked workflow dispatcher owns the
/// later send/retry loop and calls this same placement predicate before each
/// transport send.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn scheduler_selection_excludes_heartbeat_dead_worker() {
    tokio::time::pause();

    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(50),
        Duration::from_millis(10),
    ));

    // Worker A: transport is healthy, but heartbeat is marked Dead.
    // This is exactly the state a bare `dispatch` fallback
    // would slip assignments through on.
    let (dead_hb_home, dead_hb_worker) = InProcessTransport::pair(8);
    supervisor.register_worker_with_caps(SmolStr::new("dead-hb"), Arc::new(dead_hb_home), vec![]);
    heartbeat.record_heartbeat("dead-hb");
    // Two sweeps one interval apart: 80 ms of observed silence > 50 + 10.
    tokio::time::advance(Duration::from_millis(40)).await;
    assert!(heartbeat.sweep().dead.is_empty());
    tokio::time::advance(Duration::from_millis(40)).await;
    let swept = heartbeat.sweep().dead;
    assert_eq!(swept.len(), 1, "heartbeat sweep should mark dead-hb Dead");
    assert_eq!(heartbeat.liveness("dead-hb"), LivenessState::Dead);
    // Sanity: the transport itself still reports alive. A dispatch that
    // trusted the transport alone would happily route here.
    assert!(
        supervisor.get_worker("dead-hb").unwrap().is_alive(),
        "dead-hb's transport must still report alive for the regression \
         to reproduce — that's the whole point of the fix"
    );

    // Worker B: heartbeat is alive, but the transport is shut down so
    // every `dispatch_to` call fails immediately. Recording a
    // heartbeat **before** shutdown means `select_worker` will still
    // treat it as eligible (heartbeat=Alive short-circuits the
    // transport-is_alive fallback).
    let (fail_send_home, _fail_send_worker) = InProcessTransport::pair(8);
    fail_send_home.shutdown().await.unwrap();
    supervisor.register_worker_with_caps(
        SmolStr::new("fail-send"),
        Arc::new(fail_send_home),
        vec![],
    );
    heartbeat.record_heartbeat("fail-send");
    assert_eq!(heartbeat.liveness("fail-send"), LivenessState::Alive);

    let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));

    let result = scheduler.select_worker(&[]);
    assert!(
        result.is_err(),
        "selection should fail — fail-send's transport is shut and \
         dead-hb is heartbeat-Dead, leaving no eligible target"
    );

    // The load-bearing assertion: the heartbeat-Dead worker must
    // never have received the assignment, even though its transport
    // still reports alive. The channel API here is async-only, so we
    // race `recv_frame()` against a virtually-zero timeout
    // (tokio's time is still paused). The recv should time out,
    // proving the queue is empty.
    let recv_fut = dead_hb_worker.recv_frame();
    let drained = tokio::time::timeout(Duration::from_millis(1), recv_fut).await;
    assert!(
        drained.is_err(),
        "heartbeat-Dead worker received an assignment even though scheduler \
         selection found no eligible target"
    );
}

/// Regression pin: placement must skip both heartbeat-dead workers and
/// heartbeat-alive workers whose transports have since shut down, landing on a
/// genuinely healthy worker.
///
/// The scenario:
/// 1. Worker "healthy" — transport alive, heartbeat alive. The target.
/// 2. Worker "dead-tx" — heartbeat recorded as alive, transport then
///    `shutdown()`. Selected on the first pass because heartbeat is
///    Alive, but `dispatch_to` fails immediately.
/// 3. Worker "dead-hb" — heartbeat marked Dead, transport still alive.
///    Must never receive the assignment.
///
/// The checked dispatcher is responsible for the send/retry loop; the
/// scheduler's contract is the placement predicate it uses for each attempt.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn scheduler_selection_skips_dead_workers_before_dispatch_to_healthy_worker() {
    tokio::time::pause();

    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_millis(50),
        Duration::from_millis(10),
    ));

    // Worker 1: heartbeat Dead but transport still alive.
    let (dead_hb_home, dead_hb_worker) = InProcessTransport::pair(8);
    supervisor.register_worker_with_caps(SmolStr::new("dead-hb"), Arc::new(dead_hb_home), vec![]);
    heartbeat.record_heartbeat("dead-hb");
    // Two sweeps one interval apart: 80 ms of observed silence > 50 + 10.
    tokio::time::advance(Duration::from_millis(40)).await;
    assert!(heartbeat.sweep().dead.is_empty());
    tokio::time::advance(Duration::from_millis(40)).await;
    heartbeat.sweep();
    assert_eq!(heartbeat.liveness("dead-hb"), LivenessState::Dead);

    // Worker 2: heartbeat Alive, transport dead.
    let (dead_tx_home, _dead_tx_worker) = InProcessTransport::pair(8);
    dead_tx_home.shutdown().await.unwrap();
    supervisor.register_worker_with_caps(SmolStr::new("dead-tx"), Arc::new(dead_tx_home), vec![]);
    heartbeat.record_heartbeat("dead-tx");
    assert_eq!(heartbeat.liveness("dead-tx"), LivenessState::Alive);

    // Worker 3: heartbeat Alive, transport alive. The retry target.
    let (healthy_home, healthy_worker) = InProcessTransport::pair(8);
    supervisor.register_worker_with_caps(SmolStr::new("healthy"), Arc::new(healthy_home), vec![]);
    heartbeat.record_heartbeat("healthy");

    let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), Arc::clone(&heartbeat));

    // Drive `select_worker_excluding` to confirm it now excludes
    // dead-tx (Alive heartbeat but dead transport) and dead-hb (Dead
    // heartbeat), leaving healthy as the only choice.
    let selected = scheduler.select_worker(&[]).unwrap();
    assert_eq!(
        selected, "healthy",
        "select_worker must pick the only genuinely-healthy worker — \
         not dead-hb (heartbeat Dead) and not dead-tx (transport dead)"
    );

    let assignment = test_assignment();
    let assignment_id = assignment.attempt_id;
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

    // healthy must receive the assignment.
    let received = capsule_frame(
        tokio::time::timeout(Duration::from_millis(100), healthy_worker.recv_frame())
            .await
            .expect("healthy worker should receive within timeout")
            .expect("recv should succeed"),
    );
    assert_eq!(received.attempt_id, assignment_id);

    // dead-hb must never have seen the assignment.
    let dead_hb_drained =
        tokio::time::timeout(Duration::from_millis(1), dead_hb_worker.recv_frame()).await;
    assert!(
        dead_hb_drained.is_err(),
        "heartbeat-Dead worker must never receive assignments"
    );
}

/// `WorkerPoolSupervisor::dispatch_to` returns as soon as the assignment is in
/// the transport queue. Stage-completion deadlines live in the checked
/// workflow dispatcher, not in the transport scheduler.
///
/// This test pins the low-level transport semantic directly, because
/// `DispatchScheduler` is placement-only.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn supervisor_dispatch_to_returns_on_send_not_completion() {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();

    // Healthy transport with plenty of queue capacity. The worker side
    // is deliberately NOT drained — no one calls recv_frame.
    let (home, worker) = InProcessTransport::pair(16);
    supervisor.register_worker_with_caps(SmolStr::new("w1"), Arc::new(home), vec![]);

    let assignment = test_assignment();
    let expected_id = assignment.attempt_id;

    supervisor
        .dispatch_to(
            &dispatch_authority,
            "w1",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .expect("dispatch_to should only gate the send, not completion");

    // The assignment is still sitting in the worker-side queue,
    // confirming that dispatch_to returned before anything executed.
    let received = capsule_frame(worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, expected_id);
}

/// Unwrap the capsule arm of a received dispatch frame — the only arm left.
#[track_caller]
fn capsule_frame(
    frame: kata_transport::types::DispatchFrame,
) -> kata_transport::types::CapsuleAssignment {
    let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
    *capsule
}
