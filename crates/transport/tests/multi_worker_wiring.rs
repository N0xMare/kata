//! Integration tests: multi-worker wiring over the local socket.
//!
//! These tests exercise the accept-loop pattern where a main
//! binds a listener, accepts one or more worker connections, registers each
//! with the `WorkerPoolSupervisor`, dispatches assignments, and collects
//! results -- the same flow the installed main performs.

use kata_test_utils::sample_capsule_assignment;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kata_transport::types::{StageCheckpoint, WorkerMessage};
use kata_transport::{
    DispatchScheduler, HeartbeatMonitor, LocalSocketTransport, WorkerPoolSupervisor,
    WorkerSideTransport, WorkerTransport,
};
use smol_str::SmolStr;

// ---------------------------------------------------------------------------
// LocalSocket: home binds, worker connects, dispatch + result
// ---------------------------------------------------------------------------

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn multi_worker_local_socket_home_accepts_worker_dispatch_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("home.sock");

    // Home binds via the multi-accept listener.
    let listener = LocalSocketTransport::listen(&sock_path).unwrap();

    // Worker connects in a background task.
    let sock_path_clone = sock_path.clone();
    let worker_handle = tokio::spawn(async move {
        // Small delay so the listener is ready.
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        LocalSocketTransport::connect(&sock_path_clone)
            .await
            .unwrap()
    });

    // Home accepts one connection.
    let home_transport = listener.accept_next().await.unwrap();
    let worker_transport = worker_handle.await.unwrap();

    // Register with supervisor.
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
    let home_transport: Arc<dyn WorkerTransport> = Arc::new(home_transport);
    supervisor.register_worker(SmolStr::new("ls-worker-0"), Arc::clone(&home_transport));

    assert_eq!(supervisor.worker_count(), 1);

    // Dispatch an assignment via the supervisor.
    let assignment = sample_capsule_assignment();
    let assignment_id = assignment.attempt_id;
    supervisor
        .dispatch_to(
            &dispatch_authority,
            "ls-worker-0",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    // Worker receives and replies.
    let received = capsule_frame(worker_transport.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, assignment_id);

    worker_transport
        .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: received.attempt_id,
            output: serde_json::json!({"status": "passed", "transport": "local_socket"}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        }))
        .await
        .unwrap();

    // Home receives the result.
    let msg = home_transport.recv().await.unwrap();
    match msg {
        WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: id,
            output,
            ..
        }) => {
            assert_eq!(id, assignment_id);
            assert_eq!(output["status"], "passed");
            assert_eq!(output["transport"], "local_socket");
        }
        other => panic!("expected Checkpoint, got {other:?}"),
    }
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn multi_worker_local_socket_home_accepts_multiple_workers() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("multi.sock");

    let listener = LocalSocketTransport::listen(&sock_path).unwrap();
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();

    // Connect two workers sequentially (each accept_next is independent).
    let path1 = sock_path.clone();
    let w1_handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        LocalSocketTransport::connect(&path1).await.unwrap()
    });
    let home1 = listener.accept_next().await.unwrap();
    let worker1 = w1_handle.await.unwrap();

    let home1: Arc<dyn WorkerTransport> = Arc::new(home1);
    supervisor.register_worker(SmolStr::new("ls-0"), Arc::clone(&home1));

    let path2 = sock_path.clone();
    let w2_handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        LocalSocketTransport::connect(&path2).await.unwrap()
    });
    let home2 = listener.accept_next().await.unwrap();
    let worker2 = w2_handle.await.unwrap();

    let home2: Arc<dyn WorkerTransport> = Arc::new(home2);
    supervisor.register_worker(SmolStr::new("ls-1"), Arc::clone(&home2));

    assert_eq!(supervisor.worker_count(), 2);

    // Dispatch to each worker by name.
    let a1 = sample_capsule_assignment();
    let a1_id = a1.attempt_id;
    supervisor
        .dispatch_to(
            &dispatch_authority,
            "ls-0",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(a1)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let a2 = sample_capsule_assignment();
    let a2_id = a2.attempt_id;
    supervisor
        .dispatch_to(
            &dispatch_authority,
            "ls-1",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(a2)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    // Worker 1 receives its assignment.
    let r1 = capsule_frame(worker1.recv_frame().await.unwrap());
    assert_eq!(r1.attempt_id, a1_id);
    worker1
        .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: r1.attempt_id,
            output: serde_json::json!({"from": "worker-1"}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        }))
        .await
        .unwrap();

    // Worker 2 receives its assignment.
    let r2 = capsule_frame(worker2.recv_frame().await.unwrap());
    assert_eq!(r2.attempt_id, a2_id);
    worker2
        .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: r2.attempt_id,
            output: serde_json::json!({"from": "worker-2"}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        }))
        .await
        .unwrap();

    // Home receives results from both.
    let msg1 = home1.recv().await.unwrap();
    match msg1 {
        WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id,
            output,
            ..
        }) => {
            assert_eq!(assignment_id, a1_id);
            assert_eq!(output["from"], "worker-1");
        }
        other => panic!("expected Checkpoint from worker-1, got {other:?}"),
    }

    let msg2 = home2.recv().await.unwrap();
    match msg2 {
        WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id,
            output,
            ..
        }) => {
            assert_eq!(assignment_id, a2_id);
            assert_eq!(output["from"], "worker-2");
        }
        other => panic!("expected Checkpoint from worker-2, got {other:?}"),
    }
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn multi_worker_local_socket_scheduler_dispatches_to_least_loaded_worker() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("scheduled-multi.sock");

    let listener = LocalSocketTransport::listen(&sock_path).unwrap();
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();

    let path1 = sock_path.clone();
    let w1_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        LocalSocketTransport::connect(&path1).await.unwrap()
    });
    let home1 = listener.accept_next().await.unwrap();
    let worker1 = w1_handle.await.unwrap();

    let home1: Arc<dyn WorkerTransport> = Arc::new(home1);
    supervisor.register_worker(SmolStr::new("ls-busy"), Arc::clone(&home1));

    let path2 = sock_path.clone();
    let w2_handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        LocalSocketTransport::connect(&path2).await.unwrap()
    });
    let home2 = listener.accept_next().await.unwrap();
    let worker2 = w2_handle.await.unwrap();

    let home2: Arc<dyn WorkerTransport> = Arc::new(home2);
    supervisor.register_worker(SmolStr::new("ls-idle"), Arc::clone(&home2));

    supervisor
        .get_worker("ls-busy")
        .unwrap()
        .active_assignments
        .store(7, Ordering::Relaxed);

    let heartbeat = Arc::new(HeartbeatMonitor::new(
        Duration::from_secs(30),
        Duration::from_secs(10),
    ));
    let scheduler = DispatchScheduler::new(Arc::clone(&supervisor), heartbeat);

    let assignment = sample_capsule_assignment();
    let assignment_id = assignment.attempt_id;
    let selected = scheduler.select_worker(&[]).unwrap();
    assert_eq!(selected, "ls-idle");
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

    let received = capsule_frame(worker2.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, assignment_id);

    let busy_recv = tokio::time::timeout(Duration::from_millis(30), worker1.recv_frame()).await;
    assert!(
        busy_recv.is_err(),
        "busy worker should not receive the least-loaded scheduler dispatch"
    );

    assert_eq!(
        supervisor
            .get_worker("ls-busy")
            .unwrap()
            .active_assignments
            .load(Ordering::Relaxed),
        7
    );
    assert_eq!(
        supervisor
            .get_worker("ls-idle")
            .unwrap()
            .active_assignments
            .load(Ordering::Relaxed),
        0,
        "scheduler placement is read-only; the checked workflow dispatcher \
         owns active-assignment mutation around transport sends"
    );
}

// ---------------------------------------------------------------------------
// WorkerSideTransport trait: generic worker interface
// ---------------------------------------------------------------------------

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn multi_worker_worker_side_transport_trait_with_local_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("trait_test.sock");

    let listener = LocalSocketTransport::listen(&sock_path).unwrap();

    let path_clone = sock_path.clone();
    let w_handle = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        LocalSocketTransport::connect(&path_clone).await.unwrap()
    });
    let home = listener.accept_next().await.unwrap();
    let worker = w_handle.await.unwrap();

    // Use the worker through the WorkerSideTransport trait.
    let worker_side: Arc<dyn WorkerSideTransport> = Arc::new(worker);

    // Home dispatches via WorkerTransport trait.
    let assignment = sample_capsule_assignment();
    let assignment_id = assignment.attempt_id;
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(assignment),
        ))
        .unwrap(),
    )
    .await
    .unwrap();

    // Worker receives via WorkerSideTransport trait.
    let received = capsule_frame(worker_side.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, assignment_id);

    // Worker sends result via WorkerSideTransport trait.
    worker_side
        .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: received.attempt_id,
            output: serde_json::json!({"via_trait": true}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        }))
        .await
        .unwrap();

    // Home receives via WorkerTransport trait.
    let msg = home.recv().await.unwrap();
    match msg {
        WorkerMessage::Checkpoint(StageCheckpoint { output, .. }) => {
            assert!(output["via_trait"].as_bool().unwrap());
        }
        other => panic!("expected Checkpoint, got {other:?}"),
    }
}

/// Unwrap the capsule arm of a received dispatch frame — the only arm left.
#[track_caller]
fn capsule_frame(
    frame: kata_transport::types::DispatchFrame,
) -> kata_transport::types::CapsuleAssignment {
    let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
    *capsule
}
