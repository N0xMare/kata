//! Integration test: `LocalSocketTransport` full workflow flow.
//!
//! Exercises the Unix domain socket transport across a bind/connect pair,
//! dispatching a `DispatchFrame::Capsule` and collecting a
//! `WorkerMessage::Checkpoint` result — the same flow that happens
//! between a main and a worker process on the same host.

use kata_test_utils::sample_capsule_assignment;
use kata_transport::types::{StageCheckpoint, WorkerMessage};
use kata_transport::{LocalSocketTransport, WorkerTransport};

/// Helper: spin up a bind+connect pair using a tempdir socket.
async fn connected_pair(dir: &std::path::Path) -> (LocalSocketTransport, LocalSocketTransport) {
    let sock_path = dir.join("test.sock");
    let path_clone = sock_path.clone();

    let bind_handle = tokio::spawn(async move { LocalSocketTransport::bind(&path_clone).await });

    // Give the listener a moment to start before connecting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let worker = LocalSocketTransport::connect(&sock_path).await.unwrap();
    let home = bind_handle.await.unwrap().unwrap();

    (home, worker)
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn local_socket_full_workflow_flow() {
    // 1. Create tempdir for socket.
    let dir = tempfile::tempdir().unwrap();

    // 2. Bind home side and connect worker side.
    let (home, worker) = connected_pair(dir.path()).await;

    let assignment = sample_capsule_assignment();
    let assignment_id = assignment.attempt_id;
    let execution_id = assignment.execution_id;

    // 3. Spawn worker task: receive assignment, process, send result.
    let worker_handle = tokio::spawn(async move {
        // 5. Receive on worker side.
        let received = capsule_frame(worker.recv_frame().await.unwrap());
        assert_eq!(received.attempt_id, assignment_id);
        assert_eq!(received.attempt_id, assignment.attempt_id);
        assert_eq!(received.execution_id, execution_id);

        // 6. Send result back.
        worker
            .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id: received.attempt_id,
                output: serde_json::json!({
                    "stage": received.attempt_id.to_string().as_str(),
                    "status": "passed"
                }),
                stage_name: "fixture".into(),
                sequence: 1,
                fence: kata_transport::AttemptFence::default(),
            }))
            .await
            .unwrap();
    });

    // 4. Dispatch assignment through home side.
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(assignment),
        ))
        .unwrap(),
    )
    .await
    .unwrap();

    // 7. Receive completion on home side.
    let msg = home.recv().await.unwrap();

    // 8. Assert result.
    match msg {
        WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: id,
            output,
            ..
        }) => {
            assert_eq!(id, assignment_id);
            assert_eq!(output["stage"], assignment_id.to_string().as_str());
            assert_eq!(output["status"], "passed");
        }
        other => panic!("expected Checkpoint, got {other:?}"),
    }

    worker_handle.await.unwrap();

    // Verify both sides are still alive after a clean exchange.
    assert!(home.is_alive());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn local_socket_multiple_stages_in_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    let mut ids = Vec::new();
    for _ in 0..3 {
        let a = sample_capsule_assignment();
        ids.push(a.attempt_id);
        home.dispatch(
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(a)),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    }

    // Worker receives and completes each in order.
    for (i, _) in ids.iter().enumerate() {
        let received = capsule_frame(worker.recv_frame().await.unwrap());
        assert_eq!(received.attempt_id, ids[i]);

        worker
            .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id: received.attempt_id,
                output: serde_json::json!({"seq": i}),
                stage_name: "fixture".into(),
                sequence: 1,
                fence: kata_transport::AttemptFence::default(),
            }))
            .await
            .unwrap();
    }

    // Home receives all results in order.
    for (i, expected_id) in ids.iter().enumerate() {
        let msg = home.recv().await.unwrap();
        match msg {
            WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id,
                output,
                ..
            }) => {
                assert_eq!(assignment_id, *expected_id);
                assert_eq!(output["seq"], i);
            }
            other => panic!("expected Checkpoint, got {other:?}"),
        }
    }
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn local_socket_checkpoint_then_complete() {
    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    let assignment = sample_capsule_assignment();
    let assignment_id = assignment.attempt_id;

    let worker_handle = tokio::spawn(async move {
        let received = capsule_frame(worker.recv_frame().await.unwrap());

        // Send two intermediate checkpoints.
        for seq in 0..2 {
            worker
                .send_result(WorkerMessage::Checkpoint(
                    kata_transport::types::StageCheckpoint {
                        assignment_id: received.attempt_id,
                        stage_name: smol_str::SmolStr::new(received.attempt_id.to_string()),
                        output: serde_json::json!({"progress": seq}),
                        sequence: seq,
                        fence: kata_transport::AttemptFence::default(),
                    },
                ))
                .await
                .unwrap();
        }

        // Then complete.
        worker
            .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id: received.attempt_id,
                output: serde_json::json!({"final": true}),
                stage_name: "fixture".into(),
                sequence: 1,
                fence: kata_transport::AttemptFence::default(),
            }))
            .await
            .unwrap();
    });

    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(assignment),
        ))
        .unwrap(),
    )
    .await
    .unwrap();

    // Expect checkpoint 0, checkpoint 1, then completed.
    for seq in 0..2 {
        let msg = home.recv().await.unwrap();
        match msg {
            WorkerMessage::Checkpoint(cp) => {
                assert_eq!(cp.assignment_id, assignment_id);
                assert_eq!(cp.sequence, seq);
            }
            other => panic!("expected Checkpoint, got {other:?}"),
        }
    }

    let msg = home.recv().await.unwrap();
    match msg {
        WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: id,
            output,
            ..
        }) => {
            assert_eq!(id, assignment_id);
            assert!(output["final"].as_bool().unwrap());
        }
        other => panic!("expected Checkpoint, got {other:?}"),
    }

    worker_handle.await.unwrap();
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn local_socket_worker_failure_flow() {
    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    let assignment = sample_capsule_assignment();
    let assignment_id = assignment.attempt_id;

    let worker_handle = tokio::spawn(async move {
        let received = capsule_frame(worker.recv_frame().await.unwrap());
        worker
            .send_result(WorkerMessage::Failed {
                assignment_id: received.attempt_id,
                reason: "sandbox violation".into(),
                verdict: kata_types::effect::DeliveryFailureProvenance::Unclassified,
                provider_failure: None,
                fence: kata_transport::AttemptFence::default(),
                usage: None,
            })
            .await
            .unwrap();
    });

    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(assignment),
        ))
        .unwrap(),
    )
    .await
    .unwrap();

    let msg = home.recv().await.unwrap();
    match msg {
        WorkerMessage::Failed {
            assignment_id: id,
            reason,
            ..
        } => {
            assert_eq!(id, assignment_id);
            assert_eq!(reason, "sandbox violation");
        }
        other => panic!("expected Failed, got {other:?}"),
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
