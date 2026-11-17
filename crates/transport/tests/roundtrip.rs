//! Integration test: transport roundtrip exercises the full
//! home-worker communication path.
//!
//! Exercises cross-crate connections between `kata-transport`
//! (InProcessTransport, WorkerPoolSupervisor, WorkerTransport) and
//! `kata-types` (the wire types the transport layer frames).
//!
//! Tests that don't require `tokio::spawn` are wrapped in `run_seeded`
//! for deterministic execution. Tests that use `tokio::spawn` for a
//! background worker task remain `#[tokio::test]` because the commonware
//! deterministic runner does not provide spawn compatibility.

use kata_test_utils::sample_capsule_assignment;
use std::sync::Arc;

use kata_test_seeded::run_seeded;
use kata_transport::types::{StageCheckpoint, WorkerMessage};
use kata_transport::{InProcessTransport, WorkerPoolSupervisor, WorkerTransport};
use smol_str::SmolStr;

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn in_process_transport_full_workflow_flow() {
    // 1. Create InProcessTransport::pair.
    let (home_side, worker_side) = InProcessTransport::pair(16);

    // 2. Create WorkerPoolSupervisor, register home side.
    let supervisor = WorkerPoolSupervisor::new();
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
    supervisor.register_worker(SmolStr::new("embedded"), Arc::new(home_side));

    // 3. Spawn task that reads from worker side, executes, sends result.
    let worker_handle = tokio::spawn(async move {
        let assignment = capsule_frame(worker_side.recv_frame().await.unwrap());
        let output = serde_json::json!({"completed": assignment.attempt_id.to_string()});
        worker_side
            .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id: assignment.attempt_id,
                output,
                stage_name: "fixture".into(),
                sequence: 1,
                fence: kata_transport::AttemptFence::default(),
            }))
            .await
            .expect("send result back to home");
    });

    // 4. Dispatch assignment through supervisor.
    let assignment = sample_capsule_assignment();
    supervisor
        .dispatch_to(
            &dispatch_authority,
            "embedded",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .expect("dispatch should succeed");

    // 5. Receive completion on home side -- need direct access for recv.
    // Since supervisor doesn't have recv(), we test the pair directly below.
    worker_handle.await.expect("worker task should complete");
}

#[test]
fn in_process_transport_pair_roundtrip() {
    run_seeded("in_process_transport_pair_roundtrip", |_ctx| async move {
        let (home, worker) = InProcessTransport::pair(16);

        // Home dispatches assignment to worker.
        let assignment = sample_capsule_assignment();
        let assignment_id = assignment.attempt_id;
        home.dispatch(
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

        // Worker reads assignment.
        let received = capsule_frame(worker.recv_frame().await.unwrap());
        assert_eq!(received.attempt_id, assignment_id);

        // Worker sends result back.
        worker
            .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id: received.attempt_id,
                output: serde_json::json!({"result": "done"}),
                stage_name: "fixture".into(),
                sequence: 1,
                fence: kata_transport::AttemptFence::default(),
            }))
            .await
            .unwrap();

        // Home receives result.
        let msg = home.recv().await.unwrap();
        match msg {
            WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id: id,
                output,
                ..
            }) => {
                assert_eq!(id, assignment_id);
                assert_eq!(output, serde_json::json!({"result": "done"}));
            }
            _ => panic!("expected Checkpoint message"),
        }
    });
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn in_process_transport_multiple_assignments() {
    let (home, worker) = InProcessTransport::pair(16);

    // Spawn worker that processes all assignments.
    let worker_handle = tokio::spawn(async move {
        for _ in 0..3 {
            let assignment = capsule_frame(worker.recv_frame().await.unwrap());
            worker
                .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                    assignment_id: assignment.attempt_id,
                    output: serde_json::json!({"done": assignment.attempt_id.to_string()}),
                    stage_name: "fixture".into(),
                    sequence: 1,
                    fence: kata_transport::AttemptFence::default(),
                }))
                .await
                .unwrap();
        }
    });

    // Send three assignments sequentially.
    let mut ids = Vec::new();
    for _ in 0..3 {
        let assignment = sample_capsule_assignment();
        ids.push(assignment.attempt_id);
        home.dispatch(
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .expect("dispatch");
    }

    // Receive all three results.
    let mut results = Vec::new();
    for _ in 0..3 {
        results.push(home.recv().await.expect("recv"));
    }

    assert_eq!(results.len(), 3);
    // Results arrive in order for a single-threaded worker.
    for (i, result) in results.iter().enumerate() {
        match result {
            WorkerMessage::Checkpoint(StageCheckpoint { assignment_id, .. }) => {
                assert_eq!(*assignment_id, ids[i]);
            }
            _ => panic!("expected Checkpoint"),
        }
    }

    worker_handle.await.expect("worker done");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn in_process_transport_worker_failure() {
    let (home, worker) = InProcessTransport::pair(16);

    let worker_handle = tokio::spawn(async move {
        let assignment = capsule_frame(worker.recv_frame().await.unwrap());
        worker
            .send_result(WorkerMessage::Failed {
                assignment_id: assignment.attempt_id,
                reason: "out of memory".to_string(),
                verdict: kata_types::effect::DeliveryFailureProvenance::Unclassified,
                provider_failure: None,
                fence: kata_transport::AttemptFence::default(),
                usage: None,
            })
            .await
            .unwrap();
    });

    let assignment = sample_capsule_assignment();
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(assignment),
        ))
        .unwrap(),
    )
    .await
    .expect("dispatch");

    let result = home.recv().await.expect("recv");
    match result {
        WorkerMessage::Failed { reason, .. } => {
            assert_eq!(reason, "out of memory");
        }
        _ => panic!("expected Failed message"),
    }

    worker_handle.await.expect("worker done");
}

/// Unwrap the capsule arm of a received dispatch frame — the only arm left.
#[track_caller]
fn capsule_frame(
    frame: kata_transport::types::DispatchFrame,
) -> kata_transport::types::CapsuleAssignment {
    let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
    *capsule
}
