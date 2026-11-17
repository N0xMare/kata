//! Tests for crates/transport/src/in_process.rs. Extracted from the inline #[cfg(test)] module.

use kata_transport::types::{StageCheckpoint, WorkerMessage};
use kata_transport::{InProcessTransport, WorkerTransport};
use smol_str::SmolStr;
use ulid::Ulid;

fn test_assignment() -> kata_transport::types::CapsuleAssignment {
    let mut capsule = kata_test_utils::sample_capsule_assignment();
    capsule.attempt_id = Ulid::new();
    capsule.execution_id = Ulid::new();
    capsule
}

#[test]
fn pair_dispatch_and_receive_assignment() {
    kata_test_seeded::run_seeded("pair_dispatch_and_receive_assignment", |_ctx| async move {
        let (home, worker) = InProcessTransport::pair(8);
        let assignment = test_assignment();
        let expected_id = assignment.attempt_id;

        home.dispatch(
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let received = capsule_frame(worker.recv_frame().await.unwrap());
        assert_eq!(received.attempt_id, expected_id);
    });
}

#[test]
fn pair_send_result_and_receive() {
    kata_test_seeded::run_seeded("pair_send_result_and_receive", |_ctx| async move {
        let (home, worker) = InProcessTransport::pair(8);

        let msg = WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: Ulid::new(),
            output: serde_json::json!({"ok": true}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        });
        worker.send_result(msg).await.unwrap();

        let received = home.recv().await.unwrap();
        match received {
            WorkerMessage::Checkpoint(StageCheckpoint { output, .. }) => {
                assert_eq!(output, serde_json::json!({"ok": true}));
            }
            _ => panic!("expected Checkpoint message"),
        }
    });
}

#[test]
fn pair_roundtrip_assignment_and_result() {
    kata_test_seeded::run_seeded("pair_roundtrip_assignment_and_result", |_ctx| async move {
        let (home, worker) = InProcessTransport::pair(8);
        let assignment = test_assignment();
        let assignment_id = assignment.attempt_id;

        // Home dispatches assignment to worker.
        home.dispatch(
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let received = capsule_frame(worker.recv_frame().await.unwrap());
        assert_eq!(received.attempt_id, assignment_id);

        // Worker sends result back to home.
        let result = WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: received.attempt_id,
            output: serde_json::json!({"result": "done"}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        });
        worker.send_result(result).await.unwrap();

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
            _ => panic!("expected Checkpoint"),
        }
    });
}

#[test]
fn shutdown_marks_not_alive() {
    kata_test_seeded::run_seeded("shutdown_marks_not_alive", |_ctx| async move {
        let (home, _worker) = InProcessTransport::pair(8);
        assert!(home.is_alive());
        home.shutdown().await.unwrap();
        assert!(!home.is_alive());
    });
}

#[test]
fn dispatch_after_shutdown_fails() {
    kata_test_seeded::run_seeded("dispatch_after_shutdown_fails", |_ctx| async move {
        let (home, _worker) = InProcessTransport::pair(8);
        home.shutdown().await.unwrap();
        let result = home
            .dispatch(
                kata_transport::CheckedDispatchFrame::new(
                    kata_transport::types::DispatchFrame::Capsule(Box::new(test_assignment())),
                )
                .unwrap(),
            )
            .await;
        assert!(result.is_err());
    });
}

/// A task already inside `recv().await` must unblock with `Err` when the peer
/// side calls `shutdown()`. A shutdown that only flipped an `AtomicBool` would be
/// checked before each call enters `.await` — so a recv already awaiting would
/// block forever, and a reactor that won the race into `.await` before
/// `shutdown()` was observed would never see its worker die.
///
/// Uses `#[tokio::test]` rather than the `run_seeded` determinism harness
/// because the test needs real tokio spawn (commonware's deterministic
/// runtime doesn't drive `tokio::spawn`).
#[kata_test_utils::kata_timeout]
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_unblocks_in_flight_recv() {
    use std::sync::Arc;
    use std::time::Duration;

    let (home, worker) = InProcessTransport::pair(8);
    let home = Arc::new(home);
    let recv_handle = {
        let home = Arc::clone(&home);
        tokio::spawn(async move { home.recv().await })
    };

    // Yield so the recv task gets a chance to enter `.await` before
    // we shut down — this is the failure mode we're regressing.
    tokio::task::yield_now().await;
    worker.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), recv_handle)
        .await
        .expect("recv must unblock within 5s of peer shutdown")
        .expect("recv task must not panic");
    assert!(result.is_err(), "recv after peer shutdown must return Err");
}

/// A control frame crosses main→worker, and does NOT ride the
/// assignment channel.
///
/// # Why a separate channel is the property, not an implementation detail
///
/// A stop must be able to overtake queued assignments: the two share a
/// direction, not an ordering. A stop stuck behind a full dispatch buffer is a
/// stop that arrives after the stage it meant to end, which is indistinguishable
/// from no cancel at all. So this asserts BOTH that the control frame arrives
/// AND that nothing appeared on the assignment side — a single fused channel
/// would satisfy the first and fail the second.
///
/// # Counterfactual
///
/// Point `control_tx` at the assignment channel in `InProcessTransport::pair`
/// and `recv_control` blocks forever; the `kata_timeout` fires.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn in_process_carries_a_fenced_control_frame_on_its_own_channel() {
    use kata_transport::WorkerSideTransport;
    use kata_transport::types::{AttemptFence, WorkerControl};

    let (main_side, worker_side) = InProcessTransport::pair(4);
    let assignment_id = Ulid::new();
    let fence = AttemptFence::commanding(7, SmolStr::new("w-1"));

    main_side
        .send_control(WorkerControl::Stop {
            assignment_id,
            fence: fence.clone(),
            reason: "operator asked".into(),
        })
        .await
        .expect("the in-process transport really does carry control frames");

    let got = WorkerSideTransport::recv_control(&worker_side)
        .await
        .expect("the worker side receives it");
    let (got_id, got_fence) = got.fenced_attempt().expect("stop carries an attempt fence");
    assert_eq!(
        got_id, assignment_id,
        "the stop names the attempt it is for"
    );
    assert_eq!(
        got_fence, &fence,
        "the fence crosses intact — an unfenced stop is a cross-generation kill"
    );

    // The assignment channel is untouched: a stop is not an assignment, and it
    // must not consume a dispatch slot.
    let starved = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        WorkerSideTransport::recv_frame(&worker_side),
    )
    .await;
    assert!(
        starved.is_err(),
        "no assignment must appear from a control send; a fused channel would deliver one here"
    );
}

/// The socket transports refuse control SYMMETRICALLY, and say why.
///
/// Their `send_control` is the trait's defaulted refusal and their
/// `recv_control` is its mirror, so the capability is unoffered in BOTH
/// directions rather than half-present. A transport that accepted a stop it
/// cannot deliver would let `cancel` claim it stopped something it never
/// reached.
#[tokio::test]
async fn a_transport_that_cannot_carry_control_refuses_rather_than_accepting() {
    use kata_transport::types::{AttemptFence, WorkerControl};

    struct NoControl;

    #[async_trait::async_trait]
    impl WorkerTransport for NoControl {
        async fn dispatch(
            &self,
            _a: kata_transport::types::CheckedDispatchFrame,
        ) -> kata_types::error::KataResult<()> {
            Ok(())
        }
        async fn recv(&self) -> kata_types::error::KataResult<WorkerMessage> {
            unreachable!("not exercised")
        }
        async fn shutdown(&self) -> kata_types::error::KataResult<()> {
            Ok(())
        }
        fn is_alive(&self) -> bool {
            true
        }
        fn peer_pid(&self) -> Option<u32> {
            None
        }
        fn kind(&self) -> &'static str {
            "no_control"
        }
    }

    let err = NoControl
        .send_control(WorkerControl::Stop {
            assignment_id: Ulid::new(),
            fence: AttemptFence::commanding(1, SmolStr::new("w-1")),
            reason: String::new(),
        })
        .await
        .expect_err("the DEFAULT must refuse, never silently succeed");
    assert!(
        err.to_string().contains("does not carry"),
        "the refusal names the gap instead of pretending the stop landed: {err}"
    );
}

/// Unwrap the capsule arm of a received dispatch frame — the only arm left.
#[track_caller]
fn capsule_frame(
    frame: kata_transport::types::DispatchFrame,
) -> kata_transport::types::CapsuleAssignment {
    let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
    *capsule
}
