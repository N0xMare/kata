//! Integration test: `WorkerPoolSupervisor` managing multiple transport types.
//!
//! Registers InProcess and LocalSocket workers (each a distinct transport
//! implementation) in the same supervisor, dispatches assignments to each,
//! and verifies all complete correctly. This exercises the supervisor's
//! polymorphic dispatch over `Arc<dyn WorkerTransport>`.

use kata_test_utils::sample_capsule_assignment;
use std::sync::Arc;

use kata_transport::types::{StageCheckpoint, WorkerMessage};
use kata_transport::{
    InProcessTransport, LocalSocketTransport, WorkerPoolSupervisor, WorkerTransport,
};
use smol_str::SmolStr;

/// Helper: spin up a LocalSocket bind+connect pair.
async fn local_socket_pair(
    dir: &std::path::Path,
    name: &str,
) -> (LocalSocketTransport, LocalSocketTransport) {
    let sock_path = dir.join(format!("{name}.sock"));
    let path_clone = sock_path.clone();

    let bind_handle = tokio::spawn(async move { LocalSocketTransport::bind(&path_clone).await });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let worker = LocalSocketTransport::connect(&sock_path).await.unwrap();
    let home = bind_handle.await.unwrap().unwrap();
    (home, worker)
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn supervisor_manages_multiple_transport_types() {
    let dir = tempfile::tempdir().unwrap();
    let supervisor = WorkerPoolSupervisor::new();
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();

    // Register an InProcess worker.
    let (ip_home, ip_worker) = InProcessTransport::pair(8);
    supervisor.register_worker(SmolStr::new("in-process"), Arc::new(ip_home));

    // Register a LocalSocket worker.
    let (ls_home, ls_worker) = local_socket_pair(dir.path(), "ls").await;
    supervisor.register_worker(SmolStr::new("local-socket"), Arc::new(ls_home));

    assert_eq!(supervisor.worker_count(), 2);

    // Dispatch to the InProcess worker by name.
    let ip_assignment = sample_capsule_assignment();
    let ip_id = ip_assignment.attempt_id;
    supervisor
        .dispatch_to(
            &dispatch_authority,
            "in-process",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(ip_assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    // Dispatch to the LocalSocket worker by name.
    let ls_assignment = sample_capsule_assignment();
    let ls_id = ls_assignment.attempt_id;
    supervisor
        .dispatch_to(
            &dispatch_authority,
            "local-socket",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(ls_assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    // InProcess worker receives and completes.
    let received = capsule_frame(ip_worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, ip_id);
    ip_worker
        .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: received.attempt_id,
            output: serde_json::json!({"transport": "in-process"}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        }))
        .await
        .unwrap();

    // LocalSocket worker receives and completes.
    let received = capsule_frame(ls_worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, ls_id);
    ls_worker
        .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: received.attempt_id,
            output: serde_json::json!({"transport": "local-socket"}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        }))
        .await
        .unwrap();
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn supervisor_dispatch_to_specific_worker() {
    let dir = tempfile::tempdir().unwrap();
    let supervisor = WorkerPoolSupervisor::new();
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();

    let (ip_home, ip_worker) = InProcessTransport::pair(8);
    supervisor.register_worker(SmolStr::new("in-process"), Arc::new(ip_home));

    let (ls_home, ls_worker) = local_socket_pair(dir.path(), "specific").await;
    supervisor.register_worker(SmolStr::new("local-socket"), Arc::new(ls_home));

    // Dispatch specifically to local-socket.
    let assignment = sample_capsule_assignment();
    let expected_id = assignment.attempt_id;
    supervisor
        .dispatch_to(
            &dispatch_authority,
            "local-socket",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let received = capsule_frame(ls_worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, expected_id);

    // In-process worker should NOT have received anything.
    // Use a short timeout to confirm.
    let timeout_result =
        tokio::time::timeout(std::time::Duration::from_millis(50), ip_worker.recv_frame()).await;
    assert!(
        timeout_result.is_err(),
        "in-process worker should not receive the assignment"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn supervisor_skips_dead_to_healthy() {
    let dir = tempfile::tempdir().unwrap();
    let supervisor = WorkerPoolSupervisor::new();
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();

    // Dead InProcess worker.
    let (dead_home, _dead_worker) = InProcessTransport::pair(8);
    dead_home.shutdown().await.unwrap();
    supervisor.register_worker(SmolStr::new("dead-ip"), Arc::new(dead_home));

    // Healthy LocalSocket worker.
    let (ls_home, ls_worker) = local_socket_pair(dir.path(), "healthy").await;
    supervisor.register_worker(SmolStr::new("healthy-ls"), Arc::new(ls_home));

    // Explicit supervisor dispatch sends to the healthy worker selected by the
    // higher-level scheduler/dispatcher layer.
    let assignment = sample_capsule_assignment();
    let expected_id = assignment.attempt_id;
    supervisor
        .dispatch_to(
            &dispatch_authority,
            "healthy-ls",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let received = capsule_frame(ls_worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, expected_id);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn supervisor_full_roundtrip_mixed_transports() {
    let dir = tempfile::tempdir().unwrap();
    let supervisor = WorkerPoolSupervisor::new();
    let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();

    // InProcess pair.
    let (ip_home, ip_worker) = InProcessTransport::pair(8);
    let ip_home: Arc<dyn WorkerTransport> = Arc::new(ip_home);
    supervisor.register_worker(SmolStr::new("in-process"), Arc::clone(&ip_home));

    // LocalSocket pair.
    let (ls_home, ls_worker) = local_socket_pair(dir.path(), "roundtrip").await;
    let ls_home: Arc<dyn WorkerTransport> = Arc::new(ls_home);
    supervisor.register_worker(SmolStr::new("local-socket"), Arc::clone(&ls_home));

    // Dispatch and complete through InProcess.
    let ip_assignment = sample_capsule_assignment();
    let ip_id = ip_assignment.attempt_id;

    let ip_handle = tokio::spawn(async move {
        let received = capsule_frame(ip_worker.recv_frame().await.unwrap());
        ip_worker
            .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id: received.attempt_id,
                output: serde_json::json!({"from": "in-process"}),
                stage_name: "fixture".into(),
                sequence: 1,
                fence: kata_transport::AttemptFence::default(),
            }))
            .await
            .unwrap();
    });

    supervisor
        .dispatch_to(
            &dispatch_authority,
            "in-process",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(ip_assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let msg = ip_home.recv().await.unwrap();
    match msg {
        WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id,
            output,
            ..
        }) => {
            assert_eq!(assignment_id, ip_id);
            assert_eq!(output["from"], "in-process");
        }
        other => panic!("expected Checkpoint from in-process, got {other:?}"),
    }
    ip_handle.await.unwrap();

    // Dispatch and complete through LocalSocket.
    let ls_assignment = sample_capsule_assignment();
    let ls_id = ls_assignment.attempt_id;

    let ls_handle = tokio::spawn(async move {
        let received = capsule_frame(ls_worker.recv_frame().await.unwrap());
        ls_worker
            .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id: received.attempt_id,
                output: serde_json::json!({"from": "local-socket"}),
                stage_name: "fixture".into(),
                sequence: 1,
                fence: kata_transport::AttemptFence::default(),
            }))
            .await
            .unwrap();
    });

    supervisor
        .dispatch_to(
            &dispatch_authority,
            "local-socket",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(ls_assignment)),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let msg = ls_home.recv().await.unwrap();
    match msg {
        WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id,
            output,
            ..
        }) => {
            assert_eq!(assignment_id, ls_id);
            assert_eq!(output["from"], "local-socket");
        }
        other => panic!("expected Checkpoint from local-socket, got {other:?}"),
    }
    ls_handle.await.unwrap();
}

// ---------------------------------------------------------------------------
// A saturated queue is a CAPACITY event, and the supervisor must not
// read one as a death.
// ---------------------------------------------------------------------------

/// ONE OPERATOR CANCEL of a wide execution must not cost the supervisor the
/// worker it was cancelling on.
///
/// `WorkflowExecutor::cancel` issues one `send_control_to` per non-terminal
/// attempt, back to back, so a single cancel of an N-attempt execution puts N
/// stop frames on one connection — the demand scales with LIVE ATTEMPTS, not
/// with how many times an operator pressed cancel. If crossing a flat bound (say
/// 16) killed the connection, the supervisor would read a healthy worker as a
/// corpse, and `Dispatcher::handle_worker_death` would settle every live
/// attempt it held as lost (PROVEN AMBIGUOUS) — a cancel would cost the worker
/// and every attempt on it.
///
/// This walks the links that must NOT break, through the supervisor's own send
/// path rather than the transport's:
///
///   flood far past the bound → every send is accepted → the worker is still
///   live → `dispatch_to` still places work → the worker's frames still
///   reach the main → the supervisor's inventory still lists it alive.
///
/// # Counterfactual
///
/// At the previous basis the 17th stop terminated the reader; the connection
/// died, the dispatch below would refuse with "not alive", and the inventory
/// would list `ls-cancel-burst` dead.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_cancel_burst_wider_than_the_control_bound_does_not_cost_the_supervisor_its_worker() {
    use kata_transport::WorkerSideTransport;
    use kata_transport::types::WorkerControl;

    /// Past `CONTROL_QUEUE_DEPTH` (256 + 1) by enough that the drop path runs.
    const STOPS: usize = 400;

    let dir = tempfile::tempdir().unwrap();
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let authority = supervisor.claim_dispatch_authority().unwrap();

    let (ls_home, ls_worker) = local_socket_pair(dir.path(), "cancel-burst").await;
    let ls_home = Arc::new(ls_home);
    supervisor.register_worker(
        SmolStr::new("ls-cancel-burst"),
        Arc::clone(&ls_home) as Arc<dyn WorkerTransport>,
    );
    assert_eq!(
        live_inventory(&supervisor),
        vec!["ls-cancel-burst".to_owned()]
    );

    // One cancel of a very wide execution: one stop per live attempt, each a
    // DISTINCT attempt, so none of them coalesce. Not spawned — the send path
    // must not park, which is itself part of the claim.
    for _ in 0..STOPS {
        supervisor
            .send_control_to(
                "ls-cancel-burst",
                WorkerControl::Stop {
                    assignment_id: ulid::Ulid::new(),
                    fence: kata_transport::AttemptFence::default(),
                    reason: "operator cancelled a wide execution".to_string(),
                },
            )
            .await
            .expect("a cancel wider than the control bound must not fail the operator's ask");
    }

    // 1. The worker end is still live, and the stops that fit are readable.
    assert!(WorkerSideTransport::is_alive(&ls_worker));
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), ls_worker.recv_control())
        .await
        .expect("a stop must be readable")
        .expect("the connection must survive a cancel burst");
    assert!(matches!(first, WorkerControl::Stop { .. }));

    // 2. The supervisor can still place work on it.
    let assignment = sample_capsule_assignment();
    let assignment_id = assignment.attempt_id;
    supervisor
        .dispatch_to(
            &authority,
            "ls-cancel-burst",
            kata_transport::CheckedDispatchFrame::new(
                kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
            )
            .unwrap(),
        )
        .await
        .expect("a worker that absorbed a cancel burst is still dispatchable");
    let received = capsule_frame(ls_worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, assignment_id);

    // 3. And its frames still reach the main.
    ls_worker
        .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id,
            output: serde_json::json!({"from": "local-socket"}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        }))
        .await
        .unwrap();
    match ls_home.recv().await.unwrap() {
        WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: got, ..
        }) => assert_eq!(got, assignment_id),
        other => panic!("expected Checkpoint, got {other:?}"),
    }

    // 4. The supervisor still holds the worker, alive: nothing died.
    assert_eq!(
        live_inventory(&supervisor),
        vec!["ls-cancel-burst".to_owned()]
    );
}

/// The ids of the supervisor's registered workers whose transport reports alive.
fn live_inventory(supervisor: &WorkerPoolSupervisor) -> Vec<String> {
    let inventory = supervisor.worker_inventory();
    assert!(
        inventory.iter().all(|worker| worker.alive),
        "every registered worker must be alive: {inventory:?}"
    );
    inventory.into_iter().map(|worker| worker.id).collect()
}

/// Unwrap the capsule arm of a received dispatch frame — the only arm left.
#[track_caller]
fn capsule_frame(
    frame: kata_transport::types::DispatchFrame,
) -> kata_transport::types::CapsuleAssignment {
    let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
    *capsule
}
