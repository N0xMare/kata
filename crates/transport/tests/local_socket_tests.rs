//! Tests for crates/transport/src/local_socket.rs. Extracted from the inline #[cfg(test)] module.

// NOTE: All LocalSocket tests remain #[tokio::test] because they use
// tokio::spawn for bind/connect coordination, tokio::time::sleep for
// listener startup delay, and real Unix domain socket I/O.

use std::os::unix::fs::FileTypeExt;

use kata_transport::types::{StageCheckpoint, WorkerMessage};
use kata_transport::{LocalSocketTransport, WorkerSideTransport, WorkerTransport};
use ulid::Ulid;

fn test_assignment() -> kata_transport::types::CapsuleAssignment {
    let mut capsule = kata_test_utils::sample_capsule_assignment();
    capsule.attempt_id = Ulid::new();
    capsule.execution_id = Ulid::new();
    capsule
}

/// Helper: spin up a bind+connect pair using a tempdir socket.
async fn connected_pair(dir: &std::path::Path) -> (LocalSocketTransport, LocalSocketTransport) {
    let sock_path = dir.join("test.sock");
    let path_clone = sock_path.clone();

    // Spawn bind in a task so connect can proceed concurrently.
    let bind_handle = tokio::spawn(async move { LocalSocketTransport::bind(&path_clone).await });

    // Give the listener a moment to start before connecting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let worker = LocalSocketTransport::connect(&sock_path).await.unwrap();
    let home = bind_handle.await.unwrap().unwrap();

    (home, worker)
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn bind_connect_dispatch_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    let assignment = test_assignment();
    let expected_id = assignment.attempt_id;

    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(assignment),
        ))
        .unwrap(),
    )
    .await
    .unwrap();
    let received = capsule_frame(worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, expected_id);
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn send_result_and_receive() {
    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

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
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn full_roundtrip_assignment_and_result() {
    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    let assignment = test_assignment();
    let assignment_id = assignment.attempt_id;

    // Home dispatches assignment to worker.
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(assignment),
        ))
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
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn multiple_messages_in_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    // Dispatch three assignments.
    let mut ids = Vec::new();
    for _ in 0..3 {
        let a = test_assignment();
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

    // Receive all three on the worker side.
    for expected_id in &ids {
        let received = capsule_frame(worker.recv_frame().await.unwrap());
        assert_eq!(received.attempt_id, *expected_id);
    }

    // Worker sends three results.
    for id in &ids {
        let msg = WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: *id,
            output: serde_json::json!({"id": id.to_string()}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        });
        worker.send_result(msg).await.unwrap();
    }

    // Home receives all three results.
    for id in &ids {
        let msg = home.recv().await.unwrap();
        match msg {
            WorkerMessage::Checkpoint(StageCheckpoint {
                assignment_id,
                output,
                ..
            }) => {
                assert_eq!(assignment_id, *id);
                assert_eq!(output["id"], id.to_string());
            }
            _ => panic!("expected Checkpoint"),
        }
    }
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn shutdown_marks_not_alive() {
    let dir = tempfile::tempdir().unwrap();
    let (home, _worker) = connected_pair(dir.path()).await;

    assert!(home.is_alive());
    home.shutdown().await.unwrap();
    assert!(!home.is_alive());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn dispatch_after_shutdown_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (home, _worker) = connected_pair(dir.path()).await;

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
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn both_sides_shutdown_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    home.shutdown().await.unwrap();
    worker.shutdown().await.unwrap();

    assert!(!home.is_alive());
    assert!(!worker.is_alive());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn peer_eof_marks_other_side_dead_for_supervisor_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;
    assert!(home.is_alive());

    worker.shutdown().await.unwrap();
    let error = home
        .recv()
        .await
        .expect_err("peer EOF must terminate receive");
    assert!(error.to_string().contains("connection closed"), "{error}");
    assert!(
        !home.is_alive(),
        "a peer-closed local socket must not remain eligible for dispatch"
    );
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn stale_socket_cleanup_on_bind() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("stale.sock");

    // Create a stale Unix domain socket at the target path, leave it
    // there, and confirm it's actually a socket before proceeding.
    // Using a dropped listener is the standard way to produce a
    // socket-typed filesystem entry that is no longer bound to any
    // listener.
    {
        let _stale_listener = kata_transport::unix_socket::bind_tokio(&sock_path).unwrap();
        // Drop at end of scope — the socket file remains on disk.
    }
    assert!(sock_path.exists());
    let md = std::fs::symlink_metadata(&sock_path).unwrap();
    assert!(
        md.file_type().is_socket(),
        "precondition: stale entry must be a real socket"
    );

    // bind should remove the stale socket and succeed.
    let path_clone = sock_path.clone();
    let bind_handle = tokio::spawn(async move { LocalSocketTransport::bind(&path_clone).await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let worker = LocalSocketTransport::connect(&sock_path).await.unwrap();
    let home = bind_handle.await.unwrap().unwrap();

    // Verify the connection works.
    let assignment = test_assignment();
    let expected_id = assignment.attempt_id;
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(assignment),
        ))
        .unwrap(),
    )
    .await
    .unwrap();
    let received = capsule_frame(worker.recv_frame().await.unwrap());
    assert_eq!(received.attempt_id, expected_id);
}

// -- cleanup_stale_socket safety regression tests -----------------------
//
// `bind()` / `listen()` must never `rm -f` an arbitrary file at the
// socket path — an operator typo in config pointing at
// `/home/alice/important.db` would delete that file. Only actual Unix
// domain sockets are unlinked; everything else is a hard error, and the
// offending file is left untouched.

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn bind_refuses_to_delete_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let regular_file = dir.path().join("important.db");
    std::fs::write(&regular_file, b"precious data").unwrap();

    let result = LocalSocketTransport::bind(&regular_file).await;
    assert!(
        result.is_err(),
        "bind must fail when the target path is a regular file"
    );

    // The file MUST still exist, with its contents intact.
    assert!(regular_file.exists(), "bind must not delete regular files");
    let contents = std::fs::read(&regular_file).unwrap();
    assert_eq!(contents, b"precious data");
}

#[test]
fn listen_refuses_to_delete_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let regular_file = dir.path().join("important.db");
    std::fs::write(&regular_file, b"precious data").unwrap();

    let result = LocalSocketTransport::listen(&regular_file);
    assert!(
        result.is_err(),
        "listen must fail when the target path is a regular file"
    );

    assert!(
        regular_file.exists(),
        "listen must not delete regular files"
    );
    let contents = std::fs::read(&regular_file).unwrap();
    assert_eq!(contents, b"precious data");
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn bind_refuses_to_delete_directory() {
    let dir = tempfile::tempdir().unwrap();
    let subdir = dir.path().join("config-dir");
    std::fs::create_dir(&subdir).unwrap();
    let sentinel = subdir.join("sentinel.txt");
    std::fs::write(&sentinel, b"dir contents").unwrap();

    let result = LocalSocketTransport::bind(&subdir).await;
    assert!(
        result.is_err(),
        "bind must fail when the target path is a directory"
    );

    // Directory and its contents must still be there.
    assert!(subdir.is_dir());
    assert!(sentinel.exists());
}

#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn bind_refuses_to_delete_symlink_to_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.txt");
    std::fs::write(&target, b"symlink target").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let result = LocalSocketTransport::bind(&link).await;
    assert!(
        result.is_err(),
        "bind must fail when the target path is a symlink"
    );

    // Both the symlink and its target must survive.
    assert!(std::fs::symlink_metadata(&link).is_ok());
    assert!(target.exists());
    let contents = std::fs::read(&target).unwrap();
    assert_eq!(contents, b"symlink target");
}

// -- main->worker CONTROL frames over the local socket -------------------
//
// This transport delivers control frames, so the cells below assert DELIVERY.

/// An `AttemptFence` whose `lease_epoch` is `epoch`, built through the public
/// constructor so the tests do not depend on the struct's field order.
fn fence_at(epoch: i64) -> kata_transport::AttemptFence {
    kata_transport::AttemptFence {
        lease_epoch: epoch,
        ..Default::default()
    }
}

/// Bound the reader applies to the worker-side assignment queue. Mirrors
/// `ASSIGNMENT_QUEUE_DEPTH`, which is private; the tests that cross it say so by
/// exceeding this number, and any drift shows up as a red rather than a silently
/// weaker test.
const ASSIGNMENT_BOUND: usize = 256;

/// Bound the reader applies to the worker-side control queue: one undischarged
/// stop for every attempt the connection can hold. Mirrors
/// `CONTROL_QUEUE_DEPTH` (= `ASSIGNMENT_QUEUE_DEPTH + 1`).
const CONTROL_BOUND: usize = ASSIGNMENT_BOUND + 1;

/// Read one control frame, or report that none is available.
///
/// `recv_control` is cancel-safe by contract, so dropping the future on a
/// timeout loses nothing — which is exactly what makes "no stop is available"
/// an observable, non-destructive fact.
async fn next_stop_within(
    transport: &LocalSocketTransport,
    millis: u64,
) -> Option<kata_transport::types::WorkerControl> {
    tokio::time::timeout(
        std::time::Duration::from_millis(millis),
        transport.recv_control(),
    )
    .await
    .ok()
    .map(|frame| frame.expect("the connection must stay alive"))
}

/// THE LOAD-BEARING ONE. A stop must be readable while nothing is reading
/// assignments — because that is the worker loop's exact state during a running
/// stage, and it is the state a stop exists for.
///
/// `LocalSocketTransport::send_control` must DELIVER, not refuse:
/// `WorkflowExecutor::cancel` writes the durable stop request BEFORE the send and
/// never rolls it back, so a refusing transport would leave a durable row naming
/// an attempt that no frame would ever discharge — an undischargeable latch that
/// blocks the execution's workspace reclaim (`kata run park`) until a manual
/// `kata run discharge-stop`.
///
/// # What this test proves, and what it does NOT
///
/// It proves the CAPABILITY: it reds against a `send_control` that returns
/// `Protocol(...)`, and a stop overtakes an assignment already sitting
/// unread in the queue.
///
/// Two counterfactuals this cell does NOT reach — stated here because a check
/// whose advertised reach exceeds what it can observe is worse than a narrow
/// one. (a) "reds under a reader that BLOCKS on
/// `send().await`": it does not. One assignment into a 256-deep queue parks
/// nothing, so a blocking reader passes this verbatim — head-of-line blocking is
/// only observable once a queue is actually FULL, which is what
/// `a_stop_written_after_the_assignment_queue_saturates_is_delayed_but_never_lost`
/// exists for, and the shipped reader DOES block there, deliberately. (b) "reds
/// under a `select!` over `read_exact`": nothing here drops a read future
/// mid-frame and both frames are small; that counterfactual belongs to
/// `a_control_frame_between_two_large_assignments_corrupts_neither`, whose
/// half-megabyte bodies span many socket reads.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn local_socket_stop_is_readable_while_no_one_is_reading_assignments() {
    use kata_transport::types::WorkerControl;

    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    // An assignment the worker never pulls: the dispatch queue is occupied,
    // exactly as it is while a stage runs.
    let assignment = test_assignment();
    let queued_id = assignment.attempt_id;
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(assignment),
        ))
        .unwrap(),
    )
    .await
    .unwrap();

    let stop_target = Ulid::new();
    home.send_control(WorkerControl::Stop {
        assignment_id: stop_target,
        fence: fence_at(7),
        reason: "operator-initiated cancel".to_string(),
    })
    .await
    .expect("local_socket must carry a main->worker control frame");

    // CONTROL IS READ FIRST, with the assignment still queued and unread.
    let control = worker.recv_control().await.expect("stop must be readable");
    let (target, fence) = control
        .fenced_attempt()
        .expect("stop carries an attempt fence");
    assert_eq!(
        target, stop_target,
        "the stop must name the attempt the operator cancelled"
    );
    assert_eq!(
        fence.lease_epoch, 7,
        "the fence must survive the wire: an unfenced stop is a cross-generation kill"
    );

    // And the assignment that the stop overtook is still intact behind it.
    let received = capsule_frame(worker.recv_frame().await.unwrap());
    assert_eq!(
        received.attempt_id, queued_id,
        "overtaking a queued assignment must not consume or corrupt it"
    );
}

/// ORDERING: a control frame can land BETWEEN two data frames, never INSIDE
/// one. The reader task owns the read half exclusively and routes only whole
/// decoded `Envelope`s, so there is no path by which a stop can be interleaved
/// into a length-prefixed body.
///
/// The two assignments carry half-megabyte trace contexts specifically so their
/// bodies span many socket reads — a `select!`-based demux would corrupt them,
/// and a truncated or spliced body shows up as a payload whose length is wrong.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_control_frame_between_two_large_assignments_corrupts_neither() {
    use kata_transport::types::WorkerControl;

    const BIG: usize = 512 * 1024;

    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    let mut first = test_assignment();
    first.trace.traceparent = "a".repeat(BIG);
    let first_id = first.attempt_id;
    let mut second = test_assignment();
    second.trace.traceparent = "b".repeat(BIG);
    let second_id = second.attempt_id;

    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(first),
        ))
        .unwrap(),
    )
    .await
    .unwrap();
    home.send_control(WorkerControl::Stop {
        assignment_id: first_id,
        fence: fence_at(3),
        reason: "cancel between two large bodies".to_string(),
    })
    .await
    .unwrap();
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(second),
        ))
        .unwrap(),
    )
    .await
    .unwrap();

    let control = worker.recv_control().await.expect("stop must be readable");
    let (target, fence) = control
        .fenced_attempt()
        .expect("stop carries an attempt fence");
    assert_eq!(target, first_id);
    assert_eq!(fence.lease_epoch, 3);

    let a = capsule_frame(worker.recv_frame().await.expect("first assignment"));
    assert_eq!(a.attempt_id, first_id);
    assert_eq!(a.trace.traceparent.len(), BIG);
    assert!(a.trace.traceparent.bytes().all(|b| b == b'a'));

    let b = capsule_frame(worker.recv_frame().await.expect("second assignment"));
    assert_eq!(b.attempt_id, second_id);
    assert_eq!(b.trace.traceparent.len(), BIG);
    assert!(b.trace.traceparent.bytes().all(|b| b == b'b'));
}

/// OVERFLOW POLICY, HALF 1 — a saturated ASSIGNMENT queue costs throughput and
/// nothing else.
///
/// This queue's bound is REACHABLE. `max_concurrent_dispatches` does not cap
/// outstanding assignments on a connection (its own doc says the permit is
/// released when the dispatcher's insert+dispatch section returns), nothing in
/// `placement_candidates_excluding` caps them either, and a worker drains them
/// one per COMPLETED stage — so one wide fan-out at the default single-worker
/// topology crosses 256 easily.
///
/// Crossing it must therefore not kill the connection. The reader parks in
/// `Sender::send`, the kernel socket buffer fills, and the main's `write_frame`
/// blocks until the worker drains; no per-assignment deadline bounds that send.
/// Every frame already accepted is still delivered, in order, and the
/// connection survives.
///
/// # Counterfactual
///
/// Under a `try_send` + kill policy the 257th assignment would terminate the
/// reader: the worker would get exactly 256 and then a `Protocol` error, the
/// transport would go dead, and the supervisor would read a healthy worker as a
/// corpse — settling the running stage and all 256 queued attempts unfinished
/// and discarding work already paid for.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_assignment_queue_blocks_the_reader_instead_of_killing_the_connection() {
    /// Comfortably past the bound, so the reader provably parks.
    const SENT: usize = ASSIGNMENT_BOUND + 144;

    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;
    let home = std::sync::Arc::new(home);

    // Dispatched from a task: past the bound the main's writes BLOCK until the
    // worker drains, which is the property under test.
    let dispatcher = {
        let home = std::sync::Arc::clone(&home);
        tokio::spawn(async move {
            let mut ids = Vec::with_capacity(SENT);
            for _ in 0..SENT {
                let assignment = test_assignment();
                ids.push(assignment.attempt_id);
                let checked = kata_transport::CheckedDispatchFrame::new(
                    kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
                )
                .unwrap();
                home.dispatch(checked)
                    .await
                    .expect("backpressure must delay a dispatch, never refuse it");
            }
            ids
        })
    };

    // SATURATE BEFORE DRAINING. Without this the test proves nothing: a
    // consumer that keeps pace holds the queue below its bound, so the policy
    // never runs and the test passes against ANY policy. `SENT` assignments
    // exceed the queue bound plus the socket buffer, so the dispatcher is
    // provably still parked here — and a reader that kills on overflow has
    // already killed by now.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !dispatcher.is_finished(),
        "the test must observe backpressure: {SENT} assignments should not all fit \
         before anything drains"
    );

    let mut received = Vec::with_capacity(SENT);
    for _ in 0..SENT {
        received.push(
            capsule_frame(
                worker
                    .recv_frame()
                    .await
                    .expect("a saturated queue must not disconnect the worker"),
            )
            .attempt_id,
        );
    }

    let sent = dispatcher.await.unwrap();
    assert_eq!(
        sent, received,
        "backpressure must delay every assignment and lose or reorder none"
    );
    assert!(
        worker.is_alive() && home.is_alive(),
        "a queue that filled and drained must leave both ends dispatchable"
    );
}

/// OVERFLOW POLICY, HALF 1b — the price of blocking, stated and pinned.
///
/// A single stream carrying two classes cannot both bound its buffers and
/// promise neither class ever waits for the other. The stop written after the
/// assignment queue saturates DOES wait behind those assignments — and is then
/// delivered intact. That is the whole trade: the alternative policy killed the
/// connection, which loses that same stop AND settles every attempt the
/// connection held AND leaves the stop rows of the attempts it was cancelling
/// with no worker terminal to acknowledge them.
///
/// Determinism: the stop is written after `SENT > ASSIGNMENT_BOUND` assignments
/// on the same socket, so the reader is provably parked before it can be routed.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_stop_written_after_the_assignment_queue_saturates_is_delayed_but_never_lost() {
    use kata_transport::types::WorkerControl;

    const SENT: usize = ASSIGNMENT_BOUND + 44;

    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;
    let home = std::sync::Arc::new(home);

    let stop_target = Ulid::new();
    let feeder = {
        let home = std::sync::Arc::clone(&home);
        tokio::spawn(async move {
            for _ in 0..SENT {
                let checked = kata_transport::CheckedDispatchFrame::new(
                    kata_transport::types::DispatchFrame::Capsule(Box::new(test_assignment())),
                )
                .unwrap();
                home.dispatch(checked).await.unwrap();
            }
            home.send_control(WorkerControl::Stop {
                assignment_id: stop_target,
                fence: fence_at(11),
                reason: "cancel behind a saturated dispatch queue".to_string(),
            })
            .await
            .unwrap();
        })
    };

    // DELAYED: the reader cannot have routed it — it is parked on the full
    // assignment queue, and nothing has drained one yet.
    assert!(
        next_stop_within(&worker, 300).await.is_none(),
        "a stop behind a saturated assignment queue must not arrive before the queue drains"
    );

    for _ in 0..SENT {
        capsule_frame(worker.recv_frame().await.unwrap());
    }
    feeder.await.unwrap();

    // NEVER LOST: draining releases the reader, and the stop lands intact.
    let stop = next_stop_within(&worker, 5_000)
        .await
        .expect("the delayed stop must still be delivered");
    let (target, fence) = stop
        .fenced_attempt()
        .expect("stop carries an attempt fence");
    assert_eq!(target, stop_target);
    assert_eq!(fence.lease_epoch, 11);
    assert!(worker.is_alive());
}

/// OVERFLOW POLICY, HALF 2 — the CONTROL queue is the one that may not park the
/// reader, and it earns that by being unfillable rather than by killing.
///
/// Parking here would deadlock rather than merely stall: the worker drains
/// `recv_control` from inside its per-assignment execution block, so the drain
/// is reached by RECEIVING AN ASSIGNMENT — and assignments are what a parked
/// reader stops delivering. An idle worker would wait forever.
///
/// So repeats COALESCE. A stop is idempotent per `(attempt, lease_epoch)`, so an
/// operator who cancels the same execution five hundred times occupies one slot,
/// not five hundred. Together with a bound of one slot per attempt the
/// connection can hold, no sequence of operator cancels can fill it.
///
/// # Counterfactual
///
/// Without coalescing these 500 frames occupy 257 slots and drop 243, and the
/// second `next_stop_within` finds a duplicate instead of nothing. Under a flat
/// bound sized in operator cancels (say 16) that kills the connection when
/// crossed, the 17th frame would kill it — reachable from ONE cancel of a
/// 17-attempt execution.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_repeat_cancel_of_the_same_generation_coalesces_onto_one_control_slot() {
    use kata_transport::types::WorkerControl;

    const REPEATS: usize = 500;

    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    let attempt = Ulid::new();
    for n in 0..REPEATS {
        home.send_control(WorkerControl::Stop {
            assignment_id: attempt,
            fence: fence_at(2),
            reason: format!("operator cancel #{n}"),
        })
        .await
        .unwrap();
    }

    // BARRIER, in-band and exact: frames are routed in arrival order, so an
    // assignment sent after the flood cannot be read until every stop before it
    // has been routed. No polling heuristic, no sleep.
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(test_assignment()),
        ))
        .unwrap(),
    )
    .await
    .unwrap();
    capsule_frame(worker.recv_frame().await.unwrap());

    let stop = next_stop_within(&worker, 5_000)
        .await
        .expect("the operator's stop must be delivered");
    assert_eq!(
        stop.fenced_attempt()
            .expect("stop carries an attempt fence")
            .0,
        attempt
    );
    assert!(
        next_stop_within(&worker, 200).await.is_none(),
        "{REPEATS} cancels of one generation are one ask and must occupy one slot"
    );
    assert!(worker.is_alive());
}

/// OVERFLOW POLICY, HALF 2b — and if the unfillable queue fills anyway, the
/// FRAME is refused, never the connection.
///
/// Filling it takes more distinct live attempt generations than the connection
/// can hold, which correct operation cannot produce; this test produces it
/// anyway. Dropping a stop leaves one durable `attempt_stop_requests` row
/// standing, which an operator sees as `awaiting_worker_acknowledgement` and
/// clears with `kata run discharge-stop` — a recourse that exists. Killing the
/// connection instead would hand `Dispatcher::handle_worker_death` every attempt
/// the connection held, and it settles each one as lost (PROVEN AMBIGUOUS) —
/// the ones nobody cancelled included.
///
/// # Counterfactual
///
/// Under a kill-on-overflow policy the flood would kill the reader: the drain
/// would end in a `Protocol` error, `is_alive()` would go false, and the
/// dispatch that follows here would never arrive.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_control_flood_past_the_bound_drops_frames_and_keeps_the_connection() {
    use kata_transport::types::WorkerControl;

    const DISTINCT: usize = CONTROL_BOUND + 143;

    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;

    for _ in 0..DISTINCT {
        home.send_control(WorkerControl::Stop {
            assignment_id: Ulid::new(),
            fence: fence_at(1),
            reason: "distinct attempt".to_string(),
        })
        .await
        .expect("a full control queue must not fail the SEND either");
    }

    // Same in-band barrier: reaching this assignment proves the reader routed
    // all `DISTINCT` stops WITHOUT parking on any of them.
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(test_assignment()),
        ))
        .unwrap(),
    )
    .await
    .unwrap();
    capsule_frame(
        worker
            .recv_frame()
            .await
            .expect("a full control queue must never stall the assignment class"),
    );

    let mut delivered = 0usize;
    while next_stop_within(&worker, 200).await.is_some() {
        delivered += 1;
    }
    assert_eq!(
        delivered, CONTROL_BOUND,
        "every stop that FIT must be delivered — one per attempt the connection can hold"
    );

    // The connection is not merely alive, it still works in both directions.
    assert!(worker.is_alive() && home.is_alive());
    let after = test_assignment();
    let after_id = after.attempt_id;
    home.dispatch(
        kata_transport::CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(
            Box::new(after),
        ))
        .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        capsule_frame(worker.recv_frame().await.unwrap()).attempt_id,
        after_id
    );
    worker
        .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
            assignment_id: after_id,
            output: serde_json::json!({"ok": true}),
            stage_name: "fixture".into(),
            sequence: 1,
            fence: kata_transport::AttemptFence::default(),
        }))
        .await
        .unwrap();
    assert!(matches!(
        home.recv().await.unwrap(),
        WorkerMessage::Checkpoint(_)
    ));
}

/// OVERFLOW POLICY, HALF 3 — the MAIN-side queue, which was the one with no test
/// at all and the only one whose kill would fell a perfectly healthy worker.
///
/// It is reachable: the capsule emitter ships one `CapsuleProgress` frame per
/// stream chunk, while `ResultReactor::handle_message` does synchronous durable
/// work per frame — so a chatty stage only has to outrun a sqlite probe. And
/// there is no cross-class question to trade off on this side at all: a main
/// reads exactly ONE class (an attempt or a control frame arriving here is a
/// protocol kill), so parking on it cannot stall anything else. It blocks, the
/// worker's `send_result` blocks on the socket, and the explicitly best-effort
/// progress emitter self-throttles — precisely what the kernel buffer did
/// before this queue existed.
///
/// # Counterfactual
///
/// Under `try_send` + kill the main got 256 frames and then dropped the
/// connection of a healthy worker mid-stage, discarding every frame it had
/// written after that point — including the checkpoint this asserts at the end.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_message_queue_blocks_instead_of_killing_a_healthy_worker() {
    /// Past the queue bound AND past what the socket buffer can absorb behind
    /// it — a Unix stream charges ~1.3 KiB of skb overhead per frame against a
    /// 208 KiB default `SO_SNDBUF`, so ~156 frames sit there — which is what
    /// makes the emitter provably parked below rather than merely slow.
    const SENT: usize = 600;

    let dir = tempfile::tempdir().unwrap();
    let (home, worker) = connected_pair(dir.path()).await;
    let worker = std::sync::Arc::new(worker);

    let assignment_id = Ulid::new();
    let emitter = {
        let worker = std::sync::Arc::clone(&worker);
        tokio::spawn(async move {
            for chunk in 0..SENT {
                worker
                    .send_result(WorkerMessage::CapsuleProgress {
                        attempt_id: assignment_id,
                        byte_offset: chunk as u64,
                        preview: "chunk".to_string(),
                        dropped: 0,
                        fence: kata_transport::AttemptFence::default(),
                    })
                    .await
                    .expect("backpressure must delay a progress frame, never refuse it");
            }
            // The frame that matters: under a kill-on-overflow policy this one
            // would be discarded with the socket.
            worker
                .send_result(WorkerMessage::Checkpoint(StageCheckpoint {
                    assignment_id,
                    output: serde_json::json!({"chunks": SENT}),
                    stage_name: "fixture".into(),
                    sequence: 1,
                    fence: kata_transport::AttemptFence::default(),
                }))
                .await
                .unwrap();
        })
    };

    // SATURATE BEFORE DRAINING, for the same reason as the assignment test: a
    // reactor that keeps pace never reaches the bound, so the policy never runs
    // and the test would pass against ANY policy. By here the queue is full and
    // the emitter is parked on the socket — which is also where a reader that
    // kills on overflow has already killed, taking that checkpoint with it.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !emitter.is_finished(),
        "the test must observe backpressure: {SENT} progress frames should not all fit \
         before anything drains"
    );

    for expected in 0..SENT {
        match home.recv().await.expect("the main must not drop a worker") {
            WorkerMessage::CapsuleProgress { byte_offset, .. } => {
                assert_eq!(byte_offset, expected as u64, "no frame lost or reordered");
            }
            other => panic!("expected CapsuleProgress, got {other:?}"),
        }
    }
    assert!(matches!(
        home.recv().await.unwrap(),
        WorkerMessage::Checkpoint(_)
    ));
    emitter.await.unwrap();
    assert!(home.is_alive() && worker.is_alive());
}

/// The worker end must not be able to send a control frame. It is a
/// main->worker frame, so the main's reader would treat it as a protocol
/// violation and kill the connection; naming it at the send beats debugging a
/// dead socket.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn the_worker_end_refuses_to_send_a_control_frame_it_has_no_peer_for() {
    use kata_transport::types::WorkerControl;

    let dir = tempfile::tempdir().unwrap();
    let (_home, worker) = connected_pair(dir.path()).await;

    let err = WorkerTransport::send_control(
        &worker,
        WorkerControl::Stop {
            assignment_id: Ulid::new(),
            fence: fence_at(1),
            reason: "wrong direction".to_string(),
        },
    )
    .await
    .expect_err("control frames travel main->worker only");
    assert!(err.to_string().contains("main->worker only"), "{err}");
}

/// Unwrap the capsule arm of a received dispatch frame — the only arm left.
#[track_caller]
fn capsule_frame(
    frame: kata_transport::types::DispatchFrame,
) -> kata_transport::types::CapsuleAssignment {
    let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
    *capsule
}
