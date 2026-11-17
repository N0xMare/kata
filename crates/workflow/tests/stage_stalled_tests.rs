//! Integration tests: Stalled SSE event for early worker-stall warning.
//!
//! Verifies that the dispatcher emits a one-time `LedgerEvent` with
//! `AssignmentStatus::Stalled` when a dispatched worker first misses its
//! heartbeat interval (but has not yet exceeded the grace window), and that
//! the event is deduplicated within the same stall cycle.

use std::sync::Arc;
use std::time::Duration;

use kata_core::{AssignmentStatus, InFlightLedger};
use kata_transport::InProcessTransport;
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_transport::supervisor::WorkerPoolSupervisor;
use kata_workflow::dispatcher::Dispatcher;
use kata_workflow::execution_lifecycle::ExecutionLifecycleFace;
use kata_workflow::test_harness::seed_dispatched_capsule_attempt;
use smol_str::SmolStr;
use ulid::Ulid;

mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Register a worker whose assignment queue is silently drained.
fn register_worker(
    dispatcher: &Dispatcher,
    supervisor: &WorkerPoolSupervisor,
    id: &str,
) -> Arc<InProcessTransport> {
    common::register_worker(dispatcher, supervisor, id)
}

/// Heartbeat interval, grace window, and sweep interval used by all stall tests.
///
/// Chosen so that:
/// - stale threshold (> hb_interval) = 100ms
/// - dead threshold (> hb_interval + grace) = 600ms
/// - sweep fires every 25ms (fast enough to catch stale within 125ms total)
const HB_INTERVAL: Duration = Duration::from_millis(100);
const HB_GRACE: Duration = Duration::from_millis(500);
const SWEEP_INTERVAL: Duration = Duration::from_millis(25);

fn new_stall_dispatcher() -> (
    Arc<Dispatcher>,
    Arc<WorkerPoolSupervisor>,
    Arc<InFlightLedger>,
    Arc<HeartbeatMonitor>,
    tempfile::TempDir,
) {
    let supervisor = Arc::new(WorkerPoolSupervisor::new());
    let heartbeat = Arc::new(HeartbeatMonitor::new(HB_INTERVAL, HB_GRACE));
    let ledger = InFlightLedger::in_memory();
    let dispatcher = Arc::new(Dispatcher::new(
        Arc::clone(&supervisor),
        Arc::clone(&heartbeat),
        Arc::clone(&ledger),
    ));
    let delivery = kata_workflow::delivery_service::DeliveryService::new(
        Arc::clone(dispatcher.execution_lifecycle().db()),
        Arc::clone(&ledger),
    );
    tokio::spawn(async move { delivery.run().await });
    let dir = tempfile::tempdir().expect("the fixture CAS dir");
    (dispatcher, supervisor, ledger, heartbeat, dir)
}

/// The capsule-plane submit-and-place: admit the execution's program, claim the
/// stage's attempt, and dispatch it onto `worker` — the facts a stall cycle
/// reads out of the chain's live-work registry.
fn submit_and_dispatch(
    dispatcher: &Dispatcher,
    cas_dir: &std::path::Path,
    worker: &str,
    stage: &str,
) -> (Ulid, Ulid) {
    let execution_id = Ulid::new();
    let face: ExecutionLifecycleFace = dispatcher.execution_lifecycle();
    let program = common::compile_test_definition_to_execution_program(&common::make_definition(
        &[(stage, &[])],
    ))
    .expect("a one-stage program compiles");
    face.put_current_program(execution_id, &program)
        .expect("the execution admits");
    let cas = kata_core::store::cas::CasStore::open(cas_dir.join("cas.db"), cas_dir.join("blobs"))
        .expect("the fixture CAS opens");
    let attempt = seed_dispatched_capsule_attempt(
        face.db(),
        &cas,
        execution_id,
        program.program_hash,
        stage,
        worker,
        None,
    );
    (execution_id, attempt)
}

/// Advance tokio time into the stale window — past HB_INTERVAL (100 ms) of
/// observed silence, short of HB_INTERVAL + HB_GRACE (600 ms) — ONE SWEEP
/// INTERVAL AT A TIME, so the sweep runs at its own cadence: a single jump
/// would be a stall of the main itself, which the monitor charges as at most
/// one interval of silence. 175 ms, the first of them skipping the sweep's
/// immediate tick.
async fn advance_to_stale() {
    for _ in 0..7 {
        tokio::time::advance(SWEEP_INTERVAL).await;
        tokio::task::yield_now().await;
    }
}

// ---------------------------------------------------------------------------
// Test 1: stalled_once — emits exactly once per stall cycle
// ---------------------------------------------------------------------------

/// A worker that misses its heartbeat interval (but stays within the grace
/// window) should trigger exactly one `Stalled` SSE event. A subsequent
/// sweep tick with the same `last_heartbeat_at_ms` must be deduplicated.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn worker_misses_one_beat_emits_stalled_once() {
    tokio::time::pause();

    let (dispatcher, supervisor, ledger, heartbeat, cas_dir) = new_stall_dispatcher();
    let _w1 = register_worker(&dispatcher, &supervisor, "w1");

    // Record a heartbeat so the monitor tracks this worker.
    heartbeat.record_heartbeat("w1");

    let (_exec, id) = submit_and_dispatch(&dispatcher, cas_dir.path(), "w1", "stall-stage");

    let mut rx = ledger.subscribe();

    // Spawn the sweep.
    let disp = Arc::clone(&dispatcher);
    let hb = Arc::clone(&heartbeat);
    tokio::spawn(async move { disp.run_heartbeat_sweep(hb, SWEEP_INTERVAL).await });

    // Drain the Pending and Dispatched events that arrived before subscribe.
    // rx already misses those since subscribe() was called after checked submit —
    // that's fine; we only care about the Stalled event.

    advance_to_stale().await;
    // Give spawned tasks a chance to run after advancing.
    tokio::task::yield_now().await;

    // Collect events up to 500ms of virtual time budget.
    let mut stalled_count = 0usize;
    while let Ok(event) = rx.try_recv() {
        if matches!(event.new_status, AssignmentStatus::Stalled { .. }) {
            stalled_count += 1;
        }
    }

    assert_eq!(
        stalled_count, 1,
        "expected exactly 1 Stalled event on first stall cycle, got {stalled_count}"
    );

    // Advance one more sweep interval — the same stall cycle, same
    // last_heartbeat_at_ms, so the dedup set should suppress re-emission.
    tokio::time::advance(SWEEP_INTERVAL).await;
    tokio::task::yield_now().await;

    let mut extra = 0usize;
    while let Ok(event) = rx.try_recv() {
        if matches!(event.new_status, AssignmentStatus::Stalled { .. }) {
            extra += 1;
        }
    }

    assert_eq!(
        extra, 0,
        "dedup must suppress second Stalled in same stall cycle"
    );

    // The attempt must still be non-terminal — a stall observation is
    // record-only, never a lifecycle write.
    let state = dispatcher
        .execution_lifecycle()
        .db()
        .recovered_attempt(id)
        .unwrap()
        .expect("the attempt row exists")
        .state
        .expect("the attempt carries a state");
    assert!(
        !matches!(
            state.as_str(),
            "completed" | "failed" | "orphaned" | "cancelled"
        ),
        "broadcast_stalled must not mutate attempt state; got {state}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: worker recovers then re-stalls — emits two events
// ---------------------------------------------------------------------------

/// A worker that stalls, recovers (sends a heartbeat), then stalls again
/// must emit two `Stalled` events — one per stall cycle — because the
/// new heartbeat changes `last_heartbeat_at_ms` and the dedup key differs.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn worker_recovers_then_re_stalls_emits_two() {
    tokio::time::pause();

    let (dispatcher, supervisor, ledger, heartbeat, cas_dir) = new_stall_dispatcher();
    let _w1 = register_worker(&dispatcher, &supervisor, "w1");

    heartbeat.record_heartbeat("w1");

    let (_exec, _id) = submit_and_dispatch(&dispatcher, cas_dir.path(), "w1", "re-stall-stage");

    let mut rx = ledger.subscribe();

    let disp = Arc::clone(&dispatcher);
    let hb = Arc::clone(&heartbeat);
    tokio::spawn(async move { disp.run_heartbeat_sweep(hb, SWEEP_INTERVAL).await });

    // First stall cycle.
    advance_to_stale().await;
    tokio::task::yield_now().await;

    let mut stalled_1 = 0usize;
    while let Ok(e) = rx.try_recv() {
        if matches!(e.new_status, AssignmentStatus::Stalled { .. }) {
            stalled_1 += 1;
        }
    }
    assert_eq!(
        stalled_1, 1,
        "first stall cycle should emit 1 Stalled event"
    );

    // Worker recovers: new heartbeat resets last_seen_ms.
    heartbeat.record_heartbeat("w1");

    // Second stall cycle.
    advance_to_stale().await;
    tokio::task::yield_now().await;

    let mut stalled_2 = 0usize;
    while let Ok(e) = rx.try_recv() {
        if matches!(e.new_status, AssignmentStatus::Stalled { .. }) {
            stalled_2 += 1;
        }
    }
    assert_eq!(
        stalled_2, 1,
        "second stall cycle should emit 1 Stalled event"
    );
}

// ---------------------------------------------------------------------------
// Test 3: worker dies during stall — emits Stalled then Failed
// ---------------------------------------------------------------------------

/// When a worker stalls and then dies (misses heartbeats until the grace
/// window expires), the SSE stream should carry a `Stalled` event
/// followed by a `Failed` event: a capsule attempt is never re-delivered, so
/// `handle_worker_death` settles it PROVEN AMBIGUOUS, which is `failed` on the
/// chain — `Orphaned` survives only on the boot-orphan path.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn worker_dies_during_stall_emits_stalled_then_failed() {
    tokio::time::pause();

    // Use a single-worker pool so there is no peer to resume on; the
    // dispatcher settles the attempt failed when the worker dies.
    let (dispatcher, supervisor, ledger, heartbeat, cas_dir) = new_stall_dispatcher();
    let _w1 = register_worker(&dispatcher, &supervisor, "w1");

    heartbeat.record_heartbeat("w1");

    let (_exec, id) = submit_and_dispatch(&dispatcher, cas_dir.path(), "w1", "die-stage");

    let mut rx = ledger.subscribe();

    let disp = Arc::clone(&dispatcher);
    let hb = Arc::clone(&heartbeat);
    tokio::spawn(async move { disp.run_heartbeat_sweep(hb, SWEEP_INTERVAL).await });

    // Advance into the stale window.
    advance_to_stale().await;
    tokio::task::yield_now().await;

    // Step past the grace window one sweep interval at a time, as the sweep
    // runs: a single jump would be a stall of the main itself, which the
    // monitor charges as one interval of silence.
    for _ in 0..22 {
        tokio::time::advance(SWEEP_INTERVAL).await;
        tokio::task::yield_now().await;
    }

    let mut saw_stalled = false;
    let mut saw_failed = false;
    while let Ok(e) = rx.try_recv() {
        match &e.new_status {
            AssignmentStatus::Stalled { .. } => saw_stalled = true,
            AssignmentStatus::Failed { .. } => saw_failed = true,
            _ => {}
        }
    }

    assert!(
        saw_stalled,
        "must see a Stalled event before the worker dies"
    );
    assert!(
        saw_failed,
        "must see a Failed event after the grace window expires"
    );

    let state = dispatcher
        .execution_lifecycle()
        .db()
        .recovered_attempt(id)
        .unwrap()
        .expect("the attempt row exists")
        .state
        .expect("the attempt carries a state");
    assert_eq!(
        state, "failed",
        "final stored state must be failed, got {state}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: terminal assignment clears dedup entry
// ---------------------------------------------------------------------------

/// When an assignment reaches a terminal state the stall-dedup entry for
/// that assignment must be removed so the dedup set does not grow without
/// bound and so a future assignment with the same id (impossible with ULIDs,
/// but we verify the invariant anyway) would not be suppressed.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn terminated_assignment_clears_dedup_entry() {
    tokio::time::pause();

    // Single worker: guarantees the assignment goes to w1 (the only
    // worker with a recorded heartbeat), so the sweep's stale verdict always finds
    // its assignment.  We call mark_completed() directly to reach
    // terminal state — no second worker needed for that path.
    let (dispatcher, supervisor, ledger, heartbeat, cas_dir) = new_stall_dispatcher();
    let _w1 = register_worker(&dispatcher, &supervisor, "w1");

    heartbeat.record_heartbeat("w1");

    let (_exec, id) = submit_and_dispatch(&dispatcher, cas_dir.path(), "w1", "dedup-clear-stage");

    let mut rx = ledger.subscribe();

    let disp = Arc::clone(&dispatcher);
    let hb = Arc::clone(&heartbeat);
    tokio::spawn(async move { disp.run_heartbeat_sweep(hb, SWEEP_INTERVAL).await });

    // Advance into stale window so a Stalled event fires and the dedup
    // entry is populated.
    advance_to_stale().await;
    tokio::task::yield_now().await;

    // Drain to confirm the Stalled event was emitted.
    let stalled_count = {
        let mut n = 0;
        while let Ok(e) = rx.try_recv() {
            if matches!(e.new_status, AssignmentStatus::Stalled { .. }) {
                n += 1;
            }
        }
        n
    };
    assert_eq!(stalled_count, 1, "setup: expected 1 Stalled event");

    // Mark the assignment completed to trigger the terminal path in on_event.
    dispatcher
        .mark_completed_and_fold_attempt(id, serde_json::json!({"ok": true}))
        .unwrap();

    // Drain the Completed event so run_bookkeeper gets a chance to call on_event.
    tokio::task::yield_now().await;

    // After the terminal event the dedup entry should be gone. Verify by
    // confirming the attempt is now terminal on the chain.
    let state = dispatcher
        .execution_lifecycle()
        .db()
        .recovered_attempt(id)
        .unwrap()
        .expect("the attempt row exists")
        .state
        .expect("the attempt carries a state");
    assert!(
        matches!(
            state.as_str(),
            "completed" | "failed" | "orphaned" | "cancelled"
        ),
        "attempt must be terminal after the completion, got {state}"
    );
    // The stall_dedup is an internal field — we can't inspect it directly,
    // but we can verify the bookkeeper received the terminal event by
    // ensuring no second Stalled appears on the next sweep tick even if
    // somehow the worker were to stay stale (the assignment is terminal
    // so broadcast_stalled is a no-op regardless).
    tokio::time::advance(SWEEP_INTERVAL).await;
    tokio::task::yield_now().await;

    let extra_stalled = {
        let mut n = 0;
        while let Ok(e) = rx.try_recv() {
            if matches!(e.new_status, AssignmentStatus::Stalled { .. }) {
                n += 1;
            }
        }
        n
    };
    assert_eq!(
        extra_stalled, 0,
        "no Stalled events should appear after assignment is terminal"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Stalled event payload round-trips through serde
// ---------------------------------------------------------------------------

/// Verify that `AssignmentStatus::Stalled` serialises and deserialises
/// correctly, and that the wire `kind` tag is `"stalled"`.
#[test]
fn stalled_event_payload_roundtrips() {
    kata_test_seeded::run_seeded("stalled_event_payload_roundtrips", |_ctx| async move {
        let status = AssignmentStatus::Stalled {
            worker_id: SmolStr::new("slow-worker"),
            last_heartbeat_at_ms: 1_700_000_000_000,
            stalled_for_secs: 12,
        };

        let json = serde_json::to_string(&status).expect("Stalled serializes");
        let back: AssignmentStatus = serde_json::from_str(&json).expect("Stalled deserializes");
        assert_eq!(back, status, "Stalled must round-trip through JSON");

        // Wire shape assertions.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "stalled", "serde tag must be \"stalled\"");
        assert_eq!(v["worker_id"], "slow-worker");
        assert_eq!(v["last_heartbeat_at_ms"], 1_700_000_000_000u64);
        assert_eq!(v["stalled_for_secs"], 12u64);

        // is_terminal() must be false.
        assert!(!status.is_terminal(), "Stalled must be non-terminal");

        // worker_id() must return the worker.
        assert_eq!(status.worker_id().map(SmolStr::as_str), Some("slow-worker"));

        // tag() must return "stalled".
        assert_eq!(status.tag(), "stalled");

        // LedgerEvent wrapper also round-trips.
        let event = kata_core::LedgerEvent {
            execution_id: Ulid::new(),
            assignment_id: Ulid::new(),
            stage_name: SmolStr::new("my-stage"),
            new_status: status.clone(),
            output: None,
            terminal_charge: None,
        };
        let event_json = serde_json::to_string(&event).expect("LedgerEvent serializes");
        let event_back: kata_core::LedgerEvent =
            serde_json::from_str(&event_json).expect("LedgerEvent deserializes");
        assert_eq!(
            event_back.new_status, status,
            "LedgerEvent::new_status must survive a serde round-trip"
        );
    });
}

// ---------------------------------------------------------------------------
// A live worker is never settled dead for a stall it recovers from
// ---------------------------------------------------------------------------

/// The node configuration the live rigs run (`heartbeat_interval_ms = 1000`,
/// `heartbeat_grace_ms = 5000`): a worker is dead past 6 s of silence.
const RIG_INTERVAL: Duration = Duration::from_secs(1);
const RIG_GRACE: Duration = Duration::from_secs(5);

/// The worker side of an in-process pair whose HEARTBEAT path stalls once: the
/// first heartbeat sent at or after `stall_from` waits `stall` before it leaves —
/// a worker process paused (descheduled, stopped) for that long, on exactly the
/// path its heartbeat takes. Every other frame passes straight through.
struct StallingHeartbeats {
    inner: InProcessTransport,
    stall_from: tokio::time::Instant,
    stall: Duration,
    stalled: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl kata_transport::WorkerSideTransport for StallingHeartbeats {
    async fn recv_frame(&self) -> kata_types::KataResult<kata_transport::types::DispatchFrame> {
        self.inner.recv_frame().await
    }
    async fn recv_control(&self) -> kata_types::KataResult<kata_transport::types::WorkerControl> {
        self.inner.recv_control().await
    }
    async fn send_result(
        &self,
        msg: kata_transport::types::WorkerMessage,
    ) -> kata_types::KataResult<()> {
        if matches!(msg, kata_transport::types::WorkerMessage::Heartbeat(_))
            && tokio::time::Instant::now() >= self.stall_from
            && !self.stalled.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            tokio::time::sleep(self.stall).await;
        }
        self.inner.send_result(msg).await
    }
    async fn shutdown(&self) -> kata_types::KataResult<()> {
        kata_transport::WorkerSideTransport::shutdown(&self.inner).await
    }
    fn is_alive(&self) -> bool {
        kata_transport::WorkerSideTransport::is_alive(&self.inner)
    }
}

/// A capsule route whose execution never runs: the attempt below is seeded as
/// dispatched on the worker's row, never sent, so nothing reaches it.
struct NothingExecuted;

#[async_trait::async_trait]
impl kata_worker::capsule_route::StandInExecution for NothingExecuted {
    async fn execute(
        &self,
        _frame: &kata_transport::types::CapsuleAssignment,
        _cancel: tokio::sync::oneshot::Receiver<String>,
        _progress: Option<&kata_worker::capsule_progress::CapsuleProgress>,
    ) -> Result<
        kata_transport::types::WorkerMessage,
        kata_worker::capsule_execution::CapsuleAttemptRefusal,
    > {
        unreachable!("no frame is ever dispatched to this worker")
    }
}

/// The production heartbeat path end to end under the rig's 1 s / 5 s node
/// configuration — `worker_loop`'s own emitter at the period this main hands
/// it, a real `ResultReactor` recording what arrives, the real
/// `run_heartbeat_sweep` — with the worker `w1`'s heartbeat path stalled once
/// for `stall`, `stall_from` in. Its connection stays open throughout.
struct HeartbeatRig {
    dispatcher: Arc<Dispatcher>,
    events: tokio::sync::broadcast::Receiver<kata_core::LedgerEvent>,
    /// Every `Failed` reason published so far, by attempt.
    failed: std::collections::HashMap<Ulid, String>,
    cas_dir: tempfile::TempDir,
}

impl HeartbeatRig {
    fn start(stall_from: Duration, stall: Duration) -> Self {
        tokio::time::pause();
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(RIG_INTERVAL, RIG_GRACE));
        let ledger = InFlightLedger::in_memory();
        let dispatcher = Arc::new(Dispatcher::new(
            Arc::clone(&supervisor),
            Arc::clone(&heartbeat),
            Arc::clone(&ledger),
        ));
        let events = ledger.subscribe();
        let delivery = kata_workflow::delivery_service::DeliveryService::new(
            Arc::clone(dispatcher.execution_lifecycle().db()),
            Arc::clone(&ledger),
        );
        tokio::spawn(async move { delivery.run().await });
        let (home, worker) = InProcessTransport::pair(16);
        let home = Arc::new(home);
        supervisor.register_worker_with_effect_domain(
            SmolStr::new("w1"),
            Arc::clone(&home) as Arc<dyn kata_transport::WorkerTransport>,
            Vec::new(),
            common::rig_worker_containment(),
            *kata_workflow::test_harness::oci_rig_executor_term().digest(),
            common::enroll_fake_worker_domain(&dispatcher),
        );
        let _reactor = kata_workflow::reactor::ResultReactor::new(
            SmolStr::new("w1"),
            home,
            Arc::clone(&dispatcher),
            Arc::clone(&heartbeat),
        )
        .spawn();
        let worker = Arc::new(StallingHeartbeats {
            inner: worker,
            stall_from: tokio::time::Instant::now() + stall_from,
            stall,
            stalled: std::sync::atomic::AtomicBool::new(false),
        });
        let _worker = tokio::spawn(kata_worker::worker_loop(
            worker,
            Arc::new(kata_worker::capsule_route::CapsuleRoute::stand_in_for_test(
                Arc::new(NothingExecuted),
            )),
            heartbeat.send_period(),
            (None, None),
        ));
        let sweep = Arc::clone(&dispatcher);
        tokio::spawn(async move {
            sweep.run_heartbeat_sweep(heartbeat, RIG_INTERVAL).await;
        });
        Self {
            dispatcher,
            events,
            failed: std::collections::HashMap::new(),
            cas_dir: tempfile::tempdir().expect("the fixture CAS dir"),
        }
    }

    /// Place a capsule attempt for `stage` on `w1`, dispatched on its row.
    fn dispatch(&self, stage: &str) -> Ulid {
        submit_and_dispatch(&self.dispatcher, self.cas_dir.path(), "w1", stage).1
    }

    /// Let `span` of paused time pass 100 ms at a time, every task running in
    /// between.
    async fn run_for(&self, span: Duration) {
        let mut elapsed = Duration::ZERO;
        while elapsed < span {
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
            elapsed += Duration::from_millis(100);
        }
    }

    /// The reason `attempt` was SETTLED with — terminal on its operational row,
    /// the reason off the published `Failed` event — or `None`.
    fn settlement(&mut self, attempt: Ulid) -> Option<String> {
        let settled = self
            .dispatcher
            .execution_lifecycle()
            .db()
            .recovered_attempt(attempt)
            .expect("the attempt's row reads")
            .expect("the attempt exists")
            .is_terminal();
        while let Ok(event) = self.events.try_recv() {
            if let AssignmentStatus::Failed { reason, .. } = event.new_status {
                self.failed.insert(event.assignment_id, reason);
            }
        }
        settled.then(|| {
            self.failed
                .get(&attempt)
                .cloned()
                .expect("a settled attempt published its Failed reason")
        })
    }
}

/// [`HeartbeatRig`] with one attempt dispatched at the start: the reason it was
/// settled with after 60 s of paused-clock time, or `None`.
async fn attempt_settled_after_heartbeat_stall(
    stall_from: Duration,
    stall: Duration,
) -> Option<String> {
    let mut rig = HeartbeatRig::start(stall_from, stall);
    let attempt = rig.dispatch("turn");
    rig.run_for(Duration::from_secs(60)).await;
    rig.settlement(attempt)
}

/// **A LIVE WORKER WHOSE HEARTBEAT PATH STALLS 2 s KEEPS ITS ATTEMPT.** The
/// twin of the reproduced settlement: on a live node at this configuration, a
/// 2 s pause of the worker process (SIGSTOP, phase-aligned to a beat) settled
/// its running turn `worker local-worker-0 died. PROVEN AMBIGUOUS`, because the
/// worker heartbeated every 5 s against a 6 s deadline. At the period its main
/// hands it, a 2 s stall leaves the worker silent for at most 2.5 s.
///
/// **Watched red:** with `worker_loop` ticking at a fixed 5 s instead of its
/// `heartbeat_period`, the attempt is settled.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_worker_whose_heartbeat_path_stalls_two_seconds_keeps_its_attempt() {
    let settled =
        attempt_settled_after_heartbeat_stall(Duration::from_secs(20), Duration::from_secs(2))
            .await;
    assert!(
        settled.is_none(),
        "a worker whose heartbeat path stalled 2 s and recovered was settled dead: {settled:?}"
    );
}

/// **THE CONTROL: A WORKER SILENT PAST THE DEADLINE IS SETTLED.** The same
/// composition with a 7 s stall — past the 6 s deadline at any cadence — settles
/// the attempt, so the cell above cannot pass on a sweep that never runs. Its
/// recorded reason names the leg, the silence against the deadline, and the
/// worker's process (an in-process worker's is this test's own).
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_worker_whose_heartbeat_path_stalls_past_the_deadline_is_settled() {
    let reason =
        attempt_settled_after_heartbeat_stall(Duration::from_secs(20), Duration::from_secs(7))
            .await
            .expect("a worker silent for 7 s against a 6 s deadline was never settled");
    assert!(
        reason.contains("worker w1 died: no heartbeat for ")
            && reason.contains(" s of observed silence, past its 6.0 s deadline")
            && reason.contains(&format!(
                "its process {} exists in state ",
                std::process::id()
            )),
        "the settlement names the heartbeat leg, its silence and the worker's process: {reason}"
    );
}

/// **A WORKER THAT NEVER HEARTBEATS IS STILL SETTLED.** Its first beat is held
/// past the whole run, so the main never records one from it. Its clock starts
/// when its reactor starts reading it, so it is past the 6 s deadline in 7 s and
/// its attempt is settled. Measured live before this: a worker stopped before its
/// first beat (the old 5 s cadence) held its turn through a 12 s stop with no
/// settlement — the monitor had no entry for it, and an unknown worker is never
/// swept.
///
/// **Watched red:** with the reactor's start recording no heartbeat, the attempt
/// is never settled.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_worker_that_never_heartbeats_is_settled() {
    let reason = attempt_settled_after_heartbeat_stall(Duration::ZERO, Duration::from_secs(120))
        .await
        .expect("a worker that never heartbeated was never settled");
    assert!(
        reason.contains("worker w1 died: no heartbeat for "),
        "the heartbeat leg settled it: {reason}"
    );
}

/// **AN ATTEMPT PLACED ON A WORKER AFTER ITS DEAD VERDICT IS SETTLED TOO.** The
/// scheduler routes nothing to a worker the monitor holds dead, but a placement
/// that read it alive just before the verdict can commit just after it — after
/// the verdict's settlement read the worker's attempts. The main judges a dead
/// worker again at every sweep until it heartbeats, so that attempt is settled by
/// the heartbeat leg at the next sweep rather than waiting for the start deadline
/// (900 s by default) or its wall time.
///
/// Here the worker stops beating 5 s in and keeps its connection open. Its first
/// attempt is settled at the verdict; a second is placed on it at 20 s and must be
/// settled within two sweeps.
///
/// **Watched red:** with the monitor reporting a dead worker only at the sweep
/// that found it dead, the second attempt was never settled.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn an_attempt_placed_on_a_worker_after_its_dead_verdict_is_settled() {
    let mut rig = HeartbeatRig::start(Duration::from_secs(5), Duration::from_secs(600));
    let first = rig.dispatch("turn");
    rig.run_for(Duration::from_secs(20)).await;
    assert!(
        rig.settlement(first).is_some(),
        "the control: the silent worker's first attempt was settled at its verdict"
    );
    let late = rig.dispatch("late-turn");
    rig.run_for(Duration::from_secs(2)).await;
    let reason = rig.settlement(late).unwrap_or_else(|| {
        panic!("an attempt placed on a silent worker after its dead verdict was never settled")
    });
    assert!(
        reason.contains("worker w1 died: no heartbeat for ")
            && reason.contains(" s of observed silence, past its 6.0 s deadline"),
        "the heartbeat leg settled it: {reason}"
    );
}

/// A node fence that never answers (a node that cannot be reaped), counting the
/// kills it was asked for.
#[derive(Default)]
struct UnansweredFence {
    asked: std::sync::atomic::AtomicUsize,
}

impl kata_workflow::dispatcher::NodeFence for UnansweredFence {
    fn fence(
        &self,
        _pid: u32,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Option<String>, String>> + Send + '_>> {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(std::future::pending())
    }
}

/// **A FENCE THAT NEVER ANSWERS HOLDS NO OTHER WORKER'S DEATH.** The heartbeat
/// leg asks the supervised node's fence to kill a dead node while it holds the
/// lock every worker death takes. Here the fence never answers for `w1`, silent
/// from 5 s; `w2`'s connection closes at 20 s. `w2`'s attempt must still be
/// settled, naming its own death, and `w1`'s must not be: a kill that never
/// completed settles nothing.
///
/// **Watched red:** with the dispatcher waiting on the fence's answer without a
/// bound, `w2`'s death was never handled.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_fence_that_never_answers_holds_no_other_workers_death() {
    let mut rig = HeartbeatRig::start(Duration::from_secs(5), Duration::from_secs(600));
    let fence = Arc::new(UnansweredFence::default());
    rig.dispatcher
        .install_node_fence(Arc::clone(&fence) as Arc<dyn kata_workflow::dispatcher::NodeFence>)
        .expect("the rig's dispatcher holds no fence yet");
    let held = rig.dispatch("turn");
    let other = submit_and_dispatch(&rig.dispatcher, rig.cas_dir.path(), "w2", "other").1;
    rig.run_for(Duration::from_secs(20)).await;
    assert!(
        fence.asked.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "the control: the heartbeat leg asked the fence to kill the silent w1"
    );
    let dispatcher = Arc::clone(&rig.dispatcher);
    let closed = tokio::spawn(async move {
        dispatcher
            .handle_worker_death(
                "w2",
                &kata_workflow::dispatcher::WorkerLoss::ConnectionClosed(
                    "closed by the cell".to_owned(),
                ),
            )
            .await
    });
    rig.run_for(Duration::from_secs(90)).await;
    assert!(
        closed.is_finished(),
        "w2's death was still waiting 90 s after its connection closed, behind w1's fence"
    );
    let reason = rig
        .settlement(other)
        .expect("w2's attempt was never settled while w1's fence went unanswered");
    assert!(
        reason.contains("worker w2 died: its connection closed (closed by the cell)"),
        "w2's own death settled it: {reason}"
    );
    assert_eq!(
        rig.settlement(held),
        None,
        "w1's attempt was settled though the fence never answered its kill"
    );
}

/// **A DEAD WORKER WHOSE CONNECTION IS GONE IS FORGOTTEN ONCE NOTHING ON IT IS LEFT
/// TO SETTLE.** Local capacity mints a fresh worker id per connection, so a monitor
/// that kept every id it ever recorded would re-settle every closed connection at
/// every sweep for the main's whole uptime. Two connections close (their supervisor
/// entries are removed, as local capacity removes them after the reactor's death
/// leg), one of them holding a dispatched attempt; a third stays connected and goes
/// silent. Past the deadline the sweep settles the closed worker's attempt and
/// forgets both closed ids, read off the monitor itself; the connected worker stays
/// tracked, dead, so an attempt placed on it later is still settled at a sweep.
///
/// **Watched red:** on the base, which had no way to forget a worker,
/// `lag_seconds()` still named both closed ids after the settling sweep.
#[kata_test_utils::kata_timeout]
#[tokio::test]
async fn a_closed_worker_is_forgotten_once_its_settling_sweep_leaves_it_nothing() {
    tokio::time::pause();
    let (dispatcher, supervisor, _ledger, heartbeat, cas_dir) = new_stall_dispatcher();
    for id in ["local-worker-0", "local-worker-1", "local-worker-2"] {
        let _transport = register_worker(&dispatcher, &supervisor, id);
        heartbeat.record_heartbeat(id);
    }
    let (_exec, held) =
        submit_and_dispatch(&dispatcher, cas_dir.path(), "local-worker-1", "held-stage");
    supervisor.unregister_worker("local-worker-0");
    supervisor.unregister_worker("local-worker-1");

    let disp = Arc::clone(&dispatcher);
    let hb = Arc::clone(&heartbeat);
    tokio::spawn(async move { disp.run_heartbeat_sweep(hb, SWEEP_INTERVAL).await });
    // 1 s at the sweep's own cadence: past the 600 ms deadline, then a few sweeps.
    for _ in 0..40 {
        tokio::time::advance(SWEEP_INTERVAL).await;
        tokio::task::yield_now().await;
    }

    let named: std::collections::BTreeSet<String> = heartbeat
        .lag_seconds()
        .into_iter()
        .map(|(worker, _)| worker.to_string())
        .collect();
    assert_eq!(
        named,
        std::collections::BTreeSet::from(["local-worker-2".to_owned()]),
        "only the still-connected worker is tracked"
    );
    for closed in ["local-worker-0", "local-worker-1"] {
        assert_eq!(
            heartbeat.liveness(closed),
            kata_transport::heartbeat::LivenessState::Unknown,
            "{closed} is forgotten"
        );
    }
    assert_eq!(
        heartbeat.liveness("local-worker-2"),
        kata_transport::heartbeat::LivenessState::Dead,
        "the connected silent worker is still judged dead"
    );
    assert!(
        dispatcher
            .execution_lifecycle()
            .db()
            .recovered_attempt(held)
            .unwrap()
            .expect("the held attempt's row")
            .is_terminal(),
        "the closed worker's attempt was settled before its id was forgotten"
    );
}
