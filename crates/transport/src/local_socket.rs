//! Unix domain socket transport for same-host multi-process workers.
//!
//! `LocalSocketTransport::bind()` creates a listener (main side) that
//! accepts a single worker connection. `LocalSocketTransport::connect()` creates
//! a client (worker side) that connects to an existing listener.
//!
//! Messages are length-prefixed: 4 bytes big-endian length followed by
//! JSON-serialized payload. The transport distinguishes between three envelope
//! kinds — a `DispatchFrame` (main -> worker), `WorkerControl` (main -> worker)
//! and `WorkerMessage` (worker -> main) — using a tagged wrapper.
//!
//! Every connection owns a per-connection READER TASK that is the sole owner of
//! the read half. It decodes whole frames and fans them into three bounded
//! queues, which the `recv_*` methods drain with the cancel-safe
//! `mpsc::Receiver::recv`. That structure is what lets a stop frame overtake a
//! queued assignment while a stage is running — see [`reader_loop`].
//!
//! # A saturated queue NEVER kills this connection
//!
//! The three queues hold three different classes with three different failure
//! modes, and the policy is decided per class by ONE question: does the drain
//! that empties this queue depend on the socket the reader is draining? See
//! [`reader_loop`]'s "Overflow" section — the short form is that the two queues
//! whose drain is independent (`assignments`, `messages`) BLOCK, which is the
//! socket backpressure every caller was written against, and the one whose
//! drain is not (`controls`) coalesces and is bounded so that no sequence of
//! operator cancels can fill it.
//!
//! See `docs/architecture/0001-replacement-architecture.md` section 17.3.2 for the full design context.

use std::collections::HashSet;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, PoisonError};

use async_trait::async_trait;
use kata_types::error::{KataError, KataResult};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error};
use ulid::Ulid;

use crate::transport::{WorkerSideTransport, WorkerTransport};
use crate::types::{CheckedDispatchFrame, DispatchFrame, WorkerControl, WorkerMessage};

/// Maximum frame size: 16 MiB. Frames exceeding this are rejected as protocol
/// errors to prevent unbounded memory allocation from a misbehaving peer.
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// Bound on the worker-side ASSIGNMENT queue, and the point at which the reader
/// stops draining the socket rather than dropping or refusing anything.
///
/// Nothing in the scheduler caps per-worker in-flight assignments —
/// `placement_candidates_excluding` only load-ORDERS by `active_assignments` —
/// and `max_concurrent_dispatches` does NOT cap them either: its own
/// documentation says the permit is released when the dispatcher's
/// insert+dispatch critical section returns, so it bounds concurrent submission
/// CALLS, not outstanding assignments on a connection. This depth is therefore
/// REACHABLE, which is why reaching it must cost nothing but throughput: at 256
/// queued the reader parks in `Sender::send`, the kernel socket buffer fills,
/// and the main's `write_frame` blocks until the worker drains. The dispatcher
/// bounds its own wait on that send by `workers.dispatch_deadline_ms` without
/// cancelling the write: a send queued behind a running attempt keeps waiting in
/// a task of its own, and only a worker that holds no started attempt for the
/// whole deadline has the attempt settled.
///
/// The number itself is chosen, not measured — nothing has measured the real
/// distribution of queued assignments. Nothing correctness-bearing rests on
/// the value.
const ASSIGNMENT_QUEUE_DEPTH: usize = 256;

/// Bound on the main-side worker-MESSAGE queue (results, checkpoints,
/// heartbeats, progress).
///
/// `kata_worker::capsule_progress` emits `WorkerMessage::CapsuleProgress`
/// bounded — stream frames once per kind per rate window, lifecycle
/// milestones at once, each under a per-attempt byte budget — and
/// `ResultReactor::handle_message` does synchronous
/// durable work per frame, so a producer only has to outrun a sqlite probe to
/// fill this. Reaching it costs throughput and nothing else: the reader parks,
/// the worker's `send_result` blocks on the socket, and the explicitly
/// best-effort progress emitter self-throttles — which is exactly what
/// happened before this queue existed.
const MESSAGE_QUEUE_DEPTH: usize = 256;

/// Bound on the worker-side CONTROL queue: one undischarged stop for every
/// attempt this connection can hold.
///
/// The demand scales with LIVE ATTEMPTS, not with operator patience:
/// `WorkflowExecutor::cancel` issues one `send_control_to` per non-terminal
/// attempt of the execution, so a single cancel of a wide execution produces N
/// stops back to back on one connection. A constant unrelated to N is the wrong
/// shape — this one is derived: the connection can hold `ASSIGNMENT_QUEUE_DEPTH`
/// queued assignments plus the one running, and a stop is idempotent per
/// `(attempt, lease_epoch)` so repeats COALESCE into the slot already queued
/// (see `push_control`).
///
/// # WHAT THE DERIVATION COUNTS, AND WHAT IT DOES NOT ASSUME
///
/// It counts DISTINCT `(attempt, lease_epoch)` keys resident in the queue at one
/// instant, and nothing else. It does NOT assume the worker acts on a stop the
/// moment it drains it: a stop for an attempt still QUEUED on this connection is
/// drained while a DIFFERENT stage is running, and the worker remembers it
/// (`worker_loop`'s `PendingStops`) until that attempt is taken at launch, which
/// the stop then refuses. Either way, draining a frame empties the queue rather
/// than filling it, so the count holds in both directions.
///
/// # THE ONE REACHABLE WAY PAST THE COUNT, STATED
///
/// "More live attempt generations than the connection can hold" is not strictly
/// unreachable. An attempt the worker has already FINISHED stays non-terminal in
/// the ledger until the main processes its terminal frame, so `cancel` still
/// mints a stop for it while it occupies no assignment slot. A worker that
/// outruns the main's `ResultReactor` far enough therefore has more stoppable
/// attempts than `ASSIGNMENT_QUEUE_DEPTH + 1`. That is precisely the branch
/// `push_control` handles by dropping the FRAME and keeping the CONNECTION:
/// bounded loss of one idempotent ask, with a durable row and a real recourse
/// behind it, instead of a connection whose death settles every attempt it
/// held, the cancelled ones included.
const CONTROL_QUEUE_DEPTH: usize = ASSIGNMENT_QUEUE_DEPTH + 1;

// ---------------------------------------------------------------------------
// Envelope: tagged union for the three message directions
// ---------------------------------------------------------------------------

/// Wire envelope wrapping either direction of traffic so the receiver can
/// distinguish assignments from control frames from worker messages on a single
/// bidirectional stream.
///
/// The `DispatchFrame` variant is past clippy's `large_enum_variant`
/// heuristic. Boxing the inner struct would buy ~300 bytes of stack space at the
/// cost of an extra heap allocation per dispatched frame — the wire format
/// sends one envelope per message and throws it away, so the heap churn
/// has more cost than the stack waste. Allow the lint.
///
/// # `Control` is additive on the wire but NOT backward-TOLERATED
///
/// `dir = "control"` is a new tag value; an older peer decoding it gets a serde
/// error, which under [`reader_loop`] terminates the connection. That is
/// acceptable because a kata main and its `kata-worker` ship as one binary
/// version and the local-socket handshake performs no version negotiation — but
/// it is stated here rather than assumed, because "additive" usually implies
/// "ignorable" and here it does not.
///
/// This enum is PRIVATE to this module and carries no entry in
/// `crates/transport/conformance.toml`, which commits hashes only for
/// `SerdeConformance<WorkerControl>`, `<WorkerControl>` and `<WorkerMessage>`.
/// Adding a variant here moves no committed hash.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "dir", content = "payload", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum Envelope {
    /// Main -> worker WORK frame, tagged by arm.
    Assignment(DispatchFrame),
    Message(WorkerMessage),
    /// Main -> worker CONTROL frame — today, a fenced `WorkerControl::Stop`.
    Control(WorkerControl),
}

/// Which end of the connection a transport is. The reader task routes by it:
/// only a worker reads assignments and control frames, only a main reads worker
/// messages, and a frame arriving on the wrong end is a protocol violation
/// rather than something to queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Main,
    Worker,
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

/// Write a length-prefixed JSON frame to the stream.
async fn write_frame(stream: &mut (impl AsyncWriteExt + Unpin), data: &[u8]) -> KataResult<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| KataError::Protocol("frame too large to encode length".into()))?;
    if len > MAX_FRAME_SIZE {
        return Err(KataError::Protocol(format!(
            "frame size {len} exceeds max {MAX_FRAME_SIZE}"
        )));
    }
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a length-prefixed JSON frame from the stream.
///
/// Returns `Ok(None)` on clean EOF (peer closed the connection).
async fn read_frame(stream: &mut (impl AsyncReadExt + Unpin)) -> KataResult<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(KataError::Protocol(format!(
            "frame size {len} exceeds max {MAX_FRAME_SIZE}"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

// ---------------------------------------------------------------------------
// The per-connection reader task
// ---------------------------------------------------------------------------

/// Why the reader task stopped.
///
/// Published into `LocalSocketTransport::disconnect` **before** the task drops
/// its senders, so a consumer that observes a closed queue reads the real reason
/// instead of a generic "channel closed". The write-before-close plus the
/// channel's own release/acquire pair is what makes that read sound.
#[derive(Debug, Clone)]
enum Disconnect {
    Network(String),
    Protocol(String),
    Serialization(String),
}

impl Disconnect {
    fn into_error(self) -> KataError {
        match self {
            Self::Network(m) => KataError::Network(m),
            Self::Protocol(m) => KataError::Protocol(m),
            Self::Serialization(m) => KataError::Serialization(m),
        }
    }
}

/// The `(attempt, generation)` pair a stop is idempotent under. Two stops with
/// this key in common are the same ask, however many times an operator issued
/// it, so the second one need not occupy a second slot.
type StopKey = (Ulid, i64);

/// The key a control frame COALESCES under, or `None` if it may not coalesce.
///
/// This is the soundness condition for [`push_control`], written as an
/// exhaustive match rather than as a comment. Coalescing drops the later frame
/// on the floor, which is only ever sound for a frame that is IDEMPOTENT under
/// its key — and `(assignment_id, lease_epoch)` identifies an attempt
/// generation, not an instruction. A future `WorkerControl` variant carrying
/// something that is not "end this generation" would be silently swallowed by a
/// dedupe keyed that way, with a log line asserting it was a repeat.
///
/// So a new variant does not compile until its author answers the question here:
/// `Some(key)` claims idempotence under that key, `None` says every frame gets
/// its own slot. `None` is the safe answer and costs only queue depth.
///
/// [`LocalSocketTransport::recv_control_frame`] releases the slot through this
/// SAME function, so a non-coalescing variant can never release a coalescing
/// one's key.
///
/// `#[expect]` rather than `#[allow]` is deliberate: today every arm answers
/// `Some`, so clippy is right that the `Option` is unnecessary *for the current
/// enum* — and the `None` case is the whole point, the slot a future variant
/// declares itself into. The expectation self-removes the moment one does,
/// because the lint then stops firing and `unfulfilled_lint_expectations` reds.
const fn coalescing_key(frame: &WorkerControl) -> Option<StopKey> {
    match frame {
        // A stop is idempotent per (attempt, generation): it asks for one
        // specific attempt generation to end, and asking twice is the same ask.
        WorkerControl::Stop {
            assignment_id,
            fence,
            ..
        } => Some((*assignment_id, fence.lease_epoch)),
        WorkerControl::Recovery(_) | WorkerControl::Enrollment(_) => None,
    }
}

/// The set of stop keys currently queued and not yet drained, shared by the
/// reader (which inserts) and `recv_control` (which removes on delivery).
type QueuedStops = Arc<StdMutex<HashSet<StopKey>>>;

/// Lock the queued-stop set, recovering a poisoned guard rather than
/// propagating. The critical sections are a `HashSet` insert and a remove over
/// `Copy` keys, so nothing inside them can panic and a poisoned lock is
/// unreachable — but a stop-delivery path inheriting some other thread's panic
/// is the kind of failure this transport exists to prevent, so it is handled
/// rather than assumed away.
fn lock_stops(stops: &StdMutex<HashSet<StopKey>>) -> std::sync::MutexGuard<'_, HashSet<StopKey>> {
    stops.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The send halves the reader task owns, one per frame class.
struct ReaderQueues {
    assignments: mpsc::Sender<DispatchFrame>,
    messages: mpsc::Sender<WorkerMessage>,
    controls: mpsc::Sender<WorkerControl>,
    queued_stops: QueuedStops,
}

/// The receive halves the transport owns, one per frame class.
struct Inbox {
    assignments: AsyncMutex<mpsc::Receiver<DispatchFrame>>,
    messages: AsyncMutex<mpsc::Receiver<WorkerMessage>>,
    controls: AsyncMutex<mpsc::Receiver<WorkerControl>>,
}

/// The one terminal reason a queue can produce: its receiver is gone, so the
/// transport that owned it was dropped and there is nobody left to deliver to.
/// A queue being FULL is not on this list — see [`reader_loop`]'s "Overflow".
fn no_receiver(queue: &str) -> Disconnect {
    Disconnect::Network(format!(
        "local_socket: the {queue} queue has no receiver left; the transport was dropped"
    ))
}

/// Hand a stop to the worker's control queue.
///
/// The ONLY push that may not park the reader, and the reason is specific: the
/// worker drains `recv_control` from inside its per-assignment execution block,
/// so the drain that empties this queue is reached by RECEIVING AN ASSIGNMENT.
/// Parking here would stall the assignment stream behind it, and an idle worker
/// would then never reach the drain — a deadlock, not a stall.
///
/// So it coalesces instead. A repeat of a stop already queued for the same
/// `(attempt, lease_epoch)` occupies no second slot, which together with a bound
/// derived from `ASSIGNMENT_QUEUE_DEPTH` is what makes overflow unreachable by
/// correct operation: filling it needs more distinct live attempt generations
/// than the connection can hold.
///
/// If the impossible happens anyway, the FRAME is refused and the CONNECTION is
/// not. Killing the connection here is strictly worse than losing one stop: the
/// main reads a closed connection as worker death, and
/// `Dispatcher::handle_worker_death` settles EVERY live capsule attempt the
/// worker held as lost (PROVEN AMBIGUOUS) — the ones nobody cancelled included.
/// Dropping one frame leaves a single durable stop standing, which an operator
/// can see (`awaiting_worker_acknowledgement`) and clear with the recourse that
/// really exists (`kata run discharge-stop`).
fn push_control(queues: &ReaderQueues, frame: WorkerControl) -> Result<(), Disconnect> {
    let attempt_scope = frame
        .fenced_attempt()
        .map(|(id, fence)| (id, fence.lease_epoch));
    // `None` means this variant declared itself non-idempotent, so it takes its
    // own slot and releases nothing. See `coalescing_key`.
    let key: Option<StopKey> = coalescing_key(&frame);

    if let Some(key) = key {
        let mut already = lock_stops(&queues.queued_stops);
        if !already.insert(key) {
            debug!(
                ?attempt_scope,
                "local_socket: coalesced a repeat ask onto the one already queued for this \
                 generation; a stop is idempotent per (attempt, lease_epoch)"
            );
            return Ok(());
        }
    }

    match queues.controls.try_send(frame) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            if attempt_scope.is_none() {
                return Err(Disconnect::Network(
                    "recovery control queue exhausted".into(),
                ));
            }
            if let Some(key) = key {
                lock_stops(&queues.queued_stops).remove(&key);
            }
            error!(
                ?attempt_scope,
                depth = CONTROL_QUEUE_DEPTH,
                "local_socket: the control queue holds one undrained stop for every attempt this \
                 connection can hold, so THIS STOP FRAME WAS DROPPED — the connection is not, \
                 because killing it would read as worker death and settle every attempt it \
                 holds, leaving their durable stops with no worker terminal to acknowledge them. \
                 The durable stop request stands: the attempt shows `awaiting_worker_acknowledgement`, and \
                 `kata run discharge-stop` clears it. Reaching this at all means the worker has \
                 stopped draining control frames — look for a wedged stage."
            );
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            if let Some(key) = key {
                lock_stops(&queues.queued_stops).remove(&key);
            }
            Err(no_receiver("control"))
        }
    }
}

/// Route one fully decoded envelope to its queue.
///
/// Routing operates on a COMPLETE `Envelope`, never on bytes — which is the
/// whole reason a control frame cannot land inside a data frame's body.
async fn route(side: Side, queues: &ReaderQueues, envelope: Envelope) -> Result<(), Disconnect> {
    match (side, envelope) {
        // BLOCKS when full, deliberately: see `reader_loop`'s "Overflow".
        (Side::Worker, Envelope::Assignment(a)) => queues
            .assignments
            .send(a)
            .await
            .map_err(|_| no_receiver("assignment")),
        (Side::Worker, Envelope::Control(c)) => push_control(queues, c),
        (Side::Worker, Envelope::Message(_)) => Err(Disconnect::Protocol(
            "expected assignment, got worker message".into(),
        )),
        // BLOCKS when full, and on this side that is not even a cross-class
        // question: a main reads exactly one class.
        (Side::Main, Envelope::Message(m)) => queues
            .messages
            .send(m)
            .await
            .map_err(|_| no_receiver("message")),
        (Side::Main, Envelope::Assignment(_)) => Err(Disconnect::Protocol(
            "expected worker message, got assignment".into(),
        )),
        (Side::Main, Envelope::Control(_)) => Err(Disconnect::Protocol(
            "expected worker message, got a main->worker control frame".into(),
        )),
    }
}

/// The per-connection reader task.
///
/// # Ownership, termination, and the bound — stated because a spawned task owes all three
///
/// **Owner**: the `LocalSocketTransport` value, through a private
/// `JoinHandle` field. Not a registry and not a global, so the task cannot
/// outlive the thing whose read half it owns.
///
/// **Terminal cleanup, two paths, both explicit**: `Drop for
/// LocalSocketTransport` aborts it, and `LocalSocketTransport::shutdown` aborts
/// it after closing the writer. `shutdown` MUST abort: a shut-down transport
/// rejects every recv on the `is_alive()` precheck, so a reader still parked in
/// `read_exact` against a peer that never closes would be a task with no
/// reachable consumer — precisely the unbounded registry those laws forbid.
///
/// **Bound**: one task per live `LocalSocketTransport`, and the transport count
/// on the main side is bounded by `worker_slots` in
/// `bin/kata/src/local_capacity.rs`'s accept loop.
///
/// # Why `read_frame` is awaited straight-line
///
/// The task never drops a `read_frame` future while the connection lives: no
/// `select!`, no `timeout`, no cancellation. `read_exact` is not cancel-safe and
/// dropping it between a frame's length prefix and its body does not lose one
/// frame, it corrupts every frame after it. The only drop is `abort()`, which
/// happens only when the connection is already being torn down.
///
/// # The task never calls `mark_dead`
///
/// Liveness is flipped by the CONSUMER observing a closed queue, which is the
/// order `peer_eof_marks_other_side_dead_for_supervisor_replacement` pins:
/// `is_alive()` must not go false before anyone asked.
///
/// # Overflow: BLOCK where the drain is independent, COALESCE where it is not.
/// Never kill the connection.
///
/// A single stream carrying three classes cannot both bound its buffers and
/// guarantee no class is ever delayed by another; the choice is only what to
/// sacrifice. This transport sacrifices THROUGHPUT and never the connection,
/// because a killed connection is not a capacity failure at all: the supervisor
/// reads it as worker death, so every attempt the connection held is settled
/// unfinished — including attempts an operator had just cancelled, whose
/// durable stops then have no worker terminal to acknowledge them and wait on
/// an operator's discharge.
///
/// The policy is decided per class by one question — *does the drain that
/// empties this queue depend on the socket this reader is draining?*
///
/// * **`messages` (main side): BLOCK.** A main reads exactly one class (an
///   assignment or a control frame arriving here is a protocol kill), so
///   parking on it cannot stall another class — there is no other class. The
///   worker's `send_result` then blocks on the socket, which self-throttles the
///   unthrottled per-chunk `Progress` emitter exactly as the kernel buffer did
///   before this queue existed.
/// * **`assignments` (worker side): BLOCK.** The drain is independent of the
///   socket: the worker's stage finishes on its own and then calls
///   `recv_assignment`. Parking therefore always ends, and while it lasts the
///   main's dispatch send to this worker parks with it — delayed, never lost.
/// * **`controls` (worker side): COALESCE, never park.** Here the drain is NOT
///   independent: the worker polls `recv_control` only while executing an
///   assignment, so parking would stall the assignments that reach the drain and
///   an idle worker would deadlock. See [`push_control`].
///
/// The residual, stated because it is real: a stop written while the assignment
/// queue is saturated waits behind those assignments in the socket. It is
/// DELAYED, not lost — `a_stop_written_after_the_assignment_queue_saturates_is_
/// delayed_but_never_lost` pins that — and the alternative was a policy under
/// which that same stop was lost along with the connection carrying it.
///
/// **And the CALLER waits with it.** The delay is not invisible to the operator:
/// the outbound write parks in `write_all` until the worker drains,
/// and the drain is the worker finishing stages that need not declare a
/// `timeout_ms` at all. Backpressure with no deadline over it is a hang, so the
/// bound lives one layer up in `WorkerPoolSupervisor::send_control_to`, which
/// times out the JOIN of a spawned write rather than the write itself — see
/// there for why cancelling it instead would cost the connection.
async fn reader_loop(
    side: Side,
    mut read: tokio::net::unix::OwnedReadHalf,
    queues: ReaderQueues,
    disconnect: Arc<OnceLock<Disconnect>>,
) {
    let reason = loop {
        let frame = match read_frame(&mut read).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break Disconnect::Network("connection closed by peer".into()),
            Err(KataError::Protocol(m)) => break Disconnect::Protocol(m),
            Err(other) => break Disconnect::Network(format!("connection closed: {other}")),
        };

        let envelope = match serde_json::from_slice::<Envelope>(&frame) {
            Ok(envelope) => envelope,
            Err(e) => break Disconnect::Serialization(format!("envelope deserialization: {e}")),
        };

        if let Err(reason) = route(side, &queues, envelope).await {
            break reason;
        }
    };

    // PUBLISH BEFORE DROPPING THE SENDERS. A consumer only looks at this slot
    // after it has observed the queue closed, and the queue closes when
    // `queues` drops — so the store is ordered before the acquire that makes
    // the consumer look.
    let _ = disconnect.set(reason);
    drop(queues);
}

// ---------------------------------------------------------------------------
// LocalSocketTransport
// ---------------------------------------------------------------------------

/// Unix domain socket transport for same-host multi-process workers.
///
/// Created via [`LocalSocketTransport::bind`] on the main side or
/// [`LocalSocketTransport::connect`] on the worker side. After the connection
/// is established, both sides share the same `WorkerTransport` interface.
pub struct LocalSocketTransport {
    /// The socket path (used for cleanup on drop for the listener side).
    socket_path: Option<PathBuf>,
    /// Which end of the connection this is.
    side: Side,
    /// The peer's process id, read from the kernel (`SO_PEERCRED`) when the
    /// connection was made.
    peer_pid: Option<u32>,
    /// Write half, behind a mutex for concurrent senders. The READ half is
    /// owned exclusively by the reader task; there is no second path to those
    /// bytes.
    writer: AsyncMutex<tokio::net::unix::OwnedWriteHalf>,
    /// The three bounded queues the reader task fans frames into.
    inbox: Inbox,
    /// Handle to the reader task, aborted by `shutdown` and by `Drop`.
    reader: JoinHandle<()>,
    /// The reader's terminal reason, published before it drops its senders.
    disconnect: Arc<OnceLock<Disconnect>>,
    /// Stop keys queued and not yet drained. The reader inserts, `recv_control`
    /// removes on delivery; that pair is what makes a repeat cancel coalesce
    /// instead of consuming a second control slot.
    queued_stops: QueuedStops,
    /// Alive flag.
    alive: AtomicBool,
}

/// A Unix domain socket listener that accepts multiple worker connections.
///
/// Returned by [`LocalSocketTransport::listen`]. Call [`accept_next`] in a
/// loop to accept incoming worker connections, each yielding an independent
/// `LocalSocketTransport`.
///
/// [`accept_next`]: LocalSocketListener::accept_next
pub struct LocalSocketListener {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl LocalSocketListener {
    /// The socket path the listener is bound to.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Accept the next incoming connection and return a transport for it.
    pub async fn accept_next(&self) -> KataResult<LocalSocketTransport> {
        let (stream, _addr) = self.listener.accept().await?;
        // Only the listener owns socket-file cleanup.
        Ok(LocalSocketTransport::from_stream(stream, Side::Main, None))
    }
}

impl Drop for LocalSocketListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Remove a stale socket file at `path` if — and only if — it is an
/// actual Unix domain socket.
///
/// `LocalSocketTransport::listen` and `::bind` must never call
/// `std::fs::remove_file` on whatever file sits at the socket path: an
/// operator typo in config (`socket_path = "/home/alice/important.db"`)
/// would silently delete that file on startup.
///
/// This helper is the only place in the transport crate where cleanup
/// happens. It uses `std::os::unix::fs::FileTypeExt::is_socket()` to make
/// sure the target is a socket before unlinking. Regular files, symlinks,
/// directories, FIFOs, and block/char devices all produce a hard error.
fn cleanup_stale_socket(path: &Path) -> KataResult<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(KataError::Network(format!(
                "failed to stat existing path at {}: {e}",
                path.display()
            )));
        }
    };
    let file_type = metadata.file_type();
    if !file_type.is_socket() {
        return Err(KataError::Network(format!(
            "refusing to remove non-socket file at {}: file type is {}. \
             The LocalSocket transport only unlinks files that are already \
             Unix domain sockets; operators should remove the file manually \
             if the intent is really to reuse this path.",
            path.display(),
            describe_file_type(file_type),
        )));
    }
    std::fs::remove_file(path).map_err(|e| {
        KataError::Network(format!(
            "failed to remove stale socket {}: {e}",
            path.display()
        ))
    })
}

/// Human-readable label for a file type, for use in error messages.
fn describe_file_type(ft: std::fs::FileType) -> &'static str {
    if ft.is_file() {
        "regular file"
    } else if ft.is_dir() {
        "directory"
    } else if ft.is_symlink() {
        "symlink"
    } else if ft.is_fifo() {
        "fifo"
    } else if ft.is_block_device() {
        "block device"
    } else if ft.is_char_device() {
        "character device"
    } else {
        "unknown"
    }
}

impl LocalSocketTransport {
    /// Split a connected stream, spawn its reader task, and wire the queues.
    ///
    /// Every constructor funnels through here so no connection can exist
    /// without a reader owning its read half.
    ///
    /// Must be called from within a Tokio runtime — every caller
    /// (`bind`/`connect`/`accept_next`) is already `async`.
    fn from_stream(stream: UnixStream, side: Side, socket_path: Option<PathBuf>) -> Self {
        let peer_pid = stream
            .peer_cred()
            .ok()
            .and_then(|credentials| credentials.pid())
            .and_then(|pid| u32::try_from(pid).ok());
        let (read, write) = stream.into_split();

        let (assignment_tx, assignment_rx) = mpsc::channel(ASSIGNMENT_QUEUE_DEPTH);
        let (message_tx, message_rx) = mpsc::channel(MESSAGE_QUEUE_DEPTH);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);

        let disconnect: Arc<OnceLock<Disconnect>> = Arc::new(OnceLock::new());
        let queued_stops: QueuedStops = Arc::new(StdMutex::new(HashSet::new()));

        let reader = tokio::spawn(reader_loop(
            side,
            read,
            ReaderQueues {
                assignments: assignment_tx,
                messages: message_tx,
                controls: control_tx,
                queued_stops: Arc::clone(&queued_stops),
            },
            Arc::clone(&disconnect),
        ));

        Self {
            socket_path,
            side,
            peer_pid,
            writer: AsyncMutex::new(write),
            inbox: Inbox {
                assignments: AsyncMutex::new(assignment_rx),
                messages: AsyncMutex::new(message_rx),
                controls: AsyncMutex::new(control_rx),
            },
            reader,
            disconnect,
            queued_stops,
            alive: AtomicBool::new(true),
        }
    }

    /// Create a listener on the given socket path that can accept multiple
    /// connections via [`LocalSocketListener::accept_next`].
    ///
    /// If a stale **socket** exists at `path`, it is removed before
    /// binding. If `path` points at a non-socket file (regular file,
    /// directory, symlink, etc.) the call returns an error instead of
    /// unlinking — see [`cleanup_stale_socket`] for the full rationale.
    pub fn listen(path: impl AsRef<Path>) -> KataResult<LocalSocketListener> {
        let path = path.as_ref();

        cleanup_stale_socket(path)?;

        let listener = crate::unix_socket::bind_tokio(path)?;
        Ok(LocalSocketListener {
            listener,
            socket_path: path.to_path_buf(),
        })
    }

    /// Create a listener on the given socket path, accept one connection, and
    /// return the resulting transport.
    ///
    /// If a stale **socket** exists at `path`, it is removed before
    /// binding. If `path` points at a non-socket file (regular file,
    /// directory, symlink, etc.) the call returns an error instead of
    /// unlinking — see [`cleanup_stale_socket`] for the full rationale.
    pub async fn bind(path: impl AsRef<Path>) -> KataResult<Self> {
        let path = path.as_ref();

        cleanup_stale_socket(path)?;

        let listener = crate::unix_socket::bind_tokio(path)?;
        let (stream, _addr) = listener.accept().await?;

        Ok(Self::from_stream(
            stream,
            Side::Main,
            Some(path.to_path_buf()),
        ))
    }

    /// Connect to an existing listener at the given socket path.
    pub async fn connect(path: impl AsRef<Path>) -> KataResult<Self> {
        let stream = crate::unix_socket::connect_tokio(path.as_ref()).await?;
        Ok(Self::from_stream(stream, Side::Worker, None))
    }

    /// Send a raw envelope over the connection.
    async fn send_envelope(&self, envelope: &Envelope) -> KataResult<()> {
        if !self.is_alive() {
            return Err(KataError::Network("transport is shut down".into()));
        }
        let result = async {
            let data = serde_json::to_vec(envelope)
                .map_err(|e| KataError::Serialization(format!("envelope serialization: {e}")))?;
            let mut writer = self.writer.lock().await;
            write_frame(&mut *writer, &data).await
        }
        .await;
        if result.is_err() {
            self.mark_dead();
        }
        result
    }

    /// The error a closed queue means, as the reader task recorded it.
    fn disconnect_error(&self) -> KataError {
        self.disconnect
            .get()
            .cloned()
            .unwrap_or_else(|| Disconnect::Network("connection closed by peer".into()))
            .into_error()
    }

    /// Drain one frame from a queue the reader task feeds.
    ///
    /// **Cancel-safe**, which is a requirement rather than a nicety:
    /// `WorkerSideTransport::recv_control` is raced against the running stage in
    /// the worker loop's `select!`, so this future is dropped constantly.
    /// `Mutex::lock` and `mpsc::Receiver::recv` are both cancel-safe, so a drop
    /// releases the guard and loses no frame.
    ///
    /// Frames already queued when the reader terminates are still delivered —
    /// `mpsc::Receiver::recv` drains the buffer before reporting the close — so
    /// a disconnect never discards a frame that already arrived.
    async fn recv_queued<T>(&self, queue: &AsyncMutex<mpsc::Receiver<T>>) -> KataResult<T> {
        if !self.is_alive() {
            return Err(KataError::Network("transport is shut down".into()));
        }
        let mut rx = queue.lock().await;
        if let Some(value) = rx.recv().await {
            Ok(value)
        } else {
            self.mark_dead();
            Err(self.disconnect_error())
        }
    }

    /// Receive the next [`DispatchFrame`] from the connection.
    ///
    /// This is the worker-side counterpart to `dispatch()`. Whether this worker
    /// can run it is `kata_worker::capsule_route::CapsuleRoute`'s question.
    pub async fn recv_frame(&self) -> KataResult<DispatchFrame> {
        self.recv_queued(&self.inbox.assignments).await
    }

    /// Drain one stop, releasing the coalescing slot it held.
    ///
    /// The release is what keeps coalescing from being a leak: once the frame
    /// has been handed to the worker, a LATER stop for the same generation is a
    /// new ask and must queue again. There is no await between the receive and
    /// the release, so a cancelled `recv_control` cannot lose a frame between
    /// the two.
    async fn recv_control_frame(&self) -> KataResult<WorkerControl> {
        let frame = self.recv_queued(&self.inbox.controls).await?;
        // The SAME function that claimed the slot releases it, so a variant that
        // declared itself non-coalescing (`None`) cannot release the key a
        // coalescing one is still holding.
        if let Some(key) = coalescing_key(&frame) {
            lock_stops(&self.queued_stops).remove(&key);
        }
        Ok(frame)
    }

    /// Send a `WorkerMessage` back to the main side.
    ///
    /// This is the worker-side counterpart to `recv()`.
    pub async fn send_result(&self, msg: WorkerMessage) -> KataResult<()> {
        self.send_envelope(&Envelope::Message(msg)).await
    }
}

impl Drop for LocalSocketTransport {
    fn drop(&mut self) {
        // Terminal cleanup path 1 of 2: the reader task dies with the transport
        // that owns it. Without this a reader parked in `read_exact` against a
        // peer that never closes would outlive its only consumer.
        self.reader.abort();
        // If we are the listener side, clean up the socket file.
        if let Some(ref path) = self.socket_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl LocalSocketTransport {
    fn mark_dead(&self) {
        self.alive.store(false, Ordering::Release);
    }

    /// Inherent liveness check. Inherent methods take precedence over trait
    /// methods, which avoids ambiguity when both `WorkerTransport` and
    /// `WorkerSideTransport` are in scope.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Inherent shutdown that marks the transport dead, closes the writer, and
    /// stops the reader task.
    pub async fn shutdown(&self) -> KataResult<()> {
        self.mark_dead();
        {
            let mut writer = self.writer.lock().await;
            let _ = AsyncWriteExt::shutdown(&mut *writer).await;
        }
        // Terminal cleanup path 2 of 2, and it happens AFTER the writer close
        // so the peer still observes a clean EOF. A shut-down transport rejects
        // every recv on the `is_alive()` precheck, so a still-running reader
        // would have no reachable consumer.
        self.reader.abort();
        Ok(())
    }
}

#[async_trait]
impl WorkerTransport for LocalSocketTransport {
    async fn dispatch(&self, frame: CheckedDispatchFrame) -> KataResult<()> {
        self.send_envelope(&Envelope::Assignment(frame.into_inner()))
            .await
    }

    async fn recv(&self) -> KataResult<WorkerMessage> {
        self.recv_queued(&self.inbox.messages).await
    }

    /// CARRIED. A `WorkerControl` frame travels as its own length-prefixed
    /// envelope and lands in the worker's dedicated control queue, so it can
    /// overtake a queued assignment: the two share a direction, not an ordering,
    /// and a stop stuck behind a full dispatch buffer is a stop that arrives
    /// after the stage it meant to end.
    ///
    /// It must carry, not refuse: `WorkflowExecutor::cancel` writes the durable
    /// stop request BEFORE asking the transport to deliver, deliberately and with
    /// no rollback, so a refusal here would fail an operator's `kata run cancel`
    /// on a local-socket worker AND leave a durable row naming an attempt that no
    /// frame would ever discharge — blocking the execution's workspace reclaim
    /// (`kata run park`) until a manual `kata run discharge-stop`.
    async fn send_control(&self, control: WorkerControl) -> KataResult<()> {
        if self.side == Side::Worker {
            // Refused rather than sent: control is a MAIN->worker frame, so the
            // peer's reader would treat it as a protocol violation and kill the
            // connection. Naming it here beats debugging a dead socket.
            return Err(KataError::Protocol(
                "local_socket: control frames travel main->worker only; this transport is the \
                 WORKER end of the connection and has nothing to send one to"
                    .into(),
            ));
        }
        self.send_envelope(&Envelope::Control(control)).await
    }

    async fn shutdown(&self) -> KataResult<()> {
        LocalSocketTransport::shutdown(self).await
    }

    fn is_alive(&self) -> bool {
        LocalSocketTransport::is_alive(self)
    }

    fn peer_pid(&self) -> Option<u32> {
        self.peer_pid
    }

    fn kind(&self) -> &'static str {
        "local_socket"
    }
}

#[async_trait]
impl WorkerSideTransport for LocalSocketTransport {
    /// CARRIED, and cancel-safe as the trait requires: this drains the control
    /// queue the per-connection reader task feeds, via `mpsc::Receiver::recv`.
    /// The worker loop races it against a pinned stage future, so the future is
    /// dropped on every poll the stage wins; dropping it loses nothing. An `Err`
    /// means the CONNECTION is gone.
    async fn recv_control(&self) -> KataResult<WorkerControl> {
        self.recv_control_frame().await
    }

    async fn recv_frame(&self) -> KataResult<DispatchFrame> {
        LocalSocketTransport::recv_frame(self).await
    }

    async fn send_result(&self, msg: WorkerMessage) -> KataResult<()> {
        LocalSocketTransport::send_result(self, msg).await
    }

    async fn shutdown(&self) -> KataResult<()> {
        LocalSocketTransport::shutdown(self).await
    }

    fn is_alive(&self) -> bool {
        LocalSocketTransport::is_alive(self)
    }
}

/// Adversarial-draw conformance: `arbitrary`-driven conformance harness for the wire
/// frame decoder.
///
/// A worker connection is an untrusted byte stream: a misbehaving or
/// hostile peer can send any bytes. The length-prefixed frame decoder
/// (`read_frame`) and the subsequent `Envelope` JSON decode must always
/// terminate with `Ok`/`Err` — never panic, and never allocate an
/// unbounded buffer (the 4-byte length prefix is capped at
/// [`MAX_FRAME_SIZE`]). This harness feeds arbitrary bytes — including
/// deliberately crafted length prefixes that under- or over-run the
/// body — through `read_frame`, then attempts the `Envelope` decode on
/// whatever it yields, asserting graceful degradation throughout. The
/// `Control` variant added by the local-socket demux is covered for free:
/// the decode target is the whole enum.
///
/// Determinism + speed: inputs come from fixed seeds via a splitmix64
/// PRNG, the sample count is fixed, and each decode runs against an
/// in-memory `Cursor` (no real socket, no I/O wait). The `conformance`
/// module path makes it ride `just test-conformance`.
#[cfg(test)]
mod conformance {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    #[test]
    fn maximum_recovery_chunk_json_fits_the_actual_frame_limit() {
        use kata_types::{
            identity::{WorkerEffectDomain, WorkerMembraneId},
            recovery::*,
        };
        let request = RecoveryRequest {
            artifact_id: Ulid::new(),
            request_nonce: Ulid::new(),
            domain: WorkerEffectDomain {
                source_main: "\u{0001}".repeat(255),
                membrane: WorkerMembraneId(Ulid::new()),
                enrollment: Ulid::new(),
            },
        };
        assert!(request.is_valid());
        let frame = Envelope::Message(WorkerMessage::Recovery(RecoveryReply::Chunk {
            request,
            generation_id: Ulid::new(),
            offset: u64::MAX,
            bytes: vec![255; MAX_RECOVERY_CHUNK_BYTES as usize],
        }));
        let encoded = serde_json::to_vec(&frame).unwrap();
        // Maximum decimal u8 width and six-character JSON escapes, including
        // the actual transport envelope rather than a naked payload.
        assert!(encoded.len() <= MAX_FRAME_SIZE as usize);
    }

    /// Deterministic sample count. Each case decodes an in-memory
    /// cursor, so several hundred stay well under a few milliseconds.
    const FUZZ_SAMPLES: u64 = 512;

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn seed_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&splitmix64(&mut state).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Craft a frame with an attacker-controlled length prefix so the
    /// decoder's short-body (EOF) and body-present paths are both hit,
    /// rather than relying on random prefixes that almost always exceed
    /// `MAX_FRAME_SIZE` and are rejected immediately.
    fn framed(declared_len: u32, body: &[u8]) -> Vec<u8> {
        let mut buf = declared_len.to_be_bytes().to_vec();
        buf.extend_from_slice(body);
        buf
    }

    #[kata_test_utils::kata_timeout(secs = 30)]
    #[tokio::test]
    async fn frame_decode_arbitrary_bytes_never_panics() {
        let mut completed = 0u64;
        for seed in 0..FUZZ_SAMPLES {
            let raw_stream = seed_bytes(seed, 64);
            let mut u = Unstructured::new(&raw_stream);
            let body: Vec<u8> = Vec::arbitrary(&mut u).unwrap_or_default();
            let declared: u32 = u.int_in_range(0u32..=128).unwrap_or(0);

            // 1. Raw arbitrary bytes as the whole stream: exercises the
            //    length-prefix read, the MAX_FRAME_SIZE reject path, and
            //    the short-body EOF path.
            let mut raw = std::io::Cursor::new(raw_stream.clone());
            if let Ok(Some(frame)) = read_frame(&mut raw).await {
                // Whatever bytes came back must still decode gracefully
                // as an envelope (Ok or Err, no panic).
                let _ = serde_json::from_slice::<Envelope>(&frame);
            }

            // 2. Small in-range declared length with an arbitrary body —
            //    drives the successful-read and truncated-read branches
            //    deterministically.
            let crafted = framed(declared, &body);
            let mut cur = std::io::Cursor::new(crafted);
            if let Ok(Some(frame)) = read_frame(&mut cur).await {
                let _ = serde_json::from_slice::<Envelope>(&frame);
            }

            // 3. Over-cap declared length must be rejected as a protocol
            //    error without allocating — assert it never allocates the
            //    body nor panics.
            let over = framed(MAX_FRAME_SIZE + 1, &body);
            let mut cur = std::io::Cursor::new(over);
            assert!(
                read_frame(&mut cur).await.is_err(),
                "over-cap frame length must be rejected"
            );

            completed += 1;
        }
        assert_eq!(completed, FUZZ_SAMPLES);
    }
}
