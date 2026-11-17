//! The capsule attempt's PROGRESS EMITTER.
//!
//! # What this module is
//!
//! A running capsule attempt produces two kinds of observable movement: a
//! `Command` capsule's capture spools growing under the attempt root, and an
//! `Agent` capsule's adapter sessions folding wire events. This module gives
//! that movement its observability contract: when the checked stage authors
//! `progress_visibility != "off"`, the worker emits bounded, scrubbed
//! `WorkerMessage::CapsuleProgress` frames home; when it authors `"off"`,
//! nothing leaves the worker at all.
//!
//! # The arm's attribution
//!
//! `CapsuleProgress` names an `attempt_id` the main resolves through the
//! operational plane's `attempts` row, and lands on `subscribe_progress` as a
//! `ProgressEvent`.
//!
//! # The bounds, stated once
//!
//! * **Rate** — every observation carries an [`ObservationClass`], decided by
//!   the adapter that made it (a spool line is always a `Stream`).
//!   - A `Stream` observation — a model-text delta, a stdout line, a
//!     streaming-delta notification — sends at most one frame per kind per
//!     window. A window is [`PROGRESS_EMIT_INTERVAL`] long, ONE window shared
//!     by every kind, and a `Milestone` ends it early (below): the stream
//!     frames of one kind are bounded by one per interval plus one per
//!     milestone observed, never by the interval alone. Inside the window it
//!     COALESCES: it
//!     replaces the pending frame of the SAME kind, and only that one.
//!     Coalescing is how the bound is honoured, and it is deliberately NOT
//!     counted as a drop — a drop is signal lost, a coalesced observation's
//!     effect survives in the frame that does send. The pending frames send
//!     when their window ends — the drain task wakes at that instant — so a
//!     capsule that goes quiet (a turn holding on a model call, a shell
//!     sleeping) does not hold the last thing it did until its next
//!     observation or its end.
//!   - A `Milestone` — a model call's start, end or failure, a tool call or
//!     result, a turn boundary, a refusal — is NEVER coalesced and never held
//!     for a window: it sends at once, behind whatever stream frames are
//!     pending (they go first, early, and a new window opens), so the wire
//!     carries every frame that survives in the order it was observed. Its
//!     only refusals are the
//!     counted ones below: its own byte budget and a full queue.
//! * **Bytes** — per attempt, at most [`PROGRESS_TOTAL_BYTES`] of stream
//!   preview and, separately, [`PROGRESS_MILESTONE_BYTES`] of milestone
//!   preview, each charged when its frame SENDS — a coalesced frame costs
//!   nothing — so a long stream can never spend the budget a lifecycle frame
//!   needs. A frame that would take its total past its budget counts a drop;
//!   the `dropped` counter on the next frame that DOES send reports what was
//!   refused.
//! * **Queue** — frames travel a bounded channel to a drain task that is the
//!   only thing that calls `send_result`. A full channel refuses the frame
//!   and counts the drop: progress may not apply backpressure to a running
//!   capsule, and it may not grow the worker's memory with the container's
//!   output rate.
//! * **Accounting** — when any observation was refused, an attempt that
//!   reaches [`CapsuleProgress::finish`] ends on one `dropped: <n> …` frame
//!   carrying the attempt's whole count. The drain builds it after it emptied
//!   the queue and sends it straight to the transport, so neither bound it
//!   reports can refuse it. Not covered: an attempt whose handles all drop
//!   without `finish`, a drain `finish` aborts after its 2 s join bound, and
//!   a transport that already failed — each of those ends the attempt's
//!   progress, accounting included.
//! * **Preview** — [`PROGRESS_FRAME_PREVIEW_BYTES`] per frame, cut on a UTF-8
//!   boundary. `summary` shapes to an 80-byte head-of-delta
//!   ([`SUMMARY_PREVIEW_BYTES`]); `full`
//!   carries the bounded delta itself. `off` never constructs an emitter —
//!   `Option` at the call site, not a runtime check inside it.
//! * **Privacy** — every vendor-influenced string is scrubbed at the FUNNEL
//!   it enters through: the adapter's `record`/`note_*` fold scrubs against
//!   the attempt's lifted credentials exactly as the evidence record does,
//!   and a `Command` capsule's spool text is shell output whose environment
//!   names loopback URLs carrying no lifted value. This module trusts that
//!   contract rather than re-implementing a scrub of values it cannot see.
//!   An agent's text deltas are scrubbed as ONE stream
//!   (`kata_types::redaction::RollingScrub`): each delta is released only
//!   past the tail that could still begin a lifted value, so a value the
//!   vendor echoes split across deltas is replaced whole, and a value the
//!   stream never finishes leaves its head unreleased. Every other observed
//!   string is scrubbed alone: a value split between, say, a message chunk
//!   and a refusal's text is two strings, and is not joined.
//!
//! # What it is not
//!
//! Not authority, and not durable. `WorkerMessage::CapsuleProgress` is
//! informational: no settlement reads it, no recovery replays it, and the
//! main's reactor may drop a frame it cannot attribute with nothing but a
//! `debug!`. The emitter's own failure is silent by the same rule — a
//! channel that closed because the transport died is reported by the
//! terminal arm's own send error, not by progress panicking a capsule.

use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kata_agent::adapter::scope::{ObservationClass, SessionObservation, SessionProgressSink};
use kata_transport::transport::WorkerSideTransport;
use kata_transport::types::{AttemptFence, WorkerMessage};
use kata_types::workflow::ProgressVisibility;
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;
use ulid::Ulid;

/// The stream rate window: one frame per stream kind per window, and a window
/// lasts this long unless a milestone ends it first. 250 ms keeps a running
/// capsule's movement responsive to an operator reading SSE while bounding the
/// wire cost of a vendor that floods text.
pub const PROGRESS_EMIT_INTERVAL: Duration = Duration::from_millis(250);

/// The largest preview one frame may carry under `full` — 4 KiB. A `summary`
/// frame never reaches it (its shaping bound is 80 bytes), so the cap
/// exists for exactly the mode the check already warns streams model text.
pub const PROGRESS_FRAME_PREVIEW_BYTES: usize = 4096;

/// The most preview bytes one ATTEMPT may emit in its life — 64 KiB. Past it
/// the emitter counts drops rather than stopping silently: the `dropped`
/// field on later frames is how the operator learns the channel truncated.
/// Set against the transport's own `MESSAGE_QUEUE_DEPTH`-shaped world: an
/// attempt emits at most this much informational traffic no matter how the
/// container behaves, and a capsule that floods cannot spend the queue its
/// own terminal frame needs.
pub const PROGRESS_TOTAL_BYTES: u64 = 64 * 1024;

/// The most MILESTONE preview bytes one attempt may emit — 64 KiB, a budget
/// of its own so no stream can spend it. A milestone is one per model call or
/// tool call (`model_call_started: …` is about 20 bytes under `summary`), so
/// it bounds the frames a vendor that floods lifecycle events can cost the
/// wire, and is otherwise never reached.
pub const PROGRESS_MILESTONE_BYTES: u64 = 64 * 1024;

/// Frames queued for the drain task at once. `try_send` refuses a full one
/// and counts the drop — the channel's depth is the buffer between "a burst
/// of observations" and "the transport's own send latency", not a second
/// bound the capsule is sized by.
const PROGRESS_QUEUE_DEPTH: usize = 64;

/// The summary-mode head-of-delta bound: a typical UI title cell's width.
const SUMMARY_PREVIEW_BYTES: usize = 80;

/// The progress emitter for one capsule attempt, plus the channel drain that
/// owns its sends.
///
/// Constructed by [`CapsuleProgress::start`], which returns `None` for a
/// stage that authored `off` — the call sites then hold `Option<…>` and
/// `progress_visibility = "off"` costs literally nothing, not even a branch.
/// `Clone` because the attempt's execution takes a handle while the loop
/// keeps the one it finishes — clones are cheap (one `Arc`), and `finish`
/// is idempotent under them.
#[derive(Clone, Debug)]
pub struct CapsuleProgress {
    inner: Arc<Emitter>,
}

/// The frame builder — the send channel, the counters, the fence every frame
/// echoes, and the visibility the stage authored. `pub(crate)` rather than
/// private because the shell spool tailer ([`tail_capture_spools`]) holds an
/// `Arc` of it; the wire types it touches stay module-private.
#[derive(Debug)]
pub(crate) struct Emitter {
    /// The channel the drain task reads. `try_send` only: progress never
    /// applies backpressure to a running capsule.
    send: mpsc::Sender<WorkerMessage>,
    /// Set once by [`CapsuleProgress::finish`] — the drain empties the
    /// channel and exits on it, so a [`SessionProgressSink`] clone a session
    /// stashed past the attempt's end cannot hold the channel open forever.
    closed: Arc<Notify>,
    /// Signalled when a frame coalesces into an empty window: the drain's
    /// pump arms on it and wakes when that window ends.
    armed: Arc<Notify>,
    /// The drain task's join handle — `Option` because `finish` takes it.
    drain: Mutex<Option<tokio::task::JoinHandle<()>>>,
    attempt_id: Ulid,
    fence: AttemptFence,
    visibility: ProgressVisibility,
    /// The counters and the rate window, under ONE lock that is also held
    /// across every `try_send`: a frame's `byte_offset` is assigned and the
    /// frame enqueued in the same critical section, so the channel carries
    /// frames in offset order whoever sends them — an observing session, the
    /// spool tailer, or the drain's pump — and the main's per-attempt cursor
    /// never discards one as out of order.
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// Cumulative bytes of observed CONTENT offered so far — the spool bytes
    /// a `Command` capsule appended, the delta/identifier text an `Agent`
    /// capsule's session reported — whatever the frame's `byte_offset` then
    /// reports. Counts the SOURCE, never the preview.
    byte_offset: u64,
    /// Stream preview bytes sent so far, spent down from
    /// [`PROGRESS_TOTAL_BYTES`].
    emitted: u64,
    /// Milestone preview bytes sent so far, spent down from
    /// [`PROGRESS_MILESTONE_BYTES`].
    milestones_emitted: u64,
    /// Observations the bounds refused — a full queue or a spent byte
    /// budget. Coalescing under the rate window is NOT one of these.
    dropped: u64,
    /// The most recent instant a stream frame sent — the window's start.
    last: Option<Instant>,
    /// The stream frames coalesced in this window, waiting for it to end: at
    /// most one per kind, in the order they were observed.
    pending: Vec<Frame>,
}

/// One frame before it is a wire message: the `dropped` count it carries is
/// read when it SENDS, so a frame that waited reports the freshest count.
#[derive(Debug)]
struct Frame {
    kind: &'static str,
    byte_offset: u64,
    preview: String,
}

impl State {
    fn window_open(&self) -> bool {
        self.last
            .is_none_or(|last| last.elapsed() >= PROGRESS_EMIT_INTERVAL)
    }
}

impl CapsuleProgress {
    /// Start the emitter for `frame`, or return `None` when the stage
    /// authored `progress_visibility = "off"` — the case where the contract's
    /// first clause ("emits nothing") is kept by construction rather than by
    /// a check at every call site.
    ///
    /// The drain task it spawns holds `transport` and is the ONLY path that
    /// sends `CapsuleProgress` messages: every other send on the transport —
    /// the start checkpoint before this, the terminal result after — keeps
    /// the ordering the main's cursor expects, because the channel is FIFO
    /// and [`Self::finish`] flushes the last pending frame before the caller
    /// sends the terminal. The drain is also the PUMP: it wakes when a
    /// coalesced frame's window ends and sends it, so the window's last frame
    /// never waits for a later observation or for the turn to end.
    #[must_use]
    pub fn start(
        frame: &kata_transport::types::CapsuleAssignment,
        transport: Arc<dyn WorkerSideTransport>,
    ) -> Option<Self> {
        if frame.progress_visibility == ProgressVisibility::Off {
            return None;
        }
        let (send, recv) = mpsc::channel::<WorkerMessage>(PROGRESS_QUEUE_DEPTH);
        let inner = Arc::new(Emitter {
            send,
            closed: Arc::new(Notify::new()),
            armed: Arc::new(Notify::new()),
            drain: Mutex::new(None),
            attempt_id: frame.attempt_id,
            fence: AttemptFence::echoing_capsule(frame),
            visibility: frame.progress_visibility,
            state: Mutex::new(State::default()),
        });
        let drain = tokio::spawn(drain(
            recv,
            transport,
            Arc::clone(&inner.closed),
            Arc::clone(&inner.armed),
            Arc::downgrade(&inner),
        ));
        *inner.drain.lock().expect("progress drain lock") = Some(drain);
        Some(Self { inner })
    }

    /// The [`SessionProgressSink`] an `Agent` capsule's `AttemptScope` is
    /// handed — the same emitter, behind the adapter-facing trait so the
    /// session cannot reach the channel or the counters.
    #[must_use]
    pub fn session_sink(&self) -> Arc<dyn SessionProgressSink> {
        Arc::clone(&self.inner) as Arc<dyn SessionProgressSink>
    }

    /// The [`Emitter`] itself — for the spool tailer, which is this module's
    /// own machine and may hold the typed half rather than the trait object.
    pub(crate) fn emitter(&self) -> Arc<Emitter> {
        Arc::clone(&self.inner)
    }

    /// Flush any pending frame and end the drain. Called once the attempt's
    /// terminal frame is built — before `send_result` on it — so the last
    /// progress the main sees strictly precedes the settlement.
    ///
    /// `&self` and idempotent under clones: the attempt's execution holds a
    /// second handle while the loop finishes this one, and the signal is a
    /// `Notify` precisely so a session-stashed sink cannot hold the drain
    /// open. The join is still bounded — a wedged drain is aborted rather
    /// than awaited.
    pub async fn finish(&self) {
        self.inner.flush_pending();
        self.inner.closed.notify_one();
        let drain = self.inner.drain.lock().expect("progress drain lock").take();
        if let Some(mut drain) = drain
            && tokio::time::timeout(Duration::from_secs(2), &mut drain)
                .await
                .is_err()
        {
            drain.abort();
        }
    }
}

/// The drain task: the only sender of an attempt's progress, and its pump.
///
/// It holds the emitter WEAKLY, so it ends when the last handle drops even if
/// `finish` never runs: the emitter owns the channel's only sender, and a
/// dropped sender ends `recv`. The pump is a deadline, not a ticker — it is
/// armed only while a frame is pending and fires once, at the instant that
/// frame's window ends.
async fn drain(
    mut recv: mpsc::Receiver<WorkerMessage>,
    transport: Arc<dyn WorkerSideTransport>,
    closed: Arc<Notify>,
    armed: Arc<Notify>,
    emitter: Weak<Emitter>,
) {
    let mut due: Option<Instant> = None;
    loop {
        tokio::select! {
            message = recv.recv() => {
                let Some(message) = message else { break };
                // A send failure is informational: the transport's own error
                // is reported by the terminal arm's send, which progress can
                // neither repair nor outrank.
                if transport.send_result(message).await.is_err() {
                    break;
                }
            }
            () = armed.notified() => {
                let Some(emitter) = emitter.upgrade() else { break };
                due = emitter.pending_due();
            }
            () = tokio::time::sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
                let Some(emitter) = emitter.upgrade() else { break };
                emitter.pump();
                due = emitter.pending_due();
            }
            () = closed.notified() => {
                // THE DRAIN DOWN: `finish` signalled — empty the channel and
                // leave. Frames a racing observe enqueue after this point die
                // in the channel, which is the same loss a full channel is:
                // the attempt already settled its answer.
                while let Ok(message) = recv.try_recv() {
                    let _ = transport.send_result(message).await;
                }
                // The drop accounting goes last and straight to the wire —
                // never through the queue, whose refusals it may be reporting.
                let accounting = emitter.upgrade().and_then(|emitter| emitter.accounting());
                if let Some(accounting) = accounting {
                    let _ = transport.send_result(accounting).await;
                }
                break;
            }
        }
    }
}

impl Emitter {
    /// Offer one observation: `kind` names what was seen (`"stdout"`,
    /// `"stderr"`, a session-event tag), `text` is the content it carried —
    /// a spool line, a message delta, a tool id — already scrubbed at its
    /// funnel, and `class` whether the window may coalesce it.
    ///
    /// Never blocks, never fails: the frame either enters the drain channel
    /// inside its bounds, coalesces into the window's pending frames, or is
    /// counted as dropped.
    fn observe(&self, kind: &'static str, text: Option<&str>, class: ObservationClass) {
        // THE PREVIEW, shaped at emission by the authored visibility:
        // `summary` gets a head-of-delta at 80 bytes, `full`
        // gets the bounded delta itself. `off` never reaches here — the
        // emitter does not exist under it.
        let preview = shape_preview(self.visibility, kind, text);

        let mut state = self.state.lock().expect("progress state lock");
        // The offset counts SOURCE bytes observed — a kind-only observation
        // costs its tag's own bytes, so an event with no text still advances
        // the cursor that proves ordering.
        state.byte_offset += text.map_or_else(|| kind.len(), str::len) as u64;
        let frame = Frame {
            kind,
            byte_offset: state.byte_offset,
            preview,
        };

        match class {
            // A MILESTONE never waits and is never displaced. The pending
            // stream frames carry older offsets, so they go first.
            ObservationClass::Milestone => {
                self.send_pending(&mut state);
                self.send(&mut state, frame, class);
            }
            // The window is OPEN — this frame sends now, behind the pending.
            ObservationClass::Stream if state.window_open() => {
                self.send_pending(&mut state);
                state.last = Some(Instant::now());
                self.send(&mut state, frame, class);
            }
            // Inside the window the frame COALESCES: it replaces the pending
            // frame of its own kind and goes to the back, so the pending
            // frames stay in observation order. The displaced frame's loss
            // is the coalescing the rate bound exists to produce; it is not a
            // drop. The first frame into an empty window arms the drain's
            // pump.
            ObservationClass::Stream => {
                let arms = state.pending.is_empty();
                state.pending.retain(|held| held.kind != kind);
                state.pending.push(frame);
                drop(state);
                if arms {
                    self.armed.notify_one();
                }
            }
        }
    }

    /// Send every pending stream frame, in order, and start a new window.
    fn send_pending(&self, state: &mut State) {
        if state.pending.is_empty() {
            return;
        }
        state.last = Some(Instant::now());
        for frame in std::mem::take(&mut state.pending) {
            self.send(state, frame, ObservationClass::Stream);
        }
    }

    /// Charge `frame` to its class's byte budget and enqueue it, or count it
    /// dropped when the budget is spent or the channel is full. Called with
    /// the state lock held — see [`Emitter::state`].
    fn send(&self, state: &mut State, frame: Frame, class: ObservationClass) {
        let bytes = frame.preview.len() as u64;
        let (spent, budget) = match class {
            ObservationClass::Stream => (&mut state.emitted, PROGRESS_TOTAL_BYTES),
            ObservationClass::Milestone => {
                (&mut state.milestones_emitted, PROGRESS_MILESTONE_BYTES)
            }
        };
        if *spent + bytes > budget {
            state.dropped += 1;
            return;
        }
        *spent += bytes;
        let message = WorkerMessage::CapsuleProgress {
            attempt_id: self.attempt_id,
            byte_offset: frame.byte_offset,
            preview: frame.preview,
            dropped: state.dropped,
            fence: self.fence.clone(),
        };
        if self.send.try_send(message).is_err() {
            state.dropped += 1;
        }
    }

    /// The instant the pending frames' window ends, when any are pending.
    fn pending_due(&self) -> Option<Instant> {
        let state = self.state.lock().expect("progress state lock");
        if state.pending.is_empty() {
            return None;
        }
        Some(
            state
                .last
                .map_or_else(Instant::now, |last| last + PROGRESS_EMIT_INTERVAL),
        )
    }

    /// Send the pending frames if their window has ended — the drain's pump.
    fn pump(&self) {
        let mut state = self.state.lock().expect("progress state lock");
        if state.window_open() {
            self.send_pending(&mut state);
        }
    }

    /// Send the last coalesced frame regardless of the window — the attempt
    /// ended, so the interval's reason to hold it ended too.
    fn flush_pending(&self) {
        let mut state = self.state.lock().expect("progress state lock");
        self.send_pending(&mut state);
    }

    /// The drop accounting, when there is any: the drain's last frame, built
    /// after it emptied the queue. A refused frame cannot report itself, so
    /// the count's last word is a frame that carries no observed content at
    /// all — kata's own text, outside both byte budgets and never offered to
    /// the queue, so neither of the bounds it reports can refuse it.
    fn accounting(&self) -> Option<WorkerMessage> {
        let state = self.state.lock().expect("progress state lock");
        let dropped = state.dropped;
        (dropped > 0).then(|| WorkerMessage::CapsuleProgress {
            attempt_id: self.attempt_id,
            byte_offset: state.byte_offset,
            preview: format!("dropped: {dropped} observations refused by the emitter's bounds"),
            dropped,
            fence: self.fence.clone(),
        })
    }

    /// Count one progress observation the machinery refused without ever
    /// seeing its content — the tailer's skipped range is the caller.
    pub(crate) fn note_dropped(&self) {
        self.state.lock().expect("progress state lock").dropped += 1;
    }
}

impl SessionProgressSink for Emitter {
    fn observe(&self, observation: SessionObservation) {
        self.observe(
            observation.kind,
            observation.text.as_deref(),
            observation.class,
        );
    }
}

/// Shape `kind`/`text` into the preview string a frame carries.
///
/// `summary` — `kind` plus a head-of-delta at [`SUMMARY_PREVIEW_BYTES`]
/// total, cut on a UTF-8 boundary: the byte count the frame separately
/// carries in `byte_offset` is the summary's own number.
///
/// `full` — `kind` plus the whole text, bounded at
/// [`PROGRESS_FRAME_PREVIEW_BYTES`]: the mode the check-time
/// `full_progress_visibility` warning already tells the operator streams
/// content.
///
/// `off` is unreachable — the emitter is never constructed under it — but
/// the match stays exhaustive so a future variant is a compile error, not a
/// silent full.
fn shape_preview(visibility: ProgressVisibility, kind: &str, text: Option<&str>) -> String {
    let joined = match text {
        Some(text) if !text.is_empty() => format!("{kind}: {text}"),
        _ => kind.to_string(),
    };
    let bound = match visibility {
        ProgressVisibility::Summary => SUMMARY_PREVIEW_BYTES,
        ProgressVisibility::Full => PROGRESS_FRAME_PREVIEW_BYTES,
        ProgressVisibility::Off => unreachable!(
            "a capsule progress emitter is never constructed for progress_visibility = off"
        ),
    };
    cut_utf8(&joined, bound)
}

/// `text` truncated to at most `max` BYTES on a UTF-8 boundary — the reason
/// a preview can never carry half a codepoint.
fn cut_utf8(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

// ── THE SPOOL TAILER ──────────────────────────────────────────────────────
//
// A `Command` capsule's stdout/stderr are SPOOLED BY THE PROVIDER under the
// attempt root's `capture/` directory — the same files `publish_captures`
// puts into CAS when the drive ends. Tailing them is how a shell capsule's
// progress exists at all: the container writes through a bind kata never
// sees a pipe end of, so the file is the only stream kata can observe, and
// the tailer reads the bytes the provider already wrote rather than teeing
// a channel that does not exist.
//
// The tail semantics are the bound, stated: each poll reads at most
// `SPOOL_TAIL_READ_MAX` new bytes per stream, and a writer that raced past
// it has its middle dropped and COUNTED — what an operator sees of a flood
// is its tail, never a stalled capsule.
/// How often the spools are polled. Faster than the emit interval so a line
/// written the instant before a poll still earns the next window.
const SPOOL_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// The most new bytes one poll reads from one spool. A faster writer has its
/// middle skipped to the tail; the skip counts as dropped progress.
const SPOOL_TAIL_READ_MAX: u64 = 32 * 1024;
/// A single output line's length bound — longer lines are read in
/// `SPOOL_TAIL_READ_MAX` chunks anyway, so a line longer than this is
/// emitted in bounded pieces rather than buffered whole in worker memory.
const SPOOL_LINE_MAX: usize = 1024;

/// One spool file's tail state across polls.
struct SpoolCursor {
    /// The frame kind it emits under — `"stdout"` or `"stderr"`.
    kind: &'static str,
    /// `<attempt_root>/capture/<stream>`.
    path: std::path::PathBuf,
    /// The file offset the next read starts at.
    offset: u64,
    /// An unterminated line tail carried between polls.
    pending: String,
}

/// The handle `execute_capsule_frame` keeps for one attempt's pair of
/// tailers. `stop` ends the tail and flushes the partial lines; dropping the
/// sender without signalling does the same on the tailer's next poll.
#[derive(Debug)]
pub(crate) struct SpoolTail {
    stop: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}

impl SpoolTail {
    /// Signal the tail to take one last read — flushing the unterminated
    /// line a writer left mid-write — and then join it. Awaiting it AFTER
    /// the drive resolves is how the last bytes the provider spooled make
    /// their frame before the terminal message does.
    pub(crate) async fn finish(self) {
        let _ = self.stop.send(());
        let _ = self.join.await;
    }
}

/// Spawn the pair of spool tailers for `attempt_root`, or `None` when the
/// emitter is `None` — `off` builds nothing, same rule as the emitter.
///
/// `attempt_root` is `<worker_state>/attempts/<tag>` — the path the driver
/// derived for the drive now in flight; the `capture/` directory inside it
/// is created by the supervisor, so the tailer tolerates its absence until
/// the provider opens the spools. A `Command` capsule's spool content needs
/// no `LiftedSecrets` — the capsule's environment names loopback proxy URLs
/// and nothing else, which is settled in `crate::oci_driver`'s egress
/// construction — so the text enters the funnel already as clean as a scrub
/// would leave it.
pub(crate) fn tail_capture_spools(
    progress: &CapsuleProgress,
    attempt_root: std::path::PathBuf,
) -> SpoolTail {
    let emitter = progress.emitter();
    let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
    let spool = attempt_root.join(crate::oci_driver::ATTEMPT_SPOOL_DIRECTORY);
    let mut cursors = [
        SpoolCursor {
            kind: "stdout",
            path: spool.join(kata_provider_protocol::capture::SPOOL_STDOUT),
            offset: 0,
            pending: String::new(),
        },
        SpoolCursor {
            kind: "stderr",
            path: spool.join(kata_provider_protocol::capture::SPOOL_STDERR),
            offset: 0,
            pending: String::new(),
        },
    ];
    let join = tokio::spawn(async move {
        let mut poll = tokio::time::interval(SPOOL_POLL_INTERVAL);
        poll.tick().await;
        loop {
            tokio::select! {
                _ = poll.tick() => {
                    for cursor in &mut cursors {
                        read_the_tail(&emitter, cursor).await;
                    }
                }
                _ = &mut stopped => {
                    // ONE LAST READ — the provider's final bytes land between
                    // the drive resolving and this signal, and the terminal
                    // frame is not sent until the tail finishes, so the last
                    // line is progress the main still hears about.
                    for cursor in &mut cursors {
                        read_the_tail(&emitter, cursor).await;
                        if !cursor.pending.is_empty() {
                            emitter.observe(
                                cursor.kind,
                                Some(&cursor.pending.clone()),
                                ObservationClass::Stream,
                            );
                            cursor.pending.clear();
                        }
                    }
                    return;
                }
            }
        }
    });
    SpoolTail { stop, join }
}

/// Read what `cursor`'s spool appended since its last poll, emit the
/// completed lines, keep the tail.
///
/// The bound is `SPOOL_TAIL_READ_MAX` per poll: a writer ahead of it has its
/// middle skipped to the newest window and the skip counted as a drop —
/// `dropped` is how the operator learns the tail truncated, and "the tail"
/// is what the authored knob promised anyway.
async fn read_the_tail(emitter: &Emitter, cursor: &mut SpoolCursor) {
    let length = match tokio::fs::metadata(&cursor.path).await {
        Ok(metadata) => metadata.len(),
        // A missing file is a container that has not opened its capture
        // yet — the supervisor creates `capture/` at drive start and the
        // provider opens the files inside it. Neither is an error here.
        Err(_) => return,
    };
    if length <= cursor.offset {
        return;
    }
    let available = length - cursor.offset;
    if available > SPOOL_TAIL_READ_MAX {
        cursor.offset = length - SPOOL_TAIL_READ_MAX;
        // The skipped middle is a dropped range of progress signal — one
        // count per skip, because it is the SKIP that was refused, and the
        // lines inside it were never read well enough to count.
        emitter.note_dropped();
        cursor.pending.clear();
    }
    let want = usize::try_from(length - cursor.offset)
        .expect("the read window is bounded by SPOOL_TAIL_READ_MAX");
    let Ok(mut file) = tokio::fs::File::open(&cursor.path).await else {
        return;
    };
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if file
        .seek(std::io::SeekFrom::Start(cursor.offset))
        .await
        .is_err()
    {
        return;
    }
    let mut appended = vec![0u8; want];
    if file.read_exact(&mut appended).await.is_err() {
        // A file that shrank between `metadata` and `read` was rotated or
        // replaced — resume from its current length rather than asserting
        // bytes that no longer exist at the offset read.
        cursor.offset = file.metadata().await.map_or(length, |meta| meta.len());
        return;
    }
    cursor.offset = length;
    cursor.pending.push_str(&String::from_utf8_lossy(&appended));
    while let Some(newline) = cursor.pending.find('\n') {
        let mut line = cursor.pending.drain(..=newline).collect::<String>();
        if line.ends_with('\n') {
            line.pop();
        }
        if line.ends_with('\r') {
            line.pop();
        }
        while line.len() > SPOOL_LINE_MAX {
            emitter.observe(
                cursor.kind,
                Some(&take_bounded(&mut line)),
                ObservationClass::Stream,
            );
        }
        emitter.observe(cursor.kind, Some(&line), ObservationClass::Stream);
    }
    // An unterminated tail is kept, but bounded the same way — a writer
    // that never newlines cannot grow `pending` without bound either.
    while cursor.pending.len() > SPOOL_LINE_MAX {
        emitter.observe(
            cursor.kind,
            Some(&take_bounded(&mut cursor.pending)),
            ObservationClass::Stream,
        );
    }
}

/// Drain the first [`SPOOL_LINE_MAX`] bytes of `text`, rounding DOWN to a
/// char boundary so the piece is itself whole codepoints — the spool's
/// `from_utf8_lossy` already repaired any byte-split the read window made,
/// so the only boundary to respect here is a codepoint's.
fn take_bounded(text: &mut String) -> String {
    let mut end = SPOOL_LINE_MAX.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.drain(..end).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kata_transport::types::{CapsuleAssignment, CapsuleRef, TraceContext};
    use kata_types::execution_contract::{CapsuleId, OccurrenceId};
    use kata_types::primitives::FixedBytes;
    use std::sync::Mutex as StdMutex;

    fn capsule(visibility: ProgressVisibility) -> CapsuleAssignment {
        CapsuleAssignment {
            attempt_id: Ulid::new(),
            execution_id: Ulid::new(),
            occurrence_id: OccurrenceId(FixedBytes([3u8; 32])),
            capsule: CapsuleRef {
                id: CapsuleId(FixedBytes([4u8; 32])),
                object: FixedBytes([5u8; 32]),
                size_bytes: 128,
            },
            lease_epoch: 7,
            placed_on: smol_str::SmolStr::new("worker-1"),
            command_id: None,
            effect_domain: None,
            start_deadline_ms: None,
            progress_visibility: visibility,
            trace: TraceContext::default(),
        }
    }

    /// A `WorkerSideTransport` that RECORDS every `send_result` — the second
    /// handle the assertions read, so nothing under test vouches for itself.
    #[derive(Default, Debug)]
    struct Recording {
        sent: StdMutex<Vec<WorkerMessage>>,
    }

    #[async_trait::async_trait]
    impl WorkerSideTransport for Recording {
        async fn recv_frame(
            &self,
        ) -> kata_types::error::KataResult<kata_transport::types::DispatchFrame> {
            std::future::pending().await
        }
        async fn recv_control(
            &self,
        ) -> kata_types::error::KataResult<kata_transport::types::WorkerControl> {
            std::future::pending().await
        }
        async fn send_result(&self, message: WorkerMessage) -> kata_types::error::KataResult<()> {
            self.sent.lock().expect("recording lock").push(message);
            Ok(())
        }
        async fn shutdown(&self) -> kata_types::error::KataResult<()> {
            Ok(())
        }
        fn is_alive(&self) -> bool {
            true
        }
    }

    /// Offer a STREAM observation, as a spool line or a text delta is.
    fn stream(progress: &CapsuleProgress, kind: &'static str, text: Option<&str>) {
        progress.inner.observe(kind, text, ObservationClass::Stream);
    }

    /// Offer a MILESTONE observation, as a model call's start or a tool call is.
    fn milestone(progress: &CapsuleProgress, kind: &'static str, text: Option<&str>) {
        progress
            .inner
            .observe(kind, text, ObservationClass::Milestone);
    }

    fn progress_frames(recording: &Recording) -> Vec<(u64, String, u64)> {
        recording
            .sent
            .lock()
            .expect("recording lock")
            .iter()
            .filter_map(|message| match message {
                WorkerMessage::CapsuleProgress {
                    byte_offset,
                    preview,
                    dropped,
                    ..
                } => Some((*byte_offset, preview.clone(), *dropped)),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn an_off_stage_builds_no_emitter() {
        let recording = Arc::new(Recording::default());
        let emitter = CapsuleProgress::start(&capsule(ProgressVisibility::Off), recording);
        assert!(emitter.is_none(), "off authors nothing to observe through");
    }

    #[tokio::test]
    async fn a_summary_frame_carries_kind_and_a_head_of_delta() {
        let recording = Arc::new(Recording::default());
        let emitter =
            CapsuleProgress::start(&capsule(ProgressVisibility::Summary), recording.clone())
                .expect("summary builds an emitter");
        let long = "x".repeat(400);
        stream(&emitter, "agent_message_chunk", Some(&long));
        emitter.finish().await;
        let frames = progress_frames(&recording);
        assert_eq!(frames.len(), 1);
        let (offset, preview, dropped) = &frames[0];
        assert_eq!(
            *offset, 400,
            "the offset counts the source, not the preview"
        );
        assert_eq!(*dropped, 0);
        assert!(preview.starts_with("agent_message_chunk: "));
        assert!(
            preview.len() <= SUMMARY_PREVIEW_BYTES,
            "summary previews bound to 80 bytes: {preview:?}"
        );
    }

    #[tokio::test]
    async fn a_full_frame_carries_the_bounded_delta() {
        let recording = Arc::new(Recording::default());
        let emitter = CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
            .expect("full builds an emitter");
        let text = "the model says the patch looks right";
        stream(&emitter, "agent_message_chunk", Some(text));
        emitter.finish().await;
        let frames = progress_frames(&recording);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].1, format!("agent_message_chunk: {text}"));
    }

    #[tokio::test]
    async fn observations_inside_the_window_coalesce_and_the_latest_wins() {
        let recording = Arc::new(Recording::default());
        let emitter = CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
            .expect("full builds an emitter");
        for index in 0..10 {
            stream(&emitter, "stdout", Some(&format!("line-{index}")));
        }
        emitter.finish().await;
        let frames = progress_frames(&recording);
        // Ten observations, two sendable instants at most — and the SECOND
        // frame's preview is the LAST line's, because the pending slot keeps
        // the latest. The coalesced eight are not drops.
        assert!(frames.len() <= 2, "the window coalesced: {frames:?}");
        let last = frames.last().expect("at least one frame");
        assert_eq!(last.1, "stdout: line-9");
        assert_eq!(last.2, 0, "coalescing is not a drop");
        // Offsets stay monotone across whatever sent.
        let offsets: Vec<u64> = frames.iter().map(|frame| frame.0).collect();
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(offsets, sorted, "byte_offset is non-decreasing");
    }

    #[tokio::test(start_paused = true)]
    async fn the_byte_budget_counts_what_it_refused() {
        let recording = Arc::new(Recording::default());
        let emitter = CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
            .expect("full builds an emitter");
        // Sixty-five KiB of "full" text in 1 KiB chunks, one per window so
        // each one SENDS: the budget is 64 KiB, so the tail is refused — and
        // the frames that do send report the refusal count.
        let chunk = "y".repeat(1024);
        for _ in 0..65 {
            stream(&emitter, "stdout", Some(&chunk));
            tokio::time::advance(PROGRESS_EMIT_INTERVAL).await;
        }
        emitter.finish().await;
        let frames = progress_frames(&recording);
        let total_preview: u64 = frames
            .iter()
            .filter(|frame| frame.1.starts_with("stdout: "))
            .map(|frame| frame.1.len() as u64)
            .sum();
        assert!(
            total_preview <= PROGRESS_TOTAL_BYTES,
            "the attempt emitted {total_preview} preview bytes"
        );
        let last_dropped = frames.last().map_or(0, |frame| frame.2);
        assert!(
            last_dropped > 0,
            "the spent budget's refusals are reported on the wire: {frames:?}"
        );
    }

    #[tokio::test]
    async fn a_preview_never_carries_half_a_codepoint() {
        let recording = Arc::new(Recording::default());
        let emitter =
            CapsuleProgress::start(&capsule(ProgressVisibility::Summary), recording.clone())
                .expect("summary builds an emitter");
        // A 3-byte codepoint straddling the 80-byte cut must not leak a
        // fragment: the preview stays valid UTF-8 by construction.
        let text = format!("{}{}", "a".repeat(78), "€".repeat(10));
        stream(&emitter, "stdout", Some(&text));
        emitter.finish().await;
        let frames = progress_frames(&recording);
        let preview = &frames[0].1;
        assert!(preview.len() <= SUMMARY_PREVIEW_BYTES);
        assert!(std::str::from_utf8(preview.as_bytes()).is_ok());
    }

    /// Wait until a progress frame whose preview is exactly `preview` has reached
    /// the recording transport — the observable condition a cell orders its next
    /// write after, where a sleep would assume the poller's schedule.
    async fn wire_shows(recording: &Recording, preview: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !progress_frames(recording)
            .iter()
            .any(|frame| frame.1 == preview)
        {
            assert!(
                Instant::now() < deadline,
                "no `{preview}` frame reached the wire within 10s: {:?}",
                progress_frames(recording)
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn the_spool_tail_streams_bounded_lines_and_counts_a_skip() {
        // The filesystem is the second handle: bytes written as the provider
        // would write them, the wire read back as the main would receive it.
        let root = tempfile::tempdir().expect("an attempt root");
        let spool = root.path().join(crate::oci_driver::ATTEMPT_SPOOL_DIRECTORY);
        std::fs::create_dir_all(&spool).expect("the capture directory");
        let stdout = spool.join(kata_provider_protocol::capture::SPOOL_STDOUT);
        let stderr = spool.join(kata_provider_protocol::capture::SPOOL_STDERR);
        std::fs::write(&stdout, "first\n").expect("stdout's first line");
        std::fs::write(&stderr, "warn: be careful\n").expect("stderr's first line");

        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");
        let tail = tail_capture_spools(&progress, root.path().to_path_buf());

        // The periodic poll streams: stdout's first line sends at once (the window
        // is open), stderr's coalesces and follows at the next open window. Both are
        // awaited ON THE WIRE before the flood: a stdout line read later would be
        // skipped with it, and a coalesced stderr frame still pending would be
        // displaced by the flood's pieces.
        wire_shows(&recording, "stdout: first").await;
        wire_shows(&recording, "stderr: warn: be careful").await;

        // An unterminated tail and then a writer racing past the read bound,
        // published in ONE step. A single `write(2)` would not do it: a regular
        // file's size grows page by page inside one write, and a poll whose `stat`
        // lands between pages reads the flood in two windows under the bound —
        // MEASURED on ext4, 298 of 300 single 34 KiB writes were seen mid-write by
        // a concurrent `stat`. That interleaving skips nothing, and
        // `a_flood_read_in_two_polls_under_the_bound_streams_whole_and_counts_nothing`
        // pins it. Renaming a complete copy over the spool is the one write the
        // poller sees whole, so here the middle — the partial included — is
        // SKIPPED and counted, never read and never emitted. It is not a write the
        // provider makes (the container appends through youki's descriptors); the
        // append-growth interleavings are the two cells that drive `read_the_tail`
        // poll by poll.
        let mut grown = std::fs::read(&stdout).expect("the spool so far");
        grown.extend_from_slice(b"tail-partial");
        grown.resize(
            grown.len()
                + usize::try_from(SPOOL_TAIL_READ_MAX + 2048)
                    .expect("the write bound fits a usize"),
            b'q',
        );
        let next = spool.join("stdout.next");
        std::fs::write(&next, &grown).expect("the grown spool");
        std::fs::rename(&next, &stdout).expect("the grown spool replaces the old one whole");

        tail.finish().await;
        progress.finish().await;

        let frames = progress_frames(&recording);
        let previews: Vec<&str> = frames.iter().map(|frame| frame.1.as_str()).collect();
        assert!(
            previews.contains(&"stdout: first"),
            "the first line reached the wire: {previews:?}"
        );
        assert!(
            previews.contains(&"stderr: warn: be careful"),
            "stderr tails under its own kind: {previews:?}"
        );
        assert!(
            previews
                .iter()
                .any(|preview| preview.starts_with("stdout: qqq")),
            "the flooding write's tail still streams: {previews:?}"
        );
        assert!(
            !previews
                .iter()
                .any(|preview| preview.contains("tail-partial")),
            "the skipped middle is gone, not reassembled: {previews:?}"
        );
        assert!(
            frames.last().is_some_and(|frame| frame.2 >= 1)
                || previews
                    .iter()
                    .any(|preview| preview.contains("dropped: 1")),
            "the skip reached the wire as a counted drop: {frames:?}"
        );
    }

    /// **A flood the tailer reads in two polls, each under the bound, is streamed —
    /// not skipped and not counted — the held partial line with it.**
    ///
    /// The interleaving a concurrent `stat` produces when it lands between a single
    /// write's pages (see the spool-tail cell above), driven here poll by poll so no
    /// scheduler decides it. The file is the independent reader: every byte it holds
    /// is either on the wire's offset or still held in the cursor.
    ///
    /// COUNTERFACTUAL: skip at half the read bound in `read_the_tail` and each half
    /// of this flood is skipped and counted.
    #[tokio::test]
    async fn a_flood_read_in_two_polls_under_the_bound_streams_whole_and_counts_nothing() {
        let root = tempfile::tempdir().expect("an attempt root");
        let path = root.path().join("stdout");
        std::fs::write(&path, "first\n").expect("the first line");
        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");
        let emitter = progress.emitter();
        let mut cursor = SpoolCursor {
            kind: "stdout",
            path: path.clone(),
            offset: 0,
            pending: String::new(),
        };
        read_the_tail(&emitter, &mut cursor).await;

        let append = |bytes: &[u8]| {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .and_then(|mut file| file.write_all(bytes))
                .expect("append to the spool");
        };
        append(b"tail-partial");
        read_the_tail(&emitter, &mut cursor).await;
        assert_eq!(
            cursor.pending, "tail-partial",
            "an unterminated tail is held in the cursor, not emitted"
        );

        let flood = usize::try_from(SPOOL_TAIL_READ_MAX + 2048).expect("fits a usize");
        let first_half = flood / 2;
        assert!(
            first_half as u64 <= SPOOL_TAIL_READ_MAX && first_half as u64 > SPOOL_TAIL_READ_MAX / 2,
            "each half is under the bound and over half of it"
        );
        append(&vec![b'q'; first_half]);
        read_the_tail(&emitter, &mut cursor).await;
        assert!(
            !cursor.pending.contains("tail-partial"),
            "the held partial went out at the head of the flood's first bounded piece"
        );
        append(&vec![b'q'; flood - first_half]);
        read_the_tail(&emitter, &mut cursor).await;
        progress.finish().await;

        let frames = progress_frames(&recording);
        assert!(
            frames.iter().all(|frame| frame.2 == 0)
                && !frames.iter().any(|frame| frame.1.starts_with("dropped:")),
            "nothing was skipped, so nothing is counted: {frames:?}"
        );
        let on_disk = std::fs::metadata(&path).expect("the spool").len();
        let observed = frames.last().expect("frames were sent").0;
        assert_eq!(
            observed + cursor.pending.len() as u64,
            on_disk - 1,
            "every byte on disk but the one newline was observed or is still held"
        );
    }

    /// **A partial line held across polls is skipped with the flood that raced past
    /// it — counted, and never reassembled onto the flood's tail.**
    ///
    /// Driven poll by poll, as the cell above is: the partial is read and held by
    /// one poll, the flood lands whole before the next.
    ///
    /// COUNTERFACTUAL: drop `cursor.pending.clear()` from `read_the_tail`'s skip
    /// and the held partial is glued to the tail's first piece.
    #[tokio::test]
    async fn a_held_partial_line_is_skipped_with_the_flood_that_raced_past_it() {
        let root = tempfile::tempdir().expect("an attempt root");
        let path = root.path().join("stdout");
        std::fs::write(&path, "first\ntail-partial").expect("a line and a partial");
        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");
        let emitter = progress.emitter();
        let mut cursor = SpoolCursor {
            kind: "stdout",
            path: path.clone(),
            offset: 0,
            pending: String::new(),
        };
        read_the_tail(&emitter, &mut cursor).await;
        assert_eq!(cursor.pending, "tail-partial", "the partial is held");

        {
            use std::io::Write;
            let flood = usize::try_from(SPOOL_TAIL_READ_MAX + 2048).expect("fits a usize");
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .and_then(|mut file| file.write_all(&vec![b'q'; flood]))
                .expect("the flooding write");
        }
        read_the_tail(&emitter, &mut cursor).await;
        progress.finish().await;

        let frames = progress_frames(&recording);
        // Coalescing keeps only the latest piece on the wire, so the offset is the
        // witness: after `first` (5 source bytes), what was observed plus what is
        // still held is exactly the read window at the file's tail — the partial
        // added nothing.
        let observed = frames.last().expect("frames were sent").0;
        assert_eq!(
            observed - 5 + cursor.pending.len() as u64,
            SPOOL_TAIL_READ_MAX,
            "the skipped partial is gone, not reassembled: {frames:?}"
        );
        assert!(
            !frames.iter().any(|frame| frame.1.contains("tail-partial")),
            "no frame carries the skipped partial: {frames:?}"
        );
        assert!(
            frames
                .iter()
                .any(|frame| frame.1 == "dropped: 1 observations refused by the emitter's bounds"),
            "the skip reached the wire as one counted drop: {frames:?}"
        );
    }

    /// Let every task that is READY run, without moving the clock: the cells
    /// below run on the paused current-thread runtime, so no time passes here
    /// and nothing is waited for — the drain either already had what it needs
    /// to act or it does not act.
    async fn run_ready_tasks() {
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    }

    fn previews(recording: &Recording) -> Vec<String> {
        progress_frames(recording)
            .into_iter()
            .map(|(_, preview, _)| preview)
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn a_coalesced_frame_sends_when_its_window_ends_with_no_later_observation() {
        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");

        // The first observation opens the window and sends at once.
        stream(&progress, "agent_message_chunk", Some("first"));
        run_ready_tasks().await;
        assert_eq!(previews(&recording), ["agent_message_chunk: first"]);

        // 100 ms in, a second observation coalesces: the window is closed.
        tokio::time::advance(Duration::from_millis(100)).await;
        stream(&progress, "agent_message_chunk", Some("held"));
        run_ready_tasks().await;
        assert_eq!(
            previews(&recording),
            ["agent_message_chunk: first"],
            "inside the window the frame waits"
        );

        // 1 ms before the window ends it still waits — the rate bound holds.
        tokio::time::advance(Duration::from_millis(149)).await;
        run_ready_tasks().await;
        assert_eq!(previews(&recording), ["agent_message_chunk: first"]);

        // At the window's end it sends, with no later observation and no
        // `finish`: a turn that holds does not hold its last frame.
        tokio::time::advance(Duration::from_millis(1)).await;
        run_ready_tasks().await;
        assert_eq!(
            previews(&recording),
            ["agent_message_chunk: first", "agent_message_chunk: held"],
            "the coalesced frame left at its window's end"
        );

        progress.finish().await;
        assert_eq!(previews(&recording).len(), 2, "finish sent nothing twice");
    }

    #[tokio::test(start_paused = true)]
    async fn the_drain_and_its_pump_end_with_the_attempt() {
        // The drain task holds the transport; its `Arc` count is the outside
        // witness that the task — the pump inside it included — ended.
        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");
        stream(&progress, "stdout", Some("one"));
        stream(&progress, "stdout", Some("two"));
        run_ready_tasks().await;
        assert_eq!(Arc::strong_count(&recording), 2, "the drain holds the wire");
        progress.finish().await;
        assert_eq!(
            Arc::strong_count(&recording),
            1,
            "finish ended the drain with a pump armed"
        );

        // No `finish` at all: every handle dropped, a frame pending and the
        // pump armed. The drain must still end, not tick forever.
        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");
        let sink = progress.session_sink();
        stream(&progress, "stdout", Some("one"));
        sink.observe(SessionObservation {
            kind: "agent_message_chunk",
            text: Some("pending".to_string()),
            class: ObservationClass::Stream,
        });
        run_ready_tasks().await;
        drop(progress);
        drop(sink);
        run_ready_tasks().await;
        assert_eq!(
            Arc::strong_count(&recording),
            1,
            "the drain ended when its last handle dropped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_milestone_is_ever_displaced_and_a_stream_supersedes_only_its_own_kind() {
        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");

        // A model call and a tool call, all inside ONE window that the first
        // chunk opened: no clock moves between them.
        stream(&progress, "agent_message_chunk", Some("a"));
        milestone(&progress, "model_call_started", None);
        stream(&progress, "agent_message_chunk", Some("b"));
        stream(&progress, "agent_message_chunk", Some("c"));
        milestone(&progress, "model_call_completed", None);
        milestone(&progress, "tool_call", Some("t1"));
        stream(&progress, "agent_message_chunk", Some("d"));
        milestone(&progress, "tool_result", Some("t1"));
        milestone(&progress, "model_call_started", None);
        run_ready_tasks().await;
        // Every milestone is on the wire at once, none displaced, and the
        // chunk pending before each went first: `b` is the one frame the
        // window coalesced away (into `c`, its own kind).
        assert_eq!(
            previews(&recording),
            [
                "agent_message_chunk: a",
                "model_call_started",
                "agent_message_chunk: c",
                "model_call_completed",
                "tool_call: t1",
                "agent_message_chunk: d",
                "tool_result: t1",
                "model_call_started",
            ]
        );

        // Two stream kinds interleaved inside the next window: each
        // supersedes only its own kind, and both send when the window ends.
        stream(&progress, "agent_message_chunk", Some("e"));
        stream(&progress, "usage_update", Some("1"));
        stream(&progress, "agent_message_chunk", Some("f"));
        stream(&progress, "usage_update", Some("2"));
        run_ready_tasks().await;
        assert_eq!(previews(&recording).len(), 8, "the window holds them");
        tokio::time::advance(PROGRESS_EMIT_INTERVAL).await;
        run_ready_tasks().await;
        progress.finish().await;

        let frames = progress_frames(&recording);
        let sent: Vec<&str> = frames.iter().map(|frame| frame.1.as_str()).collect();
        assert_eq!(
            sent[8..],
            ["agent_message_chunk: f", "usage_update: 2"],
            "each kind kept its latest"
        );
        // The main's cursor discards a frame whose offset is behind the last:
        // every frame that sent is strictly ahead of the one before it, and
        // none of this was a drop.
        assert!(
            frames.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "byte_offset strictly increases on the wire: {frames:?}"
        );
        assert!(frames.iter().all(|frame| frame.2 == 0), "{frames:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_that_spends_its_budget_never_refuses_a_milestone() {
        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");
        // A model call whose text alone outruns the stream budget: seventy
        // 1 KiB deltas, one per window so every one sends.
        milestone(&progress, "model_call_started", None);
        let delta = "z".repeat(1024);
        for _ in 0..70 {
            stream(&progress, "agent_message_chunk", Some(&delta));
            tokio::time::advance(PROGRESS_EMIT_INTERVAL).await;
        }
        milestone(&progress, "model_call_completed", None);
        // Then a hundred more calls, each a tool call — more lifecycle bytes
        // than whatever the stream left of its own budget. The drain runs
        // between calls, as it does between a vendor's frames: a burst past
        // the queue's depth with no send in between is the queue bound's
        // counted refusal, not this cell's subject.
        for _ in 0..100 {
            milestone(&progress, "tool_call", Some("exec"));
            milestone(&progress, "model_call_started", None);
            milestone(&progress, "model_call_completed", None);
            run_ready_tasks().await;
        }
        progress.finish().await;

        let frames = progress_frames(&recording);
        let sent: Vec<&str> = frames.iter().map(|frame| frame.1.as_str()).collect();
        let count = |kind: &str| sent.iter().filter(|preview| **preview == kind).count();
        assert_eq!(
            count("model_call_started"),
            101,
            "every start reached the wire"
        );
        assert_eq!(count("model_call_completed"), 101, "every completion did");
        assert_eq!(count("tool_call: exec"), 100, "every tool call did");
        let completed = sent
            .iter()
            .position(|preview| *preview == "model_call_completed")
            .expect("the first call's completion reached the wire");
        assert!(
            frames[completed].2 > 0,
            "the stream's own refusals are counted on the milestone that followed: {:?}",
            frames[completed]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_past_the_queue_depth_reports_its_refusals_on_the_wire() {
        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");
        // Six milestones more than the queue holds, with no send in between:
        // the queue refuses six, and the attempt ends on a still-full queue.
        let burst = PROGRESS_QUEUE_DEPTH + 6;
        for _ in 0..burst {
            milestone(&progress, "model_call_started", None);
        }
        progress.finish().await;

        let frames = progress_frames(&recording);
        let starts = frames
            .iter()
            .filter(|frame| frame.1 == "model_call_started")
            .count();
        assert_eq!(starts, PROGRESS_QUEUE_DEPTH, "{frames:?}");
        let last = frames.last().expect("frames reached the wire");
        assert_eq!(
            (last.0, last.2),
            ((burst * "model_call_started".len()) as u64, 6),
            "the refusals a full queue made reach the wire after the last frame it held: {last:?}"
        );
        assert!(last.1.starts_with("dropped: 6 "), "{last:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_coalesced_frame_spends_no_budget() {
        let recording = Arc::new(Recording::default());
        let progress =
            CapsuleProgress::start(&capsule(ProgressVisibility::Full), recording.clone())
                .expect("full builds an emitter");
        // Two thousand 1 KiB deltas inside one window — thirty times the
        // budget OFFERED, two frames SENT.
        let delta = "w".repeat(1024);
        for _ in 0..2000 {
            stream(&progress, "agent_message_chunk", Some(&delta));
        }
        tokio::time::advance(PROGRESS_EMIT_INTERVAL).await;
        run_ready_tasks().await;
        stream(&progress, "agent_message_chunk", Some("after"));
        progress.finish().await;

        let frames = progress_frames(&recording);
        assert_eq!(frames.len(), 3, "{frames:?}");
        assert_eq!(frames[2].1, "agent_message_chunk: after");
        assert!(
            frames.iter().all(|frame| frame.2 == 0),
            "what the window coalesced away cost the budget nothing: {frames:?}"
        );
    }

    #[test]
    fn the_session_sink_adapts_an_observation() {
        let (send, _recv) = mpsc::channel::<WorkerMessage>(PROGRESS_QUEUE_DEPTH);
        let emitter = Emitter {
            send,
            closed: Arc::new(Notify::new()),
            armed: Arc::new(Notify::new()),
            drain: Mutex::new(None),
            attempt_id: Ulid::new(),
            fence: AttemptFence::default(),
            visibility: ProgressVisibility::Full,
            state: Mutex::new(State::default()),
        };
        SessionProgressSink::observe(
            &emitter,
            SessionObservation {
                kind: "tool_call",
                text: Some("tool-7".to_string()),
                class: ObservationClass::Milestone,
            },
        );
        assert_eq!(
            emitter
                .state
                .lock()
                .expect("progress state lock")
                .byte_offset,
            6
        );
    }
}
