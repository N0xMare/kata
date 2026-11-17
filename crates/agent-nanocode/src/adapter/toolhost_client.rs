//! The worker's end of the toolhost wire: frames out over the capsule init's
//! stdin through ONE writer task, frames in over its stdout, and the PROTOCOL
//! LATCH that records the first way the wire broke.
//!
//! # Why a latch
//!
//! nanocode's host seam answers the MODEL, not kata: `ShellExecutor::execute`
//! returns a tool result, and `FileHost` a `Result<_, String>` the tool handler
//! renders for the model. A toolhost that died would therefore be a string the
//! model reads while the loop keeps calling (and paying for) the model. So the
//! client latches the first break, with its reason, and the session classifies
//! the turn by the latch before anything nanocode returned (`session.rs`).
//!
//! # What sets the latch
//!
//! Exactly these, each a reason the latch keeps verbatim:
//! * stdout EOF, or a read error on it;
//! * a frame the codec refuses (zero or oversize length, not JSON, an unknown
//!   kind or field);
//! * an `Error` frame;
//! * a second `Hello`;
//! * a reply whose `id` names no outstanding request (unknown, or already
//!   answered), and a session frame naming a session kata never opened;
//! * a reply of a kind its request cannot be answered with (`seam.rs` asks);
//! * a write that fails (the toolhost's stdin is gone).
//!
//! A frame this side cannot encode (a body over `MAX_FRAME_BYTES`) is none of
//! these: [`Outbound::encode`] refuses it to its caller before the seam marks
//! the watermark for it, so nothing is marked, queued or latched, and the
//! model reads the refusal as that tool call's failure.
//!
//! Once set, no further frame is written: every send checks the latch first,
//! and the writer stops at it, dropping a write in progress.
//!
//! # One writer, whole frames
//!
//! Every frame reaches the toolhost's stdin through one writer task, as a whole
//! encoded frame taken off a queue ([`QUEUED_FRAMES`] deep). A seam call runs
//! inline in nanocode's futures, and nanocode drops them mid-flight: a Code Mode
//! cell that ends drops its un-awaited calls, `TaskStop` drops a background
//! `Bash`. Such a drop gives up at most the caller's wait for room in the queue,
//! so no dropped caller cuts a frame: a frame torn off part way would leave the
//! toolhost reading every later frame as the rest of its body. The writer cuts
//! the frame it is writing only when it stops (below), and the stdin closes
//! right behind that cut, so no frame follows it.
//!
//! # The gate holds the queue
//!
//! Once the turn's [`TurnGate`] is closed, the client queues only `KillAll`,
//! `Signal` and `Shutdown`, the frames a stopping turn reaches the capsule
//! with; every other frame is refused ([`WireRefusal::Stopping`]) and never
//! queued. The gate is read and the frame queued under the gate's own lock,
//! which closing the gate takes, so a frame queued while the gate was open
//! precedes everything queued after the close (the turn end's `KillAll`), and
//! no frame the gate holds is queued after it. A seam call admitted before the
//! close (`Seam::admit_effect`) is therefore refused at the queue if it had not
//! queued its frame yet: a call that sends several frames (a `write_stdin`
//! larger than one chunk) sends the ones it queued before the close and no
//! more.
//!
//! # How the writer stops
//!
//! The writer stops at the latch, and when [`ToolhostClient::close_stdin`]
//! aborts it, and either way drops the stdin with any write in progress. Only
//! that drop ends a write the toolhost no longer reads: kata's end of the stdin
//! FIFO is opened read-write (`kata-worker`'s `LiveStdio::open`), so kata
//! itself counts as a reader and the kernel never fails the write with EPIPE,
//! not even once the toolhost is gone. `close_stdin` waits on no write.
//!
//! # A session's output is held in a bounded window
//!
//! Each session's `Output` frames land in its [`SessionBuffer`], a head+tail
//! window of [`SESSION_OUTPUT_BYTES`] the reader writes and the seam drains.
//! The toolhost holds no output beyond one 64 KiB chunk, so this window is the
//! whole worker-side bound: a capsule process that floods its stdout while no
//! tool call is reading it (a session left running past its yield) grows the
//! worker by at most that much per session, never without bound. What falls
//! out of the middle of the window is counted, and the model is told how much.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use kata_agent::adapter::{IssuanceFrame, IssuanceWatermark, Marked, MayHaveIssued, observe_frame};
use kata_toolhost_protocol::{
    FRAME_HEADER_BYTES, Hello, RequestId, SessionId, SignalKind, Stream, ToolhostFrame,
    WorkerFrame, body_len, decode_frame, encode_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::AbortHandle;

/// The stdout half the session takes from the toolhost's `InteractiveProcess`.
pub(crate) type ToolhostReader = Box<dyn AsyncRead + Send + Unpin>;
/// The stdin half.
pub(crate) type ToolhostWriter = Box<dyn AsyncWrite + Send + Unpin>;

/// How long the toolhost has to state its `Hello` before the turn refuses
/// `toolhost_absent`. Part of the turn's own deadline, which the worker races.
pub(crate) const HELLO_DEADLINE: Duration = Duration::from_secs(10);

/// How many whole frames wait for the writer beyond the one it is writing. A
/// caller past them waits for room (racing the latch) holding its own encoded
/// frame, as it would if it wrote itself, so the queue adds at most one frame
/// to the worker's memory.
const QUEUED_FRAMES: usize = 1;

/// The most output bytes one session's [`SessionBuffer`] holds between two
/// drains: 1 MiB, split evenly between stdout and stderr when the caller keeps
/// them apart.
pub(crate) const SESSION_OUTPUT_BYTES: usize = 1024 * 1024;

/// What a seam call answers the model once the turn's gate is closed.
pub(crate) const STOPPING: &str = "the turn is stopping; no further tool call runs";

/// The turn's gate: the issuance watermark and whether the turn is stopping,
/// under ONE lock, shared by the session, the seam, the client and the model
/// clients (`IssuanceMark`, `MessagesMark`). It closes when a stop is asked (an
/// operator cancel, a latch), when `prompt`'s future is dropped, and at every
/// turn end; once closed, the client queues no frame that could change the
/// capsule (module doc, "The gate holds the queue"), no seam call answers the
/// model, and no model request leaves on either kind (`IssuanceMark`,
/// `MessagesMark`; `session.rs`, "The watermark is final once the gate
/// closes"). Closing takes the lock a frame is queued and a mark
/// taken under, and a mark is taken only while the gate is open, so once the
/// gate is closed the watermark never moves again.
#[derive(Debug)]
pub(crate) struct TurnGate {
    state: Mutex<GateState>,
}

#[derive(Debug)]
struct GateState {
    watermark: IssuanceWatermark,
    /// A `ToolCall` was marked while the gate was open. The watermark keeps
    /// only its FIRST crossing (a turn's first model request, `ModelTokens`),
    /// so whether a tool call followed is kept apart: it is what decides
    /// whether a provider failure stays inside the capsule
    /// (`TurnOutcome::ProviderFailed::tool_called`).
    tool_called: bool,
    closed: bool,
}

impl TurnGate {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(GateState {
                watermark: IssuanceWatermark::clean(),
                tool_called: false,
                closed: false,
            }),
        }
    }

    /// Mark the watermark for `frame` and hand back the token, while the gate
    /// is open; `None`, the watermark untouched, once it is closed.
    pub(crate) fn mark_while_open(&self, frame: IssuanceFrame) -> Option<Marked> {
        let mut state = lock(&self.state);
        if state.closed {
            return None;
        }
        state.tool_called |= frame == IssuanceFrame::ToolCall;
        Some(observe_frame(&mut state.watermark, frame))
    }

    pub(crate) fn crossed(&self) -> Option<MayHaveIssued> {
        lock(&self.state).watermark.crossed()
    }

    /// Whether any tool call was marked while the gate was open.
    pub(crate) fn tool_called(&self) -> bool {
        lock(&self.state).tool_called
    }

    /// Close the gate. Once this returns, no frame the gate holds is queued.
    pub(crate) fn close(&self) {
        lock(&self.state).closed = true;
    }

    pub(crate) fn is_closed(&self) -> bool {
        lock(&self.state).closed
    }

    /// Run `act` under the gate's lock while the gate is open; `None`, with
    /// `act` never run, once it is closed.
    fn while_open<T>(&self, act: impl FnOnce() -> T) -> Option<T> {
        let state = lock(&self.state);
        if state.closed {
            return None;
        }
        let done = act();
        drop(state);
        Some(done)
    }
}

/// The first way the toolhost wire broke. Write-once: a later break is a
/// consequence of the first, and the first is the evidence.
#[derive(Debug, Default)]
pub(crate) struct ProtocolLatch {
    reason: OnceLock<String>,
    notify: Notify,
}

impl ProtocolLatch {
    /// Record `reason` unless a break is already recorded, and wake every
    /// waiter.
    pub(crate) fn set(&self, reason: impl Into<String>) {
        if self.reason.set(reason.into()).is_ok() {
            self.notify.notify_waiters();
        }
    }

    /// The recorded break, if the wire has broken.
    pub(crate) fn reason(&self) -> Option<&str> {
        self.reason.get().map(String::as_str)
    }

    /// Resolve once the latch is set.
    pub(crate) async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.reason.get().is_some() {
                return;
            }
            notified.await;
        }
    }
}

/// Why the handshake refused the toolhost. Both arms are pre-watermark: nothing
/// was issued, so the turn settles `Refused`.
#[derive(Debug)]
pub(crate) enum HandshakeRefusal {
    /// No `Hello` arrived: stdout ended, or the deadline passed.
    Absent(String),
    /// Something other than this build's toolhost spoke first.
    Mismatch(String),
}

/// Read the toolhost's first frame and admit it only if it is this build's
/// `Hello`. No other frame is read before it.
pub(crate) async fn handshake(stdout: &mut ToolhostReader) -> Result<(), HandshakeRefusal> {
    let first = tokio::time::timeout(HELLO_DEADLINE, read_one(stdout))
        .await
        .map_err(|_| {
            HandshakeRefusal::Absent(format!(
                "toolhost_absent: the capsule's init stated no Hello within {} s",
                HELLO_DEADLINE.as_secs()
            ))
        })?;
    match first {
        Ok(ToolhostFrame::Hello(hello)) => {
            let Hello { .. } = &hello;
            hello
                .check()
                .map_err(|mismatch| HandshakeRefusal::Mismatch(mismatch.to_string()))
        }
        Ok(other) => Err(HandshakeRefusal::Mismatch(format!(
            "toolhost_mismatch: the capsule's init spoke first with a {} frame, not a Hello",
            frame_kind(&other)
        ))),
        Err(ReadEnd::Closed) => Err(HandshakeRefusal::Absent(
            "toolhost_absent: the capsule's init closed its stdout before stating a Hello"
                .to_owned(),
        )),
        Err(ReadEnd::Broken(reason)) => Err(HandshakeRefusal::Mismatch(format!(
            "toolhost_mismatch: the capsule's init's first frame is not this build's: {reason}"
        ))),
    }
}

/// How a frame read ended without a frame.
enum ReadEnd {
    /// EOF where a header would start.
    Closed,
    /// Anything else, with the reason.
    Broken(String),
}

async fn read_one(stdout: &mut ToolhostReader) -> Result<ToolhostFrame, ReadEnd> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let mut filled = 0;
    while filled < FRAME_HEADER_BYTES {
        match stdout.read(&mut header[filled..]).await {
            Ok(0) if filled == 0 => return Err(ReadEnd::Closed),
            Ok(0) => {
                return Err(ReadEnd::Broken(
                    "toolhost stdout ended inside a frame header".to_owned(),
                ));
            }
            Ok(read) => filled += read,
            Err(error) => {
                return Err(ReadEnd::Broken(format!(
                    "reading the toolhost's stdout failed: {error}"
                )));
            }
        }
    }
    let length = body_len(header).map_err(|error| ReadEnd::Broken(error.to_string()))?;
    let mut body = vec![0_u8; length];
    stdout.read_exact(&mut body).await.map_err(|error| {
        ReadEnd::Broken(format!("toolhost stdout ended inside a frame: {error}"))
    })?;
    decode_frame(&body).map_err(|error| ReadEnd::Broken(error.to_string()))
}

/// The frame's kind as the wire spells it, for a reason string.
pub(crate) const fn frame_kind(frame: &ToolhostFrame) -> &'static str {
    match frame {
        ToolhostFrame::Hello(_) => "hello",
        ToolhostFrame::Started { .. } => "started",
        ToolhostFrame::SpawnFailed { .. } => "spawn_failed",
        ToolhostFrame::Output { .. } => "output",
        ToolhostFrame::Exited { .. } => "exited",
        ToolhostFrame::SessionGone { .. } => "session_gone",
        ToolhostFrame::FileBytes { .. } => "file_bytes",
        ToolhostFrame::FileError { .. } => "file_error",
        ToolhostFrame::Done { .. } => "done",
        ToolhostFrame::Bye { .. } => "bye",
        ToolhostFrame::Error { .. } => "error",
    }
}

/// How a session ended, as its buffer records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionEnd {
    /// The toolhost reported the exit: the code, or the signal.
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
    /// The toolhost answered a `Stdin` or `Signal` for it with `SessionGone`.
    Gone,
    /// The wire broke before the session ended; the latch says why.
    Lost,
}

/// How a session's output is kept: interleaved (codex's `exec_command` reads
/// one stream), or stdout and stderr apart (claude's `Bash` reports both).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputShape {
    Combined,
    Split,
}

/// A head+tail window: the first half of what arrived and the last half,
/// with the count of what fell out between them.
#[derive(Debug)]
pub(crate) struct OutputWindow {
    capacity: usize,
    head: Vec<u8>,
    tail: std::collections::VecDeque<u8>,
    dropped: usize,
}

impl OutputWindow {
    const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            head: Vec::new(),
            tail: std::collections::VecDeque::new(),
            dropped: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let half = self.capacity / 2;
        let room = half.saturating_sub(self.head.len());
        let (into_head, rest) = bytes.split_at(room.min(bytes.len()));
        self.head.extend_from_slice(into_head);
        self.tail.extend(rest);
        let tail_room = self.capacity - half;
        if self.tail.len() > tail_room {
            let excess = self.tail.len() - tail_room;
            self.tail.drain(..excess);
            self.dropped += excess;
        }
    }

    /// Everything held, with a marker where bytes fell out, and empty after.
    pub(crate) fn take(&mut self) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.head);
        if self.dropped > 0 {
            out.extend_from_slice(format!("\n…{} bytes elided…\n", self.dropped).as_bytes());
        }
        out.extend(self.tail.drain(..));
        self.dropped = 0;
        out
    }

    /// The bytes that arrived since the last take, held or elided.
    pub(crate) fn arrived(&self) -> usize {
        self.head.len() + self.tail.len() + self.dropped
    }
}

/// What a drain of a [`SessionBuffer`] hands the seam.
#[derive(Debug, Default)]
pub(crate) struct Drained {
    /// Interleaved output (`OutputShape::Combined`).
    pub(crate) combined: Vec<u8>,
    /// stdout and stderr apart (`OutputShape::Split`), with the bytes that
    /// arrived on each, held or not.
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) stdout_arrived: usize,
    pub(crate) stderr_arrived: usize,
}

/// One session's output and end, written by the frame reader and drained by
/// the seam. Bounded: see [`SESSION_OUTPUT_BYTES`].
#[derive(Debug)]
pub(crate) struct SessionBuffer {
    state: Mutex<BufferState>,
    changed: Notify,
}

#[derive(Debug)]
struct BufferState {
    shape: OutputShape,
    combined: OutputWindow,
    stdout: OutputWindow,
    stderr: OutputWindow,
    end: Option<SessionEnd>,
    /// When output last arrived, or when the session opened.
    last_output: std::time::Instant,
}

impl SessionBuffer {
    fn new(shape: OutputShape) -> Self {
        let (combined, split) = match shape {
            OutputShape::Combined => (SESSION_OUTPUT_BYTES, 0),
            OutputShape::Split => (0, SESSION_OUTPUT_BYTES / 2),
        };
        Self {
            state: Mutex::new(BufferState {
                shape,
                combined: OutputWindow::new(combined),
                stdout: OutputWindow::new(split),
                stderr: OutputWindow::new(split),
                end: None,
                last_output: std::time::Instant::now(),
            }),
            changed: Notify::new(),
        }
    }

    fn push(&self, stream: Stream, bytes: &[u8]) {
        {
            let mut state = lock(&self.state);
            state.last_output = std::time::Instant::now();
            match state.shape {
                OutputShape::Combined => state.combined.push(bytes),
                OutputShape::Split => match stream {
                    Stream::Stdout => state.stdout.push(bytes),
                    Stream::Stderr => state.stderr.push(bytes),
                },
            }
        }
        self.changed.notify_waiters();
    }

    fn finish(&self, end: SessionEnd) {
        lock(&self.state).end.get_or_insert(end);
        self.changed.notify_waiters();
    }

    /// How long since the session last produced output (or opened).
    pub(crate) fn silent_for(&self) -> Duration {
        lock(&self.state).last_output.elapsed()
    }

    /// How the session ended, if it has.
    pub(crate) fn end(&self) -> Option<SessionEnd> {
        lock(&self.state).end
    }

    /// Resolve once the session has ended or `deadline` passes, whichever
    /// is first; answers the end, if there is one.
    pub(crate) async fn wait_end(&self, deadline: tokio::time::Instant) -> Option<SessionEnd> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(end) = self.end() {
                return Some(end);
            }
            tokio::select! {
                () = changed => {}
                () = tokio::time::sleep_until(deadline) => return self.end(),
            }
        }
    }

    /// Everything that arrived since the last drain.
    pub(crate) fn drain(&self) -> Drained {
        let mut state = lock(&self.state);
        let stdout_arrived = state.stdout.arrived();
        let stderr_arrived = state.stderr.arrived();
        Drained {
            combined: state.combined.take(),
            stdout: state.stdout.take(),
            stderr: state.stderr.take(),
            stdout_arrived,
            stderr_arrived,
        }
    }
}

/// Why the client got no answer for a frame, or queued none.
#[derive(Debug)]
pub(crate) enum WireRefusal {
    /// The wire broke (the latch's reason), or the toolhost's stdin is
    /// closed.
    Broken(String),
    /// The turn's gate is closed and the frame is not one a stopping turn
    /// sends (module doc, "The gate holds the queue"). Nothing was queued.
    Stopping,
    /// The frame does not encode ([`Outbound::encode`]'s reason). Nothing was
    /// queued.
    Unencodable(String),
}

impl std::fmt::Display for WireRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Broken(reason) => write!(formatter, "the sandbox is unavailable: {reason}"),
            Self::Stopping => formatter.write_str(STOPPING),
            Self::Unencodable(reason) => formatter.write_str(reason),
        }
    }
}

/// A worker frame encoded for the wire, before it is sent: the seam encodes
/// an effect's frame BEFORE it marks the watermark, so a frame too large to
/// send is refused with nothing marked.
pub(crate) struct Outbound {
    bytes: Vec<u8>,
    /// Whether a closed gate holds it ([`held_by_the_gate`]).
    held: bool,
}

impl Outbound {
    /// `frame` encoded, or the model-visible reason it cannot be: its body is
    /// over the wire's frame bound.
    pub(crate) fn encode(frame: &WorkerFrame) -> Result<Self, String> {
        let held = held_by_the_gate(frame);
        encode_frame(frame)
            .map(|bytes| Self { bytes, held })
            .map_err(|error| {
                format!("the tool call was not sent: its frame does not encode ({error})")
            })
    }
}

/// A request whose frame is queued, waiting for its answer
/// ([`ToolhostClient::answer`]).
pub(crate) struct QueuedRequest(oneshot::Receiver<ToolhostFrame>);

#[derive(Default)]
struct Routes {
    replies: HashMap<RequestId, oneshot::Sender<ToolhostFrame>>,
    sessions: HashMap<SessionId, Arc<SessionBuffer>>,
    /// Sessions that have exited: a `SessionGone` for one is the toolhost
    /// answering a `Stdin` that raced the exit, not a break.
    retired: BTreeSet<SessionId>,
}

/// One turn's client over the toolhost's taken streams.
pub(crate) struct ToolhostClient {
    /// Whole encoded frames, to the one writer task.
    frames: mpsc::Sender<Vec<u8>>,
    /// The writer task, aborted by [`Self::close_stdin`].
    writer: AbortHandle,
    /// Set by [`Self::close_stdin`]: nothing is queued after it.
    stdin_closed: AtomicBool,
    /// The turn's gate, read under its own lock as a frame is queued.
    gate: Arc<TurnGate>,
    routes: Arc<Mutex<Routes>>,
    latch: Arc<ProtocolLatch>,
    next_id: AtomicU64,
    next_session: AtomicU32,
}

impl ToolhostClient {
    /// Start the client: `stdout` must already have passed [`handshake`]. The
    /// frame reader runs as a task until stdout ends or the latch is set; the
    /// writer, until the latch, [`Self::close_stdin`], or the client's end.
    pub(crate) fn start(
        stdin: ToolhostWriter,
        stdout: ToolhostReader,
        latch: Arc<ProtocolLatch>,
        gate: Arc<TurnGate>,
    ) -> Arc<Self> {
        let routes = Arc::new(Mutex::new(Routes::default()));
        tokio::spawn(read_frames(stdout, Arc::clone(&routes), Arc::clone(&latch)));
        let (frames, queue) = mpsc::channel(QUEUED_FRAMES);
        let writer = tokio::spawn(write_frames(stdin, queue, Arc::clone(&latch))).abort_handle();
        Arc::new(Self {
            frames,
            writer,
            stdin_closed: AtomicBool::new(false),
            gate,
            routes,
            latch,
            next_id: AtomicU64::new(1),
            next_session: AtomicU32::new(1),
        })
    }

    pub(crate) fn latch(&self) -> &ProtocolLatch {
        &self.latch
    }

    /// A fresh request id.
    pub(crate) fn next_id(&self) -> RequestId {
        RequestId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// A fresh session number, for an `Exec` not yet routed.
    pub(crate) fn next_session(&self) -> SessionId {
        SessionId(self.next_session.fetch_add(1, Ordering::Relaxed))
    }

    /// Open `session`'s route: frames naming it land in the returned buffer.
    /// Registered BEFORE its `Exec` is queued, so no output can race the route;
    /// an `Exec` the client refuses to queue has it closed again
    /// ([`Self::forget_session`]).
    pub(crate) fn open_session(
        &self,
        session: SessionId,
        shape: OutputShape,
    ) -> Arc<SessionBuffer> {
        let buffer = Arc::new(SessionBuffer::new(shape));
        lock(&self.routes)
            .sessions
            .insert(session, Arc::clone(&buffer));
        buffer
    }

    /// Close `session`'s route, opened for an `Exec` that was never queued:
    /// a frame naming it is then a break, as for any session kata never
    /// opened.
    pub(crate) fn forget_session(&self, session: SessionId) {
        lock(&self.routes).sessions.remove(&session);
    }

    /// Record a break the caller observed (an answer of the wrong kind), and
    /// answer the latch's reason.
    pub(crate) fn break_protocol(&self, reason: impl Into<String>) -> String {
        self.latch.set(reason);
        self.latch.reason().unwrap_or_default().to_owned()
    }

    /// Send a frame that is answered by `id`, and wait for the answer.
    pub(crate) async fn request(
        &self,
        id: RequestId,
        frame: Outbound,
    ) -> Result<ToolhostFrame, WireRefusal> {
        let queued = self.queue_request(id, frame).await?;
        self.answer(queued).await
    }

    /// Queue a frame that is answered by `id`. It returns once the frame is
    /// queued, with nothing awaited after that, so a caller holding the result
    /// knows the frame was queued; dropped before then, it queued nothing.
    pub(crate) async fn queue_request(
        &self,
        id: RequestId,
        frame: Outbound,
    ) -> Result<QueuedRequest, WireRefusal> {
        let (sender, receiver) = oneshot::channel();
        lock(&self.routes).replies.insert(id, sender);
        if let Err(refusal) = self.send(frame).await {
            // Never queued: no answer can come for it.
            lock(&self.routes).replies.remove(&id);
            return Err(refusal);
        }
        Ok(QueuedRequest(receiver))
    }

    /// Wait for a queued request's answer, racing the latch.
    pub(crate) async fn answer(&self, queued: QueuedRequest) -> Result<ToolhostFrame, WireRefusal> {
        tokio::select! {
            answer = queued.0 => answer.map_err(|_| self.broken()),
            () = self.latch.wait() => Err(self.broken()),
        }
    }

    /// Queue one whole frame for the writer. Refused once the latch is set (a
    /// broken wire gets no further frame) or the stdin is closed, and, for a
    /// frame the gate holds, once the gate is closed. A caller waits for room
    /// in the queue racing the latch; dropped while it waits, it queues
    /// nothing. A frame once queued is written whole, unless the writer stops
    /// (the latch, [`Self::close_stdin`]) before or while it writes it, after
    /// which nothing more is written.
    pub(crate) async fn send(&self, frame: Outbound) -> Result<(), WireRefusal> {
        if self.latch.reason().is_some() {
            return Err(self.broken());
        }
        let Outbound { bytes, held } = frame;
        let room = tokio::select! {
            biased;
            () = self.latch.wait() => return Err(self.broken()),
            room = self.frames.reserve() => room,
        };
        let room = match room {
            Ok(room) if !self.stdin_closed.load(Ordering::SeqCst) => room,
            Ok(_) | Err(_) => {
                return Err(WireRefusal::Broken(
                    "the toolhost's stdin is closed".to_owned(),
                ));
            }
        };
        if !held {
            room.send(bytes);
            return Ok(());
        }
        self.gate
            .while_open(move || room.send(bytes))
            .ok_or(WireRefusal::Stopping)
    }

    /// `KillAll`, and its answer.
    pub(crate) async fn kill_all(&self) -> Result<ToolhostFrame, WireRefusal> {
        let id = self.next_id();
        let kill =
            Outbound::encode(&WorkerFrame::KillAll { id }).map_err(WireRefusal::Unencodable)?;
        self.request(id, kill).await
    }

    /// `Signal{Kill}` to `session`'s process group; answered by its `Exited`
    /// (or `SessionGone`) on the session's route, not here.
    pub(crate) async fn kill_session(&self, session: SessionId) -> Result<(), WireRefusal> {
        let kill = Outbound::encode(&WorkerFrame::Signal {
            session,
            signal: SignalKind::Kill,
        })
        .map_err(WireRefusal::Unencodable)?;
        self.send(kill).await
    }

    /// `Shutdown`, and its answer.
    pub(crate) async fn shutdown(&self) -> Result<ToolhostFrame, WireRefusal> {
        let id = self.next_id();
        let shutdown =
            Outbound::encode(&WorkerFrame::Shutdown { id }).map_err(WireRefusal::Unencodable)?;
        self.request(id, shutdown).await
    }

    /// Drop the toolhost's stdin: abort the writer, which drops the stdin with
    /// any write in progress, and queue nothing after. Waits on no write. A
    /// wire that broke cannot carry a `KillAll`, so this is the turn's last
    /// word to the toolhost: it reads EOF on its stdin and kills every process
    /// it started (D1 §1.4).
    pub(crate) fn close_stdin(&self) {
        self.stdin_closed.store(true, Ordering::SeqCst);
        self.writer.abort();
    }

    fn broken(&self) -> WireRefusal {
        WireRefusal::Broken(
            self.latch
                .reason()
                .unwrap_or("the toolhost dropped an outstanding request")
                .to_owned(),
        )
    }
}

/// Whether a closed gate holds `frame`: every frame but the ones a stopping
/// turn reaches the capsule with, the kills and `Shutdown`.
const fn held_by_the_gate(frame: &WorkerFrame) -> bool {
    match frame {
        WorkerFrame::Exec { .. }
        | WorkerFrame::Stdin { .. }
        | WorkerFrame::ReadFile { .. }
        | WorkerFrame::WriteFile { .. }
        | WorkerFrame::RemoveFile { .. } => true,
        WorkerFrame::Signal { .. } | WorkerFrame::KillAll { .. } | WorkerFrame::Shutdown { .. } => {
            false
        }
    }
}

/// The one writer: whole frames off the queue, in order. It stops at the
/// latch or at `close_stdin`'s abort, either of which drops the stdin with any
/// write in progress, and at the queue's end (the client is gone), which
/// comes only between writes. A write that fails latches the wire.
async fn write_frames(
    mut stdin: ToolhostWriter,
    mut queue: mpsc::Receiver<Vec<u8>>,
    latch: Arc<ProtocolLatch>,
) {
    loop {
        let bytes = tokio::select! {
            biased;
            () = latch.wait() => return,
            next = queue.recv() => match next {
                Some(bytes) => bytes,
                None => return,
            },
        };
        let written = tokio::select! {
            biased;
            () = latch.wait() => return,
            written = write_all(&mut stdin, &bytes) => written,
        };
        if let Err(error) = written {
            latch.set(format!("writing to the toolhost's stdin failed: {error}"));
            return;
        }
    }
}

async fn write_all(writer: &mut ToolhostWriter, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_all(bytes).await?;
    writer.flush().await
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The frame reader: routes every frame, and latches on the first break.
async fn read_frames(
    mut stdout: ToolhostReader,
    routes: Arc<Mutex<Routes>>,
    latch: Arc<ProtocolLatch>,
) {
    loop {
        let frame = tokio::select! {
            frame = read_one(&mut stdout) => frame,
            () = latch.wait() => break,
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(ReadEnd::Closed) => {
                latch.set("toolhost_lost: the toolhost closed its stdout mid-turn");
                break;
            }
            Err(ReadEnd::Broken(reason)) => {
                latch.set(format!("toolhost_lost: {reason}"));
                break;
            }
        };
        if let Err(reason) = route(&routes, frame) {
            latch.set(format!("toolhost_lost: {reason}"));
            break;
        }
    }
    // Drop every outstanding reply slot and end every session. With the latch
    // set, a request waiting on its answer or on room in the writer's queue
    // returns the latch's reason, and the writer drops any write in progress;
    // a request on a wire that stays whole but silent is bounded by its
    // caller (the turn's deadline, the turn end's grace), not here.
    let mut routes = lock(&routes);
    routes.replies.clear();
    for (_, buffer) in routes.sessions.drain() {
        buffer.finish(SessionEnd::Lost);
    }
}

fn route(routes: &Mutex<Routes>, frame: ToolhostFrame) -> Result<(), String> {
    let mut routes = lock(routes);
    match frame {
        ToolhostFrame::Hello(_) => Err("the toolhost sent a second Hello".to_owned()),
        ToolhostFrame::Error { id, message } => Err(format!(
            "the toolhost refused a frame (request {id:?}): {message}"
        )),
        ToolhostFrame::Output {
            session,
            stream,
            data_b64,
        } => {
            session_route(&routes, session)?.push(stream, data_b64.as_bytes());
            Ok(())
        }
        ToolhostFrame::Exited {
            session,
            code,
            signal,
        } => {
            session_route(&routes, session)?.finish(SessionEnd::Exited { code, signal });
            routes.sessions.remove(&session);
            routes.retired.insert(session);
            Ok(())
        }
        ToolhostFrame::SessionGone { session } => {
            if routes.retired.contains(&session) {
                return Ok(());
            }
            session_route(&routes, session)?.finish(SessionEnd::Gone);
            Ok(())
        }
        reply @ (ToolhostFrame::Started { .. }
        | ToolhostFrame::SpawnFailed { .. }
        | ToolhostFrame::FileBytes { .. }
        | ToolhostFrame::FileError { .. }
        | ToolhostFrame::Done { .. }
        | ToolhostFrame::Bye { .. }) => {
            let id = reply_id(&reply);
            let Some(slot) = routes.replies.remove(&id) else {
                return Err(format!(
                    "the toolhost answered request {} with a {} frame, and no request by that id \
                     is outstanding",
                    id.0,
                    frame_kind(&reply)
                ));
            };
            // A waiter that went away (its turn was cancelled) is not a break.
            drop(slot.send(reply));
            Ok(())
        }
    }
}

const fn reply_id(frame: &ToolhostFrame) -> RequestId {
    match frame {
        ToolhostFrame::Started { id, .. }
        | ToolhostFrame::SpawnFailed { id, .. }
        | ToolhostFrame::FileBytes { id, .. }
        | ToolhostFrame::FileError { id, .. }
        | ToolhostFrame::Done { id }
        | ToolhostFrame::Bye { id, .. } => *id,
        ToolhostFrame::Hello(_)
        | ToolhostFrame::Output { .. }
        | ToolhostFrame::Exited { .. }
        | ToolhostFrame::SessionGone { .. }
        | ToolhostFrame::Error { .. } => RequestId(0),
    }
}

/// The buffer of a session kata opened and has not seen exit; any other
/// session number is a break. A session nobody is reading still fills its
/// bounded buffer.
fn session_route(routes: &Routes, session: SessionId) -> Result<&SessionBuffer, String> {
    routes
        .sessions
        .get(&session)
        .map(AsRef::as_ref)
        .ok_or_else(|| {
            format!(
                "the toolhost sent a session frame for session {}, which kata never opened or has \
             already seen exit",
                session.0
            )
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use kata_toolhost_protocol::{RequestId, SessionId, WorkerFrame};
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use super::{Outbound, ProtocolLatch, ToolhostClient, TurnGate};

    /// How long a stopped writer has to drop the stdin: no grace of the
    /// session's is involved, so a second is slack.
    const DROP_BOUND: Duration = Duration::from_secs(1);

    /// A client whose toolhost reads nothing: its stdin pipe holds 64 bytes,
    /// so the writer is stuck inside the first larger frame. Answers the
    /// client, the toolhost's end of the stdin, and its stdout (dropping it
    /// ends the toolhost's stdout).
    async fn stuck_mid_frame() -> (Arc<ToolhostClient>, DuplexStream, DuplexStream) {
        let (worker_stdin, toolhost_stdin) = tokio::io::duplex(64);
        let (toolhost_stdout, worker_stdout) = tokio::io::duplex(1 << 16);
        let client = ToolhostClient::start(
            Box::new(worker_stdin),
            Box::new(worker_stdout),
            Arc::new(ProtocolLatch::default()),
            Arc::new(TurnGate::new()),
        );
        let exec = Outbound::encode(&WorkerFrame::Exec {
            id: RequestId(1),
            session: SessionId(1),
            shell: None,
            login: false,
            script: "x".repeat(4096),
            workdir: None,
        })
        .expect("a 4 KiB exec encodes");
        client.send(exec).await.expect("queued");
        // The writer takes the frame and fills the 64-byte pipe.
        tokio::time::sleep(Duration::from_millis(100)).await;
        (client, toolhost_stdin, toolhost_stdout)
    }

    /// Resolve once the worker has dropped its end of the stdin. Probed by
    /// WRITING into the toolhost's end, never by reading it: a read would
    /// make room and let the stuck write go on. A write to a pipe whose other
    /// end is gone fails `BrokenPipe`, a pending one included.
    async fn stdin_dropped(toolhost_stdin: &mut DuplexStream) {
        loop {
            match toolhost_stdin.write_all(b"\0").await {
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => return,
                Err(error) => panic!("probing the stdin failed otherwise: {error}"),
                Ok(()) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    }

    /// **The latch drops a write in progress.** The toolhost stops reading
    /// part-way into a frame and then ends its stdout; nothing calls
    /// `close_stdin`. The writer, stuck inside the write, drops the stdin at
    /// the latch: the toolhost's end reads it gone within [`DROP_BOUND`].
    ///
    /// **Would red if:** the writer waited out the write rather than racing
    /// it against the latch (watched: the stdin still held after the bound).
    #[tokio::test]
    async fn the_latch_drops_a_stuck_write() {
        let (client, mut toolhost_stdin, toolhost_stdout) = stuck_mid_frame().await;
        drop(toolhost_stdout);
        tokio::time::timeout(DROP_BOUND, client.latch().wait())
            .await
            .expect("stdout's end latches the wire");
        tokio::time::timeout(DROP_BOUND, stdin_dropped(&mut toolhost_stdin))
            .await
            .expect("the latch dropped the stdin with its write in progress");
        drop(client);
    }

    /// **The latch drops the stdin of a writer with nothing to write.** The
    /// toolhost ends its stdout while the client has queued nothing, so the
    /// one writer waits on its queue, not inside a write; the client stays
    /// alive and nothing calls `close_stdin`. The writer still drops the stdin
    /// at the latch: the toolhost's end reads it closed within
    /// [`DROP_BOUND`], so a toolhost whose stdout broke is not left holding
    /// an open stdin until the client goes.
    ///
    /// **Would red if:** the writer waited on its queue without racing it
    /// against the latch (write_frames' outer latch arm).
    #[tokio::test]
    async fn the_latch_drops_an_idle_writers_stdin() {
        use tokio::io::AsyncReadExt;

        let (worker_stdin, mut toolhost_stdin) = tokio::io::duplex(1 << 16);
        let (toolhost_stdout, worker_stdout) = tokio::io::duplex(1 << 16);
        let client = ToolhostClient::start(
            Box::new(worker_stdin),
            Box::new(worker_stdout),
            Arc::new(ProtocolLatch::default()),
            Arc::new(TurnGate::new()),
        );
        drop(toolhost_stdout);
        tokio::time::timeout(DROP_BOUND, client.latch().wait())
            .await
            .expect("stdout's end latches the wire");
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(DROP_BOUND, toolhost_stdin.read(&mut byte))
            .await
            .expect("the latch dropped the idle writer's stdin");
        assert_eq!(
            read.expect("reading the toolhost's end of the stdin"),
            0,
            "the toolhost read a byte where it should read the stdin closed"
        );
        drop(client);
    }

    /// **`close_stdin` drops a write in progress.** The toolhost stops reading
    /// part-way into a frame and stays alive, its stdout open, so nothing
    /// latches. `close_stdin` returns at once and the toolhost's end reads the
    /// stdin gone within [`DROP_BOUND`].
    ///
    /// **Would red if:** `close_stdin` did not abort the writer (watched: the
    /// stdin still held after the bound).
    #[tokio::test]
    async fn close_stdin_drops_a_stuck_write() {
        let (client, mut toolhost_stdin, _toolhost_stdout) = stuck_mid_frame().await;
        assert!(client.latch().reason().is_none(), "nothing latched");
        client.close_stdin();
        tokio::time::timeout(DROP_BOUND, stdin_dropped(&mut toolhost_stdin))
            .await
            .expect("close_stdin dropped the stdin with its write in progress");
        assert!(client.latch().reason().is_none(), "nothing latched");
    }
}
