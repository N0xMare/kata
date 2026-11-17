//! The toolhost's loop: one task that owns every session and answers every
//! frame in the order the worker sent them.
//!
//! # Tasks and order
//!
//! A reader task decodes stdin into frames; a writer task encodes the outbound
//! queue onto stdout; each session has two output pumps and a stdin writer. The
//! loop owns the session table, and it alone writes `Started`, `Exited`, `Done`
//! and `Bye`, so the order the protocol promises holds by construction:
//!
//! * a session's `Started` is queued before its pumps can queue an `Output` (the
//!   queue slot is reserved before the process spawns);
//! * a pump queues its last `Output` before it reports its pipe closed, and the
//!   loop queues `Exited` only after both pipes closed AND the reaper collected
//!   the exit status, so `Exited` follows every `Output` of its session;
//! * `KillAll`'s `Done` and `Shutdown`'s `Bye` are queued only once `/proc`
//!   shows no descendant of this process and every session that was live has
//!   queued its `Exited`;
//! * a kill that gave up writes its `Error` (if any) as the last frame: the
//!   writer takes it ahead of the queue and writes nothing after it.
//!
//! # A kill that cannot finish
//!
//! A descendant can stay listed whatever is sent to it: a zombie its tracer
//! has not waited on cannot be reaped by its parent, and a process in an
//! uninterruptible sleep dies only when the sleep ends. So a `KillAll` (and the
//! kill `Shutdown`, the end of stdin and a broken stdout begin with) walks
//! `/proc` on a backoff, [`FIRST_KILL_PASS`] doubling to [`LAST_KILL_PASS`], and
//! gives up at [`KILL_ALL_DEADLINE`]. Between walks it only reaps and pumps, so
//! a SIGCHLD flood costs `waitpid` calls, never walks. A worker that stopped
//! reading stdout cannot hold the kill past its deadline either: an `Exited`
//! the full queue cannot take by then is not queued, and its session counts as
//! one that never exited.
//!
//! Given up, it claims nothing: no `Done` and no `Bye`. A `KillAll` or
//! `Shutdown` is answered `Error` with its id, naming the pids still listed and
//! the sessions whose `Exited` was never queued; the end of stdin and a broken stdout are
//! answered nothing. That `Error` goes to the writer ahead of the queue, as the
//! last frame: no frame is read or answered after it, and no `Output` still
//! queued, or still to be read from a session's pipe, is written. The toolhost
//! then waits at most [`LAST_FRAME_GRACE`] for the `Error` to reach stdout
//! (written whole, or not at all if the writer is stuck on a frame a stalled
//! worker never reads) and exits [`crate::EXIT_UNKILLED`]: from the kill's
//! start, within `KILL_ALL_DEADLINE + LAST_FRAME_GRACE` plus one last walk,
//! whatever the worker reads. Inside a capsule that exit is the kill: when a pid
//! namespace's init exits, the kernel SIGKILLs every process left in the
//! namespace. Nothing here claims those processes are gone by the time the
//! worker reads the `Error`; the runtime's cgroup sweep is the backstop for
//! that. Outside a pid namespace (the host-free tests) they outlive it. Nor is
//! the time before a kill begins bounded: a loop blocked on a full queue reads
//! no `KillAll` until the worker reads stdout, which is the backpressure below.
//!
//! # Backpressure
//!
//! The outbound queue holds [`OUTBOUND_FRAMES`] frames. When the worker stops
//! reading stdout, the writer blocks, the queue fills, the pumps stop reading,
//! and a tool process blocks on its full pipe: memory stays bounded by the
//! queue, one 64 KiB read per pump, and one inbound frame. The worker must
//! therefore read stdout independently of writing stdin.
//!
//! The other direction never blocks the loop: a session whose process stops
//! reading its stdin holds at most `session::STDIN_QUEUE` chunks beyond the one
//! being written, and a `Stdin` its full queue cannot take is answered `Error`
//! naming the session, its bytes dropped. Reading stdin goes on, so a `KillAll`
//! behind it is still served.

use std::collections::HashMap;
use std::os::fd::AsFd as _;
use std::time::Duration;

use kata_toolhost_protocol::{
    FRAME_HEADER_BYTES, FrameError, Hello, RequestId, SessionId, SignalKind, ToolhostFrame,
    WorkerFrame, body_len, decode_frame, encode_frame,
};
use rustix::process::{Pid, Signal, WaitStatus};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::unix::pipe;
use tokio::sync::{mpsc, oneshot};

use crate::files;
use crate::procs;
use crate::session::{self, Event};

/// The most sessions live at once: nanocode's own cap on unified-exec
/// processes. Beyond it an `Exec` answers `SpawnFailed` with EAGAIN; the
/// capsule's `pids.max` is the kernel's bound regardless.
const MAX_SESSIONS: usize = 64;

/// The outbound queue's depth, in frames.
const OUTBOUND_FRAMES: usize = 8;

/// The wait between a kill's first two `/proc` walks; each later wait doubles,
/// up to [`LAST_KILL_PASS`].
const FIRST_KILL_PASS: Duration = Duration::from_millis(10);

/// The longest wait between two `/proc` walks of one kill.
const LAST_KILL_PASS: Duration = Duration::from_millis(250);

/// How long a kill walks `/proc` before it gives up (see "A kill that cannot
/// finish"). Under the worker's 5 s wait for a `KillAll`'s answer, so the worker
/// reads the `Error` naming what stayed rather than its own timeout.
const KILL_ALL_DEADLINE: Duration = Duration::from_secs(3);

/// How long a kill that gave up waits for its last frame to reach stdout
/// before the toolhost exits. With [`KILL_ALL_DEADLINE`], under the worker's 5 s
/// wait for a `KillAll`'s answer.
const LAST_FRAME_GRACE: Duration = Duration::from_secs(1);

/// The most pids an [`Unkilled`] message names.
const NAMED_PIDS: usize = 16;

/// How long a clean exit waits for the outbound queue to drain to stdout.
const FLUSH_GRACE: Duration = Duration::from_secs(5);

/// `SpawnFailed` errnos the toolhost itself decides.
const EAGAIN: i32 = 11;
const EEXIST: i32 = 17;

/// How the loop ended.
pub(crate) enum End {
    /// Stdin ended or a `Shutdown` arrived; every process was killed and reaped.
    Clean,
    /// Stdout broke; every process was killed and reaped.
    StdoutBroken,
    /// A kill gave up at [`KILL_ALL_DEADLINE`]: some process this toolhost
    /// started may still be listed, or a session's `Exited` was never queued.
    Unkilled,
}

/// What a kill that gave up left: the descendants its last `/proc` walk
/// listed, and the sessions whose `Exited` was never queued.
struct Unkilled {
    listed: Vec<i32>,
    sessions: Vec<SessionId>,
}

impl std::fmt::Display for Unkilled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let named = &self.listed[..self.listed.len().min(NAMED_PIDS)];
        let sessions: Vec<u32> = self.sessions.iter().map(|session| session.0).collect();
        write!(
            f,
            "the kill gave up after {KILL_ALL_DEADLINE:?}: /proc still lists {} descendant(s) \
             of this toolhost (pids {named:?}{}), and session(s) {sessions:?} never \
             queued their Exited; this toolhost exits so the capsule's pid namespace ends \
             them, and writes nothing after this",
            self.listed.len(),
            if named.len() < self.listed.len() {
                ", …"
            } else {
                ""
            },
        )
    }
}

/// What the stdin reader hands the loop.
enum Inbound {
    Frame(WorkerFrame),
    /// A frame the codec refused, answered `Error`.
    Refused(String),
    /// Stdin ended.
    End,
}

/// A session that has not yet written its `Exited`.
struct Live {
    pid: i32,
    /// Output pipes not yet at EOF: 2 at spawn.
    open: u8,
    status: Option<WaitStatus>,
    /// `None` once a `Stdin` closed it.
    stdin: Option<mpsc::Sender<Vec<u8>>>,
}

struct Host {
    out: mpsc::Sender<ToolhostFrame>,
    /// The writer's last frame: `Some(frame)` is written ahead of the queue and
    /// ends the writer, `None` ends it at once. Taken by a kill that gave up;
    /// dropped unsent on any other end, which lets the writer drain the queue.
    last: Option<oneshot::Sender<Option<ToolhostFrame>>>,
    /// The deadline of the kill in progress, which bounds every frame it queues.
    kill_by: Option<tokio::time::Instant>,
    events: mpsc::UnboundedSender<Event>,
    events_rx: mpsc::UnboundedReceiver<Event>,
    sigchld: tokio::signal::unix::Signal,
    sessions: HashMap<SessionId, Live>,
    pids: HashMap<i32, SessionId>,
    stdout_broken: bool,
}

/// Serve the protocol until stdin ends, a `Shutdown` arrives, stdout breaks or
/// a kill gives up (see "A kill that cannot finish").
///
/// # Errors
/// A start that cannot be made safe, before the `Hello`: stdin or stdout is not
/// a pipe, or the SIGCHLD stream cannot be installed.
pub(crate) async fn run() -> Result<End, String> {
    let stdin = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .and_then(pipe::Receiver::from_owned_fd)
        .map_err(|error| format!("stdin is not a pipe this toolhost can read ({error})"))?;
    let stdout = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .and_then(pipe::Sender::from_owned_fd)
        .map_err(|error| format!("stdout is not a pipe this toolhost can write ({error})"))?;
    // Installed before any child exists, so no exit is missed.
    let sigchld = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
        .map_err(|error| format!("the SIGCHLD stream could not be installed ({error})"))?;
    let (out, out_rx) = mpsc::channel(OUTBOUND_FRAMES);
    let (last, last_rx) = oneshot::channel();
    let (events, events_rx) = mpsc::unbounded_channel();
    let writer = tokio::spawn(write_frames(stdout, out_rx, last_rx, events.clone()));
    let (frames_tx, frames) = mpsc::channel(1);
    tokio::spawn(read_frames(stdin, frames_tx));
    let mut host = Host {
        out,
        last: Some(last),
        kill_by: None,
        events,
        events_rx,
        sigchld,
        sessions: HashMap::new(),
        pids: HashMap::new(),
        stdout_broken: false,
    };
    host.send(ToolhostFrame::Hello(Hello::current())).await;
    let end = host.serve(frames).await;
    // On a clean end every session ended, so every pump has dropped its sender
    // and dropping the loop's closes the queue: the writer drains it and
    // returns. On a broken stdout it already returned. On a kill that gave up,
    // pumps may still hold the queue open; the writer ends on its last frame.
    let grace = match end {
        End::Clean | End::StdoutBroken => FLUSH_GRACE,
        End::Unkilled => LAST_FRAME_GRACE,
    };
    drop(host);
    let _ = tokio::time::timeout(grace, writer).await;
    Ok(end)
}

impl Host {
    async fn serve(&mut self, mut frames: mpsc::Receiver<Inbound>) -> End {
        loop {
            tokio::select! {
                inbound = frames.recv() => match inbound {
                    Some(Inbound::Frame(frame)) => {
                        if let Some(end) = self.handle(frame).await {
                            return end;
                        }
                    }
                    Some(Inbound::Refused(message)) => {
                        self.send(ToolhostFrame::Error { id: None, message }).await;
                    }
                    Some(Inbound::End) | None => {
                        return match self.kill_all().await {
                            Ok(_) => End::Clean,
                            Err(unkilled) => self.give_up("the end of stdin", &unkilled, None),
                        };
                    }
                },
                Some(event) = self.events_rx.recv() => self.on_event(event).await,
                _ = self.sigchld.recv() => {
                    self.reap().await;
                }
            }
            if self.stdout_broken {
                return match self.kill_all().await {
                    Ok(_) => End::StdoutBroken,
                    Err(unkilled) => self.give_up("a broken stdout", &unkilled, None),
                };
            }
        }
    }

    /// Answer one frame; how the loop ends, when the frame ends it.
    async fn handle(&mut self, frame: WorkerFrame) -> Option<End> {
        match frame {
            WorkerFrame::Exec {
                id,
                session,
                shell,
                login,
                script,
                workdir,
            } => {
                let request = session::Request {
                    session,
                    shell: shell.as_deref(),
                    login,
                    script: &script,
                    workdir: workdir.as_deref(),
                };
                self.exec(id, &request).await;
            }
            WorkerFrame::Stdin {
                session,
                data_b64,
                close,
            } => self.stdin(session, data_b64.into_bytes(), close).await,
            WorkerFrame::Signal { session, signal } => self.signal(session, signal).await,
            WorkerFrame::KillAll { id } => match self.kill_all().await {
                Ok(_) => {
                    self.send(ToolhostFrame::Done { id }).await;
                }
                Err(unkilled) => return Some(self.refuse_kill(id, "KillAll", &unkilled)),
            },
            WorkerFrame::ReadFile { id, path } => {
                self.send(files::read(id, &path)).await;
            }
            WorkerFrame::WriteFile { id, path, data_b64 } => {
                self.send(files::write(id, &path, &data_b64)).await;
            }
            WorkerFrame::RemoveFile { id, path } => {
                self.send(files::remove(id, &path)).await;
            }
            WorkerFrame::Shutdown { id } => {
                return Some(match self.kill_all().await {
                    Ok(reaped) => {
                        self.send(ToolhostFrame::Bye { id, reaped }).await;
                        End::Clean
                    }
                    Err(unkilled) => self.refuse_kill(id, "Shutdown", &unkilled),
                });
            }
        }
        None
    }

    /// Answer the `KillAll` or `Shutdown` `id` whose kill gave up: `Error` with
    /// its id as the last frame, never `Done` or `Bye`, and end the loop.
    fn refuse_kill(&mut self, id: RequestId, verb: &str, unkilled: &Unkilled) -> End {
        let error = ToolhostFrame::Error {
            id: Some(id),
            message: format!("{verb}: {unkilled}"),
        };
        self.give_up(verb, unkilled, Some(error))
    }

    /// Say on stderr why a kill begun by `cause` gave up, hand the writer its
    /// last frame (`answer`, or none), and end the loop.
    fn give_up(&mut self, cause: &str, unkilled: &Unkilled, answer: Option<ToolhostFrame>) -> End {
        eprintln!("kata-toolhost: {cause}: {unkilled}");
        if let Some(last) = self.last.take() {
            // A writer already gone (stdout broke) takes nothing more.
            let _ = last.send(answer);
        }
        End::Unkilled
    }

    async fn exec(&mut self, id: RequestId, request: &session::Request<'_>) {
        let session = request.session;
        let refusal = if self.sessions.contains_key(&session) {
            Some((EEXIST, format!("session {} is live", session.0)))
        } else if self.sessions.len() >= MAX_SESSIONS {
            Some((
                EAGAIN,
                format!("{MAX_SESSIONS} sessions are live, the most this toolhost runs at once"),
            ))
        } else {
            None
        };
        if let Some((errno, message)) = refusal {
            self.send(ToolhostFrame::SpawnFailed {
                id,
                session,
                errno,
                message,
            })
            .await;
            return;
        }
        // The slot for `Started` first: once the process spawns its pumps may
        // queue `Output`, and none may precede the `Started`.
        let Ok(slot) = self.out.reserve().await else {
            return;
        };
        match session::spawn(request, &self.out, &self.events) {
            Ok(spawned) => {
                self.pids.insert(spawned.pid, session);
                self.sessions.insert(
                    session,
                    Live {
                        pid: spawned.pid,
                        open: 2,
                        status: None,
                        stdin: Some(spawned.stdin),
                    },
                );
                slot.send(ToolhostFrame::Started {
                    id,
                    session,
                    pid: spawned.pid.unsigned_abs(),
                    note: spawned.note,
                });
            }
            Err(error) => slot.send(ToolhostFrame::SpawnFailed {
                id,
                session,
                errno: error.errno,
                message: error.message,
            }),
        }
    }

    async fn stdin(&mut self, session: SessionId, bytes: Vec<u8>, close: bool) {
        let Some(live) = self.sessions.get_mut(&session) else {
            self.send(ToolhostFrame::SessionGone { session }).await;
            return;
        };
        let Some(stdin) = &live.stdin else {
            eprintln!(
                "kata-toolhost: session {}: stdin was already closed; {} byte(s) dropped",
                session.0,
                bytes.len()
            );
            return;
        };
        // A closed queue means the writer gave up on a pipe that no longer
        // takes writes, which it reported; only a full one is answered.
        let refused = if bytes.is_empty() {
            0
        } else {
            match stdin.try_send(bytes) {
                Err(mpsc::error::TrySendError::Full(bytes)) => bytes.len(),
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => 0,
            }
        };
        if close {
            // Dropping the sender closes the pipe after the queued chunks.
            live.stdin = None;
        }
        if refused > 0 {
            self.send(ToolhostFrame::Error {
                id: None,
                message: format!(
                    "session {}: {refused} byte(s) of stdin refused: its process is not reading \
                     its stdin and {} chunks already wait",
                    session.0,
                    session::STDIN_QUEUE
                ),
            })
            .await;
        }
    }

    async fn signal(&mut self, session: SessionId, signal: SignalKind) {
        let Some(live) = self.sessions.get(&session) else {
            self.send(ToolhostFrame::SessionGone { session }).await;
            return;
        };
        let signal = match signal {
            SignalKind::Interrupt => Signal::INT,
            SignalKind::Terminate => Signal::TERM,
            SignalKind::Kill => Signal::KILL,
        };
        // The whole group: the session's process is its group's leader. ESRCH
        // (the group already empty while a pipe is still draining) is the
        // outcome a signal wants anyway.
        if let Some(group) = Pid::from_raw(live.pid) {
            let _ = rustix::process::kill_process_group(group, signal);
        }
    }

    async fn on_event(&mut self, event: Event) {
        match event {
            Event::StreamClosed(session) => {
                if let Some(live) = self.sessions.get_mut(&session) {
                    live.open = live.open.saturating_sub(1);
                }
                self.finish_if_done(session).await;
            }
            Event::StdoutBroken(error) => {
                eprintln!("kata-toolhost: stdout broke ({error}); killing every process");
                self.stdout_broken = true;
            }
        }
    }

    /// Reap every child that ended, and finish the sessions that leaves done.
    /// Answers how many processes were reaped.
    async fn reap(&mut self) -> u32 {
        let reaped = procs::reap_children();
        let count = u32::try_from(reaped.len()).unwrap_or(u32::MAX);
        for (pid, status) in reaped {
            if let Some(session) = self.pids.remove(&pid) {
                if let Some(live) = self.sessions.get_mut(&session) {
                    live.status = Some(status);
                }
                self.finish_if_done(session).await;
            }
        }
        count
    }

    async fn finish_if_done(&mut self, session: SessionId) {
        let Some(Live {
            open: 0,
            status: Some(status),
            ..
        }) = self.sessions.get(&session)
        else {
            return;
        };
        let status = *status;
        let queued = self
            .send(ToolhostFrame::Exited {
                session,
                code: status.exit_status(),
                signal: status.terminating_signal(),
            })
            .await;
        // An `Exited` a kill could not queue by its deadline leaves the session
        // live, so the kill names it rather than claiming it.
        if queued {
            // Dropping the entry drops its stdin sender, which ends its writer.
            self.sessions.remove(&session);
        }
    }

    /// Kill every descendant and reap until `/proc` lists none and every session
    /// has queued its `Exited`, giving up at [`KILL_ALL_DEADLINE`] (see "A kill
    /// that cannot finish"). Answers how many processes were reaped.
    async fn kill_all(&mut self) -> Result<u32, Unkilled> {
        let deadline = tokio::time::Instant::now() + KILL_ALL_DEADLINE;
        self.kill_by = Some(deadline);
        let killed = self.kill_until(deadline).await;
        self.kill_by = None;
        killed
    }

    async fn kill_until(&mut self, deadline: tokio::time::Instant) -> Result<u32, Unkilled> {
        let mut pass = FIRST_KILL_PASS;
        let mut reaped = 0_u32;
        loop {
            let listed = procs::kill_descendants();
            reaped = reaped.saturating_add(self.reap().await);
            if listed.is_empty() && self.sessions.is_empty() {
                return Ok(reaped);
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                let mut sessions: Vec<SessionId> = self.sessions.keys().copied().collect();
                sessions.sort_by_key(|session| session.0);
                return Err(Unkilled { listed, sessions });
            }
            let walk = (now + pass).min(deadline);
            pass = (pass * 2).min(LAST_KILL_PASS);
            loop {
                tokio::select! {
                    Some(event) = self.events_rx.recv() => self.on_event(event).await,
                    _ = self.sigchld.recv() => {
                        reaped = reaped.saturating_add(self.reap().await);
                    }
                    () = tokio::time::sleep_until(walk) => break,
                }
            }
        }
    }

    /// Queue a frame; whether it was queued. Outside a kill it waits for room
    /// (the backpressure above); inside one, only until the kill's deadline,
    /// after which a frame the full queue cannot take at once is not queued. A
    /// closed queue means the writer is gone, which its `StdoutBroken` already
    /// reported, and counts as queued: nothing will read the frame either way.
    async fn send(&self, frame: ToolhostFrame) -> bool {
        match self.kill_by {
            None => {
                let _ = self.out.send(frame).await;
                true
            }
            Some(deadline) => tokio::time::timeout_at(deadline, self.out.send(frame))
                .await
                .is_ok(),
        }
    }
}

/// How much of a buffer one [`read_full`] filled.
enum Filled {
    Whole,
    /// Stdin ended before the first byte.
    Nothing,
    /// Stdin ended part way.
    Partial,
}

async fn read_full(stdin: &mut pipe::Receiver, buffer: &mut [u8]) -> std::io::Result<Filled> {
    let mut filled = 0;
    while filled < buffer.len() {
        match stdin.read(&mut buffer[filled..]).await {
            Ok(0) if filled == 0 => return Ok(Filled::Nothing),
            Ok(0) => return Ok(Filled::Partial),
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Filled::Whole)
}

/// Decode stdin into frames until it ends.
///
/// A body the codec refuses (not JSON, an unknown kind or field, a missing
/// field, an over-cap chunk or file body) and a zero-length header leave the
/// stream aligned, so each is answered `Error` and reading goes on. A header
/// declaring more than `MAX_FRAME_BYTES` leaves no next frame to find: it is
/// answered `Error` and the rest of stdin is read and discarded until it ends,
/// so even a broken worker's stream ends the toolhost only by ending.
async fn read_frames(mut stdin: pipe::Receiver, frames: mpsc::Sender<Inbound>) {
    loop {
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        match read_full(&mut stdin, &mut header).await {
            Ok(Filled::Whole) => {}
            Ok(Filled::Nothing) => break,
            Ok(Filled::Partial) => {
                eprintln!("kata-toolhost: stdin ended inside a frame header");
                break;
            }
            Err(error) => {
                eprintln!("kata-toolhost: reading stdin failed: {error}");
                break;
            }
        }
        let len = match body_len(header) {
            Ok(len) => len,
            Err(error @ FrameError::EmptyBody) => {
                if frames
                    .send(Inbound::Refused(error.to_string()))
                    .await
                    .is_err()
                {
                    return;
                }
                continue;
            }
            Err(error) => {
                if frames
                    .send(Inbound::Refused(error.to_string()))
                    .await
                    .is_err()
                {
                    return;
                }
                let mut sink = vec![0_u8; 64 * 1024];
                while matches!(stdin.read(&mut sink).await, Ok(read) if read > 0) {}
                break;
            }
        };
        let mut body = vec![0_u8; len];
        match read_full(&mut stdin, &mut body).await {
            Ok(Filled::Whole) => {}
            Ok(Filled::Nothing | Filled::Partial) => {
                eprintln!("kata-toolhost: stdin ended inside a frame body");
                break;
            }
            Err(error) => {
                eprintln!("kata-toolhost: reading stdin failed: {error}");
                break;
            }
        }
        let inbound = match decode_frame::<WorkerFrame>(&body) {
            Ok(frame) => Inbound::Frame(frame),
            Err(error) => Inbound::Refused(error.to_string()),
        };
        if frames.send(inbound).await.is_err() {
            return;
        }
    }
    let _ = frames.send(Inbound::End).await;
}

/// Encode the outbound queue onto stdout until the queue closes, stdout
/// breaks, or the loop hands over its last frame: that one is written ahead of
/// anything still queued, and nothing after it. The frame being written when it
/// arrives is finished first, so no frame is cut by another.
async fn write_frames(
    mut stdout: pipe::Sender,
    mut frames: mpsc::Receiver<ToolhostFrame>,
    last: oneshot::Receiver<Option<ToolhostFrame>>,
    events: mpsc::UnboundedSender<Event>,
) {
    let mut last = Some(last);
    loop {
        let frame = tokio::select! {
            biased;
            ending = async { last.as_mut().expect("polled only while held").await },
                if last.is_some() => {
                // A dropped sender: the loop ended without a last frame, so
                // the queue is drained.
                let Ok(answer) = ending else {
                    last = None;
                    continue;
                };
                if let Some(answer) = answer {
                    write_frame(&mut stdout, &answer, &events).await;
                }
                return;
            },
            frame = frames.recv() => match frame {
                Some(frame) => frame,
                None => return,
            },
        };
        if !write_frame(&mut stdout, &frame, &events).await {
            return;
        }
    }
}

/// Write one frame to stdout; whether stdout still takes writes.
async fn write_frame(
    stdout: &mut pipe::Sender,
    frame: &ToolhostFrame,
    events: &mpsc::UnboundedSender<Event>,
) -> bool {
    let bytes = match encode_frame(frame) {
        Ok(bytes) => bytes,
        // Every frame this toolhost builds is under the cap (a file body is at
        // most 4 MiB raw); a failure here is a defect, reported.
        Err(error) => {
            eprintln!("kata-toolhost: a frame did not encode and was dropped: {error}");
            return true;
        }
    };
    if let Err(error) = stdout.write_all(&bytes).await {
        let _ = events.send(Event::StdoutBroken(error.to_string()));
        return false;
    }
    true
}
