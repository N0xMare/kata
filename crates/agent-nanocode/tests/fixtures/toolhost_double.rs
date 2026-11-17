//! A toolhost DOUBLE: speaks the toolhost protocol's frames (`kata-toolhost-
//! protocol`) over in-process pipes, as an `InteractiveProcess` the adapter opens.
//!
//! It is the witness, not the code under test: every frame the worker sends is
//! logged here, in order, from the double's side of the pipe, so a cell reads
//! what kata actually put on the wire. Files live in an in-memory map the
//! cells seed and read back.

use std::collections::{BTreeMap, VecDeque};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use kata_agent::adapter::{InteractiveProcess, Signal};
use kata_toolhost_protocol::{
    Chunk, FRAME_HEADER_BYTES, FileBody, Hello, RequestId, SessionId, Stream, ToolhostFrame,
    WorkerFrame, body_len, decode_frame, encode_frame,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::watch;

/// What the double states first.
#[derive(Clone, Debug)]
pub enum HelloMode {
    /// This build's `Hello`.
    Current,
    /// A `Hello` naming another source digest.
    WrongDigest,
    /// Close stdout without a frame.
    Silent,
}

/// How the double answers one `Exec`.
#[derive(Clone, Debug)]
pub enum ExecMode {
    /// `Started`, the stdout, `Exited{code}`.
    Answer { stdout: String, code: i32 },
    /// `Started`, then nothing until a kill.
    Hold,
    /// The process runs, held until a kill, but its `Started` is never sent:
    /// the window between a toolhost's spawn and the worker reading its
    /// answer, held open.
    Unstarted,
    /// Close stdout: the toolhost is gone.
    CloseStdout,
    /// Answer with an `Error` frame.
    ErrorFrame,
    /// Answer with bytes the codec refuses: a length header and a body that
    /// is not JSON.
    Garbage,
    /// `Started`, then this many bytes of stdout in 64 KiB chunks, then
    /// `Exited{0}`.
    Flood(usize),
}

/// How the double answers a `ReadFile`.
#[derive(Clone, Debug)]
pub enum ReadMode {
    /// `FileBytes`: the seeded file, or none.
    Answer,
    /// Never, while still reading every frame: a toolhost stuck on a file
    /// read. A turn's read of `/work/AGENTS.md`, which comes before nanocode's
    /// agent is built, then holds `prompt` past any stop grace. Only the
    /// worker's `agent_turn_capsule` cells hold one.
    #[allow(dead_code)]
    Hold,
}

/// What a `SIGKILL` does to the double. Every signal is recorded either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnKill {
    /// The double exits, and a `wait` on it returns.
    Exit,
    /// The double outlives it and never exits, so a `wait` on it never
    /// returns: a process the kernel cannot reap. Only
    /// `nanocode_qualification`'s close cell configures it.
    #[allow(dead_code)]
    Outlive,
    /// The `SIGKILL`'s delivery itself never returns (a `youki kill` that
    /// hangs), and the double never exits. Only `nanocode_qualification`'s
    /// close cell configures it.
    #[allow(dead_code)]
    Hang,
}

#[derive(Clone, Debug)]
pub struct DoubleConfig {
    pub hello: HelloMode,
    /// Consumed in order; the last one repeats.
    pub execs: Vec<ExecMode>,
    /// Ignore `Shutdown` (no `Bye`, no exit) until killed.
    pub swallow_shutdown: bool,
    /// Never answer `KillAll`: no `Exited`, no `Done`, nothing killed.
    pub swallow_kill_all: bool,
    /// What a `SIGKILL` does to the double.
    pub on_kill: OnKill,
    /// How every `ReadFile` is answered.
    pub reads: ReadMode,
    /// Answer a `Stdin` to a live session as `kata-toolhost` answers one its
    /// full queue cannot take: `Error` with a null id and a message naming the
    /// session, the bytes dropped.
    pub refuse_stdin: bool,
    /// Stop reading stdin at a large frame's header ([`Wedge`]).
    pub wedge: Option<Wedge>,
    /// After the first `Stdin` frame, stop reading stdin for this long, then
    /// go on: a toolhost that falls behind its stdin, so the worker's later
    /// frames queue up behind the first.
    pub pause_after_first_stdin: Option<Duration>,
    pub files: BTreeMap<String, Vec<u8>>,
    /// When set, every `Exec` the double receives writes this file
    /// ([`EXEC_ARRIVED`]) before it is answered: a Code Mode cell polls it with
    /// `Read` to wait, without a clock, until a call it started on another task
    /// reached the capsule.
    pub exec_marker: Option<String>,
}

/// The contents of [`DoubleConfig::exec_marker`] once an `Exec` arrived.
pub const EXEC_ARRIVED: &str = "EXEC ARRIVED";

/// Where the double marks an `Exec`'s arrival for the background-`Bash` cells.
pub const EXEC_MARKER: &str = "/work/.exec-arrived";

/// A Code Mode cell that starts `sleep 600` as a background `Bash`, waits until
/// its `Exec` reached the capsule, then stops it with `TaskStop`. The model
/// reads both answers, `Bash`'s then `TaskStop`'s.
///
/// `Bash` answers the model once nanocode has SPAWNED the task that will make
/// the seam call, before that task first runs; a `TaskStop` right after it can
/// abort the task before its seam call sends anything, so no process ever
/// starts and there is nothing to kill. The cell instead polls the double's
/// [`EXEC_MARKER`] with `Read` (each poll yields to that task) until the
/// `Exec` arrived; it never reads a clock.
pub fn stop_a_background_bash_once_its_exec_arrived() -> String {
    format!(
        "const started = JSON.stringify(await tools.Bash({{command: \"sleep 600\", run_in_background: true}}));\n\
         const id = started.match(/bash-[0-9]+/)[0];\n\
         let arrived = false;\n\
         for (let poll = 0; poll < 1000 && !arrived; poll++) {{\n\
           try {{ arrived = JSON.stringify(await tools.Read({{file_path: \"{EXEC_MARKER}\"}})).includes(\"{EXEC_ARRIVED}\"); }} catch (_) {{}}\n\
         }}\n\
         if (!arrived) {{ text(\"the Exec never reached the capsule\"); }} else {{\n\
           const stopped = await tools.TaskStop({{task_id: id}});\n\
           text(started + \"\\n\" + JSON.stringify(stopped));\n\
         }}"
    )
}

/// At the first frame whose body is over `body_over` bytes, the double stops
/// reading stdin at its header, so the worker's write of that frame stops part
/// way. The double's stdin half stays open, as kata's read-write end of the
/// stdin FIFO keeps a reader there: the worker's write to it never fails, it
/// only stops.
#[derive(Clone, Debug)]
pub struct Wedge {
    pub body_over: usize,
    pub then: AfterWedge,
}

#[derive(Clone, Debug)]
pub enum AfterWedge {
    /// [`WEDGE_EXIT`] later, end stdout and exit, the stdin half held in the
    /// witness: a toolhost killed while it reads a large frame.
    Exit,
    /// Stay alive with stdout open and read nothing more, until killed: a
    /// toolhost wedged on a large frame. It records when the worker drops its
    /// end of the stdin ([`DoubleWitness::stdin_closed`]), probed by writing
    /// into the stdin pipe (a write to a pipe whose other end is gone fails),
    /// never by reading it, which would let the stuck write go on.
    Hang,
}

/// How long a wedged double holds its stdout open after it stops reading.
pub const WEDGE_EXIT: Duration = Duration::from_secs(1);

/// How often a hung double probes its stdin.
const WEDGE_PROBE: Duration = Duration::from_millis(10);

impl Default for DoubleConfig {
    fn default() -> Self {
        Self {
            hello: HelloMode::Current,
            execs: vec![ExecMode::Answer {
                stdout: "hi\n".to_owned(),
                code: 0,
            }],
            swallow_shutdown: false,
            swallow_kill_all: false,
            on_kill: OnKill::Exit,
            reads: ReadMode::Answer,
            refuse_stdin: false,
            wedge: None,
            pause_after_first_stdin: None,
            files: BTreeMap::new(),
            exec_marker: None,
        }
    }
}

/// What a cell reads back after the turn.
#[derive(Clone)]
pub struct DoubleWitness {
    frames: Arc<Mutex<Vec<WorkerFrame>>>,
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    signals: Arc<Mutex<Vec<Signal>>>,
    /// The sessions the double holds running: started, not yet killed.
    live: Arc<Mutex<Vec<SessionId>>>,
    /// The worker closed the double's stdin.
    stdin_closed: Arc<Mutex<bool>>,
    /// A [`Wedge`] began: the double stopped reading at a frame's header.
    wedged: Arc<Mutex<bool>>,
    /// When an `Exec` answered [`ExecMode::CloseStdout`] closed the double's
    /// stdout: the instant the worker's reads can first see the toolhost gone.
    stdout_closed_at: Arc<Mutex<Option<std::time::Instant>>>,
    /// A wedged double's stdin half, held open past its exit.
    held_stdin: Arc<Mutex<Option<DuplexStream>>>,
    exited: watch::Receiver<bool>,
}

impl DoubleWitness {
    /// Every frame the worker sent, in order.
    pub fn frames(&self) -> Vec<WorkerFrame> {
        self.frames.lock().expect("frames").clone()
    }

    /// The frames' kinds, in order.
    pub fn kinds(&self) -> Vec<&'static str> {
        self.frames().iter().map(worker_kind).collect()
    }

    /// A file's contents as text, when it exists and is UTF-8.
    pub fn file(&self, path: &str) -> Option<String> {
        self.file_bytes(path)
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    pub fn file_bytes(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().expect("files").get(path).cloned()
    }

    pub fn signals(&self) -> Vec<Signal> {
        self.signals.lock().expect("signals").clone()
    }

    pub fn has_exited(&self) -> bool {
        *self.exited.borrow()
    }

    /// The sessions the double holds running right now.
    pub fn live_sessions(&self) -> Vec<SessionId> {
        self.live.lock().expect("live").clone()
    }

    /// Whether the worker has closed the double's stdin.
    pub fn stdin_closed(&self) -> bool {
        *self.stdin_closed.lock().expect("stdin_closed")
    }

    /// Whether a [`Wedge`] began: the double read the header of a frame over
    /// its `body_over` and stopped reading there, so the worker's write of
    /// that frame is stuck.
    pub fn has_wedged(&self) -> bool {
        *self.wedged.lock().expect("wedged")
    }

    /// When the double closed its stdout on an [`ExecMode::CloseStdout`]
    /// `Exec`, read just before the close.
    pub fn stdout_closed_at(&self) -> Option<std::time::Instant> {
        *self.stdout_closed_at.lock().expect("stdout_closed_at")
    }

    /// Resolve once the double has logged `count` frames.
    pub async fn wait_for_frames(&self, count: usize) {
        while self.frames.lock().expect("frames").len() < count {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

pub const fn worker_kind(frame: &WorkerFrame) -> &'static str {
    match frame {
        WorkerFrame::Exec { .. } => "exec",
        WorkerFrame::Stdin { .. } => "stdin",
        WorkerFrame::Signal { .. } => "signal",
        WorkerFrame::KillAll { .. } => "kill_all",
        WorkerFrame::ReadFile { .. } => "read_file",
        WorkerFrame::WriteFile { .. } => "write_file",
        WorkerFrame::RemoveFile { .. } => "remove_file",
        WorkerFrame::Shutdown { .. } => "shutdown",
    }
}

/// Start a double; the returned process is what the adapter's `open` takes.
pub fn start(config: DoubleConfig) -> (Box<dyn InteractiveProcess>, DoubleWitness) {
    let (worker_stdin, double_stdin) = tokio::io::duplex(1 << 20);
    let (double_stdout, worker_stdout) = tokio::io::duplex(1 << 20);
    let (exited_tx, exited_rx) = watch::channel(false);
    let on_kill = config.on_kill;
    let witness = DoubleWitness {
        frames: Arc::default(),
        files: Arc::new(Mutex::new(config.files.clone())),
        signals: Arc::default(),
        live: Arc::default(),
        stdin_closed: Arc::default(),
        wedged: Arc::default(),
        stdout_closed_at: Arc::default(),
        held_stdin: Arc::default(),
        exited: exited_rx,
    };
    let task = tokio::spawn(run(
        config,
        double_stdin,
        double_stdout,
        witness.clone(),
        exited_tx.clone(),
    ));
    let process = DoubleProcess {
        stdin: Some(Box::new(worker_stdin)),
        stdout: Some(Box::new(worker_stdout)),
        task,
        exited_tx,
        exited: witness.exited.clone(),
        signals: Arc::clone(&witness.signals),
        on_kill,
    };
    (Box::new(process), witness)
}

struct DoubleProcess {
    stdin: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    stdout: Option<Box<dyn AsyncRead + Send + Unpin>>,
    task: tokio::task::JoinHandle<()>,
    exited_tx: watch::Sender<bool>,
    exited: watch::Receiver<bool>,
    signals: Arc<Mutex<Vec<Signal>>>,
    on_kill: OnKill,
}

#[async_trait]
impl InteractiveProcess for DoubleProcess {
    fn take_stdin(&mut self) -> Option<Box<dyn AsyncWrite + Send + Unpin>> {
        self.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>> {
        self.stdout.take()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn AsyncRead + Send + Unpin>> {
        None
    }

    async fn signal(&mut self, signal: Signal) -> kata_types::error::KataResult<()> {
        self.signals.lock().expect("signals").push(signal);
        if signal == Signal::Kill && self.on_kill == OnKill::Exit {
            self.task.abort();
            let _ = self.exited_tx.send(true);
        }
        if signal == Signal::Kill && self.on_kill == OnKill::Hang {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn wait(&mut self) -> kata_types::error::KataResult<ExitStatus> {
        while !*self.exited.borrow() {
            if self.exited.changed().await.is_err() {
                break;
            }
        }
        Ok(ExitStatus::from_raw(0))
    }
}

async fn write(out: &mut DuplexStream, frame: &ToolhostFrame) -> std::io::Result<()> {
    let bytes = encode_frame(frame).expect("the double encodes its frames");
    out.write_all(&bytes).await?;
    out.flush().await
}

/// The next frame's body length, read off its header; `None` at EOF.
async fn read_header(input: &mut DuplexStream) -> Option<usize> {
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    input.read_exact(&mut header).await.ok()?;
    Some(body_len(header).expect("the worker sends valid lengths"))
}

async fn read_body(input: &mut DuplexStream, length: usize) -> Option<WorkerFrame> {
    let mut body = vec![0_u8; length];
    input.read_exact(&mut body).await.ok()?;
    Some(decode_frame(&body).expect("the worker sends valid frames"))
}

async fn run(
    config: DoubleConfig,
    mut stdin: DuplexStream,
    mut stdout: DuplexStream,
    witness: DoubleWitness,
    exited: watch::Sender<bool>,
) {
    match config.hello {
        HelloMode::Current => {
            if write(&mut stdout, &ToolhostFrame::Hello(Hello::current()))
                .await
                .is_err()
            {
                let _ = exited.send(true);
                return;
            }
        }
        HelloMode::WrongDigest => {
            let hello = Hello {
                protocol: kata_toolhost_protocol::TOOLHOST_PROTOCOL_VERSION,
                source_digest: "0".repeat(64),
            };
            drop(write(&mut stdout, &ToolhostFrame::Hello(hello)).await);
        }
        HelloMode::Silent => {
            drop(stdout);
            // Hold stdin open as a live process would, until killed.
            std::future::pending::<()>().await;
            return;
        }
    }
    let mut execs: VecDeque<ExecMode> = config.execs.into();
    let mut stdin_pause = config.pause_after_first_stdin;
    let held = Arc::clone(&witness.live);
    loop {
        let frame = match read_header(&mut stdin).await {
            Some(length) => {
                if let Some(wedge) = config
                    .wedge
                    .as_ref()
                    .filter(|wedge| length > wedge.body_over)
                {
                    *witness.wedged.lock().expect("wedged") = true;
                    match wedge.then {
                        AfterWedge::Exit => {
                            tokio::time::sleep(WEDGE_EXIT).await;
                            *witness.held_stdin.lock().expect("held_stdin") = Some(stdin);
                            drop(stdout);
                            let _ = exited.send(true);
                        }
                        AfterWedge::Hang => {
                            while stdin.write_all(b"\0").await.is_ok() {
                                tokio::time::sleep(WEDGE_PROBE).await;
                            }
                            *witness.stdin_closed.lock().expect("stdin_closed") = true;
                            // Alive, stdout open, until killed.
                            let _stdout = stdout;
                            std::future::pending::<()>().await;
                        }
                    }
                    return;
                }
                read_body(&mut stdin, length).await
            }
            None => None,
        };
        let Some(frame) = frame else {
            // The worker dropped the toolhost's stdin: as the real toolhost does,
            // kill every session.
            *witness.stdin_closed.lock().expect("stdin_closed") = true;
            held.lock().expect("live").clear();
            break;
        };
        witness.frames.lock().expect("frames").push(frame.clone());
        if matches!(frame, WorkerFrame::Stdin { .. })
            && let Some(pause) = stdin_pause.take()
        {
            tokio::time::sleep(pause).await;
        }
        let answers: Vec<ToolhostFrame> = match frame {
            WorkerFrame::Exec { id, session, .. } => {
                if let Some(marker) = &config.exec_marker {
                    witness
                        .files
                        .lock()
                        .expect("files")
                        .insert(marker.clone(), EXEC_ARRIVED.as_bytes().to_vec());
                }
                let mode = if execs.len() > 1 {
                    execs.pop_front().expect("non-empty")
                } else {
                    execs.front().cloned().unwrap_or(ExecMode::Hold)
                };
                match mode {
                    ExecMode::Answer { stdout: text, code } => vec![
                        started(id, session),
                        ToolhostFrame::Output {
                            session,
                            stream: Stream::Stdout,
                            data_b64: Chunk::new(text.into_bytes()).expect("small"),
                        },
                        ToolhostFrame::Exited {
                            session,
                            code: Some(code),
                            signal: None,
                        },
                    ],
                    ExecMode::Hold => {
                        held.lock().expect("live").push(session);
                        vec![started(id, session)]
                    }
                    ExecMode::Unstarted => {
                        held.lock().expect("live").push(session);
                        Vec::new()
                    }
                    ExecMode::Flood(total) => {
                        let mut answers = vec![started(id, session)];
                        let mut left = total;
                        while left > 0 {
                            let chunk = left.min(kata_toolhost_protocol::MAX_CHUNK_BYTES);
                            answers.push(ToolhostFrame::Output {
                                session,
                                stream: Stream::Stdout,
                                data_b64: Chunk::new(vec![b'x'; chunk]).expect("one chunk"),
                            });
                            left -= chunk;
                        }
                        answers.push(ToolhostFrame::Exited {
                            session,
                            code: Some(0),
                            signal: None,
                        });
                        answers
                    }
                    ExecMode::Garbage => {
                        let body = b"this is not a frame";
                        let length = u32::try_from(body.len()).expect("small");
                        drop(stdout.write_all(&length.to_be_bytes()).await);
                        drop(stdout.write_all(body).await);
                        drop(stdout.flush().await);
                        Vec::new()
                    }
                    ExecMode::CloseStdout => {
                        *witness.stdout_closed_at.lock().expect("stdout_closed_at") =
                            Some(std::time::Instant::now());
                        drop(stdout);
                        // The process lives on with no stdout, until killed.
                        std::future::pending::<()>().await;
                        return;
                    }
                    ExecMode::ErrorFrame => vec![ToolhostFrame::Error {
                        id: Some(id),
                        message: "the double refuses this exec".to_owned(),
                    }],
                }
            }
            WorkerFrame::KillAll { .. } if config.swallow_kill_all => Vec::new(),
            WorkerFrame::KillAll { id } => {
                let mut answers: Vec<ToolhostFrame> = held
                    .lock()
                    .expect("live")
                    .drain(..)
                    .map(|session| ToolhostFrame::Exited {
                        session,
                        code: None,
                        signal: Some(9),
                    })
                    .collect();
                answers.push(ToolhostFrame::Done { id });
                answers
            }
            WorkerFrame::Signal { session, .. } => {
                let mut live = held.lock().expect("live");
                if live.contains(&session) {
                    live.retain(|running| *running != session);
                    vec![ToolhostFrame::Exited {
                        session,
                        code: None,
                        signal: Some(9),
                    }]
                } else {
                    vec![ToolhostFrame::SessionGone { session }]
                }
            }
            WorkerFrame::Stdin {
                session, data_b64, ..
            } => {
                if held.lock().expect("live").contains(&session) {
                    if config.refuse_stdin {
                        vec![ToolhostFrame::Error {
                            id: None,
                            message: format!(
                                "session {}: {} byte(s) of stdin refused: its process is not \
                                 reading its stdin",
                                session.0,
                                data_b64.as_bytes().len()
                            ),
                        }]
                    } else {
                        Vec::new()
                    }
                } else {
                    vec![ToolhostFrame::SessionGone { session }]
                }
            }
            WorkerFrame::ReadFile { .. } if matches!(config.reads, ReadMode::Hold) => Vec::new(),
            WorkerFrame::ReadFile { id, path } => vec![ToolhostFrame::FileBytes {
                id,
                data_b64: witness
                    .files
                    .lock()
                    .expect("files")
                    .get(&path)
                    .cloned()
                    .map(|bytes| FileBody::new(bytes).expect("a seeded file fits a body")),
            }],
            WorkerFrame::WriteFile { id, path, data_b64 } => {
                witness
                    .files
                    .lock()
                    .expect("files")
                    .insert(path, data_b64.into_bytes());
                vec![ToolhostFrame::Done { id }]
            }
            WorkerFrame::RemoveFile { id, path } => {
                match witness.files.lock().expect("files").remove(&path) {
                    Some(_) => vec![ToolhostFrame::Done { id }],
                    None => vec![ToolhostFrame::FileError {
                        id,
                        errno: 2,
                        message: "no such file".to_owned(),
                    }],
                }
            }
            WorkerFrame::Shutdown { id } => {
                if config.swallow_shutdown {
                    Vec::new()
                } else {
                    let reaped = {
                        let mut live = held.lock().expect("live");
                        let reaped = u32::try_from(live.len()).unwrap_or(u32::MAX);
                        live.clear();
                        reaped
                    };
                    drop(write(&mut stdout, &ToolhostFrame::Bye { id, reaped }).await);
                    break;
                }
            }
        };
        for answer in answers {
            if write(&mut stdout, &answer).await.is_err() {
                break;
            }
        }
    }
    if config.swallow_shutdown {
        // A toolhost that ignores everything: only SIGKILL ends it.
        std::future::pending::<()>().await;
    }
    let _ = exited.send(true);
}

fn started(id: RequestId, session: SessionId) -> ToolhostFrame {
    ToolhostFrame::Started {
        id,
        session,
        pid: 100 + session.0,
        note: None,
    }
}
