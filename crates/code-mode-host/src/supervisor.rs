//! The engine worker seam's backend in the process that hosts the worker: one
//! supervisor thread per `EmbeddedHost`, which runs that host's cells in an
//! interpreter process it starts, watches and reaps.
//!
//! Everything the interpreter sends is untrusted. The supervisor reads it into
//! bounded frames ([`wire::FRAME_CAP`]) and admits an event only for the cell
//! it started, kills the interpreter for anything else (a frame between cells,
//! a journal event, a `Held` no `Hold` asked for, more output than the cell's
//! limit, a `Load` while no cell runs or while two answers are still being
//! written), and kills it once a cell outlives its wall by [`WALL_GRACE`]. Its
//! own reports of an interpreter's end, and of the native stack overflow that
//! ended one ([`native_stack_report`], read off its standard error), are the
//! only texts it writes into a cell's events, and a report's `Notify` is the
//! report alone; the `Error` after it also carries, labelled, what the
//! interpreter wrote to its standard error, which is the interpreter's text,
//! not the supervisor's.
//!
//! The supervisor never waits on the interpreter: what it sends goes to a
//! writer thread of that interpreter's, so an interpreter that stops reading
//! delays neither its cell's wall nor `terminate`. Ending an interpreter shuts
//! the supervisor's end of its socket down, which ends that writer and its
//! reader whatever else still holds the other end.
//!
//! An interpreter's standard error is a socket of its own, which a drain
//! thread of the supervisor's reads to its end, keeping the last
//! [`STDERR_CAP`] bytes and counting the rest; nothing of it reaches the
//! hosting process's own standard error or log. A cell its interpreter's end
//! fails, and a cell whose interpreter could not start, carry what it kept
//! (a panic, glibc's assertion lines) in their error.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::thread;
use std::time::{Duration, Instant};

use nanocode_code_mode_engine::{
    Events, HostCommand, RuntimeEvent, StartExecution, WorkerBackend, WorkerEnds,
};
use serde_json::{Value, value::RawValue};

use crate::wire::{self, Event, FromInterpreter, ToInterpreter};
use crate::{CELL_EVENT_BYTES, CodeModeLimits, LiveWorker, Program};

/// How long an interpreter may take to answer `Ready`, after its start or
/// after a cell's terminal event, before it is killed.
const READY_WITHIN: Duration = Duration::from_secs(30);

/// How long past a cell's wall the supervisor waits for the interpreter's own
/// wall report before it kills the interpreter: the interpreter ends a cell on
/// its wall itself, except one inside a long native step (a built-in sort of
/// millions of elements), which no interrupt reaches.
pub const WALL_GRACE: Duration = Duration::from_secs(5);

/// What a cell may emit past `cell_emitted_bytes` as the supervisor counts it:
/// the interpreter's one report of the output limit, which it sends in place
/// of the event that crossed it, just before the cell's `Error`.
const REPORT_ALLOWANCE: usize = CELL_EVENT_BYTES + 256;

/// Frames the supervisor's inbox holds before the interpreter's reader (and the
/// command forwarder) waits: bounds the interpreter's frames read ahead of the
/// supervisor to this many.
const INBOX: usize = 4;

/// Answers to `Load`s queued for the interpreter and not yet written whole
/// that make its next `Load` a violation. The engine asks again only once it
/// has read the last answer whole, by when the writer has finished every answer
/// before it; so an honest interpreter asks with at most one answer unwritten
/// (the one the writer is still counting off), and two means it asks without
/// reading.
const UNWRITTEN_ANSWERS: usize = 2;

/// The characters of an interpreter's refusal its cell's error carries.
const REFUSAL_CHARS: usize = 4096;

/// What the supervisor keeps of one interpreter's standard error: its last
/// this many bytes. Earlier ones are dropped and counted.
pub const STDERR_CAP: usize = 64 << 10;

/// The start of the report of an interpreter that ended by a signal while its
/// cell ran: `Code Mode's interpreter process ended by SIGSEGV`.
pub const ENDED_BY: &str = "Code Mode's interpreter process ended by ";

/// The start of the report of an interpreter that exited while its cell ran:
/// `Code Mode's interpreter process exited with status 101`.
pub const EXITED_WITH: &str = "Code Mode's interpreter process exited with status ";

/// The backend [`crate::install`] puts behind the engine's seam.
pub fn backend(limits: CodeModeLimits, program: Program) -> WorkerBackend {
    let config = Arc::new(Config { limits, program });
    Box::new(move |ends| {
        let live = LiveWorker::claim(config.limits.live_workers)?;
        start(ends, live, Arc::clone(&config))
    })
}

struct Config {
    limits: CodeModeLimits,
    program: Program,
}

enum Input {
    Command(HostCommand),
    /// The host is gone: every command it can send has been sent.
    CommandsClosed,
    /// What interpreter `generation` said; a stale generation's is ignored.
    Interpreter {
        generation: u64,
        said: Said,
    },
}

enum Said {
    Frame(FromInterpreter),
    /// Its socket ended: at a clean end of stream (`None`), or on a frame the
    /// reader refused (why).
    Ended(Option<String>),
}

/// Starts the supervisor of one `EmbeddedHost`, and the thread that forwards
/// the host's commands into the supervisor's inbox. The host counts as live
/// (`live`) until the supervisor has reaped its interpreter.
fn start(ends: WorkerEnds, live: LiveWorker, config: Arc<Config>) -> Result<(), String> {
    let WorkerEnds {
        commands,
        events,
        startup,
        stopped,
    } = ends;
    let (inbox, received) = std_mpsc::sync_channel(INBOX);
    let forward = inbox.clone();
    thread::Builder::new()
        .name("code-mode-cmds".to_owned())
        .spawn(move || {
            for command in commands {
                if forward.send(Input::Command(command)).is_err() {
                    return;
                }
            }
            let _ = forward.send(Input::CommandsClosed);
        })
        .map_err(|error| format!("failed to start Code Mode's command forwarder: {error}"))?;
    thread::Builder::new()
        .name("code-mode-super".to_owned())
        .spawn(move || {
            let mut supervisor = Supervisor {
                config,
                events,
                inbox,
                interpreter: None,
                generation: 0,
                phase: Phase::Idle,
            };
            supervisor.run(&received);
            // `run` killed and reaped the interpreter before it returned: only
            // now does this worker stop counting as live.
            drop(live);
            drop(startup);
            stopped.send();
        })
        .map_err(|error| format!("failed to start Code Mode's supervisor: {error}"))?;
    Ok(())
}

struct Interpreter {
    child: Child,
    socket: UnixStream,
    /// The supervisor's end of its standard error, which its drain reads.
    stderr: UnixStream,
    /// Its standard error's drain ([`drain_stderr`]).
    drain: thread::JoinHandle<Stderr>,
    generation: u64,
    /// Its writer's queue ([`write_interpreter`]).
    writes: std_mpsc::Sender<Outgoing>,
    /// `Loaded` answers queued for it and not yet written whole.
    unwritten_answers: Arc<AtomicUsize>,
}

/// One encoded frame for an interpreter's writer.
struct Outgoing {
    bytes: Vec<u8>,
    /// It answers a `Load`: counted in [`Interpreter::unwritten_answers`].
    answer: bool,
}

enum Phase {
    /// No cell runs; the interpreter, if there is one, has answered `Ready`.
    Idle,
    /// Waiting for `Ready`: from an interpreter just started (`fresh`), or from
    /// one whose last cell's engine worker is ending. `pending` is the cell
    /// that waits for it.
    AwaitingReady {
        fresh: bool,
        pending: Option<StartExecution>,
        until: Instant,
    },
    Running(Cell),
}

struct Cell {
    id: u64,
    /// The stored values its `start_cell` was given, which the interpreter
    /// asks for one key at a time.
    stored: HashMap<String, Arc<RawValue>>,
    /// The cell's wall plus [`WALL_GRACE`], from when it was sent.
    until: Instant,
    /// What the cell emitted, charged as the engine charges it or less.
    charged: usize,
    /// `Hold`s sent that no `Held` has answered yet.
    holds: usize,
}

enum Step {
    Input(Input),
    Deadline,
    Stop,
}

struct Supervisor {
    config: Arc<Config>,
    events: Events,
    inbox: std_mpsc::SyncSender<Input>,
    interpreter: Option<Interpreter>,
    generation: u64,
    phase: Phase,
}

impl Supervisor {
    fn run(&mut self, received: &std_mpsc::Receiver<Input>) {
        loop {
            let step = match self.deadline() {
                None => received.recv().map_or(Step::Stop, Step::Input),
                Some(until) => {
                    match received.recv_timeout(until.saturating_duration_since(Instant::now())) {
                        Ok(input) => Step::Input(input),
                        Err(std_mpsc::RecvTimeoutError::Timeout) => Step::Deadline,
                        Err(std_mpsc::RecvTimeoutError::Disconnected) => Step::Stop,
                    }
                }
            };
            match step {
                Step::Stop
                | Step::Input(Input::CommandsClosed | Input::Command(HostCommand::Shutdown)) => {
                    break;
                }
                Step::Deadline => self.deadline_passed(),
                Step::Input(Input::Command(command)) => self.command(command),
                Step::Input(Input::Interpreter { generation, said }) => {
                    if self.interpreter.as_ref().map(|i| i.generation) == Some(generation) {
                        match said {
                            Said::Frame(frame) => self.frame(frame),
                            Said::Ended(why) => {
                                let end = self.end_interpreter();
                                self.after_end(end, why);
                            }
                        }
                    }
                }
            }
        }
        let _ = self.end_interpreter();
    }

    fn deadline(&self) -> Option<Instant> {
        match &self.phase {
            Phase::Idle => None,
            Phase::AwaitingReady { until, .. } => Some(*until),
            Phase::Running(cell) => Some(cell.until),
        }
    }

    fn command(&mut self, command: HostCommand) {
        match command {
            HostCommand::Start(start) => self.start_cell(start),
            HostCommand::ToolResult {
                execution_id,
                id,
                encoded,
                success,
            } => {
                // Encoded once: a result may come to the frame cap, and until
                // its encode is done this thread reads no other input, a
                // `terminate` included.
                if let Some(bytes) = wire::encode(&ToInterpreter::ToolResult {
                    execution_id,
                    id,
                    encoded,
                    success,
                }) {
                    return self.queue(bytes, false);
                }
                // The tool call fails in the cell, naming why, rather than
                // waiting for a result that cannot reach it.
                let why = format!(
                    "the tool's result came to more than the {}-byte frame Code Mode's \
                     interpreter process takes",
                    wire::FRAME_CAP
                );
                self.forward(&ToInterpreter::ToolResult {
                    execution_id,
                    id,
                    encoded: Value::String(why).to_string(),
                    success: false,
                });
            }
            HostCommand::Hold { execution_id } => {
                // Unreachable while kata installs no cell journal: the engine
                // asks a `Hold` only of a cell it journals (nanocode's
                // `hold_cell` sends none without the cell's journal record),
                // and `start_cell` refuses every journaled cell. Were one to
                // come for a cell that is not the running one — before the
                // interpreter's `Ready`, while that cell's `Start` waits in
                // `AwaitingReady` — the interpreter would get it before the
                // cell and hold nothing, and the cell's `Held` would never
                // come: asserted, not dropped silently.
                let running = match &mut self.phase {
                    Phase::Running(cell) if cell.id == execution_id => {
                        cell.holds += 1;
                        true
                    }
                    _ => false,
                };
                debug_assert!(
                    running,
                    "a Hold for cell {execution_id}, which is not the running cell: kata \
                     journals no cell, so the engine asks none"
                );
                self.forward(&ToInterpreter::Hold { execution_id });
            }
            HostCommand::Release { execution_id } => {
                self.forward(&ToInterpreter::Release { execution_id });
            }
            HostCommand::Shutdown => {}
        }
    }

    fn start_cell(&mut self, start: StartExecution) {
        if start.journaling.is_some() {
            self.fail(
                start.execution_id,
                "kata's Code Mode interpreter process runs no journaled cell",
            );
            return;
        }
        match &mut self.phase {
            // The engine drops a Start that arrives while a cell runs.
            Phase::Running(_)
            | Phase::AwaitingReady {
                pending: Some(_), ..
            } => {}
            Phase::AwaitingReady { pending, .. } => *pending = Some(start),
            Phase::Idle if self.interpreter.is_some() => self.send_start(start),
            Phase::Idle => self.spawn_for(start),
        }
    }

    /// Starts an interpreter for `start`, which waits for its `Ready`.
    fn spawn_for(&mut self, start: StartExecution) {
        match self.spawn() {
            Ok(()) => {
                self.phase = Phase::AwaitingReady {
                    fresh: true,
                    pending: Some(start),
                    until: Instant::now() + READY_WITHIN,
                };
            }
            Err(why) => self.fail(
                start.execution_id,
                &format!("Code Mode's interpreter process could not start: {why}"),
            ),
        }
    }

    fn spawn(&mut self) -> Result<(), String> {
        let (ours, theirs) = UnixStream::pair()
            .map_err(|error| format!("its socket could not be made ({error})"))?;
        let (read_end, write_end) = ours
            .try_clone()
            .and_then(|read_end| Ok((read_end, ours.try_clone()?)))
            .map_err(|error| format!("its socket could not be shared ({error})"))?;
        let (stderr, theirs_stderr) = UnixStream::pair()
            .map_err(|error| format!("its standard error could not be made ({error})"))?;
        let drained = stderr
            .try_clone()
            .map_err(|error| format!("its standard error could not be shared ({error})"))?;
        let mut command = Command::new(&self.config.program.path);
        command
            .args(&self.config.program.args)
            .env_clear()
            // Its one variable: the empty `TZ` is UTC to the engine's zone
            // reader, which then opens and stats no zone file (its filter
            // refuses both), and a cell reads no host's time zone.
            .env("TZ", "")
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::from(OwnedFd::from(theirs_stderr)));
        // Spawned from this thread, which outlives the child (it reaps it): the
        // child's parent-death signal fires when the THREAD that started it
        // ends.
        let child = command
            .spawn()
            .map_err(|error| format!("{} ({error})", self.config.program.path.display()))?;
        // Closes this process's copies of the child's ends.
        drop(command);
        let drain = match thread::Builder::new()
            .name("code-mode-err".to_owned())
            .spawn(move || drain_stderr(drained))
        {
            Ok(drain) => drain,
            Err(error) => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "its standard error's drain could not start ({error})"
                ));
            }
        };
        self.generation += 1;
        let generation = self.generation;
        let (writes, queued) = std_mpsc::channel();
        let unwritten_answers = Arc::new(AtomicUsize::new(0));
        self.interpreter = Some(Interpreter {
            child,
            socket: ours,
            stderr,
            drain,
            generation,
            writes,
            unwritten_answers: Arc::clone(&unwritten_answers),
        });
        let inbox = self.inbox.clone();
        let read = thread::Builder::new()
            .name("code-mode-read".to_owned())
            .spawn(move || read_interpreter(generation, read_end, &inbox));
        if let Err(error) = read {
            self.end_interpreter();
            return Err(format!("its reader could not start ({error})"));
        }
        let inbox = self.inbox.clone();
        let write = thread::Builder::new()
            .name("code-mode-write".to_owned())
            .spawn(move || {
                write_interpreter(generation, write_end, &queued, &unwritten_answers, &inbox);
            });
        if let Err(error) = write {
            self.end_interpreter();
            return Err(format!("its writer could not start ({error})"));
        }
        self.forward(&ToInterpreter::Init {
            limits: self.config.limits.into(),
            parent: i32::try_from(std::process::id()).unwrap_or(i32::MAX),
        });
        Ok(())
    }

    fn send_start(&mut self, start: StartExecution) {
        let id = start.execution_id;
        let frame = ToInterpreter::Start {
            execution_id: id,
            source: start.source,
            tools: start.tools.encoded().map(str::to_owned),
            prelude: start.prelude.map(|prelude| prelude.to_string()),
        };
        let Some(bytes) = wire::encode(&frame) else {
            self.fail(
                id,
                &format!(
                    "this cell's source and tools come to more than the {}-byte frame Code \
                     Mode's interpreter process takes",
                    wire::FRAME_CAP
                ),
            );
            return;
        };
        self.phase = Phase::Running(Cell {
            id,
            stored: start.stored,
            until: Instant::now() + self.config.limits.cell_wall + WALL_GRACE,
            charged: 0,
            holds: 0,
        });
        self.queue(bytes, false);
    }

    /// Queues `frame` for the interpreter's writer; a frame that can come to
    /// more than the cap (a cell's `Start`, a tool result, a stored value) its
    /// caller encodes and queues itself, answering one over the cap.
    fn forward(&self, frame: &ToInterpreter) {
        if let Some(bytes) = wire::encode(frame) {
            self.queue(bytes, false);
        }
    }

    /// Queues an encoded frame for the interpreter's writer. A writer that
    /// already ended reported why ([`write_interpreter`]).
    fn queue(&self, bytes: Vec<u8>, answer: bool) {
        if let Some(interpreter) = &self.interpreter {
            if answer {
                interpreter.unwritten_answers.fetch_add(1, Ordering::AcqRel);
            }
            let _ = interpreter.writes.send(Outgoing { bytes, answer });
        }
    }

    /// Answers the running cell's `Load` of `key` with its stored value.
    fn load(&mut self, key: &str) {
        let (id, value) = match &self.phase {
            Phase::Running(cell) => (cell.id, cell.stored.get(key).cloned()),
            Phase::Idle | Phase::AwaitingReady { .. } => {
                return self.violation("it asked for a stored value while no cell ran".to_owned());
            }
        };
        let unwritten = self.interpreter.as_ref().map_or(0, |interpreter| {
            interpreter.unwritten_answers.load(Ordering::Acquire)
        });
        if unwritten >= UNWRITTEN_ANSWERS {
            return self.violation(format!(
                "it asked for a stored value with {unwritten} answers not yet written to it"
            ));
        }
        if let Some(bytes) = wire::encode(&ToInterpreter::Loaded { value }) {
            return self.queue(bytes, true);
        }
        // Unreached while every stored value came out of an interpreter's
        // frame, which held it with more around it.
        let _ = self.end_interpreter();
        self.phase = Phase::Idle;
        self.fail(
            id,
            &format!(
                "this cell's stored value {key:?} comes to more than the {}-byte frame Code \
                 Mode's interpreter process takes",
                wire::FRAME_CAP
            ),
        );
    }

    fn frame(&mut self, frame: FromInterpreter) {
        match frame {
            FromInterpreter::Ready => match std::mem::replace(&mut self.phase, Phase::Idle) {
                Phase::AwaitingReady {
                    pending: Some(start),
                    ..
                } => self.send_start(start),
                Phase::AwaitingReady { pending: None, .. } => {}
                phase @ (Phase::Idle | Phase::Running(_)) => {
                    self.phase = phase;
                    self.violation("it answered Ready unasked".to_owned());
                }
            },
            FromInterpreter::Refused { message } => {
                let end = self.end_interpreter();
                self.after_end(end, Some(message.chars().take(REFUSAL_CHARS).collect()));
            }
            FromInterpreter::Load { key } => self.load(&key),
            FromInterpreter::Event(event) => self.event(event),
        }
    }

    fn event(&mut self, event: Event) {
        let cell_id = event.cell_id();
        let Phase::Running(cell) = &mut self.phase else {
            return self.violation(format!("it sent an event of cell {cell_id} while none ran"));
        };
        if cell.id != cell_id {
            let running = cell.id;
            return self.violation(format!(
                "it sent an event of cell {cell_id} while cell {running} ran"
            ));
        }
        let terminal = match &event {
            Event::Replayed { .. } | Event::Diverged { .. } | Event::Waiting { .. } => {
                return self
                    .violation("it sent a journal event of a cell kata journals not".into());
            }
            Event::Held { .. } => {
                if cell.holds == 0 {
                    return self.violation("it sent a Held no Hold asked for".to_owned());
                }
                cell.holds -= 1;
                false
            }
            Event::Notify { .. }
            | Event::Content { .. }
            | Event::ToolCall { .. }
            | Event::Yielded { .. } => {
                cell.charged = cell.charged.saturating_add(event.charge());
                false
            }
            Event::Done { .. } | Event::Error { .. } => true,
        };
        let cap = self
            .config
            .limits
            .cell_emitted_bytes
            .saturating_add(REPORT_ALLOWANCE);
        if cell.charged > cap {
            return self.violation(format!(
                "its cell emitted more than its {}-byte output limit",
                self.config.limits.cell_emitted_bytes
            ));
        }
        let Ok(event) = event.decode() else {
            return self.violation("it sent an output item that is not one".to_owned());
        };
        self.events.send(event);
        if terminal {
            self.phase = Phase::AwaitingReady {
                fresh: false,
                pending: None,
                until: Instant::now() + READY_WITHIN,
            };
        }
    }

    fn deadline_passed(&mut self) {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Idle => {}
            Phase::Running(cell) => {
                let end = self.end_interpreter();
                let report = format!(
                    "Code Mode cell exceeded its {} ms wall-time limit",
                    self.config.limits.cell_wall.as_millis()
                );
                let message = end.stderr.appended_to(format!(
                    "{report}; kata killed its interpreter process {} s past it",
                    WALL_GRACE.as_secs()
                ));
                self.report(cell.id, report, message);
            }
            phase @ Phase::AwaitingReady { .. } => {
                self.phase = phase;
                let end = self.end_interpreter();
                self.after_end(
                    end,
                    Some(format!(
                        "it did not answer Ready within {} s",
                        READY_WITHIN.as_secs()
                    )),
                );
            }
        }
    }

    /// Kills the interpreter for `why`, and answers what its end leaves.
    fn violation(&mut self, why: String) {
        let end = self.end_interpreter();
        self.after_end(end, Some(format!("kata killed it: {why}")));
    }

    /// What an interpreter's `end` leaves: the running cell fails with the
    /// report of it; a cell waiting on a fresh interpreter fails as one that
    /// could not start; a cell waiting while the last cell's worker ended gets
    /// a new interpreter; an idle end leaves the next cell to start one. A
    /// cell that fails carries what the interpreter wrote to its standard
    /// error.
    fn after_end(&mut self, end: End, why: Option<String>) {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Idle
            | Phase::AwaitingReady {
                fresh: false,
                pending: None,
                ..
            } => {}
            Phase::Running(cell) => {
                if end.overflowed_the_cell_thread() {
                    self.events.send(RuntimeEvent::Notify {
                        cell_id: cell.id,
                        text: native_stack_report(self.config.limits.thread_stack_bytes),
                    });
                }
                let report = ended(end.status);
                let message = match why {
                    Some(why) => format!("{report} ({why})"),
                    None => report.clone(),
                };
                self.report(cell.id, report, end.stderr.appended_to(message));
            }
            Phase::AwaitingReady {
                fresh: true,
                pending,
                ..
            } => {
                if let Some(start) = pending {
                    let why = why.unwrap_or_else(|| ended_before_ready(end.status));
                    self.fail(
                        start.execution_id,
                        &end.stderr.appended_to(format!(
                            "Code Mode's interpreter process could not start: {why}"
                        )),
                    );
                }
            }
            Phase::AwaitingReady {
                fresh: false,
                pending: Some(start),
                ..
            } => self.spawn_for(start),
        }
    }

    /// Kills and reaps the interpreter, if there is one: its exit status and
    /// what its standard error's drain kept. Shutting the socket down ends its
    /// reader and writer threads even while another process (one the
    /// interpreter started) holds its other end; shutting its standard error
    /// down once it is reaped ends the drain as soon as the drain has read what
    /// the interpreter wrote before it ended, and no process can write more.
    fn end_interpreter(&mut self) -> End {
        let Some(Interpreter {
            mut child,
            socket,
            stderr,
            drain,
            ..
        }) = self.interpreter.take()
        else {
            return End::default();
        };
        // A no-op on one that already ended, whose status the wait reads.
        let _ = child.kill();
        let _ = socket.shutdown(Shutdown::Both);
        drop(socket);
        let status = child.wait().ok();
        let _ = stderr.shutdown(Shutdown::Both);
        End {
            status,
            stderr: drain.join().unwrap_or_default(),
        }
    }

    /// Ends cell `id` with `report` as a notification, then an `Error` of
    /// `message`.
    fn report(&self, id: u64, report: String, message: String) {
        self.events.send(RuntimeEvent::Notify {
            cell_id: id,
            text: report,
        });
        self.fail(id, &message);
    }

    fn fail(&self, id: u64, message: &str) {
        self.events.send(RuntimeEvent::Error {
            cell_id: id,
            message: message.to_owned(),
            stored: std::collections::HashMap::new(),
        });
    }
}

/// An interpreter's end: its exit status, `None` when it could not be read
/// (or there was no interpreter), and what it wrote to its standard error.
#[derive(Default)]
struct End {
    status: Option<ExitStatus>,
    stderr: Stderr,
}

impl End {
    /// Whether the interpreter ended on its cell thread's stack: by SIGABRT,
    /// with Rust's stack-overflow handler's line for that thread
    /// ([`crate::interpreter::CELL_THREAD`]) in what its standard error kept.
    /// The guard page below that thread's `thread_stack_bytes` stops the
    /// recursion; the handler names the thread and aborts. The line is the
    /// interpreter's own text, so an interpreter that writes it and aborts
    /// reads the same: a compromised one can report a stack hit that did not
    /// happen, as it can any report.
    fn overflowed_the_cell_thread(&self) -> bool {
        let aborted = self
            .status
            .and_then(|status| status.signal())
            .is_some_and(|signal| signal == libc::SIGABRT);
        let named = format!("thread '{}' ", crate::interpreter::CELL_THREAD);
        aborted
            && self
                .stderr
                .lines()
                .iter()
                .any(|line| line.starts_with(&named) && line.ends_with(" has overflowed its stack"))
    }
}

/// The report of a cell whose native recursion overflowed its interpreter's
/// cell thread, a stack of `bytes`: sent before the report of the
/// interpreter's end, which that overflow is.
#[must_use]
pub fn native_stack_report(bytes: usize) -> String {
    format!("Code Mode cell exceeded its {bytes}-byte native stack limit")
}

/// What a drain kept of an interpreter's standard error: the last
/// [`STDERR_CAP`] bytes, and how many it dropped before them.
#[derive(Default)]
struct Stderr {
    kept: VecDeque<u8>,
    dropped: u64,
}

impl Stderr {
    fn take(&mut self, bytes: &[u8]) {
        self.kept.extend(bytes);
        let excess = self.kept.len().saturating_sub(STDERR_CAP);
        if excess > 0 {
            self.kept.drain(..excess);
            self.dropped = self
                .dropped
                .saturating_add(u64::try_from(excess).unwrap_or(u64::MAX));
        }
    }

    /// The lines of what was kept.
    fn lines(&self) -> Vec<String> {
        let kept: Vec<u8> = self.kept.iter().copied().collect();
        String::from_utf8_lossy(&kept)
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// `message`, followed by what was kept, when anything was, labelled as
    /// what the interpreter wrote since it started: one interpreter runs a
    /// host's cells one after another, so the kept bytes may be an earlier
    /// cell's.
    fn appended_to(&self, message: String) -> String {
        if self.kept.is_empty() {
            return message;
        }
        let kept: Vec<u8> = self.kept.iter().copied().collect();
        let text = String::from_utf8_lossy(&kept);
        let text = text.trim_end();
        if self.dropped == 0 {
            format!("{message}; its standard error since it started: {text}")
        } else {
            format!(
                "{message}; its standard error since it started, its last {} bytes ({} before \
                 them dropped): {text}",
                self.kept.len(),
                self.dropped
            )
        }
    }
}

/// Reads an interpreter's standard error to its end, keeping its last
/// [`STDERR_CAP`] bytes ([`Stderr`]); never blocks the interpreter on a full
/// socket, as it reads whatever comes.
fn drain_stderr(mut stderr: UnixStream) -> Stderr {
    let mut kept = Stderr::default();
    let mut buffer = [0_u8; 8192];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => return kept,
            Ok(read) => kept.take(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return kept,
        }
    }
}

/// The report of an interpreter that ended by `status`.
fn ended(status: Option<ExitStatus>) -> String {
    match status {
        Some(status) => match (status.signal(), status.code()) {
            (Some(signal), _) => format!("{ENDED_BY}{}", signal_name(signal)),
            (None, Some(code)) => format!("{EXITED_WITH}{code}"),
            (None, None) => format!("{ENDED_BY}an unknown cause"),
        },
        None => format!("{ENDED_BY}an unknown cause"),
    }
}

/// The report of an interpreter that ended by `status` before it answered
/// `Ready`. An exit with status 0 there is a program with no interpreter entry
/// (libtest selecting no test, or a `main` that never dispatched), which the
/// report names.
fn ended_before_ready(status: Option<ExitStatus>) -> String {
    let report = ended(status);
    if status.and_then(|status| status.code()) == Some(0) {
        format!(
            "{report} before it answered Ready, as a program with no interpreter entry does (a \
             binary calls kata_code_mode_host::run_if_interpreter first thing in main; a test \
             binary invokes kata_code_mode_host::interpreter_entry!)"
        )
    } else {
        report
    }
}

/// What a content item carries, in bytes: every string in it but its `type`
/// tag (a text, an image's URL or file id and its detail, an audio URL,
/// encrypted content). That is all the item admits, and no more than the
/// engine charges an honest one (its JSON, or a text run's bytes and
/// separators), so the cap never ends a cell the engine let through.
pub(crate) fn content_payload_bytes(content: &Value) -> usize {
    fn strings(value: &Value) -> usize {
        match value {
            Value::String(text) => text.len(),
            Value::Array(items) => items.iter().map(strings).fold(0, usize::saturating_add),
            Value::Object(fields) => fields.values().map(strings).fold(0, usize::saturating_add),
            Value::Null | Value::Bool(_) | Value::Number(_) => 0,
        }
    }
    match content {
        Value::Object(fields) => fields
            .iter()
            .filter(|(key, _)| key.as_str() != "type")
            .map(|(_, value)| strings(value))
            .fold(0, usize::saturating_add),
        other => strings(other),
    }
}

/// Reads interpreter `generation`'s frames into the supervisor's inbox until
/// its socket ends or a frame is refused. A socket that ends, cleanly, inside
/// a frame or by an error, is the interpreter's end, which its exit status
/// names; a frame over the cap or one that is not a frame is a refusal.
fn read_interpreter(generation: u64, mut socket: UnixStream, inbox: &std_mpsc::SyncSender<Input>) {
    loop {
        let said = match wire::read::<FromInterpreter>(&mut socket) {
            Ok(Some(frame)) => Said::Frame(frame),
            Ok(None) | Err(wire::FrameError::Truncated | wire::FrameError::Io(_)) => {
                Said::Ended(None)
            }
            Err(error @ (wire::FrameError::Oversize(_) | wire::FrameError::Malformed(_))) => {
                Said::Ended(Some(format!("kata killed it: it sent {error}")))
            }
        };
        let ended = matches!(said, Said::Ended(_));
        if inbox.send(Input::Interpreter { generation, said }).is_err() || ended {
            return;
        }
    }
}

/// Writes interpreter `generation`'s queued frames, in order, until the
/// supervisor drops the queue or a write fails, which it reports as the
/// interpreter's end (the supervisor ignores it once that interpreter is
/// gone). Its writes block only this thread.
fn write_interpreter(
    generation: u64,
    mut socket: UnixStream,
    queued: &std_mpsc::Receiver<Outgoing>,
    unwritten_answers: &AtomicUsize,
    inbox: &std_mpsc::SyncSender<Input>,
) {
    for frame in queued {
        if wire::write(&mut socket, &frame.bytes).is_err() {
            let _ = inbox.send(Input::Interpreter {
                generation,
                said: Said::Ended(None),
            });
            return;
        }
        if frame.answer {
            unwritten_answers.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// The name of Linux signal `signal`, or its number.
#[must_use]
pub fn signal_name(signal: i32) -> String {
    let name = match signal {
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGILL => "SIGILL",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGKILL => "SIGKILL",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGALRM => "SIGALRM",
        libc::SIGTERM => "SIGTERM",
        libc::SIGXCPU => "SIGXCPU",
        libc::SIGXFSZ => "SIGXFSZ",
        libc::SIGSYS => "SIGSYS",
        _ => return format!("signal {signal}"),
    };
    name.to_owned()
}
