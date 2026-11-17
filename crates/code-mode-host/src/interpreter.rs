//! The interpreter process: a fresh image of the hosting process's own
//! executable (re-executed with [`crate::INTERPRETER_ARGS`]), which confines
//! itself and then runs the engine's worker thread on the cells its parent
//! sends, one engine worker per cell.
//!
//! # Confinement, in the order it is applied
//!
//! 1. Every descriptor above 2 is closed, so the interpreter holds its socket
//!    (0), `/dev/null` (1) and its standard error (2), a socket its parent
//!    drains, and nothing it inherited by accident. Its environment is empty:
//!    the parent cleared it.
//! 2. Parent-death signal SIGKILL, then, once the first frame names its parent,
//!    a check that the process that started it is still its parent (a parent
//!    that died before the signal was armed would otherwise go unnoticed).
//! 3. `oom_score_adj` 1000: under memory pressure the kernel's OOM killer picks
//!    an interpreter before the process that hosts the worker.
//! 4. `RLIMIT_AS` at [`address_space_limit`]: whatever escapes QuickJS's own
//!    heap accounting fails an allocation here, which ends only this process.
//! 5. No core dump: `RLIMIT_CORE` 0 and not dumpable. The limit stops only a
//!    dump to a file; the kernel checks dumpability before any dump, so only
//!    not dumpable also stops a dump that `core_pattern` pipes to a helper such
//!    as apport (measured: a dumpable process aborting at limit 0 is held about
//!    a second while apport reads it). Not dumpable also keeps another process
//!    of the same user from reading its memory or descriptors through `/proc`.
//! 6. Its syscall filter (`syscall_filter`), on every thread: from here on a
//!    syscall outside the interpreter's measured set ends it by SIGSYS.
//!
//! A step that fails ends the process before it answers `Ready`, so its parent
//! fails the cell that needed it, by name; nothing runs a cell unconfined. The
//! filter comes last because steps 3 and 4 make calls it refuses (an `openat`
//! for writing, `prlimit64`), and step 4 needs the limits in its parent's
//! `Init`; `Init` carries no cell, and every frame that does is read under the
//! filter.
//!
//! # One engine worker per cell
//!
//! The engine drops a cell's QuickJS runtime only after the cell's terminal
//! event is sent, and QuickJS can abort the process in that drop
//! (`Array.fromAsync`'s out-of-memory leak trips `JS_FreeRuntime`'s assertion).
//! The engine's worker makes that drop on its own thread while this process's
//! main loop is still writing the event to the parent, so the worker waits
//! first, in the engine's cell-ended hook (`set_cell_ended`), until the main
//! loop has written that cell's terminal frame ([`Written`]): an abort in the
//! drop never takes the cell's terminal event with it. After each terminal
//! event this process ends that cell's engine worker, waiting for its thread to
//! finish, and only then starts the next worker and answers `Ready`: a death in
//! a cell's teardown happens before the parent sends the next cell, and is
//! never charged to it, nor to the cell it ends.
//!
//! # Stored values, as the cell loads them
//!
//! A cell's `Start` carries none of its stored values: the engine's
//! stored-value loader (`set_stored_loader`) asks the parent for each key the
//! cell loads (`Load`) and waits, on the engine's thread, for the answer the
//! frame reader hands it (`Loaded`). The engine runs one cell at a time on one
//! thread, so at most one `Load` is ever unanswered. A cell's stored values do
//! not change while it runs, so the loader keeps its answers ([`Answers`]) and
//! a key the cell loads again costs no round trip; the main loop empties them
//! at each `Start`.
//!
//! # An event that does not fit a frame
//!
//! An event longer than [`wire::FRAME_CAP`] (stored values or a tool-call
//! input the cell made that large) is not sent: the cell's `Error` naming it
//! is, in its place, and the cell's engine worker ends as after any terminal
//! event.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc as std_mpsc};

use nanocode_code_mode_engine::{
    EmbeddedHost, NativeLimits, RuntimeEvent, set_cell_ended, set_native_limits, set_stored_loader,
};
use serde_json::value::RawValue;
use tokio::sync::mpsc;

use crate::wire::{self, Event, FromInterpreter, ToInterpreter};

/// Exit: the parent closed the socket.
pub const EXIT_PARENT_CLOSED: i32 = 0;
/// Exit: confinement or the engine failed before or between cells.
pub const EXIT_REFUSED: i32 = 1;
/// Exit: the socket broke, or the parent sent what it never sends.
pub const EXIT_BROKEN: i32 = 2;
/// Exit: an event the engine sent does not encode.
pub const EXIT_UNENCODABLE: i32 = 3;

/// What `RLIMIT_AS` allows beside `memory_bytes` and the engine worker's
/// thread stack: the executable and its libraries mapped, the allocator's
/// per-thread arenas, the other threads' stacks, and what the engine allocates
/// outside QuickJS's accounting (frames, stored values, events in flight).
/// MEASURED (debug test binary, a cell holding its whole 256 MiB heap in typed
/// arrays, objects or strings): `VmPeak` 467 to 492 MiB, so about 240 MiB
/// past `memory_bytes` and the thread stack; this is four times that.
pub const ADDRESS_SPACE_OVERHEAD: u64 = 1 << 30;

/// The address space an interpreter process under `limits` may map.
#[must_use]
pub fn address_space_limit(limits: &NativeLimits) -> u64 {
    let bytes = |count: usize| u64::try_from(count).unwrap_or(u64::MAX);
    bytes(limits.memory_bytes)
        .saturating_add(bytes(limits.thread_stack_bytes))
        .saturating_add(ADDRESS_SPACE_OVERHEAD)
}

/// The socket to the parent, descriptor 0, read and written in place: no
/// duplicate descriptor is made. Writes are whole frames under [`WRITING`].
struct Socket;

/// Held for each frame's write: the main loop and the engine's thread (its
/// stored-value loader) both write frames.
static WRITING: Mutex<()> = Mutex::new(());

/// The running cell's answers the loader keeps, keys and values up to
/// [`ANSWERS_BYTES`] in all; a later answer past that is not kept.
#[derive(Default)]
struct Answers {
    by_key: HashMap<String, Option<Arc<RawValue>>>,
    bytes: usize,
}

/// What [`Answers`] keeps, so the cache costs a cell at most this much beside
/// its heap.
const ANSWERS_BYTES: usize = 16 << 20;

/// The last cell whose terminal frame the main loop wrote, and the engine's
/// cell-ended hook waiting for it: the engine's worker drops a cell's runtime
/// only once that cell's terminal frame is on the socket.
struct Written {
    cell: Mutex<Option<u64>>,
    changed: Condvar,
}

static WRITTEN: Written = Written {
    cell: Mutex::new(None),
    changed: Condvar::new(),
};

impl Written {
    /// The main loop wrote cell `cell_id`'s terminal frame.
    fn wrote(&self, cell_id: u64) {
        *self.cell.lock().unwrap_or_else(PoisonError::into_inner) = Some(cell_id);
        self.changed.notify_all();
    }

    /// The engine's cell-ended hook: waits until cell `cell_id`'s terminal
    /// frame is written. A main loop that cannot write it ends this process.
    fn wait_for(&self, cell_id: u64) {
        let mut cell = self.cell.lock().unwrap_or_else(PoisonError::into_inner);
        while *cell != Some(cell_id) {
            cell = self
                .changed
                .wait(cell)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(rustix::io::read(io::stdin(), buf)?)
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(rustix::io::write(io::stdin(), buf)?)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Runs this process as an interpreter until its parent closes the socket,
/// and returns its exit code.
pub fn serve() -> i32 {
    let limits = match confined() {
        Ok(limits) => limits,
        Err(code) => return code,
    };
    if let Err(installed) = set_native_limits(limits) {
        return refuse(&format!(
            "this process already ran Code Mode under {installed:?}"
        ));
    }
    let (answer, answers) = std_mpsc::channel();
    let kept = Arc::new(Mutex::new(Answers::default()));
    if set_stored_loader(Box::new(loader(answers, Arc::clone(&kept)))).is_err() {
        return refuse("this process already had a stored-value loader");
    }
    if set_cell_ended(Box::new(|cell_id| WRITTEN.wait_for(cell_id))).is_err() {
        return refuse("this process already had a cell-ended hook");
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(runtime) => runtime,
        Err(error) => return refuse(&format!("its runtime could not be built ({error})")),
    };
    runtime.block_on(run(answer, &kept))
}

/// The engine's stored-value loader: the answer kept for `key`, or the
/// parent's, asked for and waited on as [`read_parent`] hands it over, and
/// kept while [`Answers`] has room. A socket that broke answers `None`, kept
/// nowhere; this process is then ending.
fn loader(
    answers: std_mpsc::Receiver<Option<Arc<RawValue>>>,
    kept: Arc<Mutex<Answers>>,
) -> impl Fn(&str) -> Option<Arc<RawValue>> + Send + Sync {
    let answers = Mutex::new(answers);
    move |key| {
        if let Some(value) = kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_key
            .get(key)
        {
            return value.clone();
        }
        let answers = answers.lock().unwrap_or_else(PoisonError::into_inner);
        send(&FromInterpreter::Load {
            key: key.to_owned(),
        })
        .ok()?;
        let value = answers.recv().ok()?;
        let mut kept = kept.lock().unwrap_or_else(PoisonError::into_inner);
        let bytes = key
            .len()
            .saturating_add(value.as_ref().map_or(0, |value| value.get().len()));
        if kept.bytes.saturating_add(bytes) <= ANSWERS_BYTES {
            kept.bytes += bytes;
            kept.by_key.insert(key.to_owned(), value.clone());
        }
        value
    }
}

/// The module's confinement, steps 1 to 6: the limits the cells run under, or
/// the exit code of a process that cannot run one.
pub(crate) fn confined() -> Result<NativeLimits, i32> {
    let limits = hardened()?;
    crate::syscall_filter::install().map_err(|why| refuse(&why))?;
    Ok(limits)
}

/// Steps 1 to 5 of the module's confinement, around reading the parent's
/// `Init`: what a probe that reads `/proc` about itself (which step 6 forbids)
/// can observe of it.
pub(crate) fn hardened() -> Result<NativeLimits, i32> {
    close_inherited_descriptors().map_err(|why| refuse(&why))?;
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(|error| refuse(&format!("PR_SET_PDEATHSIG failed ({error})")))?;
    let limits = match wire::read::<ToInterpreter>(&mut Socket) {
        Ok(Some(ToInterpreter::Init { limits, parent })) => {
            let current = rustix::process::getppid().map(|pid| pid.as_raw_nonzero().get());
            if current != Some(parent) {
                // The parent died before the death signal was armed.
                return Err(EXIT_PARENT_CLOSED);
            }
            NativeLimits::from(limits)
        }
        Ok(None) => return Err(EXIT_PARENT_CLOSED),
        Ok(Some(_)) | Err(_) => return Err(EXIT_BROKEN),
    };
    confine(&limits).map_err(|why| refuse(&why))?;
    Ok(limits)
}

/// Steps 3 to 5 of the module's confinement. Not dumpable comes last: it makes
/// this process's `/proc/self` files root's, `oom_score_adj` among them.
fn confine(limits: &NativeLimits) -> Result<(), String> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    std::fs::write("/proc/self/oom_score_adj", "1000")
        .map_err(|error| format!("oom_score_adj 1000 failed ({error})"))?;
    let address_space = address_space_limit(limits);
    setrlimit(
        Resource::As,
        Rlimit {
            current: Some(address_space),
            maximum: Some(address_space),
        },
    )
    .map_err(|error| format!("RLIMIT_AS {address_space} failed ({error})"))?;
    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    setrlimit(Resource::Core, none).map_err(|error| format!("RLIMIT_CORE 0 failed ({error})"))?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|error| format!("PR_SET_DUMPABLE 0 failed ({error})"))?;
    Ok(())
}

/// The frames the parent sends, read on a thread of their own so the loop can
/// wait on them and on the engine at once; the channel closes when the socket
/// does, or on a frame that cannot be read. A `Loaded` answer goes to the
/// stored-value loader waiting for it (`answer`), not to the loop.
fn read_parent(
    answer: std_mpsc::Sender<Option<Arc<RawValue>>>,
) -> mpsc::UnboundedReceiver<Result<ToInterpreter, ()>> {
    let (frames, received) = mpsc::unbounded_channel();
    let spawned = std::thread::Builder::new()
        .name("code-mode-read".to_owned())
        .spawn(move || {
            loop {
                match wire::read::<ToInterpreter>(&mut Socket) {
                    Ok(Some(ToInterpreter::Loaded { value })) => {
                        if answer.send(value).is_err() {
                            return;
                        }
                    }
                    Ok(Some(frame)) => {
                        if frames.send(Ok(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(_) => {
                        let _ = frames.send(Err(()));
                        return;
                    }
                }
            }
        });
    // Without the reader the channel is closed at once, which ends the loop.
    drop(spawned);
    received
}

enum Next {
    Parent(Option<Result<ToInterpreter, ()>>),
    Engine(Result<RuntimeEvent, String>),
}

async fn run(answer: std_mpsc::Sender<Option<Arc<RawValue>>>, kept: &Mutex<Answers>) -> i32 {
    let mut frames = read_parent(answer);
    let mut host = match start_worker() {
        Ok(host) => host,
        Err(code) => return code,
    };
    loop {
        // The two waits borrow `host` and `frames`; each is dropped before the
        // arm below runs.
        let next = tokio::select! {
            frame = frames.recv() => Next::Parent(frame),
            event = host.read_event() => Next::Engine(event),
        };
        match next {
            Next::Parent(None) => return EXIT_PARENT_CLOSED,
            Next::Parent(Some(Err(()) | Ok(ToInterpreter::Init { .. }))) => return EXIT_BROKEN,
            Next::Parent(Some(Ok(command))) => command_worker(&host, command, kept),
            Next::Engine(Err(message)) => return refuse_with(&message),
            Next::Engine(Ok(event)) => {
                let cell_id = event.cell_id();
                let mut terminal = matches!(
                    event,
                    RuntimeEvent::Done { .. }
                        | RuntimeEvent::Error { .. }
                        | RuntimeEvent::Diverged { .. }
                );
                let Ok(event) = Event::encode(event) else {
                    return EXIT_UNENCODABLE;
                };
                let what = TooLong::of(&event);
                let bytes = if let Some(bytes) = wire::encode(&FromInterpreter::Event(event)) {
                    bytes
                } else {
                    terminal = true;
                    let failure = FromInterpreter::Event(Event::Error {
                        cell_id,
                        message: what.failure(),
                        stored: HashMap::new(),
                    });
                    let Some(bytes) = wire::encode(&failure) else {
                        return EXIT_UNENCODABLE;
                    };
                    bytes
                };
                if write(&bytes).is_err() {
                    return EXIT_BROKEN;
                }
                if terminal {
                    WRITTEN.wrote(cell_id);
                    host.terminate().await;
                    drop(host);
                    host = match start_worker() {
                        Ok(host) => host,
                        Err(code) => return code,
                    };
                }
            }
        }
    }
}

/// Starts an engine worker and answers `Ready`, or answers `Refused` and
/// returns the exit code.
fn start_worker() -> Result<EmbeddedHost, i32> {
    let host = EmbeddedHost::spawn().map_err(|message| refuse_with(&message))?;
    send(&FromInterpreter::Ready).map_err(|_| EXIT_BROKEN)?;
    Ok(host)
}

fn command_worker(host: &EmbeddedHost, command: ToInterpreter, kept: &Mutex<Answers>) {
    // A command the worker cannot take means the worker ended; its event
    // channel then closes, which ends this process.
    let _ = match command {
        ToInterpreter::Start {
            execution_id,
            source,
            tools,
            prelude,
        } => {
            // The cell before ended (its worker with it): no load is waiting.
            *kept.lock().unwrap_or_else(PoisonError::into_inner) = Answers::default();
            host.start_cell(
                execution_id,
                &source,
                HashMap::new(),
                tools,
                prelude.map(Into::into),
                None,
            )
        }
        ToInterpreter::ToolResult {
            execution_id,
            id,
            encoded,
            success,
        } => host.send_tool_result(execution_id, id, encoded, success),
        ToInterpreter::Hold { execution_id } => host.hold(execution_id),
        ToInterpreter::Release { execution_id } => host.release(execution_id),
        // `read_parent` hands a `Loaded` to the loader, never to the loop.
        ToInterpreter::Init { .. } | ToInterpreter::Loaded { .. } => Ok(()),
    };
}

/// What of a cell's event made it longer than a frame, and what that costs
/// the cell.
struct TooLong {
    what: &'static str,
    consequence: &'static str,
}

impl TooLong {
    fn of(event: &Event) -> Self {
        let (what, consequence) = match event {
            Event::Done { .. } => ("stored values", "none were kept"),
            Event::Error { .. } => ("error and stored values", "none were kept"),
            Event::ToolCall { .. } => ("tool-call input", "the cell ends"),
            _ => ("output", "the cell ends"),
        };
        Self { what, consequence }
    }

    /// The cell's `Error` sent in the event's place.
    fn failure(&self) -> String {
        format!(
            "Code Mode cell's {} came to more than the {}-byte frame its interpreter process \
             sends; {}",
            self.what,
            wire::FRAME_CAP,
            self.consequence
        )
    }
}

fn send(frame: &FromInterpreter) -> io::Result<()> {
    let bytes = wire::encode(frame).ok_or_else(|| io::Error::other("a frame over the cap"))?;
    write(&bytes)
}

/// Writes one [`wire::encode`]d frame whole, under [`WRITING`].
fn write(bytes: &[u8]) -> io::Result<()> {
    let _writing = WRITING.lock().unwrap_or_else(PoisonError::into_inner);
    wire::write(&mut Socket, bytes)
}

/// Tells the parent why this process cannot run a cell, and returns the exit
/// code it ends with.
pub(crate) fn refuse_with(message: &str) -> i32 {
    let message: String = message.chars().take(4096).collect();
    let _ = send(&FromInterpreter::Refused { message });
    EXIT_REFUSED
}

fn refuse(why: &str) -> i32 {
    refuse_with(&format!(
        "Code Mode's interpreter process could not confine itself: {why}"
    ))
}

/// Closes every descriptor above 2, read off `/proc/self/fd`.
fn close_inherited_descriptors() -> Result<(), String> {
    let listed = std::fs::read_dir("/proc/self/fd")
        .map_err(|error| format!("/proc/self/fd cannot be listed ({error})"))?;
    // Collected first: the listing's own descriptor closes when it drops, so
    // its number answers EBADF below.
    let inherited: Vec<RawFd> = listed
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd > 2)
        .collect();
    for fd in inherited {
        // SAFETY: `close(2)` touches no memory. Nothing in this process owns a
        // descriptor above 2 yet: it was just exec'd, every descriptor above 2
        // is one it inherited, and this runs before it opens any of its own
        // (`bin/kata/src/inherited_descriptors.rs` closes a `kata serve`'s the
        // same way). A test binary running as an interpreter has its harness's
        // threads, which hold none either.
        #[allow(unsafe_code)]
        let closed = unsafe { libc::close(fd) };
        if closed == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(format!(
                "inherited descriptor {fd} could not be closed ({error})"
            ));
        }
    }
    Ok(())
}
