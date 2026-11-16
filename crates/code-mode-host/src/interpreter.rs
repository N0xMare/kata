//! The interpreter process: a fresh image of the hosting process's own
//! executable (re-executed with [`crate::INTERPRETER_ARGS`]), which confines
//! itself and then runs the engine's own host (`EmbeddedHost`, no backend
//! installed here) on the cells its parent sends, one host per cell.
//!
//! # Confinement, in the order it is applied
//!
//! 1. Every descriptor above 2 is closed, so the interpreter holds its socket
//!    (0), `/dev/null` (1) and its standard error (2), a socket its parent
//!    drains, and nothing it inherited by accident. Its environment holds only
//!    an empty `TZ`, which its parent sets (`supervisor`).
//! 2. Parent-death signal SIGKILL, then, once the first frame names its parent,
//!    a check that the process that started it is still its parent (a parent
//!    that died before the signal was armed would otherwise go unnoticed).
//! 3. `oom_score_adj` 1000: under memory pressure the kernel's OOM killer picks
//!    an interpreter before the process that hosts the worker.
//! 4. `RLIMIT_AS` at [`address_space_limit`]: whatever escapes djs's own heap
//!    accounting fails an allocation here, which ends only this process.
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
//! # The limits this process enforces
//!
//! The engine runs a cell's JavaScript inside its host's `read_event`, one
//! slice of djs fuel at a time, on a thread of `thread_stack_bytes`; this
//! process's loop waits on that, on its parent's frames and on the cell's wall
//! at once (`run`).
//!
//! * The heap: `set_cell_memory(memory_bytes)`, before any cell. djs ends a
//!   cell whose heap would pass it, uncatchably, and the engine reports the
//!   limit (kata's patch) before the cell's `Error`.
//! * The wall: once `cell_wall` has passed since the cell's `Start`, the loop
//!   ends the cell, between two slices, with its report and an `Error` of it.
//!   A step that does not return (one long native operation) is ended by the
//!   supervisor, which kills this process `WALL_GRACE` later.
//! * The output: each event is charged as the supervisor charges it
//!   ([`wire::Event::charge`]); the event that would take the cell past
//!   `cell_emitted_bytes` is not sent, and the cell ends with the report of
//!   the limit and an `Error` of it.
//! * The stack: djs keeps a script's call stack in its heap and throws a
//!   catchable `RangeError` past its own slot limit; a cell that fails on one
//!   gets the stack report before its `Error`.
//!
//! After each terminal event this process ends that cell's host and starts
//! the next one before it answers `Ready`, so no timer, job or value of one
//! cell reaches the next.
//!
//! # Stored values, as the cell loads them
//!
//! A cell's `Start` carries none of its stored values: the engine's
//! stored-value loader (`set_stored_loader`) asks the parent for each key the
//! cell loads (`Load`) and waits, inside the cell's step, for the answer the
//! frame reader hands it (`Loaded`). One cell runs at a time on one thread, so
//! at most one `Load` is ever unanswered. A cell's stored values do not change
//! while it runs, so the loader keeps its answers ([`Answers`]) and a key the
//! cell loads again costs no round trip; the loop empties them at each
//! `Start`.
//!
//! # An event that does not fit a frame
//!
//! An event longer than [`wire::FRAME_CAP`] (stored values or a tool-call
//! input the cell made that large) is not sent: the cell's `Error` naming it
//! is, in its place, and the cell's host ends as after any terminal event.

use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, mpsc as std_mpsc};
use std::time::{Duration, Instant, SystemTime};

use nanocode_code_mode_engine::{
    CellTools, EmbeddedHost, Interrupt, RuntimeEvent, platform, set_cell_memory, set_stored_loader,
};
use serde_json::value::RawValue;
use tokio::sync::mpsc;

use crate::CodeModeLimits;
use crate::wire::{self, Event, FromInterpreter, ToInterpreter};

/// Exit: the parent closed the socket.
pub const EXIT_PARENT_CLOSED: i32 = 0;
/// Exit: confinement or the engine failed before or between cells.
pub const EXIT_REFUSED: i32 = 1;
/// Exit: the socket broke, or the parent sent what it never sends.
pub const EXIT_BROKEN: i32 = 2;
/// Exit: an event the engine sent does not encode.
pub const EXIT_UNENCODABLE: i32 = 3;
/// Exit: the thread that runs the cells panicked (its message went to the
/// standard error the supervisor drains).
pub const EXIT_PANICKED: i32 = 101;

/// What `RLIMIT_AS` allows beside `memory_bytes` and the cell thread's stack:
/// the executable and its libraries mapped, the allocator's arenas, the other
/// threads' stacks, a moment's second copy of the djs arena as it grows (the
/// allocator moves a growing block), and what the engine allocates outside
/// djs's accounting (frames, stored values, events in flight). MEASURED (debug
/// test binary, djs at `8ec3b215`, a cell filling its whole 256 MiB heap with
/// typed arrays, objects or strings until the heap cap ends it): `VmPeak` 474
/// to 486 MiB, `VmHWM` 270 to 279 MiB, so about 220 MiB past `memory_bytes`
/// and the thread stack; this is over four times that.
pub const ADDRESS_SPACE_OVERHEAD: u64 = 1 << 30;

/// The address space an interpreter process under `limits` may map.
#[must_use]
pub fn address_space_limit(limits: &CodeModeLimits) -> u64 {
    let bytes = |count: usize| u64::try_from(count).unwrap_or(u64::MAX);
    bytes(limits.memory_bytes)
        .saturating_add(bytes(limits.thread_stack_bytes))
        .saturating_add(ADDRESS_SPACE_OVERHEAD)
}

/// The report of a cell that failed on djs's call-stack limit; djs's slot
/// limit is its own (`ExecOptions::max_stack`), so the report names no size.
pub(crate) const STACK_REPORT: &str = "Code Mode cell exceeded its interpreter stack limit";

/// What djs throws past its call-stack limit, as the engine's bootstrap labels
/// an uncaught error: the end of the first line of the cell's `Error`.
const STACK_OVERFLOW: &str = "RangeError: Maximum call stack size exceeded";

/// The socket to the parent, descriptor 0, read and written in place: no
/// duplicate descriptor is made. Writes are whole frames under [`WRITING`].
struct Socket;

/// Held for each frame's write: the loop and the stored-value loader both
/// write frames.
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

/// The engine's platform in this process: the clocks, a timer on the cell
/// thread's runtime, and the kernel's randomness. Installed so that no timer
/// starts nanocode's own reactor (epoll, an eventfd and a thread of its own,
/// which the syscall filter refuses).
struct CellPlatform;

impl platform::Host for CellPlatform {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn system_time(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> platform::HostFuture {
        Box::pin(tokio::time::sleep(duration))
    }

    fn fill_random(&self, mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let filled =
                rustix::rand::getrandom(&mut *bytes, rustix::rand::GetRandomFlags::empty())?;
            bytes = &mut bytes[filled..];
        }
        Ok(())
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>) {
        drop(tokio::spawn(future));
    }
}

static CELL_PLATFORM: CellPlatform = CellPlatform;

/// Runs this process as an interpreter until its parent closes the socket,
/// and returns its exit code.
pub fn serve() -> i32 {
    let limits = match confined() {
        Ok(limits) => limits,
        Err(code) => return code,
    };
    // Without it the engine's zone reader stats `/etc/localtime` at a cell's
    // start, which the syscall filter answers with SIGSYS.
    if std::env::var_os("TZ").is_none_or(|zone| !zone.is_empty()) {
        return refuse_with(
            "Code Mode's interpreter process holds no empty TZ (UTC) to run a cell under",
        );
    }
    set_cell_memory(limits.memory_bytes);
    if platform::install(&CELL_PLATFORM).is_err() {
        return refuse("this process already had a platform host");
    }
    let (answer, answers) = std_mpsc::channel();
    let kept = Arc::new(Mutex::new(Answers::default()));
    if set_stored_loader(Box::new(loader(answers, Arc::clone(&kept)))).is_err() {
        return refuse("this process already had a stored-value loader");
    }
    let cells = std::thread::Builder::new()
        .name("code-mode-cell".to_owned())
        .stack_size(limits.thread_stack_bytes)
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => return refuse(&format!("its runtime could not be built ({error})")),
            };
            runtime.block_on(run(answer, &kept, limits))
        });
    match cells {
        Ok(cells) => cells.join().unwrap_or(EXIT_PANICKED),
        Err(error) => refuse(&format!("its cell thread could not start ({error})")),
    }
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
pub(crate) fn confined() -> Result<CodeModeLimits, i32> {
    let limits = hardened()?;
    crate::syscall_filter::install().map_err(|why| refuse(&why))?;
    Ok(limits)
}

/// Steps 1 to 5 of the module's confinement, around reading the parent's
/// `Init`: what a probe that reads `/proc` about itself (which step 6 forbids)
/// can observe of it.
pub(crate) fn hardened() -> Result<CodeModeLimits, i32> {
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
            CodeModeLimits::from(limits)
        }
        Ok(None) => return Err(EXIT_PARENT_CLOSED),
        Ok(Some(_)) | Err(_) => return Err(EXIT_BROKEN),
    };
    confine(&limits).map_err(|why| refuse(&why))?;
    Ok(limits)
}

/// Steps 3 to 5 of the module's confinement. Not dumpable comes last: it makes
/// this process's `/proc/self` files root's, `oom_score_adj` among them.
fn confine(limits: &CodeModeLimits) -> Result<(), String> {
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
    Wall,
}

/// The cell the host runs: its id, when its wall passes, and what it emitted
/// so far as [`wire::Event::charge`] counts it.
struct Running {
    id: u64,
    until: tokio::time::Instant,
    charged: usize,
}

/// What the loop does after an event.
enum After {
    /// The cell goes on.
    Next,
    /// The cell ended: end its host and start the next one.
    Ended,
}

async fn run(
    answer: std_mpsc::Sender<Option<Arc<RawValue>>>,
    kept: &Mutex<Answers>,
    limits: CodeModeLimits,
) -> i32 {
    let mut frames = read_parent(answer);
    let mut host = match start_host() {
        Ok(host) => host,
        Err(code) => return code,
    };
    let mut cell: Option<Running> = None;
    loop {
        let until = cell.as_ref().map(|cell| cell.until);
        // The waits borrow `host` and `frames`; each is dropped before the
        // arm below runs.
        let next = tokio::select! {
            frame = frames.recv() => Next::Parent(frame),
            event = host.read_event() => Next::Engine(event),
            () = wall(until) => Next::Wall,
        };
        let after = match next {
            Next::Parent(None) => return EXIT_PARENT_CLOSED,
            Next::Parent(Some(Err(()) | Ok(ToInterpreter::Init { .. }))) => return EXIT_BROKEN,
            Next::Parent(Some(Ok(ToInterpreter::Start {
                execution_id,
                source,
                tools,
                prelude,
            }))) => {
                // The cell before ended (its host with it): no load is waiting.
                *kept.lock().unwrap_or_else(PoisonError::into_inner) = Answers::default();
                cell = Some(Running {
                    id: execution_id,
                    until: tokio::time::Instant::now() + limits.cell_wall,
                    charged: 0,
                });
                let [definitions, descriptions, schemas] = tools;
                let started = host.start_cell(
                    execution_id,
                    &source,
                    HashMap::new(),
                    Arc::new(CellTools::from_encoded(definitions, descriptions, schemas)),
                    prelude.map(Into::into),
                    None,
                    Interrupt::new(),
                );
                match started {
                    Ok(()) => After::Next,
                    Err(message) => end_cell(execution_id, None, &message),
                }
            }
            Next::Parent(Some(Ok(command))) => {
                command_host(&mut host, command);
                After::Next
            }
            Next::Wall => match cell.as_ref() {
                Some(running) => {
                    let report = format!(
                        "Code Mode cell exceeded its {} ms wall-time limit",
                        limits.cell_wall.as_millis()
                    );
                    end_cell(running.id, Some(&report), &report)
                }
                None => After::Next,
            },
            Next::Engine(Err(message)) => match cell.as_ref() {
                Some(running) => end_cell(running.id, None, &message),
                None => return refuse_with(&message),
            },
            Next::Engine(Ok(event)) => match forward(event, cell.as_mut(), &limits) {
                Ok(after) => after,
                Err(code) => return code,
            },
        };
        if matches!(after, After::Ended) {
            cell = None;
            host.terminate().await;
            drop(host);
            host = match start_host() {
                Ok(host) => host,
                Err(code) => return code,
            };
        }
    }
}

/// Resolves once the running cell's wall has passed; never without a cell.
async fn wall(until: Option<tokio::time::Instant>) {
    match until {
        Some(until) => tokio::time::sleep_until(until).await,
        None => std::future::pending().await,
    }
}

/// Sends one of the running cell's events to the parent, charged against its
/// output limit, with the stack report before a stack failure.
fn forward(
    event: RuntimeEvent,
    running: Option<&mut Running>,
    limits: &CodeModeLimits,
) -> Result<After, i32> {
    let cell_id = event.cell_id();
    let mut terminal = matches!(
        event,
        RuntimeEvent::Done { .. } | RuntimeEvent::Error { .. } | RuntimeEvent::Diverged { .. }
    );
    let stack_hit = matches!(
        &event,
        RuntimeEvent::Error { message, .. }
            if message.lines().next().is_some_and(|line| line.ends_with(STACK_OVERFLOW))
    );
    let Ok(event) = Event::encode(event) else {
        return Err(EXIT_UNENCODABLE);
    };
    if let Some(running) = running {
        running.charged = running.charged.saturating_add(event.charge());
        if running.charged > limits.cell_emitted_bytes {
            let report = format!(
                "Code Mode cell output exceeded its {}-byte limit",
                limits.cell_emitted_bytes
            );
            return Ok(end_cell(cell_id, Some(&report), &report));
        }
    }
    if stack_hit {
        notify(cell_id, STACK_REPORT).map_err(|_| EXIT_BROKEN)?;
    }
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
        wire::encode(&failure).ok_or(EXIT_UNENCODABLE)?
    };
    write(&bytes).map_err(|_| EXIT_BROKEN)?;
    Ok(if terminal { After::Ended } else { After::Next })
}

/// Ends cell `cell_id` this process's way: `report` as a notification of its
/// own, when there is one, then an `Error` of `message`, keeping none of the
/// cell's writes.
fn end_cell(cell_id: u64, report: Option<&str>, message: &str) -> After {
    if let Some(report) = report {
        let _ = notify(cell_id, report);
    }
    let _ = send(&FromInterpreter::Event(Event::Error {
        cell_id,
        message: message.to_owned(),
        stored: HashMap::new(),
    }));
    After::Ended
}

fn notify(cell_id: u64, text: &str) -> io::Result<()> {
    send(&FromInterpreter::Event(Event::Notify {
        cell_id,
        text: text.to_owned(),
    }))
}

/// Starts a host and answers `Ready`, or answers `Refused` and returns the
/// exit code.
fn start_host() -> Result<EmbeddedHost, i32> {
    let host = EmbeddedHost::spawn().map_err(|message| refuse_with(&message))?;
    send(&FromInterpreter::Ready).map_err(|_| EXIT_BROKEN)?;
    Ok(host)
}

fn command_host(host: &mut EmbeddedHost, command: ToInterpreter) {
    // The engine answers a command for no running cell by ignoring it.
    let _ = match command {
        ToInterpreter::ToolResult {
            execution_id,
            id,
            encoded,
            success,
        } => host.send_tool_result(execution_id, id, encoded, success),
        ToInterpreter::Hold { execution_id } => host.hold(execution_id),
        ToInterpreter::Release { execution_id } => host.release(execution_id),
        // `run` takes `Init` and `Start`; `read_parent` hands a `Loaded` to
        // the loader, never to the loop.
        ToInterpreter::Init { .. } | ToInterpreter::Start { .. } | ToInterpreter::Loaded { .. } => {
            Ok(())
        }
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
