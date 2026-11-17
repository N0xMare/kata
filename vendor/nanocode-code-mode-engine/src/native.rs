use std::{
    collections::HashMap,
    rc::Rc,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc as std_mpsc,
    },
    thread,
    time::Duration,
};

use nanocode_platform::Instant;
use rquickjs::{CatchResultExt, Context, Ctx, Function, Persistent, Runtime};
use serde_json::{Value, value::RawValue};
use tokio::sync::{mpsc, oneshot};

use crate::{
    cell::{
        ExecutionState, Rejections, RuntimeEvent, begin_execution, clear_pending,
        completed_terminal, drain_jobs, install_bootstrap, install_prelude, invoke_timeout,
        new_state, next_due_timeout, next_timeout_wait, prepare_execution, replay_inputs,
        resolve_tool, send_terminal, start_execution, track_rejections,
    },
    journal::CellJournaling,
};

/// Resource limits for the native QuickJS worker, installed process-wide by
/// [`set_native_limits`]. Without that call every worker is unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeLimits {
    /// The QuickJS allocator's limit (`Runtime::set_memory_limit`) on the
    /// runtime one cell runs in, set once that cell's context is prepared, just
    /// before the cell starts. An allocation past it fails the cell, except on
    /// an out-of-memory path QuickJS itself mishandles, which ends the PROCESS:
    /// MEASURED on QuickJS 0.16.2, `Function.prototype.bind`, `eval` compiling
    /// a class, and `Array.fromAsync` (whose leak aborts the runtime's drop).
    pub memory_bytes: usize,
    /// The interpreter's stack limit (`Runtime::set_max_stack_size`).
    pub max_stack_bytes: usize,
    /// The worker thread's stack; it must exceed `max_stack_bytes` with headroom
    /// for the Rust frames a cell's host calls add. Not checked: without that
    /// headroom, deep recursion overflows the thread's stack and aborts the
    /// process instead of failing the cell.
    pub thread_stack_bytes: usize,
    /// Wall time one cell may take from its start, tool calls, timers and holds
    /// included. Running JavaScript past it is interrupted at its next interrupt
    /// check and the job drain stops before its next job, so a job queue that
    /// requeues itself ends too; a cell waiting on a tool result or a timer, or
    /// held (`EmbeddedHost::hold`), ends at it. One long native step (a built-in
    /// sort of millions of elements) runs to its end before the interrupt lands.
    /// Time between cells is not charged.
    pub cell_wall: Duration,
    /// What one cell may emit, in bytes: every text, content item, notification,
    /// yield and tool call is charged its payload (a tool call's input excepted)
    /// plus [`crate::CELL_EVENT_BYTES`], so the cap bounds the number of events as
    /// well as their bytes. The call that crosses it throws and emits nothing, and
    /// the cell fails.
    pub cell_emitted_bytes: usize,
    /// Native workers that may be live in this process at once, idle ones
    /// included. Each has its own thread and its own runtime under
    /// `memory_bytes`, so the process's interpreter heap is at most
    /// `live_workers` × `memory_bytes`. `EmbeddedHost::spawn` past it fails, so
    /// the cell that needed the worker fails; a worker stops counting when its
    /// thread ends.
    pub live_workers: usize,
}

/// The process's live native workers, each counted from its spawn until its
/// thread ends.
static LIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// One worker's place in [`LIVE_WORKERS`], given back when it is dropped. A
/// backend [`set_worker_backend`] installs holds it in [`WorkerEnds::live`] and
/// drops it once nothing of that worker runs any more.
pub struct LiveWorker(());

impl LiveWorker {
    /// Counts one more live worker, or refuses when `limits` allow no more.
    fn claim(limits: Option<NativeLimits>) -> Result<Self, String> {
        let cap = limits.map_or(usize::MAX, |limits| limits.live_workers);
        LIVE_WORKERS
            .try_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                if live < cap { Some(live + 1) } else { None }
            })
            .map(|_| Self(()))
            .map_err(|_| {
                format!(
                    "this process already runs {cap} Code Mode workers, its limit: end a \
                     running cell or wait for one to finish, then run this cell again"
                )
            })
    }
}

impl Drop for LiveWorker {
    fn drop(&mut self) {
        LIVE_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The native workers live in this process now, idle ones included: the count
/// [`NativeLimits::live_workers`] caps, kept with or without limits installed. A
/// worker counts from its spawn until its thread ends, so one whose cell is
/// still inside a long native step after a `terminate` or a drop is counted; a
/// worker an installed backend started counts until that backend drops its
/// [`LiveWorker`].
pub fn live_workers() -> usize {
    LIVE_WORKERS.load(Ordering::Acquire)
}

static NATIVE_LIMITS: OnceLock<NativeLimits> = OnceLock::new();

/// Installs `limits` for every worker spawned after this call. Once only: a
/// second call with the same limits is `Ok`, with different ones it changes
/// nothing and returns the installed limits.
pub fn set_native_limits(limits: NativeLimits) -> Result<(), NativeLimits> {
    let installed = *NATIVE_LIMITS.get_or_init(|| limits);
    if installed == limits {
        Ok(())
    } else {
        Err(installed)
    }
}

/// One worker's ends, handed to the backend [`set_worker_backend`] installs in
/// place of a worker thread: the commands its [`EmbeddedHost`] sends, the
/// sender of the events the host reads, the failure the host names once that
/// channel closes (`startup`), the signal `terminate` awaits (sent once nothing
/// of the worker runs any more), and the worker's place in [`live_workers`],
/// held until then.
pub struct WorkerEnds {
    pub commands: std_mpsc::Receiver<HostCommand>,
    pub events: mpsc::UnboundedSender<RuntimeEvent>,
    pub startup: Arc<OnceLock<String>>,
    pub stopped: oneshot::Sender<()>,
    pub live: LiveWorker,
}

/// What starts the worker of each [`EmbeddedHost`] spawned once it is installed
/// ([`set_worker_backend`]); an `Err` fails that spawn.
pub type WorkerBackend = Box<dyn Fn(WorkerEnds) -> Result<(), String> + Send + Sync>;

static WORKER_BACKEND: OnceLock<WorkerBackend> = OnceLock::new();

/// Installs `backend` to start the worker of every [`EmbeddedHost`] spawned
/// after this call, in place of a worker thread of this process. Once only: a
/// later call changes nothing and returns its `backend`. Without it, each
/// worker is a thread of this process running the cells itself.
pub fn set_worker_backend(backend: WorkerBackend) -> Result<(), WorkerBackend> {
    WORKER_BACKEND.set(backend)
}

/// What answers a cell's `load` of a key its stored values lack
/// ([`set_stored_loader`]): the value, or `None` for a key that holds none.
pub type StoredLoader = Box<dyn Fn(&str) -> Option<Arc<RawValue>> + Send + Sync>;

static STORED_LOADER: OnceLock<StoredLoader> = OnceLock::new();

/// Installs `loader` to answer, in every native worker of this process, a
/// cell's `load` of a key the stored values its `start_cell` was given lack.
/// It runs on the worker's thread, inside the cell's JavaScript, which waits
/// for it. Once only: a later call changes nothing and returns its `loader`.
/// Without it, such a `load` answers `undefined`.
pub fn set_stored_loader(loader: StoredLoader) -> Result<(), StoredLoader> {
    STORED_LOADER.set(loader)
}

/// What a native worker calls with a cell's id once that cell's terminal event
/// is sent and before it drops the runtime the cell ran in
/// ([`set_cell_ended`]).
pub type CellEnded = Box<dyn Fn(u64) + Send + Sync>;

static CELL_ENDED: OnceLock<CellEnded> = OnceLock::new();

/// Installs `ended` to run, in every native worker of this process, on the
/// worker's thread once a cell's terminal event is sent and before the worker
/// drops the runtime the cell ran in, which QuickJS can abort the process
/// doing ([`Engine::renew`]): a host that forwards the event elsewhere can
/// wait there until it is forwarded. Once only: a later call changes nothing
/// and returns its `ended`. Without it the worker drops the runtime at once.
pub fn set_cell_ended(ended: CellEnded) -> Result<(), CellEnded> {
    CELL_ENDED.set(ended)
}

/// One worker's per-cell budget: a wall deadline armed only while a cell runs,
/// and the flag the output counter raises. The interrupt handler reads both.
struct CellBudget {
    limits: Option<NativeLimits>,
    epoch: Instant,
    deadline_nanos: AtomicU64,
    output_exceeded: Arc<AtomicBool>,
}

#[derive(Clone, Copy)]
enum LimitHit {
    Wall(Duration),
    Output(usize),
    /// QuickJS's own exceptions under `memory_bytes` and `max_stack_bytes`.
    /// Neither raises the worker's interrupt, so [`CellBudget::hit`] never
    /// answers them: [`quickjs_limit`] reads them off a failure the bootstrap
    /// reports, and [`Engine::heap_exhausted`] names the memory limit for one
    /// it cannot.
    Memory(usize),
    Stack(usize),
}

/// The headroom under `memory_bytes` at or below which a failed cell's heap
/// is exhausted. QuickJS throws a bare `null` when it cannot allocate even its
/// own out-of-memory error, and the bootstrap, which needs the heap to report
/// a failure, then cannot report the cell's: the engine sees the cell's run
/// rejected. MEASURED (`crates/agent-nanocode/tests/code_mode_limits.rs`): such
/// a cell leaves its heap within 4 KiB of the limit, under 16 MiB and 256 MiB
/// alike; a run rejected for another reason leaves it far from it.
const EXHAUSTED_HEAP_HEADROOM: usize = 64 << 10;

impl CellBudget {
    fn new(limits: Option<NativeLimits>) -> Self {
        Self {
            limits,
            epoch: Instant::now(),
            deadline_nanos: AtomicU64::new(0),
            output_exceeded: Arc::new(AtomicBool::new(false)),
        }
    }

    fn arm(&self) {
        let Some(limits) = self.limits else {
            return;
        };
        let deadline = self.epoch.elapsed().saturating_add(limits.cell_wall);
        let nanos = u64::try_from(deadline.as_nanos())
            .unwrap_or(u64::MAX)
            .max(1);
        self.deadline_nanos.store(nanos, Ordering::Release);
    }

    fn disarm(&self) -> Option<LimitHit> {
        let hit = self.hit();
        self.deadline_nanos.store(0, Ordering::Release);
        self.output_exceeded.store(false, Ordering::Release);
        hit
    }

    fn remaining(&self) -> Option<Duration> {
        match self.deadline_nanos.load(Ordering::Acquire) {
            0 => None,
            nanos => Some(Duration::from_nanos(nanos).saturating_sub(self.epoch.elapsed())),
        }
    }

    /// Whether JavaScript must stop: the host's interrupt (a terminate or a
    /// drop) or a limit hit. The interrupt handler and the job drain both ask.
    fn stops(&self, interrupted: &AtomicBool) -> bool {
        interrupted.load(Ordering::Acquire) || self.hit().is_some()
    }

    fn hit(&self) -> Option<LimitHit> {
        let limits = self.limits?;
        if self.output_exceeded.load(Ordering::Acquire) {
            return Some(LimitHit::Output(limits.cell_emitted_bytes));
        }
        (self.remaining() == Some(Duration::ZERO)).then_some(LimitHit::Wall(limits.cell_wall))
    }

    /// The guard's report for a cell whose failure the bootstrap reports, as
    /// `failure`, while this budget is armed: the wall or output limit
    /// [`Self::hit`] names, else the QuickJS limit `failure` names
    /// ([`quickjs_limit`]); `None` for any other failure, and without limits.
    /// [`send_terminal`](crate::cell::send_terminal) sends it as a `Notify`
    /// just before the cell's `Error`, so the report is an event of its own
    /// beside the cell's output: a host that shortens the output it shows
    /// keeps a notification whole.
    fn report(&self, failure: &str) -> Option<String> {
        let limits = self.limits?;
        self.hit()
            .or_else(|| quickjs_limit(limits, failure))
            .map(|hit| hit.message())
    }
}

/// The QuickJS limit a failure the bootstrap reports names: the memory limit
/// when its first line ends with QuickJS's `InternalError: out of memory`, the
/// interpreter stack limit when it ends with QuickJS's `RangeError: Maximum
/// call stack size exceeded`. The bootstrap writes a cell's error with its
/// stack and its `cause` below that first line, so a hit the cell catches and
/// rethrows inside an error of its own names no limit; nor does a heap hit
/// QuickJS throws as a bare `null` that the bootstrap reports (`Uncaught
/// null`, `Unhandled promise rejection: null`) once the cell's frames released
/// the heap.
fn quickjs_limit(limits: NativeLimits, failure: &str) -> Option<LimitHit> {
    let first = failure.lines().next().unwrap_or_default();
    if first.ends_with("InternalError: out of memory") {
        Some(LimitHit::Memory(limits.memory_bytes))
    } else if first.ends_with("RangeError: Maximum call stack size exceeded") {
        Some(LimitHit::Stack(limits.max_stack_bytes))
    } else {
        None
    }
}

impl LimitHit {
    fn message(&self) -> String {
        match self {
            Self::Wall(wall) => format!(
                "Code Mode cell exceeded its {} ms wall-time limit",
                wall.as_millis()
            ),
            Self::Output(bytes) => {
                format!("Code Mode cell output exceeded its {bytes}-byte limit")
            }
            Self::Memory(bytes) => {
                format!("Code Mode cell exceeded its {bytes}-byte memory limit")
            }
            Self::Stack(bytes) => {
                format!("Code Mode cell exceeded its {bytes}-byte interpreter stack limit")
            }
        }
    }
}

enum CellEnd {
    Stopped,
    Failed(String),
}

impl From<String> for CellEnd {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

/// The QuickJS runtime ONE cell runs in, with the bootstrap's loader, the
/// rejection tracker, the stack limit and the worker's interrupt installed. The
/// worker builds one before each cell and drops it, with everything that cell
/// left in it, once the cell ends ([`Self::renew`]), so no cell runs in a
/// runtime another cell ran in. A runtime outlives its cell's context in two
/// ways a garbage collection cannot undo:
///
/// - rquickjs keeps, for a runtime's whole life, the prototype of the first Rust
///   function made in it (`Opaque::get_or_insert_prototype`, which
///   `RustFunction::prototype` fills with that context's `Function.prototype`),
///   holding a counted reference to its context that QuickJS's cycle collector
///   cannot see. The first cell's context, its globals and whatever any later
///   cell stores through it (every later cell's native functions inherit that
///   prototype, and its `constructor` evaluates in that context) would stay
///   allocated until the runtime goes: a cell that fills the heap that way
///   would leave every later cell an exhausted heap.
/// - QuickJS's job queue belongs to the runtime, not a context, and a queued
///   job keeps its context alive: the next preparation's module load would run
///   it with no wall armed, under the failed cell's id. QuickJS has no call that
///   empties the queue.
///
/// The memory limit is set only once the cell's context is prepared
/// ([`Self::limit_memory`]): QuickJS's context creation is not safe against
/// the limit. `JS_NewContextRaw` frees a context whose class prototypes it could
/// not allocate while that context is still linked into the runtime's garbage
/// list, and the next collection walks the freed memory and aborts the process
/// (`gc_decref`'s assertion, or `mark_children`'s `abort`); a creation that
/// fails deeper leaves its half-built context allocated. That is the one
/// QuickJS out-of-memory defect the engine keeps cells from; the others it
/// knows lie on paths a cell's own code reaches ([`NativeLimits::memory_bytes`]).
struct Engine {
    // Declared before `runtime`, so dropped before it: it holds values of it.
    rejections: Rejections,
    runtime: Runtime,
}

impl Engine {
    fn new(interrupted: &Arc<AtomicBool>, budget: &Arc<CellBudget>) -> Result<Self, String> {
        let runtime = Runtime::new()
            .map_err(|error| format!("failed to initialize embedded QuickJS runtime: {error}"))?;
        install_bootstrap(&runtime)?;
        let rejections = track_rejections(&runtime);
        if let Some(limits) = budget.limits {
            runtime.set_max_stack_size(limits.max_stack_bytes);
        }
        let interrupt_signal = Arc::clone(interrupted);
        let interrupt_budget = Arc::clone(budget);
        runtime.set_interrupt_handler(Some(Box::new(move || {
            interrupt_budget.stops(&interrupt_signal)
        })));
        Ok(Self {
            rejections,
            runtime,
        })
    }

    /// Sets `memory_bytes` on this runtime for the one cell about to run in it.
    /// Everything before (the bootstrap, a prelude's compilation, the cell's
    /// context and its preparation) ran without a memory limit, and no context
    /// is created in this runtime after it.
    fn limit_memory(&self, limits: Option<NativeLimits>) {
        if let Some(limits) = limits {
            self.runtime.set_memory_limit(limits.memory_bytes);
        }
    }

    /// Whether this runtime's heap is within [`EXHAUSTED_HEAP_HEADROOM`] of
    /// `limit`: read before the failed cell's context is dropped, while its
    /// values still hold the heap.
    fn heap_exhausted(&self, limit: usize) -> bool {
        let used = usize::try_from(self.runtime.memory_usage().malloc_size).unwrap_or(0);
        used.saturating_add(EXHAUSTED_HEAP_HEADROOM) >= limit
    }

    /// Drops this runtime, with everything the last cell (or a preparation that
    /// failed) left in it, its job queue included, and builds the next cell's.
    /// The worker thread is kept. Called only once the cell's prepared context
    /// is dropped. `JS_FreeRuntime` asserts that its last collection freed
    /// every object, so any reference this runtime still holds aborts the
    /// process here: a value of it held past the drop, and also one QuickJS
    /// itself leaked on an out-of-memory path the cell ran through
    /// (`Array.fromAsync`, MEASURED in
    /// `crates/agent-nanocode/tests/code_mode_out_of_memory_defects.rs`). The
    /// engine cannot tell such a runtime before dropping it.
    fn renew(
        self,
        interrupted: &Arc<AtomicBool>,
        budget: &Arc<CellBudget>,
    ) -> Result<Self, String> {
        drop(self);
        Self::new(interrupted, budget)
    }
}

struct Prepared {
    run_cell: Persistent<Function<'static>>,
    state: Rc<std::cell::RefCell<ExecutionState>>,
    context: Context,
    bytes: bool,
}

impl Prepared {
    fn new(
        runtime: &Runtime,
        event_tx: &mpsc::UnboundedSender<RuntimeEvent>,
        rejections: &Rejections,
        bytes: bool,
        budget: &CellBudget,
        stop: &Rc<dyn Fn() -> bool>,
        report: &Rc<dyn Fn(&str) -> Option<String>>,
    ) -> Result<Self, String> {
        let context = Context::full(runtime).map_err(|error| {
            format!("failed to create a fresh embedded QuickJS context: {error}")
        })?;
        let state = new_state(0, event_tx.clone(), HashMap::new(), Rc::clone(rejections));
        if let Some(limits) = budget.limits {
            state.borrow_mut().limit_output(
                limits.cell_emitted_bytes,
                Arc::clone(&budget.output_exceeded),
            );
        }
        state.borrow_mut().stop_draining_when(Rc::clone(stop));
        state.borrow_mut().report_limits_with(Rc::clone(report));
        if let Some(loader) = STORED_LOADER.get() {
            state
                .borrow_mut()
                .load_missing_with(Rc::new(move |key: &str| loader(key)));
        }
        let run_cell = context.with(|ctx| {
            prepare_execution(&ctx, &state, bytes).map(|run_cell| Persistent::save(&ctx, run_cell))
        });
        match run_cell {
            Ok(run_cell) => Ok(Self {
                run_cell,
                state,
                context,
                bytes,
            }),
            Err(error) => {
                clear_pending(&state);
                drop(state);
                drop(context);
                Err(error)
            }
        }
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        clear_pending(&self.state);
    }
}

pub struct EmbeddedHost {
    command_tx: std_mpsc::Sender<HostCommand>,
    events: mpsc::UnboundedReceiver<RuntimeEvent>,
    interrupted: Arc<AtomicBool>,
    startup: Arc<OnceLock<String>>,
    stopped: Option<oneshot::Receiver<()>>,
}

/// One cell to run: [`HostCommand::Start`].
pub struct StartExecution {
    pub execution_id: u64,
    pub source: String,
    pub tools: Vec<Value>,
    pub stored: HashMap<String, Arc<RawValue>>,
    pub prelude: Option<Arc<str>>,
    pub journaling: Option<CellJournaling>,
}

/// What an [`EmbeddedHost`] sends its worker.
pub enum HostCommand {
    Start(StartExecution),
    ToolResult {
        execution_id: u64,
        id: u64,
        encoded: String,
        success: bool,
    },
    Hold {
        execution_id: u64,
    },
    Release {
        execution_id: u64,
    },
    Shutdown,
}

enum CommandPoll {
    Command(HostCommand),
    TimerReady,
    Disconnected,
}

impl EmbeddedHost {
    pub fn spawn() -> Result<Self, String> {
        let (command_tx, command_rx) = std_mpsc::channel();
        let (event_tx, events) = mpsc::unbounded_channel();
        let interrupted = Arc::new(AtomicBool::new(false));
        let startup = Arc::new(OnceLock::new());
        let worker_interrupted = Arc::clone(&interrupted);
        let worker_startup = Arc::clone(&startup);
        let (stopped_tx, stopped) = oneshot::channel();
        let limits = NATIVE_LIMITS.get().copied();
        let live = LiveWorker::claim(limits)?;
        if let Some(backend) = WORKER_BACKEND.get() {
            backend(WorkerEnds {
                commands: command_rx,
                events: event_tx,
                startup: worker_startup,
                stopped: stopped_tx,
                live,
            })?;
            return Ok(Self {
                command_tx,
                events,
                interrupted,
                startup,
                stopped: Some(stopped),
            });
        }
        let mut builder = thread::Builder::new().name("nanocode-code-mode-quickjs".to_owned());
        if let Some(limits) = limits {
            builder = builder.stack_size(limits.thread_stack_bytes);
        }
        builder
            .spawn(move || {
                run_worker(
                    &command_rx,
                    &event_tx,
                    &worker_startup,
                    &worker_interrupted,
                    limits,
                );
                drop((command_rx, event_tx, live));
                let _ = stopped_tx.send(());
            })
            .map_err(|error| format!("failed to start embedded QuickJS code-mode host: {error}"))?;
        Ok(Self {
            command_tx,
            events,
            interrupted,
            startup,
            stopped: Some(stopped),
        })
    }

    fn unavailable(&self, fallback: &str) -> String {
        self.startup
            .get()
            .cloned()
            .unwrap_or_else(|| fallback.to_owned())
    }

    pub fn start_cell(
        &self,
        execution_id: u64,
        source: &str,
        stored: HashMap<String, Arc<RawValue>>,
        tools: Vec<Value>,
        prelude: Option<Arc<str>>,
        journaling: Option<CellJournaling>,
    ) -> Result<(), String> {
        self.command_tx
            .send(HostCommand::Start(StartExecution {
                execution_id,
                source: source.to_owned(),
                tools,
                stored,
                prelude,
                journaling,
            }))
            .map_err(|_| self.unavailable("embedded QuickJS code-mode host is unavailable"))
    }

    pub async fn read_event(&mut self) -> Result<RuntimeEvent, String> {
        match self.events.recv().await {
            Some(event) => Ok(event),
            None => Err(self.unavailable("embedded QuickJS code-mode host ended before a result")),
        }
    }

    pub fn send_tool_result(
        &self,
        execution_id: u64,
        id: u64,
        encoded: String,
        success: bool,
    ) -> Result<(), String> {
        self.command_tx
            .send(HostCommand::ToolResult {
                execution_id,
                id,
                encoded,
                success,
            })
            .map_err(|_| {
                "embedded QuickJS code-mode host closed before accepting a tool result".into()
            })
    }

    pub fn hold(&self, execution_id: u64) -> Result<(), String> {
        self.command_tx
            .send(HostCommand::Hold { execution_id })
            .map_err(|_| "embedded QuickJS code-mode host closed before holding a cell".into())
    }

    pub fn release(&self, execution_id: u64) -> Result<(), String> {
        self.command_tx
            .send(HostCommand::Release { execution_id })
            .map_err(|_| "embedded QuickJS code-mode host closed before releasing a cell".into())
    }

    pub async fn terminate(&mut self) {
        self.interrupted.store(true, Ordering::Release);
        let _ = self.command_tx.send(HostCommand::Shutdown);
        if let Some(stopped) = self.stopped.take() {
            let _ = stopped.await;
        }
    }
}

impl Drop for EmbeddedHost {
    fn drop(&mut self) {
        self.interrupted.store(true, Ordering::Release);
        let _ = self.command_tx.send(HostCommand::Shutdown);
    }
}

fn run_worker(
    command_rx: &std_mpsc::Receiver<HostCommand>,
    event_tx: &mpsc::UnboundedSender<RuntimeEvent>,
    startup: &OnceLock<String>,
    interrupted: &Arc<AtomicBool>,
    limits: Option<NativeLimits>,
) {
    let budget = Arc::new(CellBudget::new(limits));
    let mut engine = match Engine::new(interrupted, &budget) {
        Ok(engine) => engine,
        Err(error) => {
            let _ = startup.set(error);
            return;
        }
    };
    let drain_signal = Arc::clone(interrupted);
    let drain_budget = Arc::clone(&budget);
    let stop: Rc<dyn Fn() -> bool> = Rc::new(move || drain_budget.stops(&drain_signal));
    let report_budget = Arc::clone(&budget);
    let report: Rc<dyn Fn(&str) -> Option<String>> =
        Rc::new(move |failure| report_budget.report(failure));
    let mut prepared: Option<Prepared> = None;
    loop {
        match command_rx.recv() {
            Ok(HostCommand::Start(start)) => {
                interrupted.store(false, Ordering::Release);
                let cell_id = start.execution_id;
                if let Err(error) = install_prelude(&engine.runtime, start.prelude.as_deref()) {
                    let _ = event_tx.send(RuntimeEvent::Error {
                        cell_id,
                        message: error,
                        stored: HashMap::new(),
                    });
                    continue;
                }
                let bytes = start.prelude.is_some();
                let next = match prepared.take() {
                    Some(next) if next.bytes == bytes => Ok(next),
                    stale => {
                        drop(stale);
                        Prepared::new(
                            &engine.runtime,
                            event_tx,
                            &engine.rejections,
                            bytes,
                            &budget,
                            &stop,
                            &report,
                        )
                    }
                };
                // A context that could not be prepared fails the cell like a failed
                // run, and its runtime is renewed below like any cell's.
                let (result, hit) = match next {
                    Ok(next) => {
                        engine.limit_memory(limits);
                        budget.arm();
                        let result = run_execution(&next, start, command_rx, &budget);
                        // A cell that failed outside the bootstrap's own report
                        // failed on the wall or output limit its budget names, or,
                        // its heap exhausted, on the memory limit: QuickJS's bare
                        // `null` names none, and neither does the text the engine
                        // writes for it. Read before `next` drops the cell's values.
                        let hit = budget.disarm().or_else(|| match (&result, limits) {
                            (Err(CellEnd::Failed(_)), Some(limits))
                                if engine.heap_exhausted(limits.memory_bytes) =>
                            {
                                Some(LimitHit::Memory(limits.memory_bytes))
                            }
                            _ => None,
                        });
                        (result, hit)
                    }
                    Err(error) => {
                        tracing::error!(
                            target: "nanocode_code_mode",
                            %error,
                            "failed to create a fresh embedded QuickJS context"
                        );
                        (Err(CellEnd::Failed(error)), None)
                    }
                };
                match result {
                    Ok(()) => {}
                    Err(CellEnd::Stopped) => return,
                    Err(CellEnd::Failed(_)) if interrupted.load(Ordering::Acquire) => return,
                    Err(CellEnd::Failed(error)) => {
                        if let Some(hit) = hit {
                            let _ = event_tx.send(RuntimeEvent::Notify {
                                cell_id,
                                text: hit.message(),
                            });
                        }
                        let _ = event_tx.send(RuntimeEvent::Error {
                            cell_id,
                            message: hit.map_or(error, |hit| hit.message()),
                            stored: HashMap::new(),
                        });
                    }
                }
                if let Some(ended) = CELL_ENDED.get() {
                    ended(cell_id);
                }
                engine = match engine.renew(interrupted, &budget) {
                    Ok(engine) => engine,
                    Err(error) => {
                        let _ = startup.set(error);
                        return;
                    }
                };
                prepared = Prepared::new(
                    &engine.runtime,
                    event_tx,
                    &engine.rejections,
                    bytes,
                    &budget,
                    &stop,
                    &report,
                )
                .ok();
            }
            Ok(
                HostCommand::ToolResult { .. }
                | HostCommand::Hold { .. }
                | HostCommand::Release { .. },
            ) => {}
            Ok(HostCommand::Shutdown) | Err(_) => return,
        }
    }
}

fn run_execution(
    prepared: &Prepared,
    start: StartExecution,
    command_rx: &std_mpsc::Receiver<HostCommand>,
    budget: &CellBudget,
) -> Result<(), CellEnd> {
    prepared
        .context
        .with(|ctx| run_execution_in_context(&ctx, prepared, start, command_rx, budget))
}

fn run_execution_in_context(
    ctx: &Ctx<'_>,
    prepared: &Prepared,
    start: StartExecution,
    command_rx: &std_mpsc::Receiver<HostCommand>,
    budget: &CellBudget,
) -> Result<(), CellEnd> {
    let execution_id = start.execution_id;
    let state = &prepared.state;
    begin_execution(state, execution_id, start.stored, start.journaling);
    let run_cell = prepared
        .run_cell
        .clone()
        .restore(ctx)
        .catch(ctx)
        .map_err(|error| format!("failed to restore the QuickJS bootstrap: {error}"))?;
    let promise = start_execution(
        ctx,
        state,
        &run_cell,
        start.source,
        start.tools,
        start.prelude.is_some(),
    )?;

    let result = (|| {
        if let Some(reason) = replay_inputs(ctx, state, &promise)? {
            return Ok(state
                .borrow()
                .send(RuntimeEvent::Diverged {
                    cell_id: execution_id,
                    reason,
                })
                .map_err(|_| "embedded QuickJS execution observer closed".to_owned())?);
        }
        loop {
            if let Some(terminal) = completed_terminal(ctx, &promise)? {
                return Ok(send_terminal(state, terminal)?);
            }
            if let Some(hit) = budget.hit() {
                return Err(CellEnd::Failed(hit.message()));
            }
            let wait = match (next_timeout_wait(state), budget.remaining()) {
                (Some(timer), Some(wall)) => Some(timer.min(wall)),
                (timer, wall) => timer.or(wall),
            };
            match receive_command(command_rx, wait) {
                CommandPoll::Command(HostCommand::ToolResult {
                    execution_id: result_execution_id,
                    id,
                    encoded,
                    success,
                }) if result_execution_id == execution_id => {
                    resolve_tool(ctx, state, id, encoded, success)?;
                    drain_jobs(ctx, state);
                }
                CommandPoll::TimerReady => {
                    let now = Instant::now();
                    while let Some(id) = next_due_timeout(state, now) {
                        invoke_timeout(ctx, state, id)?;
                        drain_jobs(ctx, state);
                        if let Some(terminal) = completed_terminal(ctx, &promise)? {
                            return Ok(send_terminal(state, terminal)?);
                        }
                    }
                }
                CommandPoll::Command(HostCommand::Hold { execution_id: held })
                    if held == execution_id =>
                {
                    hold_execution(ctx, state, execution_id, command_rx, budget)?;
                }
                CommandPoll::Command(HostCommand::Shutdown) | CommandPoll::Disconnected => {
                    return Err(CellEnd::Stopped);
                }
                CommandPoll::Command(
                    HostCommand::Start(_)
                    | HostCommand::ToolResult { .. }
                    | HostCommand::Hold { .. }
                    | HostCommand::Release { .. },
                ) => {}
            }
        }
    })();
    clear_pending(state);
    result
}

fn hold_execution(
    ctx: &Ctx<'_>,
    state: &Rc<std::cell::RefCell<ExecutionState>>,
    execution_id: u64,
    command_rx: &std_mpsc::Receiver<HostCommand>,
    budget: &CellBudget,
) -> Result<(), CellEnd> {
    state
        .borrow()
        .send(RuntimeEvent::Held {
            cell_id: execution_id,
        })
        .map_err(|_| "embedded QuickJS execution observer closed".to_owned())?;
    let mut stashed = Vec::new();
    // A hold does not stop the cell's wall: the cell keeps its thread, its runtime
    // and its timers' deadlines while held, so the wait ends at the deadline.
    loop {
        match receive_command(command_rx, budget.remaining()) {
            CommandPoll::Command(HostCommand::Release {
                execution_id: released,
            }) if released == execution_id => break,
            CommandPoll::Command(HostCommand::ToolResult {
                execution_id: result_execution_id,
                id,
                encoded,
                success,
            }) if result_execution_id == execution_id => stashed.push((id, encoded, success)),
            CommandPoll::Command(HostCommand::Shutdown) | CommandPoll::Disconnected => {
                return Err(CellEnd::Stopped);
            }
            CommandPoll::TimerReady => {
                if let Some(hit) = budget.hit() {
                    return Err(CellEnd::Failed(hit.message()));
                }
            }
            CommandPoll::Command(_) => {}
        }
    }
    for (id, encoded, success) in stashed {
        resolve_tool(ctx, state, id, encoded, success)?;
        drain_jobs(ctx, state);
    }
    Ok(())
}

fn receive_command(
    receiver: &std_mpsc::Receiver<HostCommand>,
    timeout: Option<Duration>,
) -> CommandPoll {
    let Some(timeout) = timeout else {
        return receiver
            .recv()
            .map_or(CommandPoll::Disconnected, CommandPoll::Command);
    };
    match receiver.recv_timeout(timeout) {
        Ok(command) => CommandPoll::Command(command),
        Err(std_mpsc::RecvTimeoutError::Timeout) => CommandPoll::TimerReady,
        Err(std_mpsc::RecvTimeoutError::Disconnected) => CommandPoll::Disconnected,
    }
}
