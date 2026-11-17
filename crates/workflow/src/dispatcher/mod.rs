//! Dispatcher — worker selection + retry policy, built on the ledger.
//!
//! The dispatcher is layer 2 of the in-flight-ledger reorg (see
//! `docs/architecture/0001-replacement-architecture.md`). It owns three responsibilities:
//!
//! 1. **Worker selection.** Delegates to `kata_transport::DispatchScheduler`,
//!    which already does capability + liveness + lowest-load filtering.
//!    The dispatcher's contribution is wiring selection into the ledger
//!    and exposing a checked submit / failure / worker-death API the rest of
//!    the workflow machinery talks to.
//!
//! 2. **Worker-death settlement.** A capsule attempt is never re-delivered:
//!    a dead worker's victims are settled PROVEN NOT PERFORMED or NOT PROVEN
//!    through [`Dispatcher::settle_lost_capsule_attempt`], never requeued or
//!    resumed — the chain's decision is final.
//!
//! 3. **`active_assignments` bookkeeping.** `WorkerInfo.active_assignments`
//!    is read by the scheduler to pick the lowest-loaded worker, and the
//!    dispatcher is what keeps it true: it owns a consume-once charge tied to
//!    the dispatch generation and concrete worker registration. Terminal/park
//!    writers consume synchronously;
//!    [`Dispatcher::run_bookkeeper`] reconciles missed, lagged, and external
//!    transitions.
//!
//! ## Production path
//!
//! Installed and explicit scratch mains submit checked stage assignments through
//! `Dispatcher::deliver_capsule_frame`. The dispatcher owns worker selection,
//! delivery fencing, load accounting, and stage-stall settlement.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

// The dispatcher's wall clock. Aliased onto the canonical workspace helper so
// the sweeps / submit / recovery submodules keep importing `dispatcher_now_ms`
// via `super::` at the same path, with the same semantics.
use kata_types::time::now_ms as dispatcher_now_ms;

use kata_core::{AssignmentStatus, InFlightLedger, LedgerEvent};
use kata_transport::heartbeat::HeartbeatMonitor;
use kata_transport::scheduler::DispatchScheduler;
use kata_transport::supervisor::{WorkerPoolDispatchAuthority, WorkerPoolSupervisor};
use kata_transport::types::DispatchFrame;
use kata_types::error::{KataError, KataResult};
use kata_types::primitives::ContentHash;
use kata_types::sandbox::{SandboxDirective, SandboxProfile, SandboxRef, SecretRef};
use smol_str::SmolStr;
use tokio::sync::broadcast;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tracing::{Instrument, debug, info, warn};
use ulid::Ulid;

use crate::execution_lifecycle::ExecutionLifecycleFace;
use kata_program::execution_program::ExecutionProgram;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CheckedProgramAuthority {
    /// The checked program's content hash — the identity `register` compares
    /// on a re-admission of the same execution.
    program_hash: ContentHash,
    /// The TIMEOUT resolution of each blocking human request's input
    /// wait, keyed by the wait's attempt `stage_id` (`#op/<path>`) — the accepted output
    /// `Dispatcher::sweep_due_waits` commits when the request's `timeout_ms` elapses
    /// (`InputWaitRecord::timeout_default`: its authored `default_assumption`).
    input_timeouts: BTreeMap<String, serde_json::Value>,
}

/// The kata dispatcher. Clone-cheap: all fields are `Arc`.
///
/// Constructed once per main, handed to the executor and result reactor via
/// `Arc<Dispatcher>`.
/// Multi-reader safe.
#[derive(Clone)]
pub struct Dispatcher {
    supervisor: Arc<WorkerPoolSupervisor>,
    worker_pool_dispatch_authority: WorkerPoolDispatchAuthority,
    scheduler: Arc<DispatchScheduler>,
    ledger: Arc<InFlightLedger>,
    /// Shared durable top-level execution lifecycle authority (`operational.db`).
    /// Child-completion decisions must never be inferred from assignment
    /// snapshots.
    execution_lifecycle: Arc<parking_lot::RwLock<ExecutionLifecycleFace>>,
    /// Whether an OWNER attached the nucleus above, or [`Dispatcher::new`] minted
    /// a private empty one.
    ///
    /// [`Dispatcher::new`] cannot take a face (every rig constructs a dispatcher
    /// before the executor exists), so it mints
    /// `ExecutionLifecycleFace::in_memory()` — an EMPTY authority. The test-rig
    /// seam [`Dispatcher::ensure_rig_nucleus_admission`] gives that private
    /// nucleus a coherent row, and must never write into an attached one: an
    /// attached nucleus is authority, and an execution missing from it is a
    /// refusal. That seam is this flag's only reader, so the flag exists only
    /// under `test`/`test-support`; production always attaches (boot installs the
    /// face at four sites).
    #[cfg(any(test, feature = "test-support"))]
    execution_lifecycle_attached: Arc<AtomicBool>,
    /// The Nix environment this node DECLARED AND PROMOTED at boot
    /// (`kata_core::environment::bind_node_environment`), which the capsule submit path
    /// selects for every stage. `None` on a node that bound none, which boot makes
    /// unreachable under the `oci` profile (`node_environment_undeclared`).
    node_environment: Option<kata_core::environment::NodeEnvironment>,
    /// What the capsule authorization asks whether a program is in the environment.
    /// [`crate::authorization::HostProgramProbe`] in production; a rig may replace it.
    program_probe: Arc<dyn crate::authorization::ProgramProbe>,
    /// How long the delivery door waits for the worker's transport to take a
    /// capsule frame (`workers.dispatch_deadline_ms`). Past it, a send to a worker
    /// that holds no started attempt settles its attempt PROVEN AMBIGUOUS, and a
    /// send queued behind a running attempt keeps waiting in a task of its own;
    /// nothing is re-delivered to another worker.
    send_timeout: Duration,
    /// Optional queue/start deadline. Once a worker transport accepts
    /// an assignment, the worker must emit the assignment-specific
    /// start checkpoint within this window or the dispatcher fails
    /// the assignment. This is separate from stage `timeout_ms`,
    /// which counts actual execution time after the start checkpoint.
    assignment_start_deadline: Option<Duration>,
    /// One owner for checked assignment commands, timing and the current stall
    /// cycle. Authoritative terminal reconciliation retires these together;
    /// pending admissions keep their command while awaiting dispatch capacity.
    assignments: Arc<assignment_registry::AssignmentRegistry>,
    /// Per-execution retained checked-program authority. Checked dispatch
    /// commands must reference a program/stage contract registered here before
    /// the dispatcher will mutate the ledger or talk to a worker.
    checked_program_authority: Arc<execution_registry::ExecutionRegistry>,
    /// Admission control — a semaphore bounding the number of fresh
    /// worker-dispatch submissions in flight AT ONCE, so a wide fan-out cannot
    /// pile unboundedly onto the ledger connection-mutex + scheduler at the same
    /// instant (the overload "connection-mutex convoy" failure mode). Wired from
    /// [`RuntimeConfig::max_concurrent_dispatches`](kata_types::config::RuntimeConfig)
    /// via [`Dispatcher::with_max_concurrent_dispatches`] (bin/kata boot). Every fresh
    /// submission (the capsule submit's authorize+deliver section) acquires one permit for the
    /// duration of its insert+dispatch and RELEASES on return; the `N+1`th
    /// concurrent submission QUEUES on the semaphore (graceful backpressure)
    /// rather than convoying. `None` = unbounded (the test constructors that
    /// never configure a cap).
    ///
    /// SCOPE: this bounds ONE CRITICAL SECTION, not stages. The permit does not
    /// survive the submission call, so it never bounds how many stages are
    /// RUNNING. Saturation is published as the `kata_dispatch_permits_available`
    /// gauge — see [`Dispatcher::emit_dispatch_permits_available`].
    dispatch_limiter: Option<Arc<Semaphore>>,
    /// Current count of `Pending`, not-yet-dispatched
    /// assignments — the main-side dispatch queue depth. Published as the
    /// `kata_worker_queue_depth` gauge on every submit/dispatch/terminal
    /// transition. `i64` (not `usize`) so a transient underflow from an
    /// out-of-order recovery event is observable rather than wrapping.
    queued_depth: Arc<AtomicI64>,
    /// Installed-main startup recovery fence. Durable replay may rehydrate
    /// checked dispatch commands before the complete recovery batch is known
    /// good; no command may reach a worker, and no mutating deadline/heartbeat
    /// sweep may run, until boot explicitly opens this gate. Non-durable/test
    /// dispatchers start open.
    startup_recovery_dispatch_phase: Arc<AtomicU8>,
    startup_recovery_dispatch_notify: Arc<Notify>,
    /// Ordered-shutdown fence for LIVE RUNNERS. Set once, by the stopping main,
    /// at the same instant it closes admission; never cleared.
    ///
    /// # Why a runner needs to know
    ///
    /// The ordered shutdown stops main-owned producers
    /// (`BootRig::stop_background_tasks`) BEFORE it drains workflow drivers
    /// (`BootRig::drain_workflow_tasks`), and one of those producers is
    /// [`Dispatcher::run_assignment_deadline_sweep`]. Its due-wait leg,
    /// [`Dispatcher::sweep_due_waits`], is the ONLY thing that accepts a due
    /// main-resolved timer, which is where every `sleep(...)` waits: the runner
    /// parks a sleep as an `executor = 'main'` attempt in `awaiting_timer` with a
    /// durable `wait_deadline_ms`, and nothing else wakes it. A driver
    /// parked behind one therefore cannot make progress once producers
    /// stop, and waiting for it would spend the drain's whole budget.
    ///
    /// This flag lets the driver's park read the fence and DETACH instead: it
    /// terminalizes nothing, the durable Running lifecycle is left exactly as it
    /// stands, and restart recovery replays the chain — the recovery model the
    /// engine already runs on. Bounded handoff, not a longer wait.
    graceful_shutdown: Arc<AtomicBool>,
    /// Placement ownership — see [`attempt_chain::PlacementOwnership`].
    placement_ownership: Arc<attempt_chain::PlacementOwnership>,
    /// Consume-once load charges, tied to a dispatch generation and the
    /// concrete worker registration instance that was incremented.
    dispatch_charges: Arc<charge::DispatchCharges>,
    /// The supervised node's fence, installed once by the main that supervises
    /// one (`kata`'s `supervised_node`): [`Dispatcher::handle_worker_death`] kills
    /// a node its heartbeat judged dead through it before it settles anything.
    node_fence: Arc<std::sync::OnceLock<Arc<dyn NodeFence>>>,
    /// Held for the whole of one [`Dispatcher::handle_worker_death`]: see there.
    worker_deaths: Arc<tokio::sync::Mutex<()>>,
}

const STARTUP_RECOVERY_NOT_REQUIRED_OPEN: u8 = 0;
const STARTUP_RECOVERY_CLOSED_BEFORE_READY: u8 = 1;
const STARTUP_RECOVERY_READY_OPEN: u8 = 2;

/// Linear capability proving that a dispatcher was fenced before it was
/// shared. Holding this value is the only way production boot can prepare
/// recovery or release the gate; it is deliberately neither `Clone` nor
/// constructible outside this module.
pub struct StartupRecoveryGuard {
    phase: Arc<AtomicU8>,
    notify: Arc<Notify>,
}

impl std::fmt::Debug for StartupRecoveryGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StartupRecoveryGuard")
            .field("closed_before_ready", &self.is_closed_before_ready())
            .finish_non_exhaustive()
    }
}

impl StartupRecoveryGuard {
    fn authorizes(&self, dispatcher: &Dispatcher) -> bool {
        Arc::ptr_eq(&self.phase, &dispatcher.startup_recovery_dispatch_phase)
            && self.is_closed_before_ready()
    }

    fn is_closed_before_ready(&self) -> bool {
        self.phase.load(Ordering::Acquire) == STARTUP_RECOVERY_CLOSED_BEFORE_READY
    }

    /// Consume the boot-only capability and make worker dispatch permanently
    /// ready. Dropping the guard on any error path leaves the gate closed.
    ///
    /// This low-level release remains public only because dispatcher fencing
    /// and installed-main recovery live in different crates. Product
    /// boot returns to it only after `activate_recovered_runs`.
    pub fn release(self, dispatcher: &Dispatcher) -> KataResult<()> {
        if !Arc::ptr_eq(&self.phase, &dispatcher.startup_recovery_dispatch_phase) {
            return Err(KataError::Validation(
                "startup recovery guard belongs to a different dispatcher".to_string(),
            ));
        }
        self.phase
            .compare_exchange(
                STARTUP_RECOVERY_CLOSED_BEFORE_READY,
                STARTUP_RECOVERY_READY_OPEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|phase| {
                KataError::Validation(format!(
                    "startup recovery guard cannot release dispatcher from phase {phase}"
                ))
            })?;
        self.notify.notify_waiters();
        Ok(())
    }
}

/// Main-side timing anchors for the worker/dispatch-plane
/// latency metrics. Populated from the ledger event stream the dispatcher's
/// bookkeeper already consumes ([`Dispatcher::on_event`]), so no new hot-path
/// clock reads on the submit/dispatch path.
///
/// The main sees only the transition timestamps its own ledger latches
/// (`Pending` → `Dispatched` → `Running` → terminal). What it CANNOT see — and
/// so deliberately does not claim — is any per-worker in-sandbox detail: the
/// worker's local queue wait, agent-call setup, or the network leg beyond the
/// transport's own `kata_worker_dispatch_duration_seconds{transport}` ack
/// histogram. These latencies are the main-observable envelope only.
#[derive(Debug)]
struct AssignmentTiming {
    /// When the assignment first entered (or last re-entered, on requeue) the
    /// `Pending` queue, as seen by the bookkeeper.
    submitted_at: Instant,
    /// When the assignment was last `Dispatched`. `None` while still queued.
    dispatched_at: Option<Instant>,
    /// Whether this assignment is currently counted in `queued_depth` (i.e. it
    /// is `Pending` and not yet dispatched). Guards double increment/decrement
    /// across requeue and terminal-before-dispatch transitions.
    counted_in_queue: bool,
    /// Which `kata_worker_inflight_depth` series this assignment is
    /// currently counted in, or `None` when it is not on a worker (queued,
    /// parked, or terminal). Mutually exclusive with [`Self::counted_in_queue`]
    /// — see [`Dispatcher::record_queue_plane_metrics`] for why the pair is
    /// what makes the backlog conserved rather than merely counted.
    inflight: Option<InflightSeries>,
}

/// The gauge that makes the post-hand-off backlog countable.
///
/// ONE authority for the name, because the emitter ([`Dispatcher::charge_inflight`])
/// and the tests that read it back are in different modules, and a metric name
/// hand-spelled twice drifts invisibly.
const INFLIGHT_DEPTH_GAUGE: &str = "kata_worker_inflight_depth";

/// The `kata_worker_inflight_depth` series one assignment is charged
/// to — the worker it was handed to, and whether that worker has acknowledged
/// it yet.
///
/// Stored rather than re-derived because the transition that RELEASES a charge
/// does not always name the worker that holds it: `Orphaned` carries
/// `prev_worker` as an `Option`, and `AwaitingChildCompletion` carries no
/// worker id at all (parking frees the worker).
/// Re-deriving the series from the releasing event would leak exactly the
/// series an operator is looking at when a worker stops answering.
#[derive(Debug, Clone)]
struct InflightSeries {
    /// The worker the assignment is charged to.
    worker_id: SmolStr,
    /// [`AssignmentStatus::tag`] of the state it is charged in — `dispatched`
    /// or `running`. A `&'static str` from `tag()` and never a hand-spelled
    /// literal, so this label set cannot drift from the ledger's own
    /// vocabulary (the same vocabulary `kata_worker_assignments_total{status}`
    /// already counts entries with).
    status: &'static str,
}

/// The placeholder checked program [`Dispatcher::ensure_rig_nucleus_admission`]
/// admits into a rig's private nucleus, compiled ONCE per process.
///
/// A real compiled program rather than an opaque blob, because admission goes
/// through the admission chokepoint and the chokepoint validates against the program's
/// declared param contract. Cached because the compile is the only non-trivial cost
/// on the path and it is identical for every rig.
#[cfg(any(test, feature = "test-support"))]
fn rig_nucleus_program() -> &'static kata_program::execution_program::ExecutionProgram {
    static PROGRAM: std::sync::OnceLock<kata_program::execution_program::ExecutionProgram> =
        std::sync::OnceLock::new();
    PROGRAM.get_or_init(|| {
        kata_program::execution_program::compile_starlark_execution_program(
            "rig = stage(id = \"rig\", prompt = \"rig\", agent = \"shell\")\n\
             workflow(\"rig-nucleus\", root = rig)\n",
            "rig-nucleus.star",
            &[],
        )
        .expect("the rig nucleus placeholder program compiles")
    })
}

mod assignment_registry;
mod execution_registry;
pub(crate) use execution_registry::ExecutionProgramLease;
#[cfg(test)]
mod assignment_registry_tests;
pub(crate) mod attempt_chain;
mod capsule_approval;
pub(crate) mod capsule_settlement;
mod expansion;
mod main_waits;
pub(crate) mod work_apply;
mod workspace_effect;
/// The refusal when a capsule has no worker to be placed on: none live with certified
/// containment.
pub const NO_OCI_WORKER_AVAILABLE: &str = "no_oci_worker_available";

/// What a capsule asks of the worker it is placed on, as the scheduler's two arguments: NO
/// capability, and a CERTIFIED container.
///
/// No capability, because nothing a worker advertises enters what the capsule runs: a
/// shell stage is `sh -c` over the node environment's closure, which a worker reads
/// through the main's own planes, and an agent turn's adapter, model, env and credential
/// REFERENCE are resolved by the main from the node's `[agents.<label>]` at assembly
/// (`capsule_assembly::agent_turn_spec`), the turn's harness running in the worker and
/// its capsule's `kata-toolhost` init coming from the worker's provider entry.
/// An `agent:<label>` a worker advertises is an operator's or the main's own claim that
/// placement never needs. The containment half is not optional: placing a capsule on a
/// worker that claims none would hand an operator the wrap they declined.
///
/// The ONE definition both [`Dispatcher::select_capsule_worker`] (placement) and
/// [`Dispatcher::capsule_worker_count`] (the capacity preflight's read) pass.
const CAPSULE_PLACEMENT: (&[String], kata_transport::scheduler::PlacementContainment) = (
    &[],
    kata_transport::scheduler::PlacementContainment::CertifiedContainerRequired,
);

/// This node's `[node] environment`, as boot left it — a neutral fact; its operator
/// wording lives at the API's status surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeEnvironmentState {
    /// Declared, promoted and bound: every capsule this node authorizes names it.
    Bound(kata_types::execution_contract::EnvironmentId),
    /// No `[node] environment` is declared.
    None,
}

pub use capsule_settlement::{
    CAPSULE_MAIN_RESTARTED, CAPSULE_START_GRACE_MS, CAPSULE_WALL_TIME_GRACE_MS,
};
mod charge;
mod command;
#[cfg(test)]
mod dispatch_charge_tests;
#[cfg(test)]
mod execution_registry_tests;
mod recovery;
mod submit;
mod sweeps;
mod worker_results;

/// `pub` rather than `pub(crate)` because the live-work registry
/// is read outside this crate's dispatcher: the runner's subworkflow recursion cap
/// is a global authority consultation.
pub use attempt_chain::LiveWork;
/// `pub` for the same reason `LiveWork` is: both
/// consumers of the parked-gate reader live in `kata-api`.
pub use attempt_chain::ParkedApprovalGate;
pub(crate) use attempt_chain::assignment_blob_for_the_chain;
pub use recovery::{NodeFence, WorkerLoss};
/// `pub` because boot recovery, in `kata-api`, asks it.
pub use workspace_effect::{
    FORGE_OBSERVER_ASK_SPACING, FORGE_OBSERVER_UNANSWERED_BOUND, ForgeReconcile, WorkspaceTeardown,
};

impl Dispatcher {
    /// Record an authenticated worker membrane before registry admission.
    pub fn enroll_worker_membrane(
        &self,
        source_main: &str,
        membrane: kata_types::identity::WorkerMembraneId,
    ) -> KataResult<kata_types::identity::WorkerEffectDomain> {
        self.execution_lifecycle
            .read()
            .db()
            .enroll_worker_domain(source_main, membrane)
    }
    /// Build a dispatcher over the given supervisor, heartbeat monitor,
    /// and ledger. The scheduler is constructed internally so the
    /// dispatcher owns a consistent selection policy.
    pub fn new(
        supervisor: Arc<WorkerPoolSupervisor>,
        heartbeat: Arc<HeartbeatMonitor>,
        ledger: Arc<InFlightLedger>,
    ) -> Self {
        let worker_pool_dispatch_authority =
            supervisor
                .claim_dispatch_authority()
                .unwrap_or_else(|error| {
                    panic!("failed to claim worker pool dispatch authority: {error}")
                });
        let scheduler = Arc::new(DispatchScheduler::new(Arc::clone(&supervisor), heartbeat));
        Self {
            supervisor,
            worker_pool_dispatch_authority,
            scheduler,
            ledger,
            // A PRIVATE, EMPTY nucleus until an owner attaches the real one.
            execution_lifecycle: Arc::new(parking_lot::RwLock::new(
                ExecutionLifecycleFace::in_memory()
                    .expect("open dispatcher execution lifecycle authority"),
            )),
            #[cfg(any(test, feature = "test-support"))]
            execution_lifecycle_attached: Arc::new(AtomicBool::new(false)),
            node_environment: None,
            program_probe: Arc::new(crate::authorization::HostProgramProbe),
            send_timeout: Duration::from_secs(30),
            assignment_start_deadline: Some(Duration::from_mins(15)),
            assignments: Arc::default(),
            checked_program_authority: Arc::new(execution_registry::ExecutionRegistry::default()),
            // No admission cap until `with_max_concurrent_dispatches` wires one
            // (production does, from config). Test constructors run unbounded.
            dispatch_limiter: None,
            queued_depth: Arc::new(AtomicI64::new(0)),
            startup_recovery_dispatch_phase: Arc::new(AtomicU8::new(
                STARTUP_RECOVERY_NOT_REQUIRED_OPEN,
            )),
            startup_recovery_dispatch_notify: Arc::new(Notify::new()),
            graceful_shutdown: Arc::new(AtomicBool::new(false)),
            placement_ownership: Arc::default(),
            dispatch_charges: Arc::default(),
            node_fence: Arc::default(),
            worker_deaths: Arc::default(),
        }
    }

    /// Raise the ordered-shutdown fence every live runner parks against. Called
    /// once by the stopping main, beside `close_admission`. One-way: there is no
    /// clearing counterpart, because a run detached for restart recovery is not
    /// re-adopted by the process that let it go.
    pub fn begin_graceful_shutdown(&self) {
        self.graceful_shutdown.store(true, Ordering::Release);
    }

    /// Whether the owning main has entered ordered shutdown. Read by
    /// `WorkflowRunner::run`'s park; see [`Self::graceful_shutdown`].
    #[must_use]
    pub fn graceful_shutdown_began(&self) -> bool {
        self.graceful_shutdown.load(Ordering::Acquire)
    }

    /// Construct a durable-main dispatcher fenced before any worker or reactor
    /// can observe it. The phase is one-way: runtime code cannot re-close a
    /// ready dispatcher and masquerade as startup recovery.
    pub fn with_startup_recovery_fence(mut self) -> KataResult<(Self, StartupRecoveryGuard)> {
        let phase = Arc::get_mut(&mut self.startup_recovery_dispatch_phase).ok_or_else(|| {
            KataError::Validation(
                "startup recovery fence must be armed before the dispatcher is cloned or shared"
                    .to_string(),
            )
        })?;
        phase
            .compare_exchange(
                STARTUP_RECOVERY_NOT_REQUIRED_OPEN,
                STARTUP_RECOVERY_CLOSED_BEFORE_READY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|existing| {
                KataError::Validation(format!(
                    "startup recovery fence cannot be armed from phase {existing}"
                ))
            })?;
        let guard = StartupRecoveryGuard {
            phase: Arc::clone(&self.startup_recovery_dispatch_phase),
            notify: Arc::clone(&self.startup_recovery_dispatch_notify),
        };
        Ok((self, guard))
    }

    #[must_use]
    pub fn startup_recovery_dispatch_is_open(&self) -> bool {
        self.startup_recovery_dispatch_phase.load(Ordering::Acquire)
            != STARTUP_RECOVERY_CLOSED_BEFORE_READY
    }

    #[must_use]
    pub fn startup_recovery_is_authorized_by(&self, guard: &StartupRecoveryGuard) -> bool {
        guard.authorizes(self)
    }

    pub(crate) async fn wait_for_startup_recovery_dispatch(&self) {
        loop {
            let opened = self.startup_recovery_dispatch_notify.notified();
            if self.startup_recovery_dispatch_is_open() {
                return;
            }
            opened.await;
        }
    }

    /// Bound the number of concurrent fresh worker-dispatch SUBMISSIONS to
    /// `max_concurrent_dispatches` (from
    /// [`RuntimeConfig::max_concurrent_dispatches`](kata_types::config::RuntimeConfig)).
    /// Once `N` submissions are in flight, the `N+1`th QUEUES on the semaphore
    /// until one completes — graceful backpressure that keeps a wide fan-out from
    /// convoying on the ledger connection-mutex. `0` is clamped to `1` (a cap of
    /// zero would deadlock every dispatch); omit the builder entirely to run
    /// unbounded.
    ///
    /// This is NOT a running-stage ceiling: the permit covers the insert+dispatch
    /// section only. See [`Self::acquire_dispatch_permit`].
    #[must_use]
    pub fn with_max_concurrent_dispatches(mut self, max_concurrent_dispatches: usize) -> Self {
        self.dispatch_limiter = Some(Arc::new(Semaphore::new(max_concurrent_dispatches.max(1))));
        self
    }

    /// Bind the environment boot declared and promoted for this node.
    #[must_use]
    pub const fn with_node_environment(
        mut self,
        environment: kata_core::environment::NodeEnvironment,
    ) -> Self {
        self.node_environment = Some(environment);
        self
    }

    /// The node environment's state, for an operator surface to present: bound (with its
    /// id), or none (a state `required_environment` makes unreachable on a booted node).
    #[must_use]
    pub fn node_environment_state(&self) -> NodeEnvironmentState {
        match &self.node_environment {
            Some(bound) => NodeEnvironmentState::Bound(bound.environment),
            None => NodeEnvironmentState::None,
        }
    }

    /// Replace the program probe (a rig whose environment names fixture store paths).
    #[must_use]
    pub fn with_program_probe(
        mut self,
        probe: Arc<dyn crate::authorization::ProgramProbe>,
    ) -> Self {
        self.program_probe = probe;
        self
    }

    /// The program probe capsule authorization consults.
    #[must_use]
    pub fn program_probe(&self) -> &dyn crate::authorization::ProgramProbe {
        self.program_probe.as_ref()
    }

    /// The environment boot bound for this node, if any.
    #[must_use]
    pub const fn node_environment(&self) -> Option<kata_core::environment::NodeEnvironment> {
        self.node_environment
    }

    /// SELECT a worker for a capsule dispatch — refused
    /// [`NO_OCI_WORKER_AVAILABLE`] when no live worker claims certified containment.
    /// What it asks of a worker is [`CAPSULE_PLACEMENT`].
    ///
    /// # Errors
    ///
    /// [`NO_OCI_WORKER_AVAILABLE`], carrying the scheduler's own refusal, which quotes
    /// each candidate's containment claim.
    pub fn select_capsule_worker(&self) -> KataResult<SmolStr> {
        let (requirements, containment) = CAPSULE_PLACEMENT;
        self.scheduler
            .select_worker_excluding(requirements, &[], containment)
            .map_err(|refusal| {
                KataError::Validation(format!(
                    "{NO_OCI_WORKER_AVAILABLE}: a capsule needs a live worker with certified \
                     containment, and none is registered. The scheduler's refusal: {refusal}"
                ))
            })
    }

    /// DELIVER one authorized capsule attempt's frame to `worker_id`.
    ///
    /// The frame is READ OUT OF THE DURABLE ROW the authorization wrote, never composed
    /// here: `attempts.assignment_json` is the at-rest frame, and re-deriving it at the
    /// send boundary is how the bytes a worker receives come to differ from the bytes the
    /// authorization committed to. [`Self::frame_for_dispatch`] then stamps the three
    /// per-dispatch facts off the same row, so the bytes a worker receives are the
    /// bytes the authorization committed plus its per-dispatch stamp — never a
    /// re-derived frame.
    ///
    /// # The send fences
    ///
    /// The send boundary stamps the receiving membrane's enrollment from the CURRENT
    /// registration, and the send goes through `dispatch_to_current_instance` under this
    /// delivery's dispatch charge: a same-id registration replaced between the placement
    /// read and the send is refused as not sent, and the attempt is settled PROVEN NOT
    /// PERFORMED. The door answers within `send_timeout` (`workers.dispatch_deadline_ms`):
    /// a send still parked then on a worker that holds no started attempt settles the
    /// attempt PROVEN AMBIGUOUS ([`Self::settle_stalled_capsule_send`]); one queued behind
    /// a running attempt is backpressure, so the door returns `Ok` and the write's own
    /// task records its outcome when it completes.
    ///
    /// # Errors
    ///
    /// An attempt with no durable row (the authorization just wrote one, so this is a
    /// concurrent prune or a caller that never authorized), a frame blob that does not
    /// decode, a MAIN-RESOLVED attempt (this door delivers the capsule arm only), a
    /// capsule frame with no occurrence binding, the transport's own send failure, and a
    /// send still parked at the deadline on a worker that holds no started attempt.
    pub async fn deliver_capsule_frame(&self, attempt_id: Ulid) -> KataResult<()> {
        let row = self
            .execution_lifecycle
            .read()
            .db()
            .recovered_attempt(attempt_id)?
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "capsule dispatch refused: attempt {attempt_id} has no durable row to read a \
                     dispatch frame out of"
                ))
            })?;
        // THE ARM AND ITS BINDING from the row's one classifier: a main-resolved
        // attempt is refused here, and a capsule frame with no occurrence binding
        // is refused by `arm` itself rather than delivered with no authority
        // behind it.
        match row.arm()? {
            kata_core::operational::AttemptArm::Capsule(_) => {}
            kata_core::operational::AttemptArm::Main(_) => {
                return Err(KataError::Validation(format!(
                    "capsule dispatch refused: attempt {attempt_id} is MAIN-RESOLVED; it is \
                     never sent to any worker"
                )));
            }
        }
        // THE PLACEMENT COMES OFF THE ROW the authorization wrote, not from a parameter.
        // `dispatch_claimed_attempt` recorded `attempts.worker_id` in the same transaction
        // as the `dispatched` transition, so the row is the authority on where this attempt
        // was placed; a caller-passed id could name a worker the plane does not agree with,
        // and the frame would then be stamped `placed_on` a worker the fence would refuse.
        let worker_id = row.row.worker_id.clone().ok_or_else(|| {
            KataError::Validation(format!(
                "capsule dispatch refused: attempt {attempt_id} records no placement, which \
                 `dispatch_claimed_attempt` cannot leave — a dispatched attempt is \
                 worker-attributed by its own CHECK"
            ))
        })?;
        // A stored frame that does not DECODE is an attempt no worker will ever hold: this
        // door sends only the frame it decoded, so an undecodable blob has no bytes to send
        // and nothing left this process for it. Settled PROVEN NOT PERFORMED like a frame
        // the door could not build, never returned with the attempt left `dispatched`.
        let frame: DispatchFrame = match serde_json::from_slice(&row.assignment_json) {
            Ok(frame) => frame,
            Err(error) => {
                let error = KataError::Validation(format!(
                    "capsule dispatch refused: attempt {attempt_id}'s stored dispatch frame does \
                     not decode: {error}"
                ));
                self.settle_undelivered_capsule_attempt(attempt_id, worker_id.as_str(), &error);
                return Err(error);
            }
        };
        let worker_id_smol = smol_str::SmolStr::new(worker_id.as_str());
        // The placement is ALREADY durable (`dispatched` and the command), so
        // a frame this door cannot build is an attempt no worker will ever hold: settled
        // PROVEN NOT PERFORMED here like a refused send, never returned with the attempt
        // left `dispatched` for no leg to reach. The send boundary also stamps the
        // receiving membrane's enrollment — the field the at-rest frame leaves `None`
        // — from the CURRENT registration, which is what the instance-fenced send then
        // compares against its own read of the same worker.
        let checked = match self.frame_for_dispatch(&frame).and_then(|mut outgoing| {
            let DispatchFrame::Capsule(capsule) = &mut outgoing;
            capsule.effect_domain = Some(
                self.supervisor
                    .get_worker(&worker_id_smol)
                    .and_then(|info| info.value().effect_domain.clone())
                    .ok_or_else(|| {
                        KataError::Validation(
                            "physical dispatch has no durable worker membrane binding".into(),
                        )
                    })?,
            );
            kata_transport::types::CheckedDispatchFrame::new(outgoing)
        }) {
            Ok(checked) => checked,
            Err(error) => {
                self.settle_undelivered_capsule_attempt(attempt_id, worker_id.as_str(), &error);
                return Err(error);
            }
        };
        // THE CAPSULE ARM'S CHARGE — every worker delivery acquires a
        // dispatch load charge against the AUTHORITY CHAIN's pre-image, a
        // capsule delivery included: otherwise a dead worker's registration
        // would carry a capsule with nothing counted against it, and a same-id
        // replacement between the placement read above and the send would have
        // no fence at all (`dispatch_to` never compares the registration
        // instance). The placement is already durable —
        // `dispatch_claimed_attempt` wrote `attempts.worker_id` at
        // authorization — so this door's claim mints THIS delivery as the
        // placement's owner: a second delivery for one attempt declines as
        // superseded rather than sends twice.
        let dispatch = self.mint_dispatch_token();
        {
            let mut ownership = self.placement_ownership.section(attempt_id);
            if ownership.owner().is_some() {
                info!(
                    %attempt_id,
                    %worker_id,
                    "dispatcher: a concurrent capsule delivery owns this attempt's placement; \
                     abandoning without sending"
                );
                return Ok(());
            }
            ownership.claim(dispatch);
        }
        let charge =
            match self.acquire_capsule_dispatch_charge(attempt_id, &worker_id_smol, dispatch)? {
                Ok(charge) => charge,
                Err(declined) => {
                    // The attempt moved under this delivery — a terminal settled
                    // or a competing placement claimed it; nothing to send and
                    // nothing to settle: the plane that moved it owns it.
                    info!(
                        %attempt_id,
                        %worker_id,
                        status = declined.status(),
                        "dispatcher: the capsule attempt moved under this delivery; abandoning \
                         without sending"
                    );
                    return Ok(());
                }
            };
        // The capsule arm's DISPATCH BOUNDARY: the placement and its command are durable,
        // and no frame has left. A main that dies here leaves an attempt `dispatched` that
        // no worker holds; the next main's restart settlement records it terminal.
        kata_core::fault_inject::operational_crash_point("after_capsule_dispatched_before_send");
        // The send is INSTANCE-FENCED by the charge: the registration this
        // charge counts on is the only registration that may receive the
        // frame. `RegistrationReplaced` is proven-not-sent exactly as a
        // transport refusal is.
        //
        // The door's wait is BOUNDED by `send_timeout` (`workers.dispatch_deadline_ms`),
        // and the bound is on JOINING the write's own task, never on the write: dropping
        // a half-written frame desyncs the connection (the constraint
        // `WorkerPoolSupervisor::send_control_to` states for a stop). Past the deadline
        // the write either belongs to a worker that is not draining — no running attempt
        // and no freed slot for the whole deadline, the start-deadline leg's premise —
        // and is settled PROVEN AMBIGUOUS (it may still land, so never PROVEN NOT
        // PERFORMED), or it is queued behind a running attempt, which is backpressure:
        // a task of its own keeps the write and finishes the delivery when it completes.
        let write_task = {
            let supervisor = Arc::clone(&self.supervisor);
            let authority = self.worker_pool_dispatch_authority.clone();
            let counter = Arc::clone(&charge.counter);
            let worker = worker_id_smol.clone();
            tokio::spawn(
                async move {
                    supervisor
                        .dispatch_to_current_instance(
                            &authority,
                            worker.as_str(),
                            &counter,
                            checked,
                        )
                        .await
                }
                .instrument(tracing::Span::current()),
            )
        };
        let mut write_task = write_task;
        let Ok(joined) = tokio::time::timeout(self.send_timeout, &mut write_task).await else {
            let error = KataError::Timeout(format!(
                "worker {worker_id} did not take the dispatch frame within \
                 workers.dispatch_deadline_ms={} ms while it held no running attempt: it is not \
                 draining its connection. The write was not cancelled, so the frame may still \
                 reach it",
                self.send_timeout.as_millis()
            ));
            if self.settle_stalled_capsule_send(attempt_id, worker_id.as_str(), &error) {
                self.dispatch_charges
                    .release_if_owned(attempt_id, charge.token);
                return Err(error);
            }
            // Queued behind a running attempt (or already settled by another leg): the
            // frame waits exactly as one the transport queue took would, and the write's
            // own outcome is handled when it completes.
            info!(
                %attempt_id,
                %worker_id,
                deadline_ms = self.send_timeout.as_millis(),
                "dispatcher: the capsule send is queued behind the worker's running attempt; \
                 the write continues in its own task"
            );
            let dispatcher = self.clone();
            let token = charge.token;
            tokio::spawn(
                async move {
                    let joined = write_task.await;
                    // The door already answered: the outcome is recorded, not returned.
                    let _ = dispatcher.finish_capsule_send(attempt_id, &worker_id, token, joined);
                }
                .instrument(tracing::Span::current()),
            );
            return Ok(());
        };
        self.finish_capsule_send(attempt_id, &worker_id, charge.token, joined)
    }

    /// Record the outcome of one capsule frame's send: a frame the transport took is
    /// delivered; a frame it did NOT take is an attempt no worker holds, settled PROVEN NOT
    /// PERFORMED here, or it would stay `dispatched` with no leg to reach it (there is no
    /// capsule re-delivery, and it never starts); a write task that did not run to an
    /// answer may have sent part of the frame, so it is settled PROVEN AMBIGUOUS.
    fn finish_capsule_send(
        &self,
        attempt_id: Ulid,
        worker_id: &str,
        token: charge::ChargeToken,
        joined: Result<
            KataResult<kata_transport::supervisor::InstanceFencedDispatch>,
            tokio::task::JoinError,
        >,
    ) -> KataResult<()> {
        let sent = match joined {
            Ok(sent) => sent,
            Err(join) => {
                let error = KataError::Network(format!(
                    "the dispatch send to worker {worker_id} did not complete: {join}"
                ));
                self.dispatch_charges.release_if_owned(attempt_id, token);
                self.settle_unconfirmed_capsule_send(attempt_id, worker_id, &error);
                return Err(error);
            }
        };
        match sent {
            Ok(kata_transport::supervisor::InstanceFencedDispatch::Sent) => Ok(()),
            Ok(kata_transport::supervisor::InstanceFencedDispatch::RegistrationReplaced) => {
                let error = KataError::Network(format!(
                    "worker {worker_id} registration was replaced before dispatch"
                ));
                self.dispatch_charges.release_if_owned(attempt_id, token);
                self.settle_undelivered_capsule_attempt(attempt_id, worker_id, &error);
                Err(error)
            }
            Err(error) => {
                self.dispatch_charges.release_if_owned(attempt_id, token);
                self.settle_undelivered_capsule_attempt(attempt_id, worker_id, &error);
                Err(error)
            }
        }
    }

    /// Attach the same execution-lifecycle authority the executor uses.
    #[must_use]
    pub fn with_execution_lifecycle(mut self, face: ExecutionLifecycleFace) -> Self {
        self.execution_lifecycle = Arc::new(parking_lot::RwLock::new(face));
        #[cfg(any(test, feature = "test-support"))]
        {
            self.execution_lifecycle_attached = Arc::new(AtomicBool::new(true));
        }
        self
    }

    #[must_use]
    pub fn execution_lifecycle(&self) -> ExecutionLifecycleFace {
        self.execution_lifecycle.read().clone()
    }

    /// The executor term the registration currently named `worker_id` runs
    /// capsules under ([`kata_transport::supervisor::WorkerInfo::executor_term`]), or
    /// `None` when no registration holds the name or it stated none.
    pub(crate) fn worker_executor_term(
        &self,
        worker_id: &str,
    ) -> Option<kata_types::primitives::ContentHash> {
        self.supervisor
            .get_worker(worker_id)
            .and_then(|info| info.value().executor_term)
    }

    /// Construction-time synchronization used by `WorkflowExecutor` builders
    /// so dispatcher child sweeps and executor runner tasks share one authority.
    pub fn install_execution_lifecycle(&self, face: ExecutionLifecycleFace) {
        *self.execution_lifecycle.write() = face;
        #[cfg(any(test, feature = "test-support"))]
        self.execution_lifecycle_attached
            .store(true, Ordering::Release);
    }

    /// Whether an owner ATTACHED the operational nucleus, or
    /// [`Self::new`] minted the private empty one. See the
    /// `execution_lifecycle_attached` field docs.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn execution_lifecycle_is_attached(&self) -> bool {
        self.execution_lifecycle_attached.load(Ordering::Acquire)
    }

    /// Give a TEST RIG's private nucleus a coherent row for `execution_id`, so the
    /// inbox seam has a real execution to attribute attempts to instead of being
    /// skipped.
    ///
    /// # Invariant
    ///
    /// No-op — and NOT a fallback — whenever an owner attached a real face
    /// ([`Self::execution_lifecycle_is_attached`]). An attached nucleus is
    /// authority: an execution missing from it is a refusal, never something to
    /// backfill. This only ever writes to the private in-memory database
    /// [`Self::new`] minted, which no production path can be.
    ///
    /// # Why here and not in each rig
    ///
    /// The inbox seam claims an attempt, which needs a `programs` row
    /// (`attempts.execution_id` is a foreign key). Many test rigs drive the ledger
    /// through a dispatcher without admitting anything, because
    /// [`Self::new`] silently mints an empty nucleus. Fixing the ONE constructor
    /// that mints it covers all of them; editing the rigs one by one does not, and
    /// leaves the next rig broken.
    ///
    /// # Through the REAL chokepoint, not a forged record
    ///
    /// It admits a compiled placeholder program through
    /// [`ExecutionLifecycleFace::admit_current_execution`], which runs
    /// [`crate::admission::checked_admission`] — the ONE admission seam. Hand-minting an
    /// `InvocationRecord` here would be shorter and is exactly what
    /// `admission_records_are_only_minted_by_the_checked_admission_seam` forbids: the
    /// digest would not be derived from validated bytes. That guard is a legitimate
    /// property, not a check pinning a defect, so it is satisfied rather than
    /// excepted.
    ///
    /// Idempotent: admission converges on byte-identical facts and `mark_running` is
    /// an idempotent claim.
    #[cfg(any(test, feature = "test-support"))]
    pub fn ensure_rig_nucleus_admission(&self, execution_id: Ulid) -> KataResult<()> {
        if self.execution_lifecycle_is_attached() {
            return Ok(());
        }
        let face = self.execution_lifecycle();
        if face.view().lifecycle(execution_id)?.is_some() {
            return Ok(());
        }
        face.put_current_program(execution_id, rig_nucleus_program())
    }

    /// Override the capsule send deadline. Default is 30s.
    #[must_use]
    pub fn with_send_timeout(mut self, send_timeout: Duration) -> Self {
        self.send_timeout = send_timeout;
        self
    }

    /// Override the queue/start deadline. `None` disables the guard.
    #[must_use]
    pub fn with_assignment_start_deadline(mut self, deadline: Option<Duration>) -> Self {
        self.assignment_start_deadline = deadline;
        self
    }

    /// Return a handle on the underlying ledger. The executor and
    /// reactor both need a handle for their own flows, and having the
    /// dispatcher hand it out keeps construction order simple.
    #[must_use]
    pub fn ledger(&self) -> &Arc<InFlightLedger> {
        &self.ledger
    }

    /// Discover live work on this worker from the operational registry.
    /// In-memory ledger rows do not add candidates or override terminality.
    pub fn non_terminal_assignments_on_worker(&self, worker_id: &str) -> KataResult<Vec<Ulid>> {
        Ok(self
            .live_work_registry()?
            .into_iter()
            .filter(|work| work.worker_id.as_deref() == Some(worker_id))
            .map(|work| work.assignment_id)
            .collect())
    }

    /// Acquire one admission permit for a fresh worker-dispatch
    /// submission, or `None` when no cap is configured (unbounded). When a cap
    /// IS configured this AWAITS a free permit — the `N+1`th concurrent caller
    /// queues here rather than piling onto the ledger connection-mutex. The
    /// returned [`OwnedSemaphorePermit`] holds the slot until dropped; the caller
    /// keeps it alive for the whole insert+dispatch and drops it on return.
    ///
    /// This is the exact primitive `submit_stage_as_capsule` gates on, so
    /// bounding acquisitions here bounds the real dispatch admission rate.
    pub(crate) async fn acquire_dispatch_permit(&self) -> Option<OwnedSemaphorePermit> {
        let permit = match &self.dispatch_limiter {
            // `acquire_owned` only errors if the semaphore is closed, which never
            // happens — we never call `close()`. Treat a poisoned semaphore as
            // "no cap" rather than panicking a dispatch.
            Some(sem) => Arc::clone(sem).acquire_owned().await.ok(),
            None => None,
        };
        // Observation only — the acquisition above is unchanged. Post-acquire is
        // the moment saturation is real: `0` here means the next submission will
        // queue on the semaphore.
        self.emit_dispatch_permits_available();
        permit
    }

    /// Publish [`Self::dispatch_permits_available`] as the
    /// `kata_dispatch_permits_available` gauge, alongside the dispatch plane's
    /// other gauges (`kata_worker_queue_depth`,
    /// `kata_worker_heartbeat_lag_seconds`).
    ///
    /// Emitted at two points, which together make limiter saturation legible:
    /// each permit acquisition (the instant the cap can bite) and every
    /// heartbeat-sweep tick (so a quiesced dispatcher's gauge returns to the
    /// configured cap instead of latching at its last busy reading). Unbounded
    /// dispatchers — every test constructor that never calls
    /// [`Self::with_max_concurrent_dispatches`] — emit nothing, so "no series"
    /// distinguishes *no cap configured* from *cap at zero*.
    #[allow(clippy::cast_precision_loss)] // permit counts are tiny; matches the crate's other gauge casts
    pub(crate) fn emit_dispatch_permits_available(&self) {
        if let Some(available) = self.dispatch_permits_available() {
            metrics::gauge!("kata_dispatch_permits_available").set(available as f64);
        }
    }

    /// Test/observability accessor: permits currently AVAILABLE on the
    /// dispatch limiter, or `None` when unbounded. `Some(0)` means the cap is
    /// fully in use (the next submission will queue).
    ///
    /// Published as the `kata_dispatch_permits_available` gauge by
    /// [`Self::emit_dispatch_permits_available`], so limiter saturation is
    /// visible to an operator.
    #[must_use]
    pub fn dispatch_permits_available(&self) -> Option<usize> {
        self.dispatch_limiter
            .as_ref()
            .map(|s| s.available_permits())
    }

    /// How many live workers [`Self::select_capsule_worker`] could place a capsule on now:
    /// the scheduler's one eligibility predicate over [`CAPSULE_PLACEMENT`], the arguments
    /// placement passes. A capacity preflight that reads this asks the question placement
    /// asks by construction, not by keeping a second spelling of it in step.
    #[must_use]
    pub fn capsule_worker_count(&self) -> usize {
        let (requirements, containment) = CAPSULE_PLACEMENT;
        self.scheduler
            .eligible_worker_count(requirements, containment)
    }
}

/// Emit the `kata_worker_heartbeat_lag_seconds{worker_id}` gauge for
/// every tracked worker. Factored out of `run_heartbeat_sweep` so the
/// emission is unit-testable without spinning a full dispatcher loop. It
/// covers only the workers the monitor still tracks; a forgotten worker's
/// exported series is not removed and keeps its last value, since the metrics
/// facade has no removal and the recorder sets no idle timeout.
fn emit_heartbeat_lag(heartbeat: &HeartbeatMonitor) {
    for (worker_id, lag_seconds) in heartbeat.lag_seconds() {
        metrics::gauge!(
            "kata_worker_heartbeat_lag_seconds",
            "worker_id" => worker_id.to_string(),
        )
        .set(lag_seconds);
    }
}

/// Read a secret by [`SecretRef`] at dispatch time. `Env` reads the
/// operator's process env; `File` reads the file's contents and
/// trims trailing newlines (file-backed secrets almost always end
/// with one).
fn read_secret(secret: &SecretRef) -> KataResult<String> {
    match secret {
        SecretRef::Env(name) => std::env::var(name).map_err(|_| {
            KataError::Validation(format!(
                "dispatcher: env secret \"{name}\" is not set in the main \
                 process environment. Export it before dispatching or remove \
                 the secret declaration from the profile."
            ))
        }),
        SecretRef::File(path) => {
            let contents = std::fs::read_to_string(path).map_err(|e| {
                KataError::Io(std::io::Error::other(format!(
                    "dispatcher: failed to read file secret at {}: {e}",
                    path.display()
                )))
            })?;
            Ok(contents.trim_end().to_string())
        }
    }
}

#[cfg(test)]
mod worker_assignments_metric_tests {
    //! `kata_worker_assignments_total{status,transport}` is emitted
    //! once per accepted ledger transition (dispatched / completed /
    //! failed / orphaned) through the bookkeeper's `on_event`. These tests
    //! drive the real `on_event` synchronously with constructed
    //! `LedgerEvent`s so no async bookkeeper task is required.

    use std::sync::Arc;
    use std::time::Duration;

    use kata_core::{AssignmentStatus, InFlightLedger, LedgerEvent};
    use kata_transport::heartbeat::HeartbeatMonitor;
    use kata_transport::supervisor::WorkerPoolSupervisor;
    use kata_transport::{InProcessTransport, WorkerTransport};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use smol_str::SmolStr;
    use ulid::Ulid;

    use super::Dispatcher;

    const COUNTER: &str = "kata_worker_assignments_total";

    /// Read the current counter value for a given `status` + `transport`
    /// label pair. Filters by label (not position) because the snapshot
    /// ordering across distinct keys is non-deterministic.
    fn counter_value(snapshotter: &Snapshotter, status: &str, transport: &str) -> Option<u64> {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(key, _, _, _)| {
                key.key().name() == COUNTER
                    && key
                        .key()
                        .labels()
                        .any(|l| l.key() == "status" && l.value() == status)
                    && key
                        .key()
                        .labels()
                        .any(|l| l.key() == "transport" && l.value() == transport)
            })
            .and_then(|(_, _, _, value)| match value {
                DebugValue::Counter(c) => Some(c),
                _ => None,
            })
    }

    /// Build a dispatcher with a single in-process worker `w1` registered,
    /// returning the dispatcher plus the worker-side transport (held alive
    /// by the caller so the main-side `kind()` stays resolvable).
    fn dispatcher_with_worker() -> (Arc<Dispatcher>, InProcessTransport) {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let (home, worker) = InProcessTransport::pair(16);
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_millis(50),
            Duration::from_millis(50),
        ));
        let ledger = InFlightLedger::in_memory();
        let dispatcher = Arc::new(Dispatcher::new(Arc::clone(&supervisor), heartbeat, ledger));
        supervisor.register_worker_with_effect_domain(
            SmolStr::new("w1"),
            Arc::new(home) as Arc<dyn WorkerTransport>,
            Vec::new(),
            crate::test_harness::rig_worker_containment(),
            *crate::test_harness::oci_rig_executor_term().digest(),
            dispatcher
                .enroll_worker_membrane(
                    "dispatch-counter-fixture",
                    kata_types::identity::WorkerMembraneId(Ulid::new()),
                )
                .unwrap(),
        );
        (dispatcher, worker)
    }

    fn event(new_status: AssignmentStatus) -> LedgerEvent {
        LedgerEvent {
            execution_id: Ulid::new(),
            assignment_id: Ulid::new(),
            stage_name: SmolStr::new("only"),
            new_status,
            output: None,
            terminal_charge: None,
        }
    }

    #[test]
    fn counts_terminal_and_dispatch_outcomes_with_transport_label() {
        let (dispatcher, _worker) = dispatcher_with_worker();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(AssignmentStatus::Dispatched {
                worker_id: SmolStr::new("w1"),
            }));
            dispatcher.on_event(&event(AssignmentStatus::Completed {
                worker_id: Some(SmolStr::new("w1")),
            }));
        });

        assert_eq!(
            counter_value(&snapshotter, "dispatched", "in_process"),
            Some(1),
            "a Dispatched transition to a known worker must count once with its transport"
        );
        assert_eq!(
            counter_value(&snapshotter, "completed", "in_process"),
            Some(1),
            "a Completed transition must count once with the worker's transport"
        );
    }

    #[test]
    fn pre_dispatch_failure_and_orphan_count_as_unknown_transport() {
        // Failures/orphans that never reached a worker carry no worker id;
        // the metric must still count them (under transport="unknown")
        // rather than silently drop them on the `worker_id()` lookup.
        let (dispatcher, _worker) = dispatcher_with_worker();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(AssignmentStatus::Failed {
                worker_id: None,
                reason: "no live worker".to_string(),
            }));
            dispatcher.on_event(&event(AssignmentStatus::Orphaned {
                prev_worker: None,
                reason: "retries exhausted".to_string(),
            }));
        });

        assert_eq!(
            counter_value(&snapshotter, "failed", "unknown"),
            Some(1),
            "a pre-dispatch Failed must count under transport=unknown"
        );
        assert_eq!(
            counter_value(&snapshotter, "orphaned", "unknown"),
            Some(1),
            "an Orphaned with no prev_worker must count under transport=unknown"
        );
    }

    /// A CANCEL IS A TERMINAL AND MUST BALANCE ITS `dispatched`.
    ///
    /// `AssignmentStatus::Cancelled` is its own terminal, distinct from `Failed`,
    /// and the emit gate must list it. Without it the cost is not a missing
    /// label — it is an ops dashboard that watches
    /// `dispatched - (completed + failed + orphaned + cancelled)` as an in-flight
    /// estimate and drifts up by one per operator cancel, permanently.
    ///
    /// The pair is asserted TOGETHER, deliberately: a test that only checked for
    /// `status="cancelled"` would pass against a gate that had started counting
    /// everything, and the balance is the property an operator actually reads.
    #[test]
    fn a_cancelled_terminal_counts_and_balances_its_dispatch() {
        let (dispatcher, _worker) = dispatcher_with_worker();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(AssignmentStatus::Dispatched {
                worker_id: SmolStr::new("w1"),
            }));
            dispatcher.on_event(&event(AssignmentStatus::Cancelled {
                worker_id: Some(SmolStr::new("w1")),
                reason: "operator asked for a stop".to_string(),
            }));
        });

        assert_eq!(
            counter_value(&snapshotter, "dispatched", "in_process"),
            Some(1),
            "PRECONDITION: the entry of the worker lifecycle still counts"
        );
        assert_eq!(
            counter_value(&snapshotter, "cancelled", "in_process"),
            Some(1),
            "an operator cancel is a TERMINAL of the worker lifecycle and must emit \
             its counterpart; without it `dispatched - (completed+failed+orphaned)` \
             drifts up by one per cancel and never recovers"
        );
    }

    /// A cancel that never reached a worker counts under `transport=unknown`,
    /// exactly as its `failed`/`orphaned` siblings do — `AssignmentStatus::Cancelled`
    /// carries an `Option` placement for the same reason `Failed` does.
    #[test]
    fn a_cancel_with_no_placement_counts_as_unknown_transport() {
        let (dispatcher, _worker) = dispatcher_with_worker();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(AssignmentStatus::Cancelled {
                worker_id: None,
                reason: "cancelled after its placement was reclaimed".to_string(),
            }));
        });

        assert_eq!(
            counter_value(&snapshotter, "cancelled", "unknown"),
            Some(1),
            "a cancel with no placement must count under transport=unknown rather \
             than being dropped on the `worker_id()` lookup"
        );
    }

    #[test]
    fn non_lifecycle_transitions_do_not_count() {
        // `Running` is neither a dispatch nor a terminal outcome and must
        // not move the assignment-outcome counter.
        let (dispatcher, _worker) = dispatcher_with_worker();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(AssignmentStatus::Running {
                worker_id: SmolStr::new("w1"),
            }));
        });

        assert!(
            snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .all(|(key, _, _, _)| key.key().name() != COUNTER),
            "a Running transition must not emit kata_worker_assignments_total"
        );
    }
}

#[cfg(test)]
mod heartbeat_lag_metric_tests {
    //! `kata_worker_heartbeat_lag_seconds{worker_id}` is emitted for
    //! every tracked worker each sweep tick via `emit_heartbeat_lag`.

    use std::time::Duration;

    use kata_transport::heartbeat::HeartbeatMonitor;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

    use super::emit_heartbeat_lag;

    const GAUGE: &str = "kata_worker_heartbeat_lag_seconds";

    fn lag_for_worker(snapshotter: &Snapshotter, worker_id: &str) -> Option<f64> {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(key, _, _, _)| {
                key.key().name() == GAUGE
                    && key
                        .key()
                        .labels()
                        .any(|l| l.key() == "worker_id" && l.value() == worker_id)
            })
            .and_then(|(_, _, _, value)| match value {
                DebugValue::Gauge(g) => Some(g.into_inner()),
                _ => None,
            })
    }

    #[test]
    fn emits_a_lag_series_per_tracked_worker() {
        let monitor = HeartbeatMonitor::new(Duration::from_millis(50), Duration::from_millis(50));
        monitor.record_heartbeat("w1");
        monitor.record_heartbeat("w2");

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || emit_heartbeat_lag(&monitor));

        let lag_w1 =
            lag_for_worker(&snapshotter, "w1").expect("a heartbeat-lag series must exist for w1");
        let lag_w2 =
            lag_for_worker(&snapshotter, "w2").expect("a heartbeat-lag series must exist for w2");
        assert!(lag_w1 >= 0.0, "lag is a non-negative elapsed duration");
        assert!(lag_w2 >= 0.0, "lag is a non-negative elapsed duration");
    }

    #[test]
    fn no_workers_emits_no_series() {
        let monitor = HeartbeatMonitor::new(Duration::from_millis(50), Duration::from_millis(50));
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || emit_heartbeat_lag(&monitor));

        assert!(
            snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .all(|(key, _, _, _)| key.key().name() != GAUGE),
            "no tracked workers must emit no heartbeat-lag series"
        );
    }
}

#[cfg(test)]
mod admission_control_tests {
    //! `max_concurrent_dispatches` is wired to a REAL dispatch limiter. With a
    //! cap of N, at most N fresh submissions run their insert+dispatch section at
    //! once and the excess QUEUES gracefully (not a connection-mutex convoy, not
    //! a drop). These drive both the limiter primitive
    //! (`acquire_dispatch_permit` — the exact seam the real path gates on) and
    //! the real capsule submit path.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use kata_core::InFlightLedger;
    use kata_transport::heartbeat::HeartbeatMonitor;
    use kata_transport::supervisor::WorkerPoolSupervisor;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

    use super::Dispatcher;

    fn dispatcher_with_limit(n: usize) -> Arc<Dispatcher> {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_millis(50),
            Duration::from_millis(50),
        ));
        let ledger = InFlightLedger::in_memory();
        Arc::new(Dispatcher::new(supervisor, heartbeat, ledger).with_max_concurrent_dispatches(n))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn limiter_bounds_concurrency_and_queues_the_excess() {
        const N: usize = 3;
        const EXTRA: usize = 5;
        let dispatcher = dispatcher_with_limit(N);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..(N + EXTRA) {
            let d = Arc::clone(&dispatcher);
            let in_flight = Arc::clone(&in_flight);
            let peak = Arc::clone(&peak);
            let completed = Arc::clone(&completed);
            handles.push(tokio::spawn(async move {
                let permit = d.acquire_dispatch_permit().await;
                assert!(permit.is_some(), "a configured limiter must issue a permit");
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                // Hold long enough that all N+EXTRA tasks overlap in time, so the
                // excess must actually queue on the semaphore.
                tokio::time::sleep(Duration::from_millis(50)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
                drop(permit);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            peak.load(Ordering::SeqCst) <= N,
            "at most N={N} submissions may hold a permit at once, saw peak {}",
            peak.load(Ordering::SeqCst)
        );
        assert_eq!(
            completed.load(Ordering::SeqCst),
            N + EXTRA,
            "every submission — including the queued excess — must eventually run"
        );
        assert_eq!(
            dispatcher.dispatch_permits_available(),
            Some(N),
            "all permits are released once the submissions complete"
        );
    }

    #[tokio::test]
    async fn unbounded_dispatcher_issues_no_permit() {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_millis(50),
            Duration::from_millis(50),
        ));
        let ledger = InFlightLedger::in_memory();
        // No `with_max_concurrent_dispatches` ⇒ unbounded.
        let dispatcher = Dispatcher::new(supervisor, heartbeat, ledger);
        assert_eq!(dispatcher.dispatch_permits_available(), None);
        assert!(
            dispatcher.acquire_dispatch_permit().await.is_none(),
            "an unbounded dispatcher must not gate submissions"
        );
    }

    #[tokio::test]
    async fn real_submit_path_blocks_on_exhausted_limiter() {
        // The cap's REAL seam is the capsule submit: `submit_stage_as_capsule`
        // acquires the permit around authorize+deliver, so a saturated limiter blocks
        // BEFORE the attempt's claim transaction — "no row, nothing sent".
        let dir = tempfile::tempdir().unwrap();
        let rig = crate::test_harness::OciNodeRig::open_with_caps_and_dispatch_limit(
            dir.path(),
            &["sh"],
            vec!["agent:shell".to_owned()],
            Some(1),
        );
        rig.declare_bound_environment();
        let program = kata_program::execution_program::compile_starlark_execution_program(
            "only = stage(id = \"only\", run = \"echo hi\")\nworkflow(\"cap\", root = only)\n",
            "cap.star",
            &[],
        )
        .expect("the fixture program checks");
        let execution_id = ulid::Ulid::new();
        let runner = rig.runner(&program, execution_id);
        let directive = rig.directive(&program, "only", execution_id).await;

        // Exhaust the single permit and HOLD it.
        let held = dispatcher_with_limit_acquires(&rig.dispatcher).await;
        assert_eq!(rig.dispatcher.dispatch_permits_available(), Some(0));

        let stage_name = smol_str::SmolStr::new("only");
        let command = crate::capsule_assembly::RenderedCommand::rendered("echo hi".to_owned());
        let submit = runner.submit_stage_as_capsule_for_test(&stage_name, directive, &command);
        let timed = tokio::time::timeout(Duration::from_millis(150), submit).await;
        assert!(
            timed.is_err(),
            "the capsule submit must block while the limiter is exhausted, got {timed:?}"
        );
        assert!(
            !rig.dispatcher
                .execution_stage_states(execution_id)
                .expect("the rig nucleus admits this execution, so the chain read SUCCEEDS")
                .iter()
                .any(|state| state.stage_name.as_str() == "only"),
            "a submission blocked at admission control must not have claimed the attempt"
        );

        // Releasing the held permit frees the cap again (graceful, not a drop).
        drop(held);
        assert_eq!(
            rig.dispatcher.dispatch_permits_available(),
            Some(1),
            "the permit is returned to the limiter on release"
        );
    }

    async fn dispatcher_with_limit_acquires(
        dispatcher: &Dispatcher,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let permit = dispatcher.acquire_dispatch_permit().await;
        assert!(permit.is_some());
        permit
    }

    /// `dispatch_permits_available()` had ZERO production readers, so limiter
    /// saturation was invisible to an operator: the one knob whose whole purpose
    /// is overload backpressure published nothing when it engaged. The
    /// `kata_dispatch_permits_available` gauge closes that.
    ///
    /// Drives the real `acquire_dispatch_permit` seam (the exact primitive
    /// `submit_stage_as_capsule` gates on) rather than calling the emitter
    /// directly, so the test fails if the emission is unwired from acquisition.
    ///
    /// Sync `#[test]` with an explicit current-thread runtime because
    /// `metrics::with_local_recorder` takes a SYNC closure — the recorder must be
    /// installed across the whole `block_on`, not merely across the poll that
    /// happens to complete the future.
    #[test]
    fn permit_acquisition_publishes_the_saturation_gauge() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let dispatcher = dispatcher_with_limit(2);
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        assert_eq!(
            permits_gauge(&snapshotter),
            None,
            "no series before any acquisition"
        );

        let first = metrics::with_local_recorder(&recorder, || {
            runtime.block_on(dispatcher.acquire_dispatch_permit())
        });
        assert_eq!(
            permits_gauge(&snapshotter),
            Some(1.0),
            "one of two permits taken leaves one available"
        );

        let second = metrics::with_local_recorder(&recorder, || {
            runtime.block_on(dispatcher.acquire_dispatch_permit())
        });
        assert_eq!(
            permits_gauge(&snapshotter),
            Some(0.0),
            "SATURATED: the cap is fully in use and the next submission will queue"
        );

        // The sweep-tick refresh is what returns a quiesced dispatcher's gauge to
        // the full cap; without it the gauge would latch at its last busy reading.
        drop(first);
        drop(second);
        metrics::with_local_recorder(&recorder, || dispatcher.emit_dispatch_permits_available());
        assert_eq!(
            permits_gauge(&snapshotter),
            Some(2.0),
            "an idle dispatcher reports the full configured cap"
        );
    }

    /// An UNBOUNDED dispatcher must publish NO series — "no cap configured" and
    /// "cap at zero" are different operator situations and must not collapse to
    /// the same reading.
    #[test]
    fn unbounded_dispatcher_publishes_no_saturation_gauge() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_millis(50),
            Duration::from_millis(50),
        ));
        let ledger = InFlightLedger::in_memory();
        let dispatcher = Dispatcher::new(supervisor, heartbeat, ledger);
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();

        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(dispatcher.acquire_dispatch_permit())
        });
        assert_eq!(
            permits_gauge(&snapshotter),
            None,
            "an unbounded dispatcher has no cap to report saturation against"
        );
    }

    fn permits_gauge(snapshotter: &Snapshotter) -> Option<f64> {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(key, _, _, _)| key.key().name() == "kata_dispatch_permits_available")
            .and_then(|(_, _, _, value)| match value {
                DebugValue::Gauge(g) => Some(g.into_inner()),
                _ => None,
            })
    }
}

#[cfg(test)]
mod queue_plane_metrics_tests {
    //! The main-side dispatch-plane metrics
    //! (`kata_worker_queue_depth`, `kata_worker_submit_to_dispatch_seconds`,
    //! `kata_worker_dispatch_to_start_seconds`) are folded off the SAME accepted
    //! ledger-transition stream `on_event` already consumes, so these drive the
    //! real `on_event` synchronously with constructed `LedgerEvent`s.
    //!
    //! `kata_worker_inflight_depth` is tested here rather than in its own module,
    //! because the property that matters is the one BETWEEN the two gauges: what
    //! the queue gauge stops counting at `Dispatched` is exactly what the
    //! in-flight gauge starts counting, so a test that read only one of them
    //! could not see a backlog fall between them.

    use std::sync::Arc;
    use std::time::Duration;

    use kata_core::{AssignmentStatus, InFlightLedger, LedgerEvent};
    use kata_transport::heartbeat::HeartbeatMonitor;
    use kata_transport::supervisor::WorkerPoolSupervisor;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use smol_str::SmolStr;
    use ulid::Ulid;

    use super::Dispatcher;

    fn dispatcher() -> Arc<Dispatcher> {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let heartbeat = Arc::new(HeartbeatMonitor::new(
            Duration::from_millis(50),
            Duration::from_millis(50),
        ));
        let ledger = InFlightLedger::in_memory();
        Arc::new(Dispatcher::new(supervisor, heartbeat, ledger))
    }

    fn event(id: Ulid, new_status: AssignmentStatus) -> LedgerEvent {
        LedgerEvent {
            execution_id: Ulid::new(),
            assignment_id: id,
            stage_name: SmolStr::new("only"),
            new_status,
            output: None,
            terminal_charge: None,
        }
    }

    fn gauge_value(snapshotter: &Snapshotter, name: &str) -> Option<f64> {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(key, _, _, _)| key.key().name() == name)
            .and_then(|(_, _, _, value)| match value {
                DebugValue::Gauge(g) => Some(g.into_inner()),
                _ => None,
            })
    }

    /// Read a gauge + a histogram sample count from a SINGLE snapshot.
    ///
    /// `Snapshotter::snapshot()` DRAINS histogram samples, so a phase that wants
    /// both a gauge and a just-recorded histogram must read them from one
    /// snapshot — two `snapshot()` calls would let the first drain the samples
    /// the second is looking for. Gauges are last-value (survive the drain);
    /// histograms accumulate between snapshots and reset at each one.
    fn gauge_and_hist(
        snapshotter: &Snapshotter,
        gauge: &str,
        histogram: &str,
    ) -> (Option<f64>, usize) {
        let snap = snapshotter.snapshot().into_vec();
        let gauge_value = snap
            .iter()
            .find(|(key, _, _, _)| key.key().name() == gauge)
            .and_then(|(_, _, _, value)| match value {
                DebugValue::Gauge(g) => Some(g.0),
                _ => None,
            });
        let hist_count: usize = snap
            .iter()
            .filter(|(key, _, _, _)| key.key().name() == histogram)
            .map(|(_, _, _, value)| match value {
                DebugValue::Histogram(samples) => samples.len(),
                _ => 0,
            })
            .sum();
        (gauge_value, hist_count)
    }

    #[test]
    fn queue_depth_and_latencies_track_the_assignment_lifecycle() {
        let dispatcher = dispatcher();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let id = Ulid::new();

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(id, AssignmentStatus::Pending));
        });
        // One snapshot per phase: gauge + the phase's histogram together, because
        // the snapshot drains histogram samples.
        let (depth, submit_hits) = gauge_and_hist(
            &snapshotter,
            "kata_worker_queue_depth",
            "kata_worker_submit_to_dispatch_seconds",
        );
        assert_eq!(
            depth,
            Some(1.0),
            "a Pending assignment enqueues one onto the main-side queue"
        );
        assert_eq!(
            submit_hits, 0,
            "no submit→dispatch sample before the first dispatch"
        );

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(
                id,
                AssignmentStatus::Dispatched {
                    worker_id: SmolStr::new("w1"),
                },
            ));
        });
        let (depth, submit_hits) = gauge_and_hist(
            &snapshotter,
            "kata_worker_queue_depth",
            "kata_worker_submit_to_dispatch_seconds",
        );
        assert_eq!(depth, Some(0.0), "Dispatched dequeues the assignment");
        assert_eq!(
            submit_hits, 1,
            "the submit→dispatch queue wait is recorded once on first dispatch"
        );

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(
                id,
                AssignmentStatus::Running {
                    worker_id: SmolStr::new("w1"),
                },
            ));
        });
        let (_, start_hits) = gauge_and_hist(
            &snapshotter,
            "kata_worker_queue_depth",
            "kata_worker_dispatch_to_start_seconds",
        );
        assert_eq!(
            start_hits, 1,
            "the dispatch→start latency is recorded once when the worker starts"
        );

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(
                id,
                AssignmentStatus::Completed {
                    worker_id: Some(SmolStr::new("w1")),
                },
            ));
        });
        assert_eq!(
            gauge_value(&snapshotter, "kata_worker_queue_depth"),
            Some(0.0),
            "a terminal transition after dispatch must not double-decrement the depth"
        );
    }

    #[test]
    fn orphan_before_dispatch_releases_the_queue_slot() {
        let dispatcher = dispatcher();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let id = Ulid::new();

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(id, AssignmentStatus::Pending));
            dispatcher.on_event(&event(
                id,
                AssignmentStatus::Orphaned {
                    prev_worker: None,
                    reason: "no live worker".to_string(),
                },
            ));
        });
        assert_eq!(
            gauge_value(&snapshotter, "kata_worker_queue_depth"),
            Some(0.0),
            "an assignment orphaned before any dispatch must release its queue slot"
        );
    }

    /// Read one `kata_worker_inflight_depth{worker_id,status}` series.
    ///
    /// `None` means the series was never touched, which is a DIFFERENT
    /// observation from `Some(0.0)` (touched and released) and the tests below
    /// depend on the difference.
    fn inflight(snapshotter: &Snapshotter, worker_id: &str, status: &str) -> Option<f64> {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(key, _, _, _)| {
                key.key().name() == super::INFLIGHT_DEPTH_GAUGE
                    && key
                        .key()
                        .labels()
                        .any(|l| l.key() == "worker_id" && l.value() == worker_id)
                    && key
                        .key()
                        .labels()
                        .any(|l| l.key() == "status" && l.value() == status)
            })
            .and_then(|(_, _, _, value)| match value {
                DebugValue::Gauge(g) => Some(g.into_inner()),
                _ => None,
            })
    }

    fn dispatch_to(worker: &str) -> AssignmentStatus {
        AssignmentStatus::Dispatched {
            worker_id: SmolStr::new(worker),
        }
    }

    /// The backlog behind a worker is COUNTABLE, and the count MOVES with it.
    ///
    /// A cap nobody can see in a gauge is a cap nobody can tune:
    /// `kata_worker_queue_depth` decrements on `Dispatched`, so the dispatched
    /// population would grow where that gauge reads zero. This asserts the two gauges hand the
    /// assignment to each other — at the mid-point the queue reads 0 while
    /// three assignments are demonstrably still the main's problem.
    #[test]
    fn inflight_depth_counts_the_backlog_the_queue_gauge_hands_off() {
        let dispatcher = dispatcher();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let ids: Vec<Ulid> = (0..3).map(|_| Ulid::new()).collect();

        metrics::with_local_recorder(&recorder, || {
            for id in &ids {
                dispatcher.on_event(&event(*id, AssignmentStatus::Pending));
            }
        });
        assert_eq!(
            gauge_value(&snapshotter, "kata_worker_queue_depth"),
            Some(3.0),
            "three submitted assignments are three deep on the main-side queue"
        );
        assert_eq!(
            inflight(&snapshotter, "w1", "dispatched"),
            None,
            "nothing has been handed to a worker yet, so no in-flight series exists"
        );

        // Hand all three to one worker, one at a time, and watch the count RISE.
        for (handed, id) in ids.iter().enumerate() {
            metrics::with_local_recorder(&recorder, || {
                dispatcher.on_event(&event(*id, dispatch_to("w1")));
            });
            #[allow(clippy::cast_precision_loss)] // 0..3
            let expected = (handed + 1) as f64;
            assert_eq!(
                inflight(&snapshotter, "w1", "dispatched"),
                Some(expected),
                "the in-flight depth must track each hand-off, not merely exist"
            );
        }
        assert_eq!(
            gauge_value(&snapshotter, "kata_worker_queue_depth"),
            Some(0.0),
            "the queue is empty — the queue gauge reads `0` while the dispatched \
             backlog is non-zero"
        );
        assert_eq!(
            inflight(&snapshotter, "w1", "dispatched"),
            Some(3.0),
            "and the backlog it handed off is now three, on the worker holding it"
        );

        // ... and FALL as the worker drains it.
        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(
                ids[0],
                AssignmentStatus::Completed {
                    worker_id: Some(SmolStr::new("w1")),
                },
            ));
        });
        assert_eq!(
            inflight(&snapshotter, "w1", "dispatched"),
            Some(2.0),
            "a completion releases exactly one charge"
        );

        metrics::with_local_recorder(&recorder, || {
            for id in &ids[1..] {
                dispatcher.on_event(&event(
                    *id,
                    AssignmentStatus::Completed {
                        worker_id: Some(SmolStr::new("w1")),
                    },
                ));
            }
        });
        assert_eq!(
            inflight(&snapshotter, "w1", "dispatched"),
            Some(0.0),
            "a drained worker returns to zero — the series never latches at its \
             busiest reading"
        );
    }

    /// A SATURATED worker and a worker that took work and started
    /// nothing are different readings, not the same one.
    ///
    /// Both hold three assignments the main handed off, so a total-only
    /// in-flight count says the same thing about both. The `status` split is
    /// what separates them: `w1` has acknowledged one and is executing it;
    /// `w2` has acknowledged nothing.
    #[test]
    fn a_saturated_worker_reads_differently_from_one_that_started_nothing() {
        let dispatcher = dispatcher();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let busy: Vec<Ulid> = (0..3).map(|_| Ulid::new()).collect();
        let stuck: Vec<Ulid> = (0..3).map(|_| Ulid::new()).collect();

        metrics::with_local_recorder(&recorder, || {
            for id in &busy {
                dispatcher.on_event(&event(*id, AssignmentStatus::Pending));
                dispatcher.on_event(&event(*id, dispatch_to("w1")));
            }
            // w1 acknowledges the first and starts running it.
            dispatcher.on_event(&event(
                busy[0],
                AssignmentStatus::Running {
                    worker_id: SmolStr::new("w1"),
                },
            ));
            for id in &stuck {
                dispatcher.on_event(&event(*id, AssignmentStatus::Pending));
                dispatcher.on_event(&event(*id, dispatch_to("w2")));
            }
            // w2 acknowledges nothing.
        });

        assert_eq!(
            inflight(&snapshotter, "w1", "running"),
            Some(1.0),
            "a saturated worker is EXECUTING one of the assignments it holds"
        );
        assert_eq!(
            inflight(&snapshotter, "w1", "dispatched"),
            Some(2.0),
            "and the rest of its backlog is queued behind that one"
        );
        assert_eq!(
            inflight(&snapshotter, "w2", "dispatched"),
            Some(3.0),
            "the second worker holds just as much work"
        );
        assert_eq!(
            inflight(&snapshotter, "w2", "running"),
            None,
            "but has acknowledged NONE of it — the reading that separates a \
             worker that is busy from one that is not answering"
        );
        assert_ne!(
            inflight(&snapshotter, "w1", "running"),
            inflight(&snapshotter, "w2", "running"),
            "the two shapes must not be the same reading; an operator paging on \
             one must not be looking at the other"
        );
    }

    /// A requeue moves the charge BACK to the queue rather than
    /// leaving it on the worker that no longer holds the work. Nothing is
    /// counted twice and nothing is dropped.
    #[test]
    fn a_requeue_returns_the_charge_from_the_worker_to_the_queue() {
        let dispatcher = dispatcher();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let id = Ulid::new();

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(id, AssignmentStatus::Pending));
            dispatcher.on_event(&event(id, dispatch_to("w1")));
        });
        assert_eq!(inflight(&snapshotter, "w1", "dispatched"), Some(1.0));
        assert_eq!(
            gauge_value(&snapshotter, "kata_worker_queue_depth"),
            Some(0.0)
        );

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(id, AssignmentStatus::Pending));
        });
        assert_eq!(
            inflight(&snapshotter, "w1", "dispatched"),
            Some(0.0),
            "a requeued assignment is no longer this worker's backlog"
        );
        assert_eq!(
            gauge_value(&snapshotter, "kata_worker_queue_depth"),
            Some(1.0),
            "it is the queue's again — one assignment, one charge, never both"
        );
    }

    /// The work a DEAD worker was holding leaves its series when the
    /// death sweep orphans it, and lands on the worker that takes it over.
    ///
    /// Without this the gauge would pin a dead worker's backlog forever and
    /// the fleet total would drift up by one per death — a saturation reading
    /// that is pure history.
    #[test]
    fn a_dead_workers_backlog_migrates_instead_of_pinning_its_series() {
        let dispatcher = dispatcher();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let migrated = Ulid::new();
        let lost = Ulid::new();

        metrics::with_local_recorder(&recorder, || {
            for id in [migrated, lost] {
                dispatcher.on_event(&event(id, AssignmentStatus::Pending));
                dispatcher.on_event(&event(id, dispatch_to("w1")));
            }
            dispatcher.on_event(&event(
                migrated,
                AssignmentStatus::Running {
                    worker_id: SmolStr::new("w1"),
                },
            ));
        });
        assert_eq!(inflight(&snapshotter, "w1", "running"), Some(1.0));
        assert_eq!(inflight(&snapshotter, "w1", "dispatched"), Some(1.0));

        metrics::with_local_recorder(&recorder, || {
            // w1 died: one assignment is re-placed onto w2, the other is orphaned.
            dispatcher.on_event(&event(migrated, dispatch_to("w2")));
            dispatcher.on_event(&event(
                lost,
                AssignmentStatus::Orphaned {
                    prev_worker: Some(SmolStr::new("w1")),
                    reason: "worker died".to_string(),
                },
            ));
        });

        assert_eq!(
            inflight(&snapshotter, "w1", "running"),
            Some(0.0),
            "the re-placed assignment left the dead worker's running series"
        );
        assert_eq!(
            inflight(&snapshotter, "w1", "dispatched"),
            Some(0.0),
            "and the orphaned one left its dispatched series"
        );
        assert_eq!(
            inflight(&snapshotter, "w2", "dispatched"),
            Some(1.0),
            "the surviving worker now carries the work, charged exactly once"
        );
    }

    /// A parked assignment is on no queue and no worker, and the
    /// gauges say so. `AwaitingChildCompletion` carries NO worker id, so a
    /// release that re-derived the series from the event would leak the charge.
    #[test]
    fn a_parked_child_wait_holds_neither_a_queue_slot_nor_a_worker_charge() {
        let dispatcher = dispatcher();
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let id = Ulid::new();

        metrics::with_local_recorder(&recorder, || {
            dispatcher.on_event(&event(id, AssignmentStatus::Pending));
            dispatcher.on_event(&event(id, dispatch_to("w1")));
            dispatcher.on_event(&event(
                id,
                AssignmentStatus::AwaitingChildCompletion {
                    child_execution_id: Ulid::new(),
                    reason: "child workflow".to_string(),
                },
            ));
        });

        assert_eq!(
            inflight(&snapshotter, "w1", "dispatched"),
            Some(0.0),
            "a parked child wait un-dispatches: the worker is no longer charged for it"
        );
        assert_eq!(
            gauge_value(&snapshotter, "kata_worker_queue_depth"),
            Some(0.0),
            "and it is not back on the queue either"
        );
    }
}
