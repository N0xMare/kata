//! `WorkflowRunner` — chain-driven workflow execution loop.
//!
//! The runner is a thin shell around three ideas:
//!
//! 1. **Select ready static stages** — use the retained checked
//!    `ExecutionProgram` dependency graph, then promote matching
//!    orchestrator states to `Ready`.
//! 2. **Dispatch capsules** — assemble each execute-shaped stage into a
//!    `DispatchFrame::Capsule`, authorize it on the operational transition
//!    chain, and hand it to the dispatcher for delivery. Typed lowered
//!    operations that resolve on the main side (joins, waits, invokes,
//!    workspace effects, expansions, memory snapshots) never leave the
//!    runner; they land as main-side chain transitions.
//! 3. **Fold chain events** — apply the operational chain's terminal and
//!    main-resolved frames to the orchestrator, filtered by `execution_id`.
//!
//! The runner is intentionally program-backed. It has no raw
//! `WorkflowDefinition` constructor and no direct worker transport handle.
//! The dispatcher owns capsule delivery and durable authority; the
//! operational chain is the deciding read for attempt lifecycle.
//!
//! ## Execution id vs run id
//!
//! The runner is constructed with an `execution_id: Ulid` that the
//! executor passes in. It scopes every chain admission, occurrence, and
//! ledger row this run writes, so the fold only ever sees this run's own
//! frames.
//!
//! ## Module layout
//!
//! This file hosts the struct definition, constructors, and the small
//! fold-time helpers. Larger method groupings live in sibling submodules:
//!
//! * [`dispatch`] — capsule submission and reuse, main-resolved routing,
//!   child invocation, validation/failure retries, and synthetic evidence.
//! * [`drive`] — the main `run()` loop: authority-chain wake handling, pure
//!   fold boot, action-queue drains, recovery.
//! * [`expansion`] — durable claim-and-drive for bounded/dynamic expansions.
//! * [`cache`] — stage-cache admission and write-back drain.
//! * [`json`] — pure JSON helpers for the structured-output validator
//!   (`validate_and_inject_parsed`, type check tables).
//!
//! All `impl WorkflowRunner` blocks share a single struct via Rust's
//! multi-impl-block support; submodules expose their methods through
//! `pub(super)` (or `pub(crate)` where the API surface crosses file
//! boundaries), so callers `use kata_workflow::runner::WorkflowRunner;` alone.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use kata_core::store::{SqliteNativeMemoryStore, SqliteWorkflowStore};
use kata_types::error::{KataError, KataResult};
use kata_types::workflow::StageId;
use parking_lot::RwLock;
use smol_str::SmolStr;
use ulid::Ulid;

use crate::dispatcher::Dispatcher;
use kata_program::execution_program::ExecutionProgram;
use kata_program::orchestrator::{Orchestrator, StageState};

mod apply_event;
mod branch_routes;
mod budget;
mod dispatch;
mod drive;
mod effect;
mod expansion;
mod input_wait;
mod json;
mod resume_authority;
mod select;
mod work_apply;

pub use dispatch::invoke::{ChildInvocation, ChildInvoker};

/// Suffix of the synthetic reserved-metadata row that records a
/// branch-routing skip. A row named `"<target>#branch-skip"` is a durable
/// marker that the live routing path marked `<target>` Skipped; it is NEVER a
/// real stage (the `#` sentinel is reserved for synthetic names, exactly as
/// `#branch-failure` / `#bound-halt-time` / `#iter-N` are, so a real stage name
/// can never collide).
// The WALK-AWAY halt-row markers and their predicate live in
// [`kata_types::bound`], not here. Five sites across two crates depend on those
// names agreeing — this module's writer and its once-per-execution idempotence
// read, the fold's walk-away latch, its terminal-outcome read, and `kata-api`'s
// record projection — so the lowest shared crate is the only place "one
// spelling" is enforceable. See [`kata_types::bound::is_walkaway_halt_row`].
use kata_types::bound::{BOUND_HALT_MARKER_INFIX, BUDGET_HALT_MARKER_SUFFIX};

fn is_reserved_execution_metadata_stage(stage_name: &str) -> bool {
    // `__workflow__` is the workflow-level failure row — filtered from
    // normal-stage handling (in-flight counts, generic apply_event dispatch).
    stage_name == "__workflow__"
}

/// Observability: RAII balance for the `kata_workflow_active_count`
/// gauge (the count of currently executing workflows).
///
/// Constructed at the top of [`WorkflowRunner::run`] and held for the
/// lifetime of the run future, so the gauge increments when a run starts
/// and decrements when the run future ends **for any reason** — normal
/// completion, an early `?` error return, a panic unwind, or future
/// cancellation (e.g. the `run_agent` timeout dropping the `run()`
/// future mid-flight). Balancing on `Drop` rather than on a single
/// "happy path" decrement is what makes the gauge leak-free: a gauge
/// that only decrements on success drifts upward every time a run fails
/// or is cancelled.
///
/// Placing the guard inside `run()` (rather than at each executor spawn
/// site) means every caller — fresh submit, post-restart resume,
/// and `run_agent` on the installed main — is covered by one
/// site with one invariant.
struct ActiveWorkflowGuard;

impl ActiveWorkflowGuard {
    fn new() -> Self {
        metrics::gauge!("kata_workflow_active_count").increment(1.0);
        Self
    }
}

impl Drop for ActiveWorkflowGuard {
    fn drop(&mut self) {
        metrics::gauge!("kata_workflow_active_count").decrement(1.0);
    }
}

/// Test-only re-exports for `runner` internals. `validate_and_inject_parsed`
/// is `pub(crate)` for production callers, and integration tests reach it
/// through the wrapper below. `BudgetTracker` is re-exported here for the
/// `budget_metrics_tests` integration test.
#[doc(hidden)]
pub mod testing {
    pub use super::budget::BudgetTracker;

    use kata_types::KataResult;
    #[cfg(any(test, feature = "test-support"))]
    use kata_types::workflow::StageId;
    use kata_types::workflow::StageOutput;
    use smol_str::SmolStr;
    #[cfg(any(test, feature = "test-support"))]
    use ulid::Ulid;

    /// Forwarding wrapper for `super::json::validate_and_inject_parsed`.
    pub fn validate_and_inject_parsed(
        stage_name: &SmolStr,
        outputs: &[StageOutput],
        envelope: serde_json::Value,
    ) -> KataResult<serde_json::Value> {
        super::json::validate_and_inject_parsed(stage_name, outputs, envelope)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn inject_parsed_if_declared_for_test(
        runner: &super::WorkflowRunner,
        stage_name: &str,
        assignment_id: Ulid,
        envelope: serde_json::Value,
    ) -> KataResult<bool> {
        match runner.inject_parsed_if_declared(
            &SmolStr::new(stage_name),
            assignment_id,
            envelope,
        )? {
            super::dispatch::InjectOutcome::Augmented(_) => Ok(false),
            super::dispatch::InjectOutcome::QueuedRetry => Ok(true),
        }
    }

    /// The queued validation retries as `(base, attempt)` pairs — the dedup's
    /// content, not just its count: a doubled queue holds two seats of one
    /// retry, which a count cannot tell from two stages' first retries.
    #[cfg(any(test, feature = "test-support"))]
    pub fn pending_validate_retries_for_test(runner: &super::WorkflowRunner) -> Vec<(String, u32)> {
        runner
            .pending_validate_retries
            .read()
            .iter()
            .map(|retry| (retry.base.to_string(), retry.attempt))
            .collect()
    }

    /// The fold's `capsule_failure_retry` decision for `stage_name`'s failed
    /// attempt — `true` when it answers `Retrying` — exposed so a cell can
    /// drive a re-fold exactly as the broadcast-plus-resync pair does.
    #[cfg(any(test, feature = "test-support"))]
    pub fn capsule_failure_retry_for_test(
        runner: &super::WorkflowRunner,
        stage_name: &str,
        assignment_id: Ulid,
        reason: &str,
    ) -> KataResult<bool> {
        Ok(matches!(
            runner.capsule_failure_retry(
                &SmolStr::new(stage_name),
                assignment_id,
                reason,
                kata_types::time::now_ms(),
            )?,
            super::dispatch::FailureRetryDecision::Retrying
        ))
    }

    /// The queued failure retries as `(base, attempt)` pairs, as
    /// [`Self::pending_validate_retries_for_test`] reads the validation queue.
    #[cfg(any(test, feature = "test-support"))]
    pub fn pending_failure_retries_for_test(runner: &super::WorkflowRunner) -> Vec<(String, u32)> {
        runner
            .pending_failure_retries
            .read()
            .iter()
            .map(|retry| (retry.base.to_string(), retry.attempt))
            .collect()
    }

    /// The successor gate's answer for `stage`: whether its successors stay
    /// gated on an un-landed `/work` apply — the predicate a cell pins without
    /// a whole drive.
    #[cfg(any(test, feature = "test-support"))]
    pub fn work_apply_blocks_successors_for_test(
        runner: &super::WorkflowRunner,
        stage: &str,
    ) -> KataResult<bool> {
        runner.work_apply_blocks_successors(&StageId(SmolStr::new(stage)))
    }
}

/// Close-the-loop seam: apply one completed loop iteration's declared
/// memory writebacks immediately, so the NEXT iteration's live selector reads see
/// them (iteration N+1 reads a fact iteration N wrote).
///
/// The writeback machinery (proposal-build + contract validation + revision-CAS)
/// lives in kata-api's executor; this trait is the inversion seam that lets the
/// kata-workflow runner drive it without depending on kata-api. The runner calls
/// [`Self::on_iteration_complete`] for iteration `N` right before dispatching
/// iteration `N+1`'s first stage; the final iteration is reconciled by the
/// (idempotent) terminal writeback at run-end, so this is purely an
/// earlier-visibility hook — never the sole writeback path.
pub trait IterationWritebackHook: Send + Sync {
    /// Apply the declared memory writebacks produced by the stages of
    /// `completed_iteration` (their `#iter-N` ledger assignments are recorded by
    /// the time this is called). Idempotent: re-invocation (crash-resume, or the
    /// terminal pass) re-applies already-written objects as no-ops via the
    /// revision-CAS. Returns the number of objects newly applied.
    fn on_iteration_complete(&self, completed_iteration: u32) -> KataResult<usize>;
}

/// A runner's per-execution working tree ([`WorkflowRunner::with_working_tree`]).
#[derive(Clone, Debug)]
pub(super) enum WorkingTree {
    /// The run is not `worktree_isolated`: it has none.
    NotIsolated,
    /// The live workspace at this path, until the run's own `park`/`promote`
    /// removes it.
    At(std::path::PathBuf),
    /// Resumed after the run's own `park`/`promote` removed it.
    Removed,
}

impl WorkingTree {
    /// The workspace's path, `None` when the run has none or resumed after its
    /// removal.
    pub(super) fn path(&self) -> Option<&std::path::Path> {
        match self {
            Self::At(path) => Some(path),
            Self::NotIsolated | Self::Removed => None,
        }
    }

    /// Whether the run HAD a working tree that is gone now.
    pub(super) fn is_removed(&self) -> bool {
        match self {
            Self::At(path) => !path.exists(),
            Self::Removed => true,
            Self::NotIsolated => false,
        }
    }
}

/// Drives a workflow to completion by dispatching ready stages as capsules and
/// folding chain events filtered by the runner's `execution_id`.
pub struct WorkflowRunner {
    pub(super) orchestrator: Orchestrator,
    pub(super) dispatcher: Arc<Dispatcher>,
    pub(super) execution_id: Ulid,
    /// Optional per-stage cache store. When set, stages with a
    /// non-`Disabled` [`kata_types::cache::CachePolicy`] consult the
    /// store before dispatching; on a hit the stage is satisfied from
    /// the recorded result and no capsule is delivered. On a miss, the
    /// output is written back into the store as soon as the chain
    /// reports completion.
    pub(super) cache_store: Option<Arc<SqliteWorkflowStore>>,
    /// Native memory store used to materialize checked `memory_selectors` into
    /// stage prompt context packets.
    pub(super) memory_store: Option<Arc<SqliteNativeMemoryStore>>,
    /// The execution's memory base scope. When `Some`,
    /// every memory selector read is restricted to this scope's visibility window
    /// (`base.ancestors_inclusive()` — the scope itself plus its strict ancestors),
    /// so a run scoped to workflow A never reads a sibling workflow B's objects.
    /// `None` keeps flat visibility (every scope visible) — the
    /// factory/operator default, which every shipped pack relies on because all
    /// runtime writebacks land at `Global`. Set via
    /// [`WorkflowRunner::with_memory_scope`].
    pub(super) memory_scope: Option<kata_types::memory::MemoryScope>,
    /// Close-the-loop hook. When a loop iteration completes (all its
    /// body + gate stages recorded, before the next iteration's first stage
    /// dispatches), the runner calls this so that iteration's declared memory
    /// writebacks land NOW — making them visible to the next iteration's live
    /// selector reads. The implementation lives in kata-api (where the writeback
    /// machinery is); the trait seam keeps the dependency direction
    /// kata-api → kata-workflow. With `None` (no memory store / no writebacks),
    /// writebacks reconcile only at terminal run-end.
    pub(super) iteration_writeback_hook: Option<Arc<dyn IterationWritebackHook>>,
    /// The seam that starts a subworkflow stage's `Invoke` under the
    /// `oci` profile — claim and child admission in one transaction, then the child's runner
    /// (`dispatch::invoke`). `None` leaves the divert's `Invoke` arm refusing by name.
    pub(super) child_invoker: Option<Arc<dyn ChildInvoker>>,
    /// Pending schema-validation retry actions.
    /// `apply_event`'s Completed branch pushes here when validation
    /// fails AND the stage's `validate_retries` budget allows another
    /// attempt. The async outer-loop method
    /// `execute_validate_retries` drains the queue and dispatches
    /// follow-up `<base>#validate-N` synthetic assignments through
    /// the dispatcher. `apply_event` is sync and the checked dispatcher
    /// submit is async, so the submit is queued and drained.
    pub(super) pending_validate_retries: RwLock<Vec<PendingValidateRetry>>,
    /// Queued `oci` failure retries, re-derived by the failed
    /// attempt's fold and drained by `execute_failure_retries` once due.
    pub(super) pending_failure_retries: RwLock<Vec<PendingFailureRetry>>,
    /// The backoff before each transient model provider re-run: the shipped
    /// `TRANSIENT_PROVIDER_RERUN_BACKOFF_MS`, which only a test-support door
    /// ([`Self::with_transient_rerun_backoff_for_test`]) replaces.
    pub(super) transient_rerun_backoff_ms: [u64; dispatch::TRANSIENT_PROVIDER_RERUNS as usize],
    /// Workflow-root cost-budget policy. Default `Unlimited`
    /// when not declared by the checked workflow. Read by `apply_event` on
    /// each Completed transition.
    pub(super) workflow_budget: kata_types::BudgetPolicy,
    /// Per-stage cost-budget policies. Populated from
    /// `StageDefinition.cost_budget` for each stage in the workflow.
    /// Lookups default to `Unlimited` for stages not present.
    pub(super) stage_budgets: HashMap<StageId, kata_types::BudgetPolicy>,
    /// Running-cost tracker. Updated on each Completed.
    pub(super) budget_tracker: Arc<budget::BudgetTracker>,
    /// Captured workflow-scope `Bound::Cost`
    /// ceiling in micro-USD, extracted from `ExecutionProgram.bounds` at
    /// construction. `Some(limit)` enforces a walk-away halt the moment the
    /// workflow running cost exceeds `limit` (same accumulator the workflow
    /// budget watches); `None` when the workflow declares no cost bound.
    pub(super) cost_bound_micro_usd: Option<u64>,
    /// Captured workflow-scope `Bound::Time`
    /// ceiling in milliseconds of TOTAL-LIFETIME wall-clock, extracted from
    /// `ExecutionProgram.bounds` at construction (the DSL admits ≤1 per kind).
    /// `Some(limit)` enforces a walk-away halt the moment total elapsed since
    /// [`Self::execution_started_at_ms`] exceeds `limit`, evaluated at each
    /// charged frame, at the instant the chain recorded it; `None` when the
    /// workflow declares no time bound. Mirrors
    /// [`Self::cost_bound_micro_usd`].
    pub(super) time_bound_ms: Option<u64>,
    /// Captured workflow-scope `Bound::Tokens` ceiling, extracted from
    /// `ExecutionProgram.bounds` at construction. `Some(limit)` enforces a
    /// walk-away halt the moment [`Self::running_tokens`] exceeds `limit`, and a
    /// fail-closed halt on a stage whose token count is unknown; `None` when the
    /// workflow declares no token bound. Mirrors [`Self::cost_bound_micro_usd`].
    pub(super) token_bound: Option<u64>,
    /// The tokens the execution's stages have RECORDED so far, every class
    /// counted (`kata_types::metering::envelope_tokens`) — folded on every
    /// terminal exactly where the running cost is, so a pure-fold resume that
    /// re-applies each terminal rebuilds it.
    pub(super) running_tokens: std::sync::atomic::AtomicU64,
    /// Whether the FOLD has passed this execution's walk-away: a trip
    /// [`Self::act_on_stage_halt_trip`] acted on, or a durable walk-away row the
    /// fold applied. Every stage terminal the fold applies after it releases
    /// nothing ([`Self::release_nothing_after_walk_away`]).
    ///
    /// In memory, and set in CHAIN ORDER, never read off the whole chain: a
    /// replay folds a stage that completed BEFORE the walk-away while the row
    /// is already durable, and that stage released its dependents on the live
    /// path — answering from the chain would skip dependents whose own frames
    /// the replay is about to fold. A fresh runner re-derives it from the same
    /// frames: a trip of the running cost, tokens or metering re-fires at its
    /// own frame; a `time_bound`'s, measured at each frame's recorded instant,
    /// at its own frame too — or, where the live runner's first-dispatch anchor
    /// preceded the chain's, at a later frame or not at all, never an earlier
    /// one; and the row's own frame sets it in any case.
    walk_away_latched: std::sync::atomic::AtomicBool,
    /// The execution's ORIGINAL wall-clock start in ms since
    /// epoch, the anchor for the `Bound::Time` total-lifetime elapsed check.
    /// Interior-mutable because the runner is driven through `&self`. Set once on
    /// the FIRST stage dispatch (when still `None`) via
    /// [`Self::mark_execution_start_if_unset`]; on RESUME it is restored from the
    /// ledger as the MINIMUM `started_at_ms` across already-recorded assignments
    /// (the ORIGINAL start, not the resume time) by the replay fold
    /// ([`Self::absorb_started_at_ms_anchor`]). `None` until the first dispatch or a
    /// resume with at least one started assignment; while `None` the time bound
    /// cannot trip.
    pub(super) execution_started_at_ms: RwLock<Option<u64>>,
    /// The per-execution working tree of a `worktree_isolated` run, as the
    /// executor handed it over: [`WorkflowRunner::with_working_tree`] or
    /// [`WorkflowRunner::with_working_tree_removed`]. Two readers consult it:
    /// the validation-report record skips a replayed report once the tree is
    /// gone, and the `workspace` template namespace is defined only over a
    /// live one.
    pub(super) working_tree: WorkingTree,
    /// The `params.*` template namespace, built from the execution's ADMITTED
    /// invocation rows by [`WorkflowRunner::with_invocation_params`] — the executor
    /// sets it on the submit path and on the recovery path, both from the durable
    /// invocation. `None` leaves the namespace undefined, so a template that reads
    /// `params.*` fails its strict render instead of rendering a value nobody
    /// admitted.
    pub(super) params_namespace: Option<serde_json::Value>,
    /// The execution's frozen target, read by templates as `target.*`
    /// ([`kata_program::target_namespace`]) — set by [`WorkflowRunner::with_invocation_target`]
    /// from the admitted invocation on the submit path and on the recovery path.
    /// `None` (a run that froze no target) leaves the namespace undefined.
    pub(super) target: Option<Arc<kata_types::target::ExecutionTarget>>,
    /// The execution-workspace provider the `/work` apply driver drives —
    /// the executor's own, attached for an isolated `oci` run. `None` everywhere
    /// else, which is the shape that keeps
    /// `drive_pending_work_applies` a no-op where no apply can exist.
    pub(super) workspace_provider:
        Option<Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>>,
    /// The `forge_export` `workspace_effect`'s PR door under `oci` — the
    /// executor wires `GhCliForge` (or a test's recording double); a `None`
    /// forge makes `forge_export` fail CLOSED at PR time.
    pub(super) forge: Option<Arc<dyn kata_effects_contract::Forge>>,
    /// Backend label for runtime-attached validation candidate bindings. This
    /// is set by the executor when it creates or reuses a provider-owned
    /// execution workspace.
    pub(super) candidate_binding_backend: Option<String>,
    /// Submit-time checked orchestration program. Normal static ready-stage
    /// eligibility comes from this retained graph, and every stage dispatch is
    /// guarded against the same program instead of rebuilding a fresh
    /// projection at dispatch time.
    pub(super) execution_program: ExecutionProgram,
    /// Every PROGRAM-LEVEL operation (a branch route's `Select`,
    /// under the `oci` profile) that resolved FAILED, keyed by its path, with the reason.
    ///
    /// Fed by the `Select` resolver and by the fold of the `Select`'s own `failed` frame,
    /// so a live run and its replay hold the same set; read by `collect_failures`, so a
    /// route that decided nothing fails the run exactly as the `#branch-failure`
    /// row does. A map, because both feeders may insert the same path.
    /// Keyed by the operation's rendered coordinate — `#op/<path>` for a Select or an
    /// input wait, `#apply/<stage>` for a `/work` apply — so the three kinds cannot
    /// collide on one key.
    pub(super) failed_program_operations: RwLock<BTreeMap<String, String>>,
    /// Every stage HELD in the orchestrator for a blocking human
    /// request's input wait (`runner::input_wait`). The hold is `AwaitingApproval` on the
    /// orchestrator; this set is what says it is an INPUT hold, so only an input wait's
    /// resolution releases it. Derived from the fold (a live hold and the replay of its
    /// claim frame both insert), never read off a second plane.
    pub(super) held_for_input: RwLock<BTreeSet<SmolStr>>,
    /// Replay-local recovered stage checkpoints, keyed by assignment id.
    /// `fold_to_head` retains the last worker safe point from authority records.
    ///
    /// The checkpoint is fold-READABLE only: no worker/stage resume decision
    /// consumes it, so a resumed stage re-runs from the start.
    pub(super) recovered_checkpoints: RwLock<HashMap<Ulid, u64>>,
    /// Augmented output envelopes whose ledger PROJECTION is still
    /// owed, keyed by assignment id.
    ///
    /// # The ordering this exists for, and why it is a queue rather than a retry
    ///
    /// `inject_parsed_if_declared` validates a stage's structured output and
    /// writes the augmented envelope back through
    /// [`Dispatcher::amend_output_and_fold_attempt`](crate::dispatcher::Dispatcher::amend_output_and_fold_attempt),
    /// whose projection half REQUIRES the row to be `Completed`.
    ///
    /// The chain DECIDES, and the inbox seam commits that decision before the
    /// projection transition. So a fold woken by the chain commit legitimately
    /// observes the terminal while the projected row still reads `running`, and
    /// the amendment arrives before the row it amends.
    ///
    /// The precondition is a REAL property, not a defect to invert: setting
    /// `output` on a non-terminal row fabricates an output for work still in
    /// flight. So it is SATISFIED — the amendment waits for the projection instead of overruling
    /// it, and [`Self::drain_pending_output_amendments`] lands it as soon as the
    /// row is terminal. The end state is byte-identical to an amendment that
    /// arrived late; only the instant differs.
    pub(super) pending_output_amendments: RwLock<BTreeMap<Ulid, serde_json::Value>>,
    /// The opt-in FORCED-rerun gate. `false` (the default) leaves every
    /// dispatch/reuse path byte-identical; set via
    /// [`WorkflowRunner::with_rerun_repeatability`]. Under `oci` its only
    /// remaining effect is a REFUSAL: set, a capsule stage never consults the
    /// reuse table and runs the container instead; capsules have no
    /// rerun-and-compare falsifier, so honouring the toggle means paying a
    /// re-execution.
    pub(super) rerun_repeatability: bool,
    /// The CAPSULE REUSE HINTS this run owes the content cache,
    /// keyed by stage name: a capsule stage that MISSED notes its `(reuse key,
    /// occurrence)` at submit, and the drive loop records the hint once the fold shows
    /// the stage completed and its occurrence accepted
    /// (`WorkflowRunner::flush_pending_capsule_reuse_hints`). In memory only, and
    /// deliberately: a hint lost to a crash is a miss, never a wrong answer.
    pub(in crate::runner) pending_capsule_reuse_hints:
        RwLock<BTreeMap<SmolStr, dispatch::capsule_reuse::PendingCapsuleReuseHint>>,
    /// Whether this execution has already warned that `KATA_RERUN_REPEATABILITY`
    /// switches capsule reuse off — ONE warning per execution, not one per stage.
    pub(in crate::runner) capsule_reuse_rerun_warned: std::sync::atomic::AtomicBool,
    _execution_lifecycle: crate::dispatcher::ExecutionProgramLease,
}

/// One pending schema-validation retry action queued by
/// `apply_event` for the outer run-loop's async drain pass.
#[derive(Debug, Clone)]
pub(super) struct PendingValidateRetry {
    pub(super) base: SmolStr,
    /// The loop iteration N that DISPATCHED the failing assignment, or 0
    /// for a non-loop stage / a loop's iteration-0 pass. Threaded into
    /// the synthetic retry name as `<base>#iter-N#validate-M` (N≥1) so
    /// the retry-completion ledger row carries an iteration-stable
    /// identity — see [`kata_program::loops::validate_retry_name`].
    pub(super) iteration: u32,
    /// Attempt number for this retry — the retry's CHAIN SEAT
    /// (`[i].child(attempt)`), which a mixed validation+failure chain counts
    /// past the budget — `dispatch_capsule_validation_retry` re-derives the
    /// budget's ordinal off the durable chain.
    pub(super) attempt: u32,
    /// The validation error string passed to the LLM as feedback.
    pub(super) error: String,
}

/// A queued `oci` FAILURE retry: the plain stage `base`'s
/// attempt failed with a settlement its agent fallback panel admits, so
/// chain seat `attempt` (`[i].child(attempt)`) runs on the panel's next
/// member, at once. Its driver is re-derived from the chain at dispatch.
#[derive(Debug, Clone)]
pub(super) struct PendingFailureRetry {
    pub(super) base: SmolStr,
    pub(super) attempt: u32,
    /// The failed attempt's reason — what the stage fails with when a walk-away
    /// stops the seat before it dispatches.
    pub(super) reason: String,
    /// The instant (ms since the epoch) the seat is due: the failed frame's
    /// recorded instant for a fallback, that plus its backoff for a transient
    /// re-run.
    pub(super) due_at_ms: u64,
}

/// Pure truthy-parse for the `KATA_RERUN_REPEATABILITY` operator toggle,
/// split out of [`WorkflowRunner::with_rerun_repeatability_from_env`] so it is
/// testable without mutating process env (this crate denies `unsafe_code`, and
/// `std::env::set_var` is `unsafe` under edition 2024). Accepts
/// `1`/`true`/`yes`/`on` (case-insensitive, trimmed) as ON; unset / empty / any
/// other value is OFF.
#[must_use]
fn rerun_repeatability_enabled_from_env(value: Option<&str>) -> bool {
    matches!(
        value.map(|raw| raw.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Unified per-stage-completion halt signal returned by
/// [`WorkflowRunner::check_halts_for_stage`].
///
/// A stage completion can trip a cost-`Budget` Halt,
/// a workflow-scope cost-`Bound` walk-away, or a
/// workflow-scope time-`Bound` walk-away. The cost guards
/// watch the same accumulated `workflow_running_micro_usd`; the time guard
/// watches total-lifetime wall-clock elapsed. Each persists a distinct synthetic
/// ledger name + counts a distinct metric, so the `apply_event` Completed branch
/// must distinguish them. The `Budget` variant is the cost-budget halt; the
/// `Bound` variants are the walk-aways.
#[derive(Debug, Clone)]
pub(super) enum StageHaltTrip {
    /// A cost-budget Halt policy crossed. Carries the existing
    /// [`budget::BudgetTrip`] so the budget-halt action is unchanged.
    Budget(budget::BudgetTrip),
    /// A workflow-scope [`kata_types::bound::Bound`] walk-away crossed
    /// `kind` distinguishes the cost ceiling from the
    /// time ceiling; `limit`/`observed` are kind-relative integers (the
    /// UNIT — micro-USD vs milliseconds — is implied by `kind`), and drive both
    /// the synthetic name suffix (`#bound-halt-<kind>`) and the halt's
    /// metric and log fields.
    Bound {
        kind: kata_types::bound::BoundKind,
        limit: u64,
        observed: u64,
    },
    /// A stage reported a cost kata could NOT measure while a HARD
    /// cost policy (`cost_bound(..)` or `cost_budget("halt", ..)`) is in force.
    ///
    /// The third walk-away cause, and the one that fires because the promise
    /// became *unknowable* rather than because it was *exceeded*. The other two
    /// compare a running total against a ceiling; this one fires when a
    /// contribution to that total is missing, which makes the comparison
    /// meaningless in the unsafe direction (the total under-reports, so the
    /// ceiling can be blown through without either guard ever tripping).
    ///
    /// Carries the `(backend, model)` pair so the halt reason names a
    /// recourse for that pair (`metering_unavailable_reason`) — a halt whose
    /// recourse nobody can invoke is worse than no halt.
    ///
    /// `TokensUnknown` is its token twin: a stage whose TOKEN count is unknown
    /// while a `token_bound` is in force.
    MeteringUnavailable {
        /// The stage path whose cost could not be measured — the completing or
        /// failing stage's own name, or the `<child stage>/<stage>` path an
        /// unmetered call rode in on through a `child_invocation_summary` (so
        /// the trip names where the unmeasurable call ran, not the parent
        /// whose envelope carried the fact).
        stage: smol_str::SmolStr,
        backend: smol_str::SmolStr,
        model: smol_str::SmolStr,
    },
    /// A stage recorded no token count while a `token_bound` is in force —
    /// the token ceiling became unknowable, so the run walks away rather than
    /// keep spending against a total that under-counts.
    TokensUnknown {
        /// The stage path whose tokens are unknown (a child's re-rooted
        /// `<child stage>/<stage>` when a summary carried it).
        stage: smol_str::SmolStr,
        backend: smol_str::SmolStr,
        model: smol_str::SmolStr,
    },
}

impl WorkflowRunner {
    /// Create a runner directly from a checked execution program.
    ///
    /// This is the program-backed runtime path used by durable resume and by
    /// callers that already compiled Starlark or constructed the narrow API
    /// representation into the execution IR. The
    /// source definition is not consulted for dispatch semantics.
    pub fn new_from_program(
        execution_program: ExecutionProgram,
        dispatcher: Arc<Dispatcher>,
        execution_id: Ulid,
    ) -> KataResult<Self> {
        if execution_program.schema_version
            != kata_program::execution_program::EXECUTION_PROGRAM_SCHEMA_VERSION
        {
            return Err(KataError::Validation(format!(
                "execution {execution_id} cannot dispatch checked-program schema {}; current schema is {}",
                execution_program.schema_version,
                kata_program::execution_program::EXECUTION_PROGRAM_SCHEMA_VERSION
            )));
        }
        let orchestrator = Orchestrator::from_execution_program(&execution_program)?;
        Self::from_orchestrator(orchestrator, dispatcher, execution_id, execution_program)
    }

    fn from_orchestrator(
        orchestrator: Orchestrator,
        dispatcher: Arc<Dispatcher>,
        execution_id: Ulid,
        execution_program: ExecutionProgram,
    ) -> KataResult<Self> {
        let execution_lifecycle =
            dispatcher.retain_execution_program(execution_id, &execution_program)?;
        // Capture budget policies from the checked program so
        // program-backed resume enforces the same limits as submit.
        let workflow_budget = execution_program.workflow_budget;
        let stage_budgets: HashMap<StageId, kata_types::BudgetPolicy> = execution_program
            .stages
            .iter()
            .map(|(id, stage)| (id.clone(), stage.policies.cost_budget))
            .collect();
        // Capture the single workflow-scope `Bound::Cost`
        // and `Bound::Time` ceilings (the DSL admits at most one per kind). Cost
        // is enforced as an accumulated-cost walk-away, Time as a total-lifetime
        // wall-clock walk-away.
        let bound_of = |kind: kata_types::bound::BoundKind| {
            execution_program
                .bounds
                .iter()
                .find(|bound| bound.kind() == kind)
                .map(kata_types::bound::Bound::limit)
        };
        let cost_bound_micro_usd = bound_of(kata_types::bound::BoundKind::Cost);
        let time_bound_ms = bound_of(kata_types::bound::BoundKind::Time);
        let token_bound = bound_of(kata_types::bound::BoundKind::Tokens);
        Ok(Self {
            orchestrator,
            dispatcher,
            execution_id,
            cache_store: None,
            memory_store: None,
            memory_scope: None,
            iteration_writeback_hook: None,
            child_invoker: None,
            pending_validate_retries: RwLock::new(Vec::new()),
            pending_failure_retries: RwLock::new(Vec::new()),
            transient_rerun_backoff_ms: dispatch::TRANSIENT_PROVIDER_RERUN_BACKOFF_MS,
            workflow_budget,
            stage_budgets,
            budget_tracker: Arc::new(budget::BudgetTracker::new(execution_id)),
            cost_bound_micro_usd,
            time_bound_ms,
            token_bound,
            running_tokens: std::sync::atomic::AtomicU64::new(0),
            walk_away_latched: std::sync::atomic::AtomicBool::new(false),
            execution_started_at_ms: RwLock::new(None),
            working_tree: WorkingTree::NotIsolated,
            params_namespace: None,
            target: None,
            workspace_provider: None,
            forge: None,
            candidate_binding_backend: None,
            execution_program,
            failed_program_operations: RwLock::new(BTreeMap::new()),
            held_for_input: RwLock::new(BTreeSet::new()),
            recovered_checkpoints: RwLock::new(HashMap::new()),
            pending_output_amendments: RwLock::new(BTreeMap::new()),
            rerun_repeatability: false,
            pending_capsule_reuse_hints: RwLock::new(BTreeMap::new()),
            capsule_reuse_rerun_warned: std::sync::atomic::AtomicBool::new(false),
            _execution_lifecycle: execution_lifecycle,
        })
    }

    /// Replace the backoff before each transient model provider re-run (the
    /// shipped `TRANSIENT_PROVIDER_RERUN_BACKOFF_MS`, 30 s then 120 s) — a
    /// test-support door, so a cell can drive a chain's re-runs in milliseconds.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_transient_rerun_backoff_for_test(
        mut self,
        backoff_ms: [u64; dispatch::TRANSIENT_PROVIDER_RERUNS as usize],
    ) -> Self {
        self.transient_rerun_backoff_ms = backoff_ms;
        self
    }

    /// Enable the opt-in FORCED-rerun gate. Off by default, so kata never
    /// spends a second execution unasked.
    ///
    /// Under `oci` the gate's whole remaining effect is a REFUSAL: with it set,
    /// capsule reuse is not consulted — the rerun-and-compare falsifier is not
    /// implemented for capsules, so honouring the toggle means running the container.
    #[must_use]
    pub fn with_rerun_repeatability(mut self, enabled: bool) -> Self {
        self.rerun_repeatability = enabled;
        self
    }

    /// The minimal OPERATOR surface for the rerun gate: read
    /// the `KATA_RERUN_REPEATABILITY` env toggle at runner/boot construction and
    /// flip [`Self::with_rerun_repeatability`] on when it is truthy
    /// (`1`/`true`/`yes`/`on`, case-insensitive, trimmed). Unset / empty / any
    /// other value leaves the gate OFF, so the default dispatch path stays
    /// byte-identical. Wired into every live-run runner
    /// construction site (API submit + resume and explicit scratch runs) so an
    /// operator can enable the gate on a real run without a code change.
    #[must_use]
    pub fn with_rerun_repeatability_from_env(self) -> Self {
        let enabled = rerun_repeatability_enabled_from_env(
            std::env::var("KATA_RERUN_REPEATABILITY").ok().as_deref(),
        );
        self.with_rerun_repeatability(enabled)
    }

    /// Attach a cache store so cacheable stages can skip dispatch
    /// on a hit. Builder-style so checked-program runner construction can
    /// opt into caching without changing the execution IR.
    #[must_use]
    pub fn with_cache_store(mut self, cache_store: Arc<SqliteWorkflowStore>) -> Self {
        self.cache_store = Some(cache_store);
        self
    }

    /// In the pure-fold boot, a stage the CURRENT runner never submitted
    /// is still `Pending` on the orchestrator when its durable terminal/approval
    /// event is folded (the prior run dispatched it; this instance did not).
    /// Promote it to `Ready` first so the follow-up complete/fail/pause transition
    /// lands from an accepted source state.
    ///
    /// Pending-only guard so it can NEVER perturb a non-resume path: a fresh run
    /// is untouched (its stages are driven to `Dispatched` by `submit_stage`
    /// before the fold sees their events), and an already-terminal stage is left
    /// alone (the guard excludes it, so this never fights the terminal latch).
    fn replay_promote_if_pending(&self, stage: &str) {
        if matches!(
            self.orchestrator.stage_state(stage),
            Some(StageState::Pending)
        ) {
            // Idempotent + infallible for a Pending source; ignore the Result so
            // a concurrently-advanced stage never turns a fold into an error.
            let _ = self.orchestrator.promote_to_ready(stage);
        }
    }

    /// A stage whose fold queued a retry is IN FLIGHT: live, `submit_stage`
    /// left it `Dispatched` and the queued retry's dispatch rides the queue;
    /// a pure-fold resume must converge to the same state. Left `Pending`,
    /// `advance_checked_ready_stages` re-submits the base stage beside the
    /// queued retry, and `has_in_flight_stage` reads the run as stuck behind
    /// it. `Dispatched` is the orchestrator's own spelling of "attempt settled,
    /// next attempt owed" — it is what both retry folds keep.
    ///
    /// A stage already `Dispatched` keeps its worker attribution; a synthetic
    /// name (`<base>#iter-N`, `<base>#validate-M`) is no orchestrator stage and
    /// marks nothing.
    fn mark_retry_pending_in_flight(&self, stage_name: &SmolStr) -> KataResult<()> {
        match self.orchestrator.stage_state(stage_name) {
            Some(StageState::Pending | StageState::Ready | StageState::AwaitingApproval { .. }) => {
                self.orchestrator
                    .force_dispatched_for_resume(stage_name.as_str(), None)
            }
            _ => Ok(()),
        }
    }

    /// Land the augmented output envelope on BOTH planes, or QUEUE it until the
    /// ledger projection can accept it.
    ///
    /// See [`Self::pending_output_amendments`] for the ordering this exists for.
    /// The pre-check is deliberately optimistic rather than a lock: if the row
    /// turns terminal between the read and the write, the write simply succeeds;
    /// if it turns terminal just after, the queue lands it. Both directions
    /// converge, and neither can write an output onto a non-terminal row.
    ///
    /// Through [`Dispatcher::amend_output_and_fold_attempt`]: this and
    /// [`Self::drain_pending_output_amendments`]
    /// are the only two production amendment writers in the workspace, so a
    /// writer that skipped the chain would leave every consumer of the chain's
    /// row reader reading the PRE-amendment output.
    ///
    /// # The AUTHORITY half is never deferred
    ///
    /// The projected row is written AFTER the chain commit this fold woke on, so
    /// gating the whole amendment on that row would queue an entry whose release
    /// condition says nothing about authority — and the chain would lose the
    /// amendment. The queue defers only the PROJECTION.
    pub(super) fn amend_or_defer_output(
        &self,
        assignment_id: Ulid,
        envelope: serde_json::Value,
    ) -> KataResult<()> {
        // A CAPSULE attempt settles by its occurrence's acceptance, which the
        // attempt-fold gate below cannot see; it is amended on the chain directly or not at all.
        if self.dispatcher.amend_accepted_capsule_output(
            self.execution_id,
            assignment_id,
            &envelope,
        )? {
            return Ok(());
        }
        if self
            .dispatcher
            .amend_output_and_fold_attempt(assignment_id, envelope.clone())?
        {
            return Ok(());
        }
        tracing::debug!(
            execution_id = %self.execution_id,
            %assignment_id,
            "runner: the chain holds no attempt or stage admission for this amendment's subject yet; \
             queueing the augmented envelope for a later drain"
        );
        self.pending_output_amendments
            .write()
            .insert(assignment_id, envelope);
        Ok(())
    }

    /// Land every queued amendment the ledger PROJECTION can now carry.
    ///
    /// # What is queued here
    ///
    /// Only the PROJECTION half. `amend_or_defer_output` lands the authority half
    /// the instant the deciding plane reports the subject settled, so an entry in
    /// this map names a derived row that is behind — never a durable fact that is
    /// missing. That is what makes the terminal epilogue's budget a latency
    /// question rather than a durability one.
    ///
    /// # Invariant
    ///
    /// IDEMPOTENT AND ORDER-FREE, ON BOTH PLANES. An amendment is
    /// status-preserving and overwrites, and each key holds the LATEST envelope
    /// computed for that assignment, so draining twice, or draining after the row
    /// was amended by another path, converges on the same bytes. The CHAIN half is
    /// idempotent too (`Dispatcher::amend_output_and_fold_attempt` skips
    /// an append the chain already holds), which is what lets a still-unprojected
    /// entry be re-offered every pass without leaving one frame per pass behind it.
    /// An entry whose row has not caught up STAYS queued — that is the whole point
    /// — so this is a no-op-until-ready rather than a retry with a budget.
    pub(super) fn drain_pending_output_amendments(&self) -> KataResult<()> {
        let ready: Vec<(Ulid, serde_json::Value)> = {
            let pending = self.pending_output_amendments.read();
            if pending.is_empty() {
                return Ok(());
            }
            pending
                .iter()
                .map(|(assignment_id, envelope)| (*assignment_id, envelope.clone()))
                .collect()
        };
        for (assignment_id, envelope) in ready {
            // The entry is retired only when the chain append lands — `false`
            // means the chain still holds no attempt or admission for the
            // subject, so the entry stays queued for a later pass.
            if self
                .dispatcher
                .amend_output_and_fold_attempt(assignment_id, envelope)?
            {
                self.pending_output_amendments
                    .write()
                    .remove(&assignment_id);
            }
        }
        Ok(())
    }

    /// Attach the native memory store so checked memory selectors can be
    /// materialized into bounded prompt/context packets at dispatch time.
    #[must_use]
    pub fn with_memory_store(mut self, memory_store: Arc<SqliteNativeMemoryStore>) -> Self {
        self.memory_store = Some(memory_store);
        self
    }

    /// Set the execution's memory base scope. Every memory
    /// selector read is then restricted to `scope.ancestors_inclusive()`, so the
    /// run sees only its own scope + ancestors and never a sibling's objects.
    /// Omitting this (the default) keeps the flat visibility every shipped
    /// pack relies on. Builder-style, mirroring [`Self::with_memory_store`].
    #[must_use]
    pub fn with_memory_scope(mut self, scope: kata_types::memory::MemoryScope) -> Self {
        self.memory_scope = Some(scope);
        self
    }

    /// Attach the close-the-loop writeback hook. Builder-style so the
    /// executor opts in only when a memory store + declared writebacks are
    /// present. See [`IterationWritebackHook`].
    #[must_use]
    pub fn with_iteration_writeback_hook(mut self, hook: Arc<dyn IterationWritebackHook>) -> Self {
        self.iteration_writeback_hook = Some(hook);
        self
    }

    /// Attach the [`ChildInvoker`] the `Invoke` arm
    /// starts a subworkflow child through.
    #[must_use]
    pub fn with_child_invoker(mut self, invoker: Arc<dyn ChildInvoker>) -> Self {
        self.child_invoker = Some(invoker);
        self
    }

    /// Attach the per-execution working tree at `path` — the live workspace
    /// of a `worktree_isolated` run. A `park`/`promote` of the run removes it
    /// later; [`WorkingTree::is_removed`] reads that off the filesystem.
    #[must_use]
    pub fn with_working_tree(mut self, path: std::path::PathBuf) -> Self {
        self.working_tree = WorkingTree::At(path);
        self
    }

    /// Resume a `worktree_isolated` run whose workspace the run's own
    /// `park`/`promote` already removed (`Dispatcher::workspace_teardown`
    /// names which): the runner treats the tree as gone, as a live runner does
    /// once that effect returned.
    #[must_use]
    pub fn with_working_tree_removed(mut self) -> Self {
        self.working_tree = WorkingTree::Removed;
        self
    }

    /// Attach the execution's admitted invocation params as the `params.*`
    /// template namespace (see [`kata_program::template::params_namespace`]: the program's
    /// declared non-secret params, each its admitted value or `none`).
    ///
    /// `rows` must be the invocation the admission digest binds — the one the
    /// executor accepted, or the one recovery re-admits — so a resumed execution
    /// renders the same commands its first dispatch did.
    #[must_use]
    pub fn with_invocation_params(mut self, rows: &[kata_types::params::InvocationParam]) -> Self {
        self.params_namespace = Some(kata_program::template::params_namespace(
            &self.execution_program.params,
            rows,
        ));
        self
    }

    /// Attach the execution's frozen target as the `target.*` template namespace
    /// ([`kata_program::target_namespace`]).
    ///
    /// `target` must be the admitted invocation's — the one the admission digest
    /// binds, on the submit path and on recovery — so a resumed execution renders
    /// the same text its first dispatch did.
    #[must_use]
    pub fn with_invocation_target(
        mut self,
        target: Option<&kata_types::target::ExecutionTarget>,
    ) -> Self {
        self.target = target.cloned().map(Arc::new);
        self
    }

    /// Attach the executor's execution-workspace provider — the `/work` apply
    /// driver's jj surface for an isolated `oci` run.
    #[must_use]
    pub fn with_workspace_provider(
        mut self,
        provider: Arc<dyn kata_effects_contract::ExecutionWorkspaceProvider>,
    ) -> Self {
        self.workspace_provider = Some(provider);
        self
    }

    /// Attach the `oci` `workspace_effect` forge (`forge_export`'s PR door).
    /// `None` makes `forge_export` fail closed at PR time.
    #[must_use]
    pub fn with_forge(mut self, forge: Option<Arc<dyn kata_effects_contract::Forge>>) -> Self {
        self.forge = forge;
        self
    }

    /// Attach the backend label used in validation candidate bindings.
    #[must_use]
    pub fn with_candidate_binding_backend(mut self, backend: impl Into<String>) -> Self {
        self.candidate_binding_backend = Some(backend.into());
        self
    }

    /// Persist the run's ONE walk-away row: a synthetic `synthetic_name`
    /// (`<stage>#budget-halt`, `<stage>#bound-halt-<kind>` or
    /// `<stage>#metering-halt`, the cause in the NAME) Failed assignment, so
    /// `aggregate_status` (in
    /// `kata-api::execution_record_from_assignments_with_program_and_evidence`)
    /// promotes the run to `Failed`, the operator-visible error carries the
    /// reason, and the terminal-outcome read (`collect_durable_walkaway_halts`)
    /// reports it. The same stage-scope row class as the `__workflow__` sentinel
    /// (`kata-api::persist_workflow_level_failure_for_program`).
    ///
    /// # One transaction
    ///
    /// The admission and its `failed` settlement commit together
    /// (`Dispatcher::admit_failed_undispatched_stage`), so a crash leaves no
    /// walk-away row or the settled one — never a `pending` row, which the read
    /// below does not count: a resumed fold would write a second row beside it,
    /// and it would hold the execution non-terminal.
    ///
    /// # Once per execution
    ///
    /// Writes NOTHING when the authority chain already holds ANY walk-away row,
    /// whatever its kind or stage: an execution walks away once, and its first
    /// trip is the sole authority. Within one fold the walk-away latch keeps a
    /// later trip — a bound the total still exceeds, a workflow budget
    /// re-crossed, a second kind — from reaching here at all
    /// ([`Self::settle_charged_frame`]); this read is what a RESUMED fold
    /// converges on, whose re-applied tripping frame re-runs its trip with the
    /// row already durable — at that frame, or, for a `time_bound` whose live
    /// anchor preceded the chain's, at a later frame the live fold folded after
    /// its walk-away.
    ///
    /// Reads the AUTHORITY chain: the answer decides whether a row is written,
    /// and a projection behind the chain would answer "none yet" and write a
    /// second one.
    fn persist_walkaway_halt(&self, synthetic_name: &str, reason: &str) -> KataResult<()> {
        if !self.durable_walkaway_halt_rows()?.is_empty() {
            return Ok(());
        }
        // The chain records the synthetic row at STAGE scope (no attempt).
        self.dispatcher.admit_failed_undispatched_stage(
            self.execution_id,
            Ulid::new(),
            synthetic_name,
            reason,
        )
    }
    /// Extract `cost_micro_usd` from the envelope,
    /// fold it into the running-cost accumulator, then evaluate BOTH the
    /// cost-budget Halt machinery AND the captured workflow-scope
    /// `Bound::Cost` walk-away against the SAME accumulated
    /// `workflow_running_micro_usd`.
    ///
    /// `Warn`-mode budget crossings are emitted as a side effect (event +
    /// metric) inside the closure passed to `record_completion` and never reach
    /// the caller.
    ///
    /// Returns:
    ///   - `Some(StageHaltTrip::Budget(..))` when a cost-budget `Halt` policy
    ///     crossed.
    ///   - `Some(StageHaltTrip::Bound { .. })` when no budget halt fired but the
    ///     captured `Bound::Cost` ceiling was exceeded. A `Bound` is an
    ///     unconditional walk-away (no `Warn` mode), checked with the same
    ///     `running > limit` semantics the budget tracker uses.
    ///   - `None` when neither guard tripped (including when no cost bound was
    ///     authored, in which case the budget path is unchanged).
    ///
    /// Budget is checked first so that when a budget and a bound would both trip
    /// on the same stage, the existing budget halt wins (the bound is redundant
    /// there). When their limits differ, whichever is lower exceeds the shared
    /// accumulator on an earlier stage and trips first. Stages whose envelope has
    /// no `cost_micro_usd` (non-LLM stages) contribute 0 — they
    /// cannot trip either guard on their own.
    fn check_halts_for_stage(
        &self,
        stage_name: &SmolStr,
        envelope: &serde_json::Value,
        recorded_at_ms: u64,
    ) -> Option<StageHaltTrip> {
        // The SAME extraction the per-loop bound path uses, so workflow-scope
        // and per-loop cost accounting are guaranteed to agree (direct
        // `token_usage.cost_micro_usd` + child summary, saturating-added).
        let cost_micro_usd = kata_types::metering::envelope_cost_micro_usd(envelope);
        let (workflow_policy, stage_policy) = self.cost_policies_for(stage_name);
        let budget_trip = self.fold_running_cost(stage_name, cost_micro_usd);
        let tokens = self.fold_running_tokens(stage_name, envelope);
        // FAIL CLOSED — evaluated BEFORE the budget trip is consumed,
        // because an unmeasurable stage means the accumulator the budget policy
        // just evaluated is itself incomplete. Reporting "you are under budget"
        // from a total that is missing a contribution is the failure mode this
        // guard refuses, so the metering verdict has to be able to
        // pre-empt it.
        if let Some(trip) = Self::check_metering_enforceable(
            stage_name,
            envelope,
            workflow_policy,
            stage_policy,
            self.cost_bound_micro_usd.is_some(),
        ) {
            tracing::warn!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                "metering fail-closed: a hard cost policy is in force and this stage \
                 reported no measurable cost"
            );
            return Some(trip);
        }
        if let Some(trip) = self.check_tokens_enforceable(tokens) {
            return Some(trip);
        }
        self.bound_and_time_trips(budget_trip, recorded_at_ms)
    }

    /// The TERMINAL-CHARGE twin of [`Self::check_halts_for_stage`]: the
    /// charge a `failed`/`cancelled`/`orphaned` stage made, evaluated under
    /// the SAME trips through the SAME helpers — running-cost fold, metering
    /// fail-closed, cost bound, time bound — so "failed stages are charged"
    /// is one rule with two input shapes, not a second policy that can drift.
    ///
    /// The input is the typed charge off the durable terminal frame rather
    /// than a completion envelope; [`Self::check_charge_metering_enforceable`]
    /// applies the identical hard-policy gate to its `token_usage.cost` and
    /// its `child_invocation_summary.metering`.
    pub(super) fn check_halts_for_terminal_charge(
        &self,
        stage_name: &SmolStr,
        charge: &kata_types::metering::TerminalCharge,
        recorded_at_ms: u64,
    ) -> Option<StageHaltTrip> {
        let envelope = charge.envelope();
        let cost_micro_usd = kata_types::metering::envelope_cost_micro_usd(&envelope);
        let (workflow_policy, stage_policy) = self.cost_policies_for(stage_name);
        let budget_trip = self.fold_running_cost(stage_name, cost_micro_usd);
        let tokens = self.fold_running_tokens(stage_name, &envelope);
        if let Some(trip) = Self::check_charge_metering_enforceable(
            stage_name,
            charge,
            workflow_policy,
            stage_policy,
            self.cost_bound_micro_usd.is_some(),
        ) {
            tracing::warn!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                "metering fail-closed: a hard cost policy is in force and a terminated \
                 stage's charge could not be measured"
            );
            return Some(trip);
        }
        if let Some(trip) = self.check_tokens_enforceable(tokens) {
            return Some(trip);
        }
        self.bound_and_time_trips(budget_trip, recorded_at_ms)
    }

    /// Fold one stage record's KNOWN tokens into [`Self::running_tokens`] — on
    /// every terminal, bound or not, exactly as the running cost folds — and
    /// return what the record states, for [`Self::check_tokens_enforceable`].
    fn fold_running_tokens(
        &self,
        stage_name: &SmolStr,
        envelope: &serde_json::Value,
    ) -> kata_types::metering::EnvelopeTokens {
        let tokens = kata_types::metering::envelope_tokens(stage_name.as_str(), envelope);
        self.running_tokens
            .fetch_add(tokens.known, std::sync::atomic::Ordering::SeqCst);
        tokens
    }

    /// FAIL CLOSED on an unknown token count under a `token_bound`: the token
    /// twin of the metering gate. A stage record that cannot state its tokens
    /// makes [`Self::running_tokens`] a lower bound, and a ceiling enforced
    /// against a lower bound is the unenforceable case. No bound, no halt — the
    /// fact still reaches the record's `metering.tokens_unknown`.
    fn check_tokens_enforceable(
        &self,
        tokens: kata_types::metering::EnvelopeTokens,
    ) -> Option<StageHaltTrip> {
        self.token_bound?;
        let unknown = tokens.unknown?;
        tracing::warn!(
            execution_id = %self.execution_id,
            stage = %unknown.stage,
            "token metering fail-closed: a token bound is in force and a stage recorded no \
             token count"
        );
        Some(StageHaltTrip::TokensUnknown {
            stage: SmolStr::new(unknown.stage),
            backend: SmolStr::new(unknown.backend),
            model: SmolStr::new(unknown.model),
        })
    }

    /// The `cost_budget` policies ONE stage resolves under — the pair
    /// [`Self::check_halts_for_stage`] and [`Self::check_halts_for_terminal_charge`]
    /// both look up, so the two cannot read a different policy for the same
    /// stage.
    fn cost_policies_for(
        &self,
        stage_name: &SmolStr,
    ) -> (kata_types::BudgetPolicy, kata_types::BudgetPolicy) {
        let stage_id = StageId(stage_name.clone());
        let stage_policy = self
            .stage_budgets
            .get(&stage_id)
            .copied()
            .unwrap_or(kata_types::BudgetPolicy::Unlimited);
        (self.workflow_budget, stage_policy)
    }

    /// Fold `cost_micro_usd` into the shared running-cost accumulator and
    /// evaluate the `cost_budget` policies — the fold BOTH terminal shapes
    /// perform identically, including the `Warn` side effects emitted inside
    /// the closure. Returns the Halt trip, when one crossed.
    fn fold_running_cost(
        &self,
        stage_name: &SmolStr,
        cost_micro_usd: u64,
    ) -> Option<budget::BudgetTrip> {
        let stage_id = StageId(stage_name.clone());
        let stage_policy = self
            .stage_budgets
            .get(&stage_id)
            .copied()
            .unwrap_or(kata_types::BudgetPolicy::Unlimited);
        let workflow_policy = self.workflow_budget;
        let execution_id = self.execution_id;
        // Fold this stage's cost into the running totals and evaluate the
        // budget policies. `record_completion` is the single accumulator mutation
        // for this stage; the bound check below reads the post-fold workflow total
        // so both guards see the same number.
        self.budget_tracker.record_completion(
            &stage_id,
            cost_micro_usd,
            workflow_policy,
            stage_policy,
            |scope, observed, limit| {
                metrics::counter!(
                    "kata_workflow_budget_exceeded_total",
                    "scope" => scope.label(),
                    "mode" => "warn",
                )
                .increment(1);
                tracing::warn!(
                    %execution_id,
                    stage = %stage_name,
                    scope = %scope.label(),
                    observed_micro_usd = observed,
                    limit_micro_usd = limit,
                    "budget warn: running cost exceeds limit; workflow continues"
                );
            },
        )
    }

    /// The bound-and-time tail BOTH terminal shapes evaluate after their
    /// metering check: the budget trip first (so the authored budget wins a
    /// tie against the bound), then the `Bound::Cost` walk-away on the same
    /// accumulated total, then the `Bound::Time` lifetime wall-clock at the
    /// charged frame's `recorded_at_ms`.
    fn bound_and_time_trips(
        &self,
        budget_trip: Option<budget::BudgetTrip>,
        recorded_at_ms: u64,
    ) -> Option<StageHaltTrip> {
        if let Some(trip) = budget_trip {
            return Some(StageHaltTrip::Budget(trip));
        }
        // Evaluate the captured cost bound against the SAME
        // accumulated workflow running cost. A `Bound::Cost` is always a hard
        // walk-away (Halt semantics) — `running > limit` mirrors
        // `BudgetTracker::check_scope`.
        //
        if let Some(limit_micro_usd) = self.cost_bound_micro_usd {
            let observed_micro_usd = self.budget_tracker.workflow_running_micro_usd();
            if observed_micro_usd > limit_micro_usd {
                return Some(StageHaltTrip::Bound {
                    kind: kata_types::bound::BoundKind::Cost,
                    limit: limit_micro_usd,
                    observed: observed_micro_usd,
                });
            }
        }
        // The `Bound::Tokens` walk-away on the recorded-token total, with the
        // cost bound's strictly-greater semantics.
        if let Some(limit_tokens) = self.token_bound {
            let observed_tokens = self
                .running_tokens
                .load(std::sync::atomic::Ordering::SeqCst);
            if observed_tokens > limit_tokens {
                return Some(StageHaltTrip::Bound {
                    kind: kata_types::bound::BoundKind::Tokens,
                    limit: limit_tokens,
                    observed: observed_tokens,
                });
            }
        }
        // Evaluate the captured time bound as a total-lifetime
        // wall-clock walk-away anchored to the execution's ORIGINAL start, at
        // the instant the chain RECORDED the charged frame — never the clock the
        // fold runs under. A resumed fold re-folds every frame at the instant the
        // live fold measured it, so it never trips the bound at a frame the live
        // fold passed inside it: that trip would skip dependents whose own frames
        // follow in the chain, and the fold would die completing one. Its anchor
        // is the earliest start the chain records, never earlier than the one a
        // live runner stamped at its first dispatch, so it trips at a frame the
        // live fold tripped at, or folded after its walk-away, or not at all.
        // `at - start > limit` is strictly-greater.
        if let Some(limit_ms) = self.time_bound_ms
            && let Some(start_ms) = *self.execution_started_at_ms.read()
        {
            let elapsed_ms = recorded_at_ms.saturating_sub(start_ms);
            if elapsed_ms > limit_ms {
                return Some(StageHaltTrip::Bound {
                    kind: kata_types::bound::BoundKind::Time,
                    limit: limit_ms,
                    observed: elapsed_ms,
                });
            }
        }
        None
    }

    /// Decide whether this stage's cost is ENFORCEABLE against the
    /// cost policies in force, and produce the fail-closed trip when it is not.
    ///
    /// # What "fails closed" means here, and why it is a halt rather than a
    /// refusal to dispatch
    ///
    /// The alternative design — refuse to dispatch a stage whose backend
    /// *might* not report cost — cannot be made sound. Whether a provider
    /// reports a charge is not a static property of a backend: the observed
    /// failure is precisely a `claude` CLI version that stops emitting its
    /// total-cost field, and a codex run whose usage event fails to parse on one
    /// call and succeeds on the next. A pre-dispatch check could only reject on
    /// statically-known-unmeterable backends, which is a strictly weaker
    /// property that goes green while every dynamic case still slips through —
    /// a check that pins the defect rather than catching it.
    ///
    /// So the halt fires at the first moment the fact is KNOWN: a completed
    /// stage whose cost is [`MeteredCost::Unavailable`], in a scope carrying a
    /// hard policy. From there it reuses the walk-away machinery verbatim
    /// (synthetic durable row, `status: failed`, an `error` naming the reason,
    /// a `warnings` line, non-zero exit), because "kata stopped rather than keep
    /// running against a promise it can no longer keep" is exactly what a
    /// walk-away already means.
    ///
    /// # And why an ADVISORY scope does not halt
    ///
    /// `cost_budget("warn", ..)` and no policy at all make no promise about
    /// spend, so there is nothing to fail closed on and halting would be
    /// gratuitous — it would stop every model-free or unpriced workflow that
    /// never asked for a ceiling. The fact is still recorded: the stage's
    /// `MeteredCost::Unavailable` reaches `ExecutionRecord::metering` and adds a
    /// warning line either way.
    /// The check also reads the envelope's `child_invocation_summary.
    /// metering`, under the same hard-policy gate: an `Invoke` stage that
    /// completed a child carrying unmetered spend trips exactly as an
    /// unmeterable stage of the parent's own would, and the trip names the
    /// `<child stage>/<stage>` path the summary records. A child summary
    /// whose `metering` key is ABSENT is a pre-change record — skipped, never
    /// failed — the same carve-out [`kata_program::loops::envelope_cost_quality`]
    /// documents for the cost object itself.
    fn check_metering_enforceable(
        stage_name: &SmolStr,
        envelope: &serde_json::Value,
        workflow_policy: kata_types::BudgetPolicy,
        stage_policy: kata_types::BudgetPolicy,
        has_cost_bound: bool,
    ) -> Option<StageHaltTrip> {
        // A hard cost policy is a `cost_bound` (always a walk-away) or a
        // `Halt`-mode cost budget at EITHER scope. A `Warn` budget is advisory
        // by construction — it already declares that crossing it is not fatal.
        let hard = has_cost_bound || workflow_policy.is_halt() || stage_policy.is_halt();
        if !hard {
            return None;
        }
        // The rule a loop `cost_bound` fails closed by too: the stage's own
        // `Unavailable` cost, else a child summary's first unmetered stage
        // re-rooted under this stage's name — the same path prefix
        // `MeteringSummary::absorb` gives a parent's record, so the halt names
        // `sub/only`, not a bare child stage an operator cannot place.
        let unmetered =
            kata_program::loops::envelope_unmetered_cost(stage_name.as_str(), envelope)?;
        Some(StageHaltTrip::MeteringUnavailable {
            stage: SmolStr::new(unmetered.stage),
            backend: SmolStr::new(unmetered.backend),
            model: SmolStr::new(unmetered.model),
        })
    }

    /// [`Self::check_metering_enforceable`]'s TYPED sibling: the same
    /// fail-closed gate applied to a terminal frame's [`TerminalCharge`]
    /// instead of a completion envelope. The gate itself is unchanged —
    /// hard policy AND unmeterable spend, the direct `token_usage.cost`
    /// first and then the `child_invocation_summary.metering` re-rooted
    /// under this stage's name — so a failed or cancelled `Invoke` parent
    /// whose child carried unmetered spend trips identically to a
    /// completed one.
    ///
    /// A charge with no `token_usage` (a child-summary-only charge) states
    /// NO direct spend — not an unmeterable one — so it is `None`, not a
    /// decode failure.
    fn check_charge_metering_enforceable(
        stage_name: &SmolStr,
        charge: &kata_types::metering::TerminalCharge,
        workflow_policy: kata_types::BudgetPolicy,
        stage_policy: kata_types::BudgetPolicy,
        has_cost_bound: bool,
    ) -> Option<StageHaltTrip> {
        let hard = has_cost_bound || workflow_policy.is_halt() || stage_policy.is_halt();
        if let Some(cost) = charge.token_usage.as_ref().map(|usage| &usage.cost)
            && let kata_types::metering::CostCharge::FailClosed { backend, model } =
                cost.charge_under(kata_types::metering::CostEnforcement::from_hard(hard))
        {
            return Some(StageHaltTrip::MeteringUnavailable {
                stage: stage_name.clone(),
                backend,
                model,
            });
        }
        if hard
            && let Some(first) = charge
                .child_invocation_summary
                .as_ref()
                .and_then(|summary| summary.metering.as_ref())
                .and_then(|metering| metering.unmetered.first())
        {
            return Some(StageHaltTrip::MeteringUnavailable {
                stage: SmolStr::new(format!("{stage_name}/{}", first.stage)),
                backend: SmolStr::new(first.backend.as_str()),
                model: SmolStr::new(first.model.as_str()),
            });
        }
        None
    }

    /// Stamp the execution's ORIGINAL wall-clock start the
    /// first time a stage is dispatched (when [`Self::execution_started_at_ms`]
    /// is still `None`). Idempotent — a no-op once set, so a resume that already
    /// restored the original start from the ledger is never overwritten by a
    /// later new dispatch. Uses the runner's single wall-clock source
    /// ([`dispatch::now_ms`]).
    pub(super) fn mark_execution_start_if_unset(&self) {
        let mut guard = self.execution_started_at_ms.write();
        if guard.is_none() {
            *guard = Some(dispatch::now_ms());
        }
    }

    /// Fold a durable `started_at_ms` anchor (read off a replayed
    /// `LedgerEventV1` frame) into the execution's original-start clock.
    ///
    /// The replay fold threads each frame's anchor through here as it applies
    /// it. Idempotent and order-independent —
    /// it only ever moves the anchor EARLIER (`min`), so repeated folds and
    /// out-of-order arrivals converge on the same earliest start, never later
    /// than an already-stamped value. A no-op when the execution carries no time
    /// bound (the anchor is only consulted by `Bound::Time`).
    pub(super) fn absorb_started_at_ms_anchor(&self, candidate_ms: u64) {
        if self.time_bound_ms.is_none() {
            return;
        }
        let mut guard = self.execution_started_at_ms.write();
        *guard = Some(guard.map_or(candidate_ms, |existing| existing.min(candidate_ms)));
    }

    /// Whether the fold has passed this execution's walk-away
    /// ([`Self::walk_away_latched`]).
    fn walked_away(&self) -> bool {
        self.walk_away_latched
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A stage terminal the fold applies AFTER the run walked away releases
    /// nothing: every stage whose `depends_on` chain reaches `stage_name` is
    /// skipped, whatever kind of walk-away it was — a workflow bound's, a
    /// halting `cost_budget`'s or a metering halt's. Before the walk-away it is
    /// a no-op, and the terminal releases its dependents as the DAG says.
    ///
    /// Called at every stage terminal the fold applies that no charge rides —
    /// a settled topology's completion, a loop record's member completions —
    /// and, through [`Self::settle_charged_frame`], at every charged one.
    pub(super) fn release_nothing_after_walk_away(&self, stage_name: &str) {
        if self.walked_away() {
            tracing::debug!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                "walk-away: a stage that terminated after the run walked away releases nothing"
            );
            self.orchestrator.skip_dependents(stage_name);
        }
    }

    /// The fold applied a durable walk-away row (`stage_name` names one): latch
    /// the walk-away there too. The trip that wrote the row latched it already
    /// when this runner folded that trip; this keeps a fold that did not — a
    /// resume whose re-fold of the tripping frame did not re-run its trip —
    /// from releasing anything after the row's own position in the chain.
    pub(super) fn latch_durable_walk_away(&self, stage_name: &str) {
        if kata_types::bound::is_walkaway_halt_row(stage_name) {
            self.walk_away_latched
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Settle one CHARGED frame's walk-away: `trip` is what the frame's charge
    /// (`check_halts_for_stage`, `check_halts_for_terminal_charge`) tripped.
    ///
    /// Once the fold has passed the run's walk-away, the frame releases nothing
    /// ([`Self::release_nothing_after_walk_away`]) and its own trip — a bound
    /// the total still exceeds, a budget re-crossed, a second kind — is not
    /// acted on: the first walk-away is the run's only one, so no second row,
    /// metric or log is written for it. Before it, a trip is acted on
    /// ([`Self::act_on_stage_halt_trip`]) and no trip changes nothing.
    pub(super) fn settle_charged_frame(
        &self,
        stage_name: &SmolStr,
        trip: Option<StageHaltTrip>,
        context: &'static str,
    ) -> KataResult<()> {
        if self.walked_away() {
            self.release_nothing_after_walk_away(stage_name);
            return Ok(());
        }
        match trip {
            Some(trip) => self.act_on_stage_halt_trip(stage_name, trip, context),
            None => Ok(()),
        }
    }

    /// Act on a unified stage-completion halt trip — the run's walk-away.
    ///
    /// Persists the variant's synthetic Failed assignment (once per execution,
    /// [`Self::persist_walkaway_halt`]), emits the matching metric + structured
    /// log, cascades `skip_dependents`, and latches [`Self::walk_away_latched`]. The
    /// budget-halt (`<stage>#budget-halt`), bound-halt
    /// (`<stage>#bound-halt-<kind>`) and metering-halt (`<stage>#metering-halt`)
    /// actions live here so every frame that is charged — a stage's completion,
    /// its rejected structured-output turn, a failure-class terminal, and an
    /// expansion member's completion or terminal — acts on a trip byte-for-byte
    /// identically. In-flight already-dispatched stages are not cancelled (the
    /// budget-halt semantics), and each releases nothing when it terminates; a
    /// pending `loop(..)` or `topology(..)` dispatches no further member (its
    /// derive resolves it), and no stage starts: the ready-advance
    /// ([`Self::advance_checked_ready_stages`]) and a plain stage's retry drains
    /// read the durable row this writes and dispatch nothing past it. The runner's
    /// boot dispatch of a claim the previous main never dispatched
    /// (`Dispatcher::dispatch_claims_left_undispatched`) does not read it: such a
    /// claim is dispatched whether or not the row is on the chain.
    fn act_on_stage_halt_trip(
        &self,
        stage_name: &SmolStr,
        trip: StageHaltTrip,
        context: &'static str,
    ) -> KataResult<()> {
        match trip {
            StageHaltTrip::Budget(trip) => {
                let stage_id = StageId(stage_name.clone());
                let reason = trip.reason(&stage_id);
                tracing::warn!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    scope = %trip.scope.label(),
                    observed_micro_usd = trip.observed_micro_usd,
                    limit_micro_usd = trip.limit_micro_usd,
                    context,
                    "budget halt: persisting synthetic failure + cascading skip-dependents"
                );
                metrics::counter!(
                    "kata_workflow_budget_exceeded_total",
                    "scope" => trip.scope.label(),
                    "mode" => "halt",
                )
                .increment(1);
                self.persist_walkaway_halt(
                    &format!("{stage_name}{BUDGET_HALT_MARKER_SUFFIX}"),
                    &reason,
                )?;
                self.orchestrator.skip_dependents(stage_name);
            }
            StageHaltTrip::Bound {
                kind,
                limit,
                observed,
            } => {
                // A workflow-scope `Bound` walk-away — `Cost` (accumulated
                // micro-USD) or `Time` (total-lifetime wall-clock ms).
                // Exactly like the budget-halt path, the operator-facing
                // signal is the metric + structured log + the durable synthetic
                // ledger failure (which is what `aggregate_status` and resume
                // read). `kind.label()` ("cost"/"time") drives both the synthetic
                // name suffix and the metric/log dimension; the UNIT of
                // `limit`/`observed` is implied by `kind` (micro-USD / ms).
                let unit = kind.unit();
                let reason = format!(
                    "bound_exceeded: workflow {} bound reached {observed} {unit} (limit: {limit} {unit}); halted at stage {:?}",
                    kind.label(),
                    stage_name.as_str(),
                );
                tracing::warn!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    bound_kind = kind.label(),
                    observed,
                    limit,
                    context,
                    "bound halt: workflow bound tripped; persisting synthetic failure + cascading skip-dependents"
                );
                metrics::counter!(
                    "kata_workflow_bound_exceeded_total",
                    "bound_kind" => kind.label(),
                )
                .increment(1);
                self.persist_walkaway_halt(
                    &format!("{stage_name}{BOUND_HALT_MARKER_INFIX}{}", kind.label()),
                    &reason,
                )?;
                self.orchestrator.skip_dependents(stage_name);
            }
            StageHaltTrip::MeteringUnavailable {
                stage: unmetered_stage,
                backend,
                model,
            } => {
                // The same three actions as the two ceiling walk-aways
                // — durable synthetic Failed row, metric + structured log, skip
                // cascade — because the operator-facing consequence is
                // identical: the run stopped early and downstream work was
                // never dispatched. Only the reason differs — it names the
                // stage path whose cost could not be measured, which may be a
                // `<child stage>/<stage>` path a `child_invocation_summary`
                // carried, while the halt row itself rides on the stage
                // this fold was evaluating.
                let reason = kata_types::metering::metering_unavailable_reason(
                    unmetered_stage.as_str(),
                    backend.as_str(),
                    model.as_str(),
                );
                tracing::warn!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    unmetered = %unmetered_stage,
                    backend = %backend,
                    model = %model,
                    context,
                    "metering halt: a hard cost policy cannot be enforced against an \
                     unmeasurable stage cost; persisting synthetic failure + cascading \
                     skip-dependents"
                );
                metrics::counter!(
                    "kata_workflow_metering_halt_total",
                    "backend" => backend.to_string(),
                )
                .increment(1);
                self.persist_walkaway_halt(
                    &format!(
                        "{stage_name}{}",
                        kata_types::bound::METERING_HALT_MARKER_SUFFIX
                    ),
                    &reason,
                )?;
                self.orchestrator.skip_dependents(stage_name);
            }
            StageHaltTrip::TokensUnknown {
                stage: unknown_stage,
                backend,
                model,
            } => {
                // The metering walk-away's three actions, for the token
                // ceiling: the same `#metering-halt` row (the run stopped because
                // its promise became unknowable), the reason naming the stage
                // path whose tokens are unknown.
                let reason = kata_types::metering::token_metering_unavailable_reason(
                    unknown_stage.as_str(),
                    backend.as_str(),
                    model.as_str(),
                );
                tracing::warn!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    unknown = %unknown_stage,
                    backend = %backend,
                    model = %model,
                    context,
                    "token metering halt: a token bound cannot be enforced against an \
                     uncounted stage; persisting synthetic failure + cascading skip-dependents"
                );
                metrics::counter!(
                    "kata_workflow_metering_halt_total",
                    "backend" => backend.to_string(),
                )
                .increment(1);
                self.persist_walkaway_halt(
                    &format!(
                        "{stage_name}{}",
                        kata_types::bound::METERING_HALT_MARKER_SUFFIX
                    ),
                    &reason,
                )?;
                self.orchestrator.skip_dependents(stage_name);
            }
        }
        self.walk_away_latched
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Whether `stage_name` is a declared participant in one of this program's
    /// `review_loops` — worker (exit), reviewer, or any body member. Read off
    /// the checked program, not a runtime map: membership is a durable fact of
    /// the program and a `#iter-N` re-dispatch peels to its base name before
    /// this consult.
    pub(super) fn stage_participates_in_loop(&self, stage_name: &SmolStr) -> bool {
        let base = kata_program::loops::base_stage_name(stage_name);
        self.execution_program.review_loops.iter().any(|cfg| {
            cfg.worker_stage == base
                || cfg.reviewer_stage == base
                || cfg
                    .body_stages
                    .iter()
                    .any(|member| member.0.as_str() == base.as_str())
        })
    }

    /// The execution id the runner was constructed with. Exposed so
    /// the executor can record it in `ExecutionRecord.id` without
    /// having to thread it through two separate code paths.
    #[must_use]
    pub fn execution_id(&self) -> Ulid {
        self.execution_id
    }

    /// A dependency counts as terminal for successor release only when the
    /// stage is terminal AND its `/work` apply has been
    /// accepted: a stage whose accepted outcome recorded a delta holds its
    /// dependents gated until `#apply/<stage>` commits the head advance.
    /// Failure is sticky-checked (`propagate` semantics) — a plane error
    /// answers `Err`, never silently releases.
    fn checked_dependency_is_terminal(&self, stage_id: &StageId) -> KataResult<bool> {
        let terminal = matches!(
            self.orchestrator.stage_state(stage_id.0.as_str()),
            Some(StageState::Completed { .. } | StageState::Skipped { .. })
        );
        if !terminal {
            return Ok(false);
        }
        Ok(!self.work_apply_blocks_successors(stage_id)?)
    }

    fn missing_checked_program_stage_is_ready(&self, stage_id: &StageId) -> KataResult<bool> {
        for dependency in self
            .orchestrator
            .dag()
            .dependencies(stage_id.0.as_str())
            .unwrap_or_default()
        {
            if !self.checked_dependency_is_terminal(&StageId(dependency.clone()))? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn advance_checked_ready_stages(&self) -> KataResult<Vec<SmolStr>> {
        // `static_ready_stage_ids`'s predicate cannot fail, so the
        // `work_apply` half of terminality is asked in a first fallible pass —
        // a dependency that is stage-terminal but still owed its apply is not
        // a dependency a successor may read.
        let mut candidates = BTreeSet::new();
        for candidate in self.execution_program.static_ready_stage_ids(|dependency| {
            matches!(
                self.orchestrator.stage_state(dependency.0.as_str()),
                Some(StageState::Completed { .. } | StageState::Skipped { .. })
            )
        }) {
            // The SAME dependency list `static_ready_stage_ids` consulted — the
            // CHECKED program's `depends_on`, not the orchestrator's retained
            // DAG — now asking the fallible half of terminality the static
            // predicate could not: a stage-terminal dependency still owed its
            // `/work` apply.
            let mut released = true;
            if let Some(stage) = self.execution_program.stages.get(&candidate) {
                for dependency in stage.depends_on.clone() {
                    if !self.checked_dependency_is_terminal(&dependency)? {
                        released = false;
                        break;
                    }
                }
            }
            if released {
                candidates.insert(candidate);
            }
        }

        // If the retained program is missing a normalized stage, surface the
        // divergence through the existing submit-stage preflight path once the
        // normalized definition would otherwise be ready. That path records the
        // checked dispatch guard failure evidence before returning an error.
        for stage_name in self.orchestrator.dag().topological_order() {
            let stage_id = StageId(stage_name.clone());
            if !self.execution_program.stages.contains_key(&stage_id)
                && self.missing_checked_program_stage_is_ready(&stage_id)?
            {
                candidates.insert(stage_id);
            }
        }

        // `parallel` primitive: workflow-level concurrency throttle.
        // When `workflow(max_concurrency=N)` is set, cap how many stages we
        // promote+return (and therefore submit) THIS pass so the count of
        // concurrently in-flight stages never exceeds `N`. Excess ready stages
        // are deliberately LEFT in `Pending` (we never promote past capacity),
        // so `static_ready_stage_ids` re-surfaces them as candidates on every
        // subsequent pass — they are picked up as in-flight stages complete and
        // free capacity. `None` (the default) leaves `remaining_capacity` at
        // `usize::MAX`, so the loop promotes every candidate exactly as before:
        // byte-identical behavior for every workflow that omits the throttle.
        //
        // Always-progress / no-deadlock: capacity is `0` only when
        // `in_flight >= N >= 1`, i.e. at least one stage IS in flight. That
        // stage will reach a terminal ledger row, emit an event, and wake the
        // run loop, which re-advances with freed capacity. When `in_flight == 0`
        // and there is ready work, capacity is `N >= 1 > 0`, so we always
        // promote+submit at least one stage. The runner is never left idle with
        // ready work and spare capacity. `N == 1` therefore serializes the
        // workflow to completion.
        // Capacity and stage state resolve against the SAME plane (the chain),
        // so one decision never reads two answers.
        let mut remaining_capacity = match self.execution_program.max_concurrency {
            Some(limit) => {
                let in_flight = self.in_flight_stage_count()?;
                (limit as usize).saturating_sub(in_flight)
            }
            None => usize::MAX,
        };

        // THE READY-ADVANCE IS A DISPATCH POINT, so a walk-away stops it, as it
        // stops a loop's and a topology's: once any walk-away row is durable
        // (`durable_walkaway_halt_rows`, the read theirs make) no candidate is
        // promoted. A completion folded before the trip may have released it, or
        // the throttle held it `Pending`; either way it never started, so it is
        // skipped with every stage behind it
        // ([`Self::skip_unstarted_after_walk_away`]), whatever its operation — a
        // capsule, a join, a timer, a child invocation, a workspace effect. An
        // expansion's claim trigger is the one exception: its submit claims (or,
        // on a resumed fold, re-claims) the loop or topology, whose own derive
        // dispatches nothing past the row and resolves it. Read only when a
        // candidate is still `Pending`, the one state this pass promotes.
        let promotable = candidates.iter().any(|candidate| {
            matches!(
                self.orchestrator.stage_state(candidate.0.as_str()),
                Some(StageState::Pending)
            )
        });
        let walked_away = if promotable {
            self.durable_walkaway_halt_rows()?.into_iter().next()
        } else {
            None
        };
        let mut newly_ready = Vec::new();
        for stage_id in candidates {
            match self.orchestrator.stage_state(stage_id.0.as_str()) {
                Some(StageState::Pending) => {
                    if let Some(row) = &walked_away
                        && !self.stage_seats_an_expansion(&stage_id)
                    {
                        self.skip_unstarted_after_walk_away(&stage_id.0, row)?;
                        continue;
                    }
                    if remaining_capacity == 0 {
                        // Throttled: leave this stage `Pending`. It re-surfaces
                        // as a ready candidate next pass once an in-flight stage
                        // completes and frees capacity. NOT dropped.
                        continue;
                    }
                    self.orchestrator.promote_to_ready(stage_id.0.as_str())?;
                    newly_ready.push(stage_id.0);
                    remaining_capacity -= 1;
                }
                Some(_) => {}
                None => {
                    return Err(KataError::Validation(format!(
                        "checked execution program selected unknown stage: \"{}\"",
                        stage_id.0
                    )));
                }
            }
        }
        Ok(newly_ready)
    }

    /// A stage the ready-advance reached after the run walked away (`row` is the
    /// walk-away row): it never started, so it is skipped, naming the row, and
    /// so is every stage behind it — the skip a tripping stage's dependents get.
    ///
    /// Decided at the chain's head off the durable row, so a resumed fold reaches
    /// the same answer: a stage the live run skipped here has no frame, and is
    /// `Pending` again at the resumed head; one dispatched before the row has
    /// frames, and the fold has it in flight or terminal.
    fn skip_unstarted_after_walk_away(&self, stage_name: &SmolStr, row: &str) -> KataResult<()> {
        tracing::debug!(
            execution_id = %self.execution_id,
            stage = %stage_name,
            walk_away = %row,
            "walk-away: a stage the run never started is skipped"
        );
        self.orchestrator.skip_stage(
            stage_name,
            format!(
                "the run walked away (\"{row}\" recorded a walk-away halt), so the stage was \
                 never dispatched"
            ),
        )?;
        self.orchestrator.skip_dependents(stage_name);
        Ok(())
    }

    /// Count stages currently in flight for this execution, derived from the
    /// AUTHORITY chain (the `parallel` throttle).
    ///
    /// # One plane for state and capacity
    ///
    /// [`Self::advance_checked_ready_stages`] takes the stage STATE it promotes and
    /// the CAPACITY it promotes within from the same chain: one decision, one
    /// answer.
    ///
    /// The cap engages only while `in_flight >= N`, so an under-count never
    /// throttles — a count read off a plane that lags the chain would fail OPEN,
    /// and a throttle that fails open is indistinguishable from a workflow that
    /// never set one.
    ///
    /// Resume-safe by construction: the source is
    /// `Dispatcher::execution_stage_states(self.execution_id)` filtered to
    /// non-terminal, non-reserved stages. After a mid-run restart the chain holds
    /// those same durable rows, so the throttle re-derives capacity from persisted
    /// in-flight state rather than any in-memory counter, and never double-dispatches
    /// a stage the chain already records as dispatched/running. The count includes
    /// every non-terminal stage — static stages, review-loop iterations, and
    /// dynamic-fanout children alike. SCOPE: the cap GATES fresh inter-stage
    /// promotion — a `Pending → Ready` promotion is deferred
    /// when the cap is full. Loop-iteration and dynamic-fanout re-dispatch
    /// self-drive through the expansion claim (bypassing
    /// `advance_checked_ready_stages`), so they are COUNTED toward the cap (and
    /// therefore correctly defer fresh static stages) but are NOT themselves gated
    /// by it — a loop never stalls on the cap. The cap is therefore NOT a
    /// workflow-wide ceiling on loop/fanout re-dispatch.
    fn in_flight_stage_count(&self) -> KataResult<usize> {
        Ok(self
            .dispatcher
            .execution_stage_states(self.execution_id)?
            .iter()
            .filter(|s| !is_reserved_execution_metadata_stage(s.stage_name.as_str()))
            // A PROGRAM-LEVEL operation's main attempt (`#op/<path>`) is not a stage and
            // takes no concurrency slot. Recognized through the one inverse of its
            // coordinate, never by the reader omitting it.
            .filter(|s| {
                kata_types::execution_contract::OperationPath::from_program_operation_stage_id(
                    s.stage_name.as_str(),
                )
                .is_none()
            })
            // A `/work` apply's own attempt (`#apply/<stage>`) is not a stage
            // either — the same exclusion, one coordinate space over.
            .filter(|s| {
                kata_types::execution_contract::work_apply_stage(s.stage_name.as_str()).is_none()
            })
            .filter(|s| !s.is_terminal())
            .count())
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod active_workflow_gauge_tests;

#[cfg(test)]
#[path = "terminal_charge_tests.rs"]
mod terminal_charge_tests;

#[cfg(test)]
#[path = "walkaway_tests.rs"]
mod walkaway_crash_tests;

/// THE STAGE-SUBMIT INTERLEAVE — a rig lever, `test-support` only: the window between a
/// runner deciding a stage is ready and that stage's first durable write (its claim, its
/// park, or its main-side resolution), which is where an execution sits BETWEEN two
/// stages with nothing live. No arrangement of production calls made from outside holds
/// a runner there, so a rig that must act in that window (an operator cancel of a root
/// whose previous stage has been accepted and whose next is not yet claimed) installs a
/// mover here; it runs on entry to `WorkflowRunner::submit_stage` with the execution and
/// the stage, and the stage's submission continues when it returns. The mover is
/// synchronous, like the placement-writer seam's: one that must wait on async production
/// code blocks on it (a multi-thread runtime keeps the rest of the node running).
///
/// A process global rather than a runner field: `cargo nextest` runs each test in
/// its own process, so one rig's mover reaches no other.
#[cfg(any(test, feature = "test-support"))]
static STAGE_SUBMIT_INTERLEAVE: parking_lot::Mutex<Option<crate::test_harness::StageSubmitMover>> =
    parking_lot::Mutex::new(None);

/// Install the mover — see [`STAGE_SUBMIT_INTERLEAVE`]. The rigs' door onto it is
/// `crate::test_harness::interleave_before_a_stage_submit`.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn install_stage_submit_interleave(interleave: crate::test_harness::StageSubmitMover) {
    *STAGE_SUBMIT_INTERLEAVE.lock() = Some(interleave);
}

/// Run the installed mover, if a rig installed one. Cloned out of the lock before the
/// call, so a mover that blocks holds nothing another runner needs.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn run_stage_submit_interleave(execution_id: Ulid, stage_name: &str) {
    let interleave = STAGE_SUBMIT_INTERLEAVE.lock().clone();
    if let Some(interleave) = interleave {
        interleave(execution_id, stage_name);
    }
}

/// THE PASS-FOLD INTERLEAVE — a rig lever, `test-support` only: run the mover once per
/// drive-pass iteration, between the pass's owed-obligation drives and the fold that
/// lands a commit's effects this iteration. The window it opens is the exact one the
/// blocked-check rechecks the derived-obligation plane for: a capsule completion that
/// commits here owes a `/work` apply no pass has driven — the stage reads terminal,
/// the obligation is derived, and nothing bumps the chain head.
///
/// A process global rather than a runner field for the reason
/// [`STAGE_SUBMIT_INTERLEAVE`] states: `cargo nextest` runs each test in its own
/// process, so one rig's mover reaches no other. Synchronous for the same reason: a
/// mover that must wait on the test's deposit blocks, and a multi-thread runtime
/// keeps the rest of the node running.
#[cfg(any(test, feature = "test-support"))]
static PASS_FOLD_INTERLEAVE: parking_lot::Mutex<Option<crate::test_harness::PassFoldMover>> =
    parking_lot::Mutex::new(None);

/// Install the mover — see [`PASS_FOLD_INTERLEAVE`]. The rigs' door onto it is
/// `crate::test_harness::interleave_before_the_pass_fold`.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn install_pass_fold_interleave(interleave: crate::test_harness::PassFoldMover) {
    *PASS_FOLD_INTERLEAVE.lock() = Some(interleave);
}

/// Run the installed mover, if a rig installed one. Cloned out of the lock before the
/// call, so a mover that blocks on a deposit holds nothing another runner needs.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn run_pass_fold_interleave(execution_id: Ulid) {
    let interleave = PASS_FOLD_INTERLEAVE.lock().clone();
    if let Some(interleave) = interleave {
        interleave(execution_id);
    }
}

/// THE MEMBER-READ INTERLEAVE — a rig lever, `test-support` only: run the mover each time
/// an expansion drive has read a member's occurrence UNACCEPTED, before it judges the
/// member live or dead off that read. A completion that commits here lands between the
/// read and the judgment — the window in which a judgment built from two reads would see
/// an unaccepted occurrence beside a `completed` attempt and call a finished member dead.
/// The seam sits after the one settlement read, so the cells that drive it catch a split
/// read only when the split's second read lands after the seam.
///
/// A process global rather than a runner field, and synchronous, for the reasons
/// [`PASS_FOLD_INTERLEAVE`] states.
#[cfg(any(test, feature = "test-support"))]
static MEMBER_READ_INTERLEAVE: parking_lot::Mutex<Option<crate::test_harness::MemberReadMover>> =
    parking_lot::Mutex::new(None);

/// Install the mover — see [`MEMBER_READ_INTERLEAVE`]. The rigs' door onto it is
/// `crate::test_harness::interleave_after_a_member_read`.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn install_member_read_interleave(interleave: crate::test_harness::MemberReadMover) {
    *MEMBER_READ_INTERLEAVE.lock() = Some(interleave);
}

/// Run the installed mover, if a rig installed one, with the execution and the member's
/// occurrence id. Cloned out of the lock before the call, so a mover that blocks holds
/// nothing another runner needs.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn run_member_read_interleave(execution_id: Ulid, occurrence_id: [u8; 32]) {
    let interleave = MEMBER_READ_INTERLEAVE.lock().clone();
    if let Some(interleave) = interleave {
        interleave(execution_id, occurrence_id);
    }
}
