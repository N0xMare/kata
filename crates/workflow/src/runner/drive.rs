//! The runner drive loop.
//!
//! Hosts the top-level `run` loop that drives a workflow to completion (the
//! replay drive, `run_replay`), the boot fold and in-flight rehydration, the
//! ordered-shutdown detach, and the failure-collection helper
//! (`collect_failures`). Event application (`apply_event`) lives in its own
//! module.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use kata_core::AssignmentStatus;
use kata_core::operational::liveness::Wake;
use kata_types::error::{KataError, KataResult};
use smol_str::SmolStr;
use tracing::{info, warn};

use crate::attempt_delivery::{MappedFrame, foldable_frame};
use kata_program::orchestrator::StageState;

use super::{ActiveWorkflowGuard, WorkflowRunner};

/// How long the drive loop parks on the AUTHORITY PLANE'S wake before re-reading
/// it anyway.
///
/// # This bounds a RESIDUE, and is never on the wake path
///
/// Every operational transaction publishes its wake inside
/// `OperationalDb::in_writer_txn`, welded to the commit, so an in-process writer
/// cannot commit a fact this loop needs without waking it — the budget does not
/// participate in ordinary progress and shortening it would buy nothing. What it
/// covers is the residue an in-process signal structurally cannot: another
/// process holding the same data directory. Under an UNBOUNDED park that residue
/// is a permanent hang.
///
/// One second, because both failure directions are cheap and asymmetric: too
/// long is bounded latency on a case that does not arise in a single-process
/// node, while each expiry costs one indexed tail probe on the operational
/// reader — and that read shares the writer's connection mutex, so a much
/// shorter budget would put every parked execution in contention with live
/// writers for no correctness gain.
const CHAIN_WAKE_BUDGET: Duration = Duration::from_secs(1);

impl WorkflowRunner {
    /// Drive the workflow to completion, returning stage outputs keyed by
    /// stage name.
    ///
    /// The durable-replay watermark state machine ([`Self::run_replay`])
    /// is the sole engine: every run — fresh or resumed — drives by folding the durable event log
    /// ("recovery is replay").
    pub async fn run(&self) -> KataResult<BTreeMap<SmolStr, serde_json::Value>> {
        // `SandboxDirective` is large enough to tip this future past clippy's
        // 16384-byte large-future line (mirrors the other `Box::pin`s in this
        // runner). Box the driver future so the enclosing frame holds a
        // pointer, not the inline state machine.
        Box::pin(self.run_replay()).await
    }

    /// Shared terminal epilogue for the drive loop. On a clean finish
    /// (`is_finished()` satisfied and the loop broken), perform the final
    /// cache flush, surface any `Failed` stage as an error, enforce the
    /// orchestrator-vs-ledger consistency invariant, and log completion.
    /// `run_replay` calls it on every terminal exit.
    fn finalize_run(
        &self,
        outputs: BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<BTreeMap<SmolStr, serde_json::Value>> {
        // Final cache flush. Both break paths (inner-loop finish
        // and stuck-branch resync-then-finish) can exit without
        // having routed the very last terminal events through
        // `flush_pending_capsule_reuse_hints`, so any stages whose output
        // arrived in the final iteration need one more chance to
        // land in the cache store before we return. This is idempotent
        // and cheap — the flush is a no-op when pending is empty.
        self.flush_pending_capsule_reuse_hints(&outputs);

        // Post-finish failure scan. Even though is_finished() was
        // satisfied, a stage may have ended in Failed state — we
        // surface that as an Err so a silent Ok({}) cannot mask a
        // workflow-level failure.
        //
        // The scan is TWO scans because a walk-away is durable on a
        // plane the orchestrator does not model. `collect_failures` enumerates the
        // DAG; the walk-away rows are synthetic by construction and are not DAG
        // stages, so a single scan would leave a bound/budget halt invisible to the
        // terminal decision and every operator surface downstream of it. See
        // [`WorkflowRunner::collect_durable_walkaway_halts`].
        let mut failures = self.collect_failures();
        failures.extend(self.collect_durable_walkaway_halts()?);
        if !failures.is_empty() {
            let count = failures.len();
            let joined = failures.join("; ");
            return Err(KataError::Internal(format!(
                "workflow completed with {count} failed stage(s): {joined}"
            )));
        }

        // Orchestrator-vs-ledger consistency invariant. The
        // ledger-driven exit conditions above (stuck recovery,
        // is_finished, no-pending) can all fire while the
        // orchestrator still has stages in non-terminal state (a
        // validation retry on a loop reviewer can leave the loop
        // unresolved while the ledger reports all-terminal). Surface
        // that divergence loud rather than silently returning Ok with
        // an incomplete output map.
        let unfinished = self.orchestrator.unfinished_stages();
        if !unfinished.is_empty() {
            let detail = unfinished
                .iter()
                .map(|(name, tag)| format!("{name}:{tag}"))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::error!(
                execution_id = %self.execution_id,
                unfinished_count = unfinished.len(),
                detail = %detail,
                "runner.terminal.divergence: ledger reports all-terminal but orchestrator has non-terminal stages"
            );
            return Err(KataError::Internal(format!(
                "workflow run exited with {} non-terminal stage(s) in the orchestrator \
                 despite a clean ledger drain (likely a loop or retry path bypassed \
                 the orchestrator transition): {detail}",
                unfinished.len()
            )));
        }

        info!(
            execution_id = %self.execution_id,
            stages = outputs.len(),
            "workflow run finished"
        );

        Ok(outputs)
    }

    /// The durable-replay watermark state machine — the sole drive
    /// engine.
    ///
    /// It drives by WATERMARK rather than by a stuck detector hedged with
    /// pass counts or event-head snapshots:
    ///
    /// - `H` = this execution's authority-chain head
    ///   (`execution_chain_head`).
    /// - `A` = the local applied-watermark: the highest chain sequence this
    ///   runner has folded into the orchestrator.
    ///
    /// The loop's phases:
    ///
    /// 1. **Boot**: a PURE FOLD — seed `A = 0` (via `boot_pure_fold`)
    ///    and let phase 2 replay every durable event from seq 1, so `apply_event`
    ///    reconstructs the entire orchestrator + loop state by replay (fresh run
    ///    ⟹ empty log ⟹ no-op): "recovery is replay".
    /// 2. **Advancing (the fold)**: while `A < H`, `fold_to_head` reads the chain
    ///    from `A+1` and `apply_event`s each frame in strict chain-seq order,
    ///    advancing `A`.
    ///    Applying an event NEVER re-invokes the model — the recorded
    ///    `Completed.output` is read straight off the log frame, exactly as the
    ///    live broadcast path does.
    /// 3. **Drive**: select + submit ready static stages and drain the four
    ///    queues (loop / validate / fanout / subworkflow). New dispatches/resolutions emit ledger
    ///    events, bumping `H`; the fold in the next pass consumes them.
    /// 4. **Blocked-check**: stuck is declarable ONLY at `A == H` (every durable
    ///    event folded) AND `!is_finished()` AND the orchestrator has NO in-flight
    ///    stage. Because `H` bumps before broadcast and a completing stage stays
    ///    non-terminal in the orchestrator until its event is durable-and-folded,
    ///    no terminal can land unobserved — the fold IS the check, and a
    ///    spurious stuck verdict is unrepresentable. If work is still in flight, block on the
    ///    ledger broadcast as a wake (a lost/lagged broadcast just means the next
    ///    fold catches up from the durable log).
    #[allow(clippy::too_many_lines)]
    async fn run_replay(&self) -> KataResult<BTreeMap<SmolStr, serde_json::Value>> {
        self.dispatcher
            .execution_lifecycle()
            .db()
            .require_imports_reconciled()?;
        // The pending-`/work`-apply sweep runs BEFORE the
        // fold resumes: a crash between an apply's jj publish and its resolve
        // leaves a pending `work_apply` attempt and possibly a stale working
        // copy, and neither the fold nor any stage dispatch may observe the
        // candidate before the sweep reconciles it
        // (`classify_work_apply`/`repair_stale_checkout`).
        self.drive_pending_work_applies()?;
        // The pending-`workspace_effect` sweep rides the same pre-fold slot: a
        // crash between an effect's claim and its resolve leaves `pending`, and
        // neither the fold nor a dispatch may observe the workspace before the
        // sweep classifies it.
        self.drive_pending_workspace_effects()?;
        // kata_workflow_active_count gauge — RAII balance held for the whole
        // future, released on every exit (Ok, Err, panic, cancellation).
        let _active = ActiveWorkflowGuard::new();
        info!(
            execution_id = %self.execution_id,
            "workflow run started (replay engine)"
        );

        // Take the AUTHORITY PLANE'S liveness handle BEFORE the first fold, so no
        // wake is lost. The handle must be the plane the fold reads: a second
        // plane's broadcast is a disjoint publisher, so a chain write would land
        // unannounced and the runner would park forever.
        //
        // ONE handle for the whole loop, never a fresh one per park. A waiter
        // starts deliberately behind any plane that has ever committed, so a
        // handle taken at the park would return `Recheck` immediately every time
        // and turn the park into a spin. Taken here it advances its own high-water
        // mark only as `wait` returns — which is strictly before the next read —
        // so a commit concurrent with that read is still unobserved when the park
        // begins and the park returns at once.
        let mut wake = self.dispatcher.chain_liveness();
        let mut outputs: BTreeMap<SmolStr, serde_json::Value> = BTreeMap::new();

        // boot: PURE FOLD. Seed `A = 0` and complete the boot ONCE,
        // before the drive loop — `boot_pure_fold` folds the whole durable log
        // through `apply_event` (the exact per-event handler the live path uses,
        // reconstructing the ENTIRE orchestrator + loop state; the model is NEVER
        // re-invoked — a recorded `Completed.output` is read straight off the log
        // frame), then rehydrates any in-flight-at-crash assignment (dispatch
        // authority + orchestrator force-dispatch / pause, bare-Pending
        // orphan+fail). On a fresh run the log is empty, so this is a no-op. This
        // is what makes recovery a replay: no separate ledger reconciliation
        // runs. The drive loop's own folds below stay `fold_to_head` (no
        // re-rehydration).
        let mut applied: i64 = 0;
        self.boot_pure_fold(&mut applied, &mut outputs)?;
        // A capsule claim the previous main committed and never dispatched. The boot
        // fold has marked its stage in flight and nothing presents its occurrence
        // again, so it is dispatched here — once, after the fold, before the drive
        // loop can submit anything of its own.
        Box::pin(
            self.dispatcher
                .dispatch_claims_left_undispatched(self.execution_id),
        )
        .await?;

        loop {
            // Inner drive loop: fold the durable tail, drain the four action
            // queues, then select + submit ready static stages. Repeat while it
            // makes progress (a completed stage can unlock a downstream one, and
            // a drain can dispatch synthetic work whose events must be folded in
            // the same burst) so a chained workflow on fast workers advances
            // without waiting on a broadcast between every stage.
            loop {
                // Land any augmented envelope whose ledger
                // projection has caught up since the last pass. First in the pass
                // rather than last, because the projection it waits on is written
                // by ANOTHER task and the longest gap in this loop is the park
                // above it. See `WorkflowRunner::pending_output_amendments`.
                self.drain_pending_output_amendments()?;
                // Fold every durable event we have not applied yet.
                self.fold_to_head(&mut applied, &mut outputs)?;
                // Drain the retry queue: a due failure retry
                // re-dispatches its stage's capsule at the chain's next seat.
                self.execute_failure_retries(&outputs).await?;
                self.flush_pending_capsule_reuse_hints(&outputs);
                // Re-fold: the drains above may have emitted new ledger events
                // (loop iterations, retries, fanout children, resumed parents).
                self.fold_to_head(&mut applied, &mut outputs)?;

                // The apply leg of a capsule stage's acceptance rides the pass:
                // drive pending applies BEFORE the ready-advance, so a stage
                // whose delta is still owed holds its successors gated rather
                // than letting them map a head that has not advanced.
                self.drive_pending_work_applies()?;
                self.drive_pending_workspace_effects()?;
                // A validation retry rides AFTER the apply drive:
                // its capsule maps the stage's `/work` head, and the invalid
                // attempt's delta must have landed for the retry to "start from
                // the advanced head" (validation_retry.rs's documented seat).
                // Drained earlier in the pass it maps the pre-apply head, and
                // its own delta is the second delta over a moved base —
                // `work_delta_base_stale` at `#apply` fails the run a converged
                // retry should have completed.
                self.execute_validate_retries(&outputs).await?;
                // A `pending` expansion attempt rides the same
                // pass: derive member state from durable occurrences, dispatch
                // the next member capsule, or resolve the main attempt with its
                // `ExpansionRecord`. Before the ready-advance so a resolved
                // expansion's orchestrator transitions are visible to it.
                self.drive_pending_expansions(&outputs).await?;
                // A rig lever — a completion committed here owes a `/work`
                // apply no pass has driven; the seam lets a cell hold that
                // window open (test-support only).
                #[cfg(any(test, feature = "test-support"))]
                crate::runner::run_pass_fold_interleave(self.execution_id);
                // Fold the transitions the drives above just committed BEFORE
                // the ready-advance: an apply's `#apply/<stage>` completion is
                // what re-persists a deferred validation report bound to the
                // post-write candidate, and a promote's gate — checked at the
                // successor's submit — must see that evidence, not the
                // `proof:missing` of a fold that has not run yet. Without this
                // fold the gate always raced: the apply resolved in this pass,
                // its transition folded in the next, and the gate sat between.
                self.fold_to_head(&mut applied, &mut outputs)?;
                let ready = self.advance_checked_ready_stages()?;
                if ready.is_empty() {
                    break;
                }
                for stage_name in ready {
                    // Box the submit future — `SandboxDirective` is large enough
                    // to push it past clippy's large-future line; boxing keeps
                    // the loop frame small.
                    Box::pin(self.submit_stage(&stage_name, &outputs)).await?;
                }
            }

            // Termination check — a run is NOT finished while it owes a `/work`
            // apply: the obligation is derived (a completed outcome carrying a
            // delta) and records no chain row until the drive claims it, so a
            // leaf stage's completion folding after the pass's apply drive
            // would let `is_finished` exit with the last stage's write absent
            // from the recorded head — the tree promote, forge and the
            // operator read. An owed apply is unfinished work: the next pass
            // claims and resolves it, then this check passes.
            if self.orchestrator.is_finished()
                && self
                    .dispatcher
                    .execution_lifecycle()
                    .db()
                    .pending_work_applies(self.execution_id)?
                    .is_empty()
            {
                break;
            }

            // The blocked-check. `H` is re-read AFTER the fold+drive
            // above: if a concurrent writer committed during this pass (or a
            // terminal landed that we have not yet folded), `A < H` and we MUST
            // NOT declare stuck — loop back to fold it. This is the deterministic
            // check: no yield, no sleep, no consecutive-empty count.
            //
            // `applied` is a PER-EXECUTION
            // watermark — the fold reads only this execution's rows and advances
            // `A` over its sequences alone — so the head MUST be this execution's,
            // never a global one. With a global head a per-execution `A` can never
            // reach it whenever the log interleaves a concurrent execution's rows:
            // `A < H` stays true forever and `run_replay` live-locks, folding an
            // empty tail on every pass.
            //
            // The SAME live-lock, one plane over: `A` is a CHAIN sequence, so `H` is
            // read from the chain too. A `ledger_events` sequence would span a
            // disjoint sequence space — a chain watermark below a larger ledger
            // head reproduces the sentence above verbatim. The watermark's TYPE
            // is what stops that: `applied` is `i64` (the chain's space) and
            // delivery sequences are `u64`, so the mixed comparison is a compile
            // error rather than a comment.
            let head = self.dispatcher.execution_chain_head(self.execution_id)?;
            if applied < head {
                continue;
            }

            // `A == H`: every durable event is folded. Is anything still in
            // flight? We ask the ORCHESTRATOR, not the ledger DashMap: a stage
            // that has completed in the DashMap but whose event is not yet
            // durable still reads as in-flight here (it stays `Ready` until its
            // Completed event is folded), so the DashMap-leads-durable-head
            // window that produced the ~5% flake is invisible to this check.
            if self.orchestrator.has_in_flight_stage() {
                // In-flight work exists; park until the AUTHORITY PLANE commits
                // something, then re-fold.
                //
                // BOTH DIRECTIONS TERMINATE. The tail-reached-and-nothing-in-flight case never
                // gets here: it falls through to the stuck verdict below and
                // returns. The genuinely-still-in-flight case parks under a
                // MANDATORY budget, so even a plane that never publishes re-reads
                // and rescues itself — a redundant fold, never a missed one, and
                // never the silent hang an unbounded park carries.
                //
                // The wake decides NOTHING. It says only "read the plane again",
                // and it cannot even distinguish a real commit from an expired
                // budget, so nothing here can be tempted to treat a quiet plane as
                // a settled one. The verdict below is still derived entirely from
                // the durable chain and the orchestrator.
                //
                // ORDERED-SHUTDOWN DETACH.
                //
                // The stopping main aborts its producers — including
                // `Dispatcher::run_assignment_deadline_sweep`, which wakes every due
                // main-resolved timer — BEFORE it drains workflow drivers. A run whose
                // remaining work is one of the parks below loses nothing by detaching:
                // nothing this runner could run in the drain is lost (see
                // `detach_loses_nothing` for each park's argument), and waiting
                // would cost the whole 10s drain budget on every graceful stop
                // that held a non-terminal execution (one parked
                // `sleep(for_ms = 5000)` measured at ~13 s in
                // `workflow_tasks_drained` alone in `installed-main.shutdown.json`).
                //
                // THE REFUSED SET IS EXACTLY FOUR PARKS, and each is read off the plane
                // its waker decides from, not inferred from a timer or a count of quiet
                // passes: detach only when every open unit of work this execution owns is
                // a main-resolved wait parked in `awaiting_timer` / `awaiting_input`, a
                // main-resolved `Invoke` parked in `awaiting_child_completion`, or a
                // transient re-run whose backoff has not passed — a plain stage's queued
                // failure retry, or a `loop(..)` whose member's next seat is one (see
                // `detach_loses_nothing`). Any open WORKER attempt keeps the run in the
                // drain: a stage genuinely executing on a still-live worker is
                // `dispatched` or `running`, and it keeps the full drain budget,
                // unchanged. An unreadable main-attempt state answers `false`, so
                // corruption keeps today's behavior rather than buying an exit.
                //
                // Detaching terminalizes NOTHING. The durable Running lifecycle
                // stands, every committed frame stands, and restart recovery replays
                // the chain — "recovery is replay from a durable transition chain",
                // which is the property the restart half of that same smoke asserts.
                // `AdmissionClosed` is the state's existing name and its own docs
                // already forbid reading it as a failed occurrence.
                if self.dispatcher.graceful_shutdown_began() && self.detach_loses_nothing() {
                    info!(
                        execution_id = %self.execution_id,
                        applied,
                        "runner(replay): detaching a quiet park for restart recovery; the main is \
                         stopping and every unit of work this execution still owns is parked on a \
                         main-resolved timer or input wait, or on a child invocation whose \
                         child resolves it durably"
                    );
                    return Err(KataError::AdmissionClosed(format!(
                        "execution {} detached at a quiet park during ordered shutdown; the durable \
                         chain carries its resumption and restart recovery replays it",
                        self.execution_id
                    )));
                }
                match wake.wait(CHAIN_WAKE_BUDGET).await {
                    Wake::Recheck => {}
                    Wake::Closed => {
                        return Err(KataError::Internal(
                            "runner(replay): the operational plane's liveness channel closed, so \
                             no further commit can be observed and re-reading is no longer \
                             possible"
                                .into(),
                        ));
                    }
                }
                continue;
            }

            // BLOCKED — or is it? Before the verdict, ask the DERIVED
            // obligation plane: a stage's `/work` apply is owed from the
            // moment its completed outcome records a delta, and the obligation
            // carries NO chain row until the drive claims it. A completion this
            // pass's last fold landed — after `drive_pending_work_applies`
            // already ran — leaves exactly this: A == H, the stage terminal,
            // its successor gated on an apply nothing has driven. Undriven
            // owed work is not a stuck execution — fold and drive it on the
            // next pass.
            if !self
                .dispatcher
                .execution_lifecycle()
                .db()
                .pending_work_applies(self.execution_id)?
                .is_empty()
            {
                continue;
            }

            // BLOCKED: `A == H`, not finished, the orchestrator has no
            // in-flight stage, and the derived-obligation plane owes nothing.
            // Every unfinished stage is `Pending` behind a failed/skipped
            // upstream — genuinely stuck. Surface the blocking failures with
            // the same two scans `finalize_run` makes: the DAG's failed stages
            // and the durable walk-away rows, which are no DAG stage — before
            // the emptiness check, so a walk-away is never reported as a run
            // stuck on nothing.
            let mut failures = self.collect_failures();
            failures.extend(self.collect_durable_walkaway_halts()?);
            if !failures.is_empty() {
                let count = failures.len();
                let joined = failures.join("; ");
                return Err(KataError::Internal(format!(
                    "workflow stuck after {count} failed stage(s) blocked downstream: {joined}"
                )));
            }
            return Err(KataError::Validation(
                "workflow is stuck: no stages are ready or in-flight, \
                 but the workflow is not finished (a failed stage may \
                 have blocked downstream dependents)"
                    .into(),
            ));
        }

        // The LAST stage's amendment has no later pass to land in, because the
        // pass that folded its terminal is the one that broke out of the loop. Its
        // ledger projection is written by the reactor straight-line after the
        // chain commit that woke this task.
        //
        // What is outstanding here is the PROJECTION and nothing else. The
        // augmented envelope reached the deciding plane when the fold computed it
        // — `amend_or_defer_output` does not wait on this row to record it — so a
        // residue leaves the projected row holding the RAW envelope while the chain
        // holds the amended one.
        // Shared terminal epilogue (identical to the fixed-point exit).
        self.finalize_run(outputs)
    }

    /// Is every open unit of work this execution owns a park that detaching loses nothing
    /// by — a MAIN-RESOLVED wait in `awaiting_timer` / `awaiting_input`, a
    /// MAIN-RESOLVED `Invoke` in `awaiting_child_completion`, or a transient re-run
    /// whose backoff has not passed (a plain stage's queued failure retry, or a
    /// `loop(..)` whose member's next seat is one)?
    ///
    /// The ordered-shutdown detach's whole discriminator — see its call site in
    /// [`Self::run_replay`]'s park. The classes are narrow ON PURPOSE, each by its waker:
    /// `Dispatcher::sweep_due_waits` is a main timer's, and the shutdown aborts the deadline
    /// sweep that runs it a phase before it drains drivers; an input wait is ended by an
    /// operator's answer or cancel, which the closed admission no longer takes. So a run in
    /// those two states provably cannot advance in this process.
    ///
    /// The third class is a MAIN-RESOLVED `Invoke` parked in `awaiting_child_completion`,
    /// and its argument is a different one, stated rather than borrowed: its waker is its
    /// CHILD's terminal publication, which CAN still fire in this process while the child
    /// drains — but it resolves the parent's attempt in the child's own transaction, never
    /// through this runner. So the parent owns no work here: the child's runner keeps (or
    /// detaches from) the drain on its own open work, and whichever happens, the parent's
    /// resolution is on the chain for restart recovery to replay. Holding the parent's drive
    /// open buys nothing but the drain budget.
    ///
    /// The fourth class is a transient model provider re-run not yet DUE, inside its
    /// backoff: a plain stage's queued failure retry, or a `loop(..)` whose pending main
    /// attempt's derive reaches a member's re-run seat before its due instant
    /// (`expansion_waits_out_a_backoff`; no member attempt is live then). Neither is a row
    /// of its own: nothing dispatches it before the due instant, and the replay re-derives
    /// the seat and that same instant from the failed frame on the chain. A due one keeps
    /// the run in the drain, as an open worker attempt does, and so does a `loop(..)` with
    /// a live member or a `topology` (whose members are never re-run).
    ///
    /// Every other non-terminal state — every open WORKER attempt (`pending`,
    /// `dispatched`, `running`, `stalled`, `awaiting_approval`) — answers `false` here and
    /// keeps the full drain budget; the ones whose wakers this shutdown also stops are not
    /// in the refused set because their unwakeability has not been established the way
    /// these have.
    ///
    /// Two reads, one per plane of work: [`Dispatcher::live_work_registry`] — the SAME
    /// non-terminal chain snapshot the stopped deadline sweep discovers candidates from, which
    /// excludes main attempts by name — and this execution's `attempts` rows for the
    /// main-resolved ones, which that registry cannot see. Called only under the shutdown
    /// fence, so an ordinary park still costs nothing.
    ///
    /// # Polarity
    ///
    /// Fails toward WAITING in every ambiguous case, and returns `bool` rather
    /// than `KataResult<bool>` so that is not optional at the call site. No open
    /// work for this execution on the chain (a stage in flight in the orchestrator
    /// but not yet on the plane) answers `false`; a main attempt whose state the
    /// chain cannot decode answers `false`; and a plane the process cannot read at
    /// all answers `false` too — an unreadable plane must never be what buys a run
    /// its exit, because the exit's whole justification is that the chain is
    /// carrying the run.
    fn detach_loses_nothing(&self) -> bool {
        let unread = |error: &dyn std::fmt::Display| {
            warn!(
                execution_id = %self.execution_id,
                %error,
                "runner(replay): could not read the non-terminal plane while stopping; \
                 keeping this run in the shutdown drain rather than detaching on an unread plane"
            );
            false
        };
        let live = match self.dispatcher.live_work_registry() {
            Ok(live) => live,
            Err(error) => return unread(&error),
        };
        let attempts = match self
            .dispatcher
            .execution_lifecycle()
            .db()
            .attempts_for_execution(self.execution_id)
        {
            Ok(attempts) => attempts,
            Err(error) => return unread(&error),
        };
        if live
            .iter()
            .any(|work| work.execution_id == self.execution_id)
        {
            return false;
        }
        // A queued failure retry whose BACKOFF has not passed is the fourth
        // park: nothing dispatches it before its due instant, and the replay
        // re-derives it — seat and due instant alike — from the failed frame. A
        // due one keeps the run in the drain: the next pass dispatches it here.
        let mut open = {
            let now = super::dispatch::now_ms();
            let queued = self.pending_failure_retries.read();
            if queued.iter().any(|retry| retry.due_at_ms <= now) {
                return false;
            }
            queued.len()
        };
        for attempt in attempts {
            if attempt.row.executor != kata_core::operational::AttemptExecutor::Main {
                continue;
            }
            let Some(state) = attempt.state.as_deref() else {
                return false;
            };
            if kata_core::operational::ATTEMPT_TERMINAL_STATES.contains(&state) {
                continue;
            }
            let lifecycle = kata_core::operational::AttemptLifecycle::from_state(state);
            let parked = lifecycle.is_some_and(|state| {
                state.is_main_resolved_wait()
                    || state == kata_core::operational::AttemptLifecycle::AwaitingChildCompletion
            });
            // A `loop(..)` whose only open work is a member's transient re-run
            // inside its backoff is the fourth park's loop form.
            let backoff = !parked
                && lifecycle == Some(kata_core::operational::AttemptLifecycle::Pending)
                && match self.expansion_waits_out_a_backoff(attempt.row.attempt_id) {
                    Ok(backoff) => backoff,
                    Err(error) => return unread(&error),
                };
            if !parked && !backoff {
                return false;
            }
            open += 1;
        }
        open > 0
    }

    /// The "Advancing" phase of the replay state machine. Fold every
    /// durable AUTHORITY transition with sequence `> *applied` into the
    /// orchestrator, in strict authority order, advancing `*applied` to the
    /// highest sequence consumed.
    ///
    /// Applying a frame goes through `apply_event`, the ONE routing body, so
    /// replay and the live path share identical per-status semantics (loop
    /// routing, validate retries, branch routes, cache writes). The model is
    /// NEVER re-invoked: the recorded `Completed.output` on the frame is the
    /// result.
    ///
    /// # The reader
    ///
    /// It reads `OperationalDb::read_transitions_for_execution` through
    /// [`AttemptDeliveryMapper::map_page`](crate::attempt_delivery::AttemptDeliveryMapper::map_page),
    /// the chain→fold half, proven against the real writers on both provenances.
    /// Four properties of this reader are load-bearing:
    ///
    /// 1. **It is GATED.** [`Dispatcher::deciding_chain_reader`] fails CLOSED on
    ///    an execution the nucleus does not hold. Ungated, an absent execution
    ///    reads as an empty history, which composes with the main-side writer's
    ///    deliberate fail-SAFE to replay COMPLETED WORK AS NEVER-RUN.
    /// 2. **It never SKIPS.** The chain reader REFUSES a row it cannot decode, so
    ///    there is nothing to step over and the cursor is derivable from the
    ///    frames themselves — one watermark, because two independently advanced
    ///    watermarks is a place for them to disagree.
    /// 3. **It reports BOTH classes as one.** A stage satisfied WITHOUT DISPATCH
    ///    (a cache hit, an escalation gate, a synthetic marker row, a parked
    ///    subworkflow parent) has no attempt and no worker; its stage-scope record
    ///    maps onto a [`MappedFrame::Delivery`] whose event names no worker,
    ///    interleaved in authority order with the attempt-scope frames it must not
    ///    overtake. Dropping that class would replay a cache-hit stage as
    ///    never-run on ORDINARY runs.
    /// 4. **An empty page is not the tail.** `reached_tail` is the reader's own
    ///    answer; a page can be empty because this execution's next transition is
    ///    beyond the limit's window of a chain that is global.
    pub(super) fn fold_to_head(
        &self,
        applied: &mut i64,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        const PAGE: usize = 1000;
        let chain = self.dispatcher.deciding_chain_reader(self.execution_id)?;
        loop {
            let page = chain.map_page(self.execution_id, applied.saturating_add(1), PAGE)?;
            for mapped in &page.mapped {
                match mapped {
                    MappedFrame::Delivery(frame) => {
                        let frame = foldable_frame(frame)?;
                        // Fold the durable start anchor so a resumed
                        // `Bound::Time` execution measures its total lifetime from
                        // the ORIGINAL start the chain recorded, not the resume
                        // time — the pure-replay derivation of the time-bound
                        // anchor. A frame that states no anchor
                        // carries `None` and is skipped.
                        if let Some(anchor_ms) = frame.started_at_ms {
                            self.absorb_started_at_ms_anchor(anchor_ms);
                        }
                        // Preserve the safe point captured by this lifecycle
                        // frame. Later record-only checkpoints are folded below;
                        // neither path reads a later mutable attempt row.
                        if let Some(cp) = frame.last_checkpoint {
                            self.absorb_recovered_checkpoint(frame.event.assignment_id, cp);
                        }
                        self.apply_event(&frame.event, frame.recorded_at_ms, outputs)?;
                    }
                    MappedFrame::Checkpoint {
                        assignment_id,
                        last_checkpoint,
                        ..
                    } => {
                        // A safe point preserves recovery evidence without
                        // replaying a lifecycle edge or publishing a wire event.
                        // Worker-side mid-stage skipping remains a separate
                        // capability: the dispatch frame carries no resume point.
                        self.absorb_recovered_checkpoint(*assignment_id, *last_checkpoint);
                    }
                }
            }
            // The chain reader's own cursor, never `from_seq + limit`: this
            // execution's sequences are sparse within a GLOBAL chain, so advancing
            // by the page size would step over another execution's rows AND this
            // one's next frame alike. `next_from_seq` is derived from the last
            // frame RETURNED and is unchanged from the request on an empty page,
            // so the watermark never leads what was consumed.
            *applied = (*applied).max(page.next_from_seq.saturating_sub(1));
            if page.reached_tail {
                break;
            }
        }
        Ok(())
    }

    fn absorb_recovered_checkpoint(&self, assignment_id: ulid::Ulid, checkpoint: u64) {
        let mut recovered = self.recovered_checkpoints.write();
        let slot = recovered.entry(assignment_id).or_insert(checkpoint);
        *slot = (*slot).max(checkpoint);
    }

    /// Complete a pure-fold Replay boot. Fold the ENTIRE durable log
    /// to head (reconstructing every terminal + orchestrator transition via
    /// `apply_event`), then rehydrate any assignment that was IN-FLIGHT at crash
    /// — the limbs a per-event fold cannot derive on its own because they need
    /// the durable attempt's stored capsule facts to be re-dispatchable on
    /// resume. Together this is the whole of recovery ("recovery is
    /// replay").
    ///
    /// Called ONCE from `run_replay`'s boot, BEFORE the drive loop: the
    /// rehydration reads the latest-status projection and re-dispatches every
    /// non-terminal in-flight row, so it must NEVER run mid-drive where a
    /// freshly-`submit_stage`d live stage still reads `Pending`/`Dispatched` in
    /// the projection — the drive loop's subsequent folds use `fold_to_head`
    /// directly.
    pub(super) fn boot_pure_fold(
        &self,
        applied: &mut i64,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        // Installed recovery prepares this runner before activation starts a
        // fresh output context. Every completed orchestrator stage contributes
        // its settled value, including child aggregates and loop bases whose
        // terminal handlers intentionally skip repeated finalization. Seed before
        // replay can consume dependencies; never replace newer caller context.
        for stage in self.orchestrator.dag().topological_order() {
            if let Some(StageState::Completed { output }) = self.orchestrator.stage_state(stage) {
                outputs.entry(stage.clone()).or_insert(output);
            }
        }
        self.drain_buffered_worker_inputs_before_boot_fold()?;
        self.fold_to_head(applied, outputs)?;
        self.rehydrate_in_flight_from_ledger()?;
        Ok(())
    }

    /// Only this bounded retained-input pass runs before the initial fold: every worker
    /// failure of this execution still retained undecided (`accepted = 0`) is offered
    /// again, re-deriving its commands from the frozen program, never from an operator
    /// packet or the derived mirror. A refusal keeps startup closed; earlier inputs may
    /// already be durably resolved and converge on the next boot.
    ///
    /// On a restart, the restart leg (`Dispatcher::settle_capsule_attempts_after_restart`)
    /// has already adjudicated each retained failure of a dispatched capsule attempt,
    /// before any runner was built, and settled the attempt where it could not. An input
    /// whose attempt is terminal by now is recorded as superseded
    /// (`worker_failure_superseded`) by the offer and marked accepted; only an input whose
    /// attempt that leg could neither adjudicate nor settle is still `Ready`, and is
    /// adjudicated here.
    fn drain_buffered_worker_inputs_before_boot_fold(&self) -> KataResult<()> {
        const BUFFERED_INPUT_BOOT_BUDGET: Duration = Duration::from_secs(30);
        let deadline = Instant::now() + BUFFERED_INPUT_BOOT_BUDGET;
        let face = self.dispatcher.execution_lifecycle();
        let inputs = face
            .db()
            .buffered_worker_failures(self.execution_id, deadline)?;
        for input in inputs {
            if Instant::now() >= deadline {
                return Err(KataError::Validation(
                    "buffered worker failure startup drain deadline elapsed".into(),
                ));
            }
            match face.db().buffer_worker_failure(&input)? {
                kata_core::operational::WorkerFailureOffer::AlreadyAccepted
                | kata_core::operational::WorkerFailureOffer::Superseded => continue,
                kata_core::operational::WorkerFailureOffer::Ready => {}
            }
            // A buffered failure needs no rehydrated dispatch authority: the
            // adjudication records the worker's terminal on the chain off the durable
            // attempt row and its occurrence (`Dispatcher::plan_worker_failure`).
            self.dispatcher.adjudicate_worker_failure_input(&input)?;
        }
        Ok(())
    }

    /// Rehydrate every in-flight ATTEMPT into the orchestrator after the boot
    /// fold. A capsule attempt needs no recovered dispatch command: one the
    /// previous main dispatched was settled before this runner was built
    /// (`Dispatcher::settle_capsule_attempts_after_restart`), and one it only
    /// claimed is dispatched off its durable row once this boot returns
    /// (`Dispatcher::dispatch_claims_left_undispatched`). What the fold cannot
    /// derive is the
    /// orchestrator's IN-FLIGHT marker for a stage this runner never
    /// submitted — without it `advance()` would re-submit a stage whose attempt
    /// the chain already owns. Parked states the fold's `FoldOutcome` arms
    /// already reconstructed are left alone; anything still `Pending`/`Ready`
    /// with a live chain attempt is marked dispatched.
    fn rehydrate_in_flight_from_ledger(&self) -> KataResult<()> {
        let mut entries = self
            .dispatcher
            .deciding_chain_reader(self.execution_id)?
            .execution_assignment_states(self.execution_id)?;
        // Deterministic order (stage name, then assignment id).
        entries.sort_by(|a, b| {
            a.stage_name
                .cmp(&b.stage_name)
                .then_with(|| a.assignment_id.cmp(&b.assignment_id))
        });
        for state in entries {
            // Terminal rows are already reconstructed by the fold; never
            // re-complete/re-fail them here.
            if state.is_terminal() {
                continue;
            }
            let stage_name = state.stage_name.clone();
            if state.is_awaiting_approval() {
                // The fold's `FoldOutcome::AwaitingApproval` arm already
                // promoted-then-paused the orchestrator stage. If a crash
                // window left it Pending, land the same park here.
                if matches!(
                    self.orchestrator.stage_state(stage_name.as_str()),
                    Some(StageState::Pending | StageState::Ready)
                ) {
                    let reason = match &state.status {
                        AssignmentStatus::AwaitingApproval { reason, .. } => reason.clone(),
                        _ => format!("stage {stage_name} parked awaiting approval"),
                    };
                    self.orchestrator.promote_to_ready(stage_name.as_str())?;
                    self.orchestrator
                        .pause_stage_for_approval(stage_name.as_str(), reason)?;
                }
                continue;
            }
            // Live on the chain: a capsule claim the previous main never
            // dispatched (`pending`; `run_replay` dispatches it once this boot
            // returns), a main-resolved attempt its own drive resolves, or a
            // worker attempt still dispatched. The orchestrator marks the stage
            // in flight so `advance()` never re-submits it.
            if matches!(
                self.orchestrator.stage_state(stage_name.as_str()),
                Some(StageState::Pending | StageState::Ready)
            ) {
                self.orchestrator
                    .force_dispatched_for_resume(stage_name.as_str(), None)?;
            }
        }
        Ok(())
    }

    /// Every DURABLE walk-away halt this execution recorded, read off the
    /// AUTHORITY chain.
    ///
    /// # Why it exists
    ///
    /// `time_bound` / `cost_bound` / `cost_budget("halt", ..)` are kata's headline
    /// unattended guarantee — *don't run forever, don't spend forever*. A trip
    /// writes the synthetic `<stage>#bound-halt-<kind>` / `<stage>#budget-halt`
    /// Failed row and dispatches nothing downstream, but [`Self::collect_failures`]
    /// — which decides an execution's terminal outcome — enumerates
    /// `orchestrator.dag()`, and a synthetic halt row is deliberately not a DAG
    /// stage. Without this read, `run()` would return `Ok`, `kata-api`'s
    /// workflow task (`WorkflowExecutor::run_submitted_workflow_task`) would latch
    /// the lifecycle `Completed` from
    /// `run_result.is_ok()`, and `try_get_execution_by_ulid` would reassign
    /// `ExecutionRecord.status` from that lifecycle — clobbering the `Failed` its
    /// own `aggregate_status` derived from this row (`kata run --wait` would report
    /// `"status":"completed"` for `workflows/examples/cost-walkaway.star`).
    ///
    /// # Why the AUTHORITY chain and not the runner's own memory
    ///
    /// The trip is a durable fact, and this read DECIDES the terminal outcome, so
    /// it belongs on the authority chain — the same plane and the
    /// same reader [`WorkflowRunner::persist_walkaway_halt`] already consults for
    /// exactly this row class. An in-memory "did I trip" flag would also answer
    /// wrong on the path that matters most: a RESUMED runner never re-mints the
    /// row (the persist writes one per execution), so it would report a halted
    /// execution as clean on every restart.
    ///
    /// # Failure: PROPAGATE
    ///
    /// [`Dispatcher::execution_stage_states`](crate::dispatcher::Dispatcher::execution_stage_states)
    /// fails closed on an execution the nucleus cannot speak for, and that
    /// polarity is load-bearing here rather than merely inherited: an empty answer
    /// reads as *"this run walked away from nothing"*, which is the same silence
    /// this method exists to end. A run whose terminal evidence cannot be read
    /// fails loudly instead of completing quietly.
    fn collect_durable_walkaway_halts(&self) -> KataResult<Vec<String>> {
        Ok(self
            .durable_walkaway_halt_rows()?
            .into_iter()
            .map(|row| {
                format!(
                    "\"{row}\" recorded a walk-away halt; stages downstream of it were skipped \
                     and never dispatched"
                )
            })
            .collect())
    }

    /// Every walk-away row (`kata_types::bound::is_walkaway_halt_row`) this
    /// execution's authority chain holds FAILED, by stage name — the one read
    /// the terminal outcome ([`Self::collect_durable_walkaway_halts`]), the
    /// once-per-execution persist ([`WorkflowRunner::persist_walkaway_halt`]) and
    /// every DISPATCH POINT decide from — a pending loop's or topology's next
    /// member (`WorkflowRunner::derive_expansion`, `derive_topology`), the
    /// ready-advance (`advance_checked_ready_stages`) and a plain stage's retry
    /// drains (`execute_validate_retries`, `execute_failure_retries`), none of
    /// which dispatches past the row. The
    /// fold does NOT: it applies frames in chain order, and a stage that
    /// completed before the walk-away must release what it released live — see
    /// `WorkflowRunner::walk_away_latched`.
    ///
    /// The chain unions two row classes and a resumed fold re-reads both, so a
    /// sorted, de-duplicated set keeps every reader's answer identical across a
    /// fresh run and its replay. Propagates a plane read failure for the reason
    /// [`Self::collect_durable_walkaway_halts`] states.
    pub(super) fn durable_walkaway_halt_rows(&self) -> KataResult<Vec<String>> {
        let mut rows: Vec<String> = self
            .dispatcher
            .execution_stage_states(self.execution_id)?
            .into_iter()
            .filter(|state| {
                state.is("failed") && kata_types::bound::is_walkaway_halt_row(&state.stage_name)
            })
            .map(|state| state.stage_name)
            .collect();
        rows.sort();
        rows.dedup();
        Ok(rows)
    }

    /// Scan the orchestrator for any stages in the `Failed` state
    /// and format a human-readable reason line for each. Used by
    /// both the replay blocked-check and the post-finish scan to
    /// surface real failures instead of generic "stuck" or
    /// `Ok({})` results.
    fn collect_failures(&self) -> Vec<String> {
        let mut failures: Vec<String> = Vec::new();
        for name in self.orchestrator.dag().topological_order() {
            if let Some(StageState::Failed { reason, retries }) =
                self.orchestrator.stage_state(name)
            {
                failures.push(format!(
                    "\"{name}\" failed after {retries} retries: {reason}"
                ));
            }
        }
        // A route whose `Select` decided nothing: not a DAG stage,
        // so the scan above cannot see it.
        failures.extend(self.failed_program_operation_lines());
        failures
    }
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod tests;
