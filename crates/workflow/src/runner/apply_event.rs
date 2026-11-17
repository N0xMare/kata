//! `apply_event`: fold a single ledger event into orchestrator state.
//!
//! Concern-split out of `runner/mod.rs` (behavior-preserving move).

use ulid::Ulid;

use super::{
    BTreeMap, KataError, KataResult, SmolStr, StageState, WorkflowRunner, dispatch,
    is_reserved_execution_metadata_stage,
};
use crate::attempt_delivery::FoldOutcome;
use kata_core::LedgerEvent;

impl WorkflowRunner {
    /// Apply a single ledger event to the orchestrator. Ignores
    /// non-terminal events (Dispatched, Running) — those are
    /// observability signals, not state transitions the orchestrator
    /// cares about. `recorded_at_ms` is the instant the chain recorded the
    /// frame.
    ///
    /// A stage satisfied WITHOUT DISPATCH — a walk-away row such as
    /// `<stage>#bound-halt-<kind>`, or the workflow-level failure sentinel —
    /// arrives here too, as the event its stage-scope record's delivery
    /// envelope carries (no worker named, no placement invented), so its
    /// routing is this one body's rather than a second handler's.
    pub(super) fn apply_event(
        &self,
        event: &LedgerEvent,
        recorded_at_ms: u64,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        self.fold_frame(
            &event.stage_name,
            event.assignment_id,
            &FoldOutcome::from_status(
                &event.new_status,
                event.output.as_ref(),
                event.terminal_charge.clone(),
            ),
            recorded_at_ms,
            outputs,
        )
    }

    /// The FOLD: apply one durable frame's outcome to the orchestrator.
    ///
    /// Takes the four things the fold reads — the stage name it routes on,
    /// the assignment identity, the outcome, and the instant the chain recorded
    /// the frame, at which every charge it makes is measured against a
    /// `time_bound`.
    #[allow(clippy::too_many_lines)]
    fn fold_frame(
        &self,
        stage_name: &SmolStr,
        assignment_id: Ulid,
        outcome: &FoldOutcome,
        recorded_at_ms: u64,
        outputs: &mut BTreeMap<SmolStr, serde_json::Value>,
    ) -> KataResult<()> {
        // A PROGRAM-LEVEL operation's own attempt (a branch
        // route's `Select`, `#op/<path>`) is no stage. Intercepted FIRST — before the
        // `#branch-skip` interception and before any stage-name route — because every
        // later arm reads the name as a stage and the structured-output door would refuse
        // it as an unknown one.
        // A `/work` apply's own attempt (`#apply/<stage>`) is
        // no stage either. Intercepted beside the `#op/` arm for the same
        // reason: every later arm reads the name as a stage's.
        if kata_types::execution_contract::work_apply_stage(stage_name.as_str()).is_some() {
            return self.fold_work_apply(stage_name.as_str(), assignment_id, outcome);
        }
        if let Some(path) =
            kata_types::execution_contract::OperationPath::from_program_operation_stage_id(
                stage_name.as_str(),
            )
        {
            return self.fold_program_operation(&path, outcome, outputs);
        }
        // An expansion MEMBER's frames carry its authored stage
        // id, and only the attempt's bound occurrence — at a child coordinate
        // `expand_path.child(N).child(m)` — says it is a member. Intercepted
        // before every stage-name route: a member's durable terminal is the
        // expansion's input, and its stage's orchestrator transitions are the
        // accepted record's to apply, never this frame's.
        if self.expansion_member_path_of(assignment_id)?.is_some() {
            return self.fold_expansion_member(stage_name, assignment_id, outcome, recorded_at_ms);
        }
        if is_reserved_execution_metadata_stage(stage_name.as_str()) {
            tracing::debug!(
                execution_id = %self.execution_id,
                stage = %stage_name,
                status = outcome.tag(),
                "runner: ignoring reserved execution metadata ledger event"
            );
            return Ok(());
        }
        match outcome {
            FoldOutcome::Completed { output } => {
                let Some(output) = output.clone() else {
                    return Err(KataError::Internal(format!(
                        "runner: Completed event for assignment {assignment_id} has no output"
                    )));
                };
                // Validate the envelope first (and inject `parsed` for a
                // declared output contract); a failed validation queues a
                // retry instead of completing the stage.
                let inject_outcome =
                    self.inject_parsed_if_declared(stage_name, assignment_id, output.clone())?;
                let envelope = match inject_outcome {
                    dispatch::InjectOutcome::Augmented(env) => env,
                    dispatch::InjectOutcome::QueuedRetry => {
                        // Validation failed; a retry was queued
                        // by `inject_parsed_if_declared`. Don't
                        // advance the orchestrator — the retry's
                        // Completed event will route here again. The
                        // rejected turn BILLED, though: it is charged at
                        // its own frame, exactly as the completion it
                        // failed to be would have been, and the retry's
                        // completion is charged at ITS frame. The stage IS
                        // in flight on that retry, and a pure-fold resume
                        // left it `Pending` — mark it or `advance`
                        // re-submits the base stage.
                        let trip = self.check_halts_for_stage(stage_name, &output, recorded_at_ms);
                        self.settle_charged_frame(stage_name, trip, "rejected structured output")?;
                        self.mark_retry_pending_in_flight(stage_name)?;
                        return Ok(());
                    }
                };
                // Check the orchestrator's view before transitioning —
                // if the stage is already Completed (re-sync races,
                // late-arriving broadcasts), skip rather than error.
                if matches!(
                    self.orchestrator.stage_state(stage_name),
                    Some(StageState::Completed { .. })
                ) {
                    return Ok(());
                }
                // Structured-output validation already ran
                // above (shared with the loop path). Hand the envelope
                // to the orchestrator and record the output for
                // downstream template context.
                // In a pure-fold resume this static stage may still be
                // Pending (this runner never submitted it); promote it first so
                // `complete_stage` lands from an accepted source.
                self.replay_promote_if_pending(stage_name);
                self.orchestrator
                    .complete_stage(stage_name, envelope.clone())?;
                outputs.insert(stage_name.clone(), envelope.clone());

                // RECORD (not enforce) the declared-vs-observed
                // OUTPUT CLOSURE. For a stage that declared a `produces_files=`
                // closure, capture the OBSERVED worktree output set at completion
                // and persist it (+ any undeclared violations) as durable evidence
                // A stage without a declared closure, or a non-isolated / torn-down
                // worktree, records NOTHING. Best-effort: never fails
                // the completion path. The checked stage name equals the runtime
                // name for a static stage.
                self.record_output_closure_observation(stage_name, stage_name);

                // Cost-budget AND cost-`Bound`
                // walk-away check after the stage completes. Reads
                // `cost_micro_usd` from the envelope's `token_usage` blob (set by
                // `capsule_result_output`) and folds it into the shared
                // running-cost accumulator both guards watch. On a `Halt` trip
                // (either guard):
                //   1. The just-completed stage stays Completed (the
                //      worker did finish; we don't rewrite history).
                //   2. A synthetic `<base>#budget-halt` (budget) or
                //      `<base>#bound-halt-cost` (bound) Failed assignment is
                //      persisted into the ledger so `aggregate_status` promotes
                //      the run to Failed (matches the existing `__workflow__`
                //      synthetic pattern from
                //      `kata-api::persist_workflow_level_failure_for_program`).
                //   3. `skip_dependents` cascades the skip across downstream
                //      stages. Already-dispatched in-flight stages are not
                //      cancelled — the bound halt matches the budget-halt
                //      semantics exactly.
                // And once the run HAS walked away — at this frame or any earlier
                // one, whatever its kind — this completion releases nothing: its
                // dependents are skipped and no second walk-away row is written
                // (`settle_charged_frame`).
                let trip = self.check_halts_for_stage(stage_name, &envelope, recorded_at_ms);
                self.settle_charged_frame(stage_name, trip, "stage completion")?;

                // Branch verdict routing. After the halt check
                // (so a halted run never re-routes) and before the run loop's
                // next `advance()`, evaluate every `BranchRoute` whose condition
                // stage is the one that just completed. The taken arm's targets
                // proceed (their `depends_on` on the condition is now Completed);
                // the non-taken arms' targets are marked `Skipped` so the next
                // `advance()` submits ONLY the taken arm. The decision is derived
                // from the accepted outcome of the route's `Select` occurrence
                // (`runner::select`), so replay reads the decision back rather
                // than re-evaluating it.
                self.route_after_completion(stage_name, &envelope)?;
            }
            // ONE ARM FOR BOTH, and shared rather than duplicated on purpose. Every
            // routing rule below (child-invocation finalization, the escalate gate,
            // the loop abort, the synthetic-evidence skip) applies to an operator
            // stop as to a failure. Giving the cancel its own arm would be a second
            // implementation of that routing — a data-loss class. The split is a discrimination the
            // TERMINALIZATION reader needs; the orchestrator's DAG advance is the same either way,
            // because a stage the operator stopped did not produce its output and its dependents
            // must not run.
            FoldOutcome::Failed {
                reason,
                terminal_charge,
            }
            | FoldOutcome::Cancelled {
                reason,
                terminal_charge,
            } => {
                // Charge the terminated stage BEFORE any routing on its
                // death: the same trips a completion's charge evaluates
                // (`check_halts_for_terminal_charge` shares every helper with
                // `check_halts_for_stage`), so a hard policy halts the run on
                // the spend the dead stage already made, and `warn`/no-policy
                // records the charge best-effort while nothing halts. The halt
                // row is persisted through `settle_charged_frame`, exactly as a
                // completion's is, and a stage that dies after the run walked
                // away releases nothing either.
                let trip = terminal_charge.as_ref().and_then(|charge| {
                    self.check_halts_for_terminal_charge(stage_name, charge, recorded_at_ms)
                });
                self.settle_charged_frame(stage_name, trip, "stage termination")?;
                // A durable walk-away row latches the walk-away at its own
                // position in the chain (`latch_durable_walk_away`).
                self.latch_durable_walk_away(stage_name);
                // A synthetic evidence row with NO orchestrator stage
                // (`#branch-failure` / `#bound-halt-<kind>` / `#budget-halt`) is
                // durable-only — the run's Failed disposition comes from the
                // durable row (`aggregate_status`) + the in-memory `skip_dependents`
                // cascade the live halt/branch path already ran, NOT from an
                // orchestrator transition on the synthetic name. Folding it must be
                // a no-op (`fail_stage` on a non-DAG name errors "unknown stage").
                // Real stages are always in the DAG, so this only ever skips
                // synthetic evidence rows.
                if self.orchestrator.stage_state(stage_name).is_none() {
                    return Ok(());
                }
                if matches!(
                    self.orchestrator.stage_state(stage_name),
                    Some(StageState::Failed { .. })
                ) {
                    return Ok(());
                }
                // Under `oci` a plain stage's failed attempt may
                // be retried on its seat chain (an agent fallback panel's next
                // member); the decision is pure over durable rows, so a re-fold
                // after a crash re-derives it.
                let reason = if matches!(outcome, FoldOutcome::Failed { .. }) {
                    match self.capsule_failure_retry(
                        stage_name,
                        assignment_id,
                        reason,
                        recorded_at_ms,
                    )? {
                        dispatch::FailureRetryDecision::Retrying => {
                            self.mark_retry_pending_in_flight(stage_name)?;
                            return Ok(());
                        }
                        dispatch::FailureRetryDecision::Fail(reason) => reason,
                    }
                } else {
                    reason.clone()
                };
                self.replay_promote_if_pending(stage_name);
                self.orchestrator.fail_stage(stage_name, reason)?;
            }
            FoldOutcome::Orphaned {
                reason,
                terminal_charge,
            } => {
                // The same charge-first rule the `Failed`/`Cancelled` arm
                // states: an orphan is the class whose outcome is BY
                // DEFINITION unknowable, so its recorded charge is evaluated
                // through the same trips before the terminal routes.
                let trip = terminal_charge.as_ref().and_then(|charge| {
                    self.check_halts_for_terminal_charge(stage_name, charge, recorded_at_ms)
                });
                self.settle_charged_frame(stage_name, trip, "stage orphan")?;
                // Synthetic evidence row with no orchestrator stage —
                // durable-only, skip (see the `Failed` arm's note).
                if self.orchestrator.stage_state(stage_name).is_none() {
                    return Ok(());
                }
                if matches!(
                    self.orchestrator.stage_state(stage_name),
                    Some(StageState::Failed { .. })
                ) {
                    return Ok(());
                }
                // Orphaned means the dispatcher gave up retrying;
                // downstream stages should treat this as a hard
                // failure with the supplied reason.
                self.replay_promote_if_pending(stage_name);
                self.orchestrator.fail_stage(stage_name, reason.clone())?;
            }
            FoldOutcome::Dispatched { worker_id } => {
                // Usually observability-only, but if the
                // orchestrator is still in `AwaitingApproval` for
                // this stage (operator just approved and the
                // dispatcher's dispatch_once landed the transition
                // in the ledger), promote the orchestrator state
                // machine forward so downstream stages can advance
                // once the stage completes.
                if matches!(
                    self.orchestrator.stage_state(stage_name),
                    Some(StageState::AwaitingApproval { .. })
                ) {
                    self.orchestrator
                        .dispatch_stage_after_approval(stage_name, Some(worker_id.clone()))?;
                }
            }
            FoldOutcome::AwaitingChildCompletion { .. } | FoldOutcome::InFlight => {
                // No writer produces a stage-scope `awaiting_child_completion` park.
                // Observability-only events; orchestrator doesn't track
                // mid-flight state. `Pending`, `Running` and `Stalled` all
                // mean the stage is STILL in flight, so the runner must NOT
                // fail it here; the eventual terminal Completed/Failed drives
                // the orchestrator transition. That is why the chain reader
                // collapses all three into one outcome. (A panel failure retry
                // is a new attempt the runner queues on the `Failed` arm above,
                // via `capsule_failure_retry`.)
            }
            FoldOutcome::AwaitingApproval { reason } => {
                // Runner parked a gated stage on the durable
                // approval gate. Drive the
                // orchestrator into its parallel `AwaitingApproval`
                // state so `advance()` treats the stage as in
                // progress and downstream dependents stay Pending
                // until the operator approves or rejects.
                if matches!(
                    self.orchestrator.stage_state(stage_name),
                    Some(StageState::AwaitingApproval { .. })
                ) {
                    // Already paused — idempotent no-op for
                    // replay / resync paths.
                    return Ok(());
                }
                // In a pure-fold resume the gated stage is still Pending
                // (never submitted by this runner); promote it to Ready so
                // `pause_stage_for_approval` (which rejects Pending) lands.
                self.replay_promote_if_pending(stage_name);
                self.orchestrator
                    .pause_stage_for_approval(stage_name, reason.clone())?;
            }
        }
        Ok(())
    }
}
