//! A BLOCKING HUMAN REQUEST under the `oci` profile: a program-level `Wait(Input)` occurrence that
//! HOLDS its target stage until it is accepted, and whose accepted answer the target then renders
//! from.
//!
//! # The hold
//!
//! The oci divert asks [`WorkflowRunner::hold_for_blocking_inputs`] first, before it routes
//! the stage's own operation: for every blocking request targeting the stage whose input
//! occurrence is not accepted, it claims one `executor = 'main'` attempt parked
//! `awaiting_input` (at the program-operation coordinate `#op/<path>`, with the request's
//! `timeout_ms` as a durable deadline anchored at the claim), and holds the target in the
//! orchestrator as `AwaitingApproval` — in flight, so its dependents stay `Pending`. A
//! re-presentation converges: `AlreadyLive` in `awaiting_input` is the wait still in flight,
//! `AlreadyAccepted` is an answered one, and neither writes anything.
//!
//! # The fold
//!
//! The wait's own frames (`#op/<path>`) reach [`WorkflowRunner::fold_input_wait`] from the
//! program-operation interception at the top of the fold:
//!
//! | frame | effect on the target |
//! |---|---|
//! | the claim (`pending`) | HELD, if its dependencies are complete (a replay of a hold) |
//! | `completed` | RELEASED to `Pending`, if held; the ready pass then submits it |
//! | `failed` / `cancelled` | FAILED, and the operation recorded as a failed one |
//!
//! The claim of an answer that arrived BEFORE its target was ready (claimed and accepted
//! in one transaction by the answer door) folds while the target's dependencies are still
//! running, so it holds nothing; the target is submitted by the ordinary ready pass and its
//! hold converges on the acceptance.
//!
//! # The render
//!
//! [`WorkflowRunner::accepted_input_records`] reads the ACCEPTED outcomes, so the target's
//! command renders the answer — `{{ human_requests.by_id.<id>.effective_answer }}` — into
//! its argv and therefore into its capsule's identity.

use kata_core::operational::{
    AttemptLifecycle, MainAttemptSpec, MainClaimOutcome, MainWait, OccurrenceBinding,
};
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::OperationPath;
use kata_types::wait::WaitDeadline;
use kata_types::workflow::{ExecutionId, StageId};
use smol_str::SmolStr;
use tracing::info;
use ulid::Ulid;

use super::{StageState, WorkflowRunner};
use crate::attempt_delivery::FoldOutcome;
use kata_program::execution_program::input_wait::{InputWaitRecord, input_request_at};
use kata_program::execution_program::{
    ExecutionHumanRequest, blocking_input_requests, lower_blocking_request, occurrence_for,
};

/// An input wait that already resolved WITHOUT an answer (cancelled) is presented again: its
/// target can never run, and claiming a second wait would re-open a resolved one.
const INPUT_WAIT_RESOLVED_WITHOUT_ANSWER: &str = "input_wait_resolved_without_answer";

impl WorkflowRunner {
    /// HOLD `stage_name` on every blocking request targeting it whose input occurrence is not
    /// accepted — claiming each one's wait, or converging on it. `Ok(true)` when the stage is
    /// held (nothing may be rendered or dispatched for it), `Ok(false)` when every request
    /// targeting it is accepted, or none does.
    ///
    /// # Errors
    ///
    /// [`INPUT_WAIT_RESOLVED_WITHOUT_ANSWER`]; a request that does not lower; a live main
    /// attempt at the wait in a state no writer leaves one in; the claim's refusals and
    /// storage faults.
    pub(in crate::runner) fn hold_for_blocking_inputs(
        &self,
        stage_name: &SmolStr,
    ) -> KataResult<bool> {
        let db = std::sync::Arc::clone(self.dispatcher.execution_lifecycle().db());
        let mut holding: Option<&ExecutionHumanRequest> = None;
        for (index, request) in blocking_input_requests(&self.execution_program).enumerate() {
            if request.stage.as_ref().map(|stage| &stage.0) != Some(stage_name) {
                continue;
            }
            let (spec, occurrence_id) = self.input_wait_spec(index, request)?;
            if let Some((attempt_id, state)) = db
                .main_attempts_at_occurrence(occurrence_id)?
                .into_iter()
                .find(|(_, state)| {
                    matches!(
                        state,
                        AttemptLifecycle::Failed | AttemptLifecycle::Cancelled
                    )
                })
            {
                return Err(KataError::Validation(format!(
                    "{INPUT_WAIT_RESOLVED_WITHOUT_ANSWER}: stage {stage_name}'s blocking request \
                     {id:?} resolved `{state}` (attempt {attempt_id}) without an answer, so the \
                     stage can never run",
                    id = request.id,
                    state = state.as_str(),
                )));
            }
            let deadline = request
                .timeout_ms
                .map(|delay_ms| WaitDeadline::AfterClaim { delay_ms });
            let attempt_id = Ulid::new();
            match db.claim_main_attempt(attempt_id, &spec, MainWait::Input(deadline))? {
                MainClaimOutcome::Claimed {
                    claim_seq,
                    wait_deadline_ms,
                    ..
                } => info!(
                    execution_id = %self.execution_id,
                    stage = %stage_name,
                    request = %request.id,
                    %attempt_id,
                    claim_seq,
                    ?wait_deadline_ms,
                    "runner: a blocking human request holds its stage on a main-side input wait"
                ),
                MainClaimOutcome::AlreadyLive {
                    state: AttemptLifecycle::AwaitingInput,
                    ..
                } => {}
                MainClaimOutcome::AlreadyLive { attempt_id, state } => {
                    return Err(KataError::Storage(format!(
                        "input wait {} holds a LIVE main attempt {attempt_id} in `{}`; an input \
                         wait is claimed parked in `awaiting_input` and leaves it only by its \
                         resolution",
                        spec.stage_id,
                        state.as_str()
                    )));
                }
                MainClaimOutcome::AlreadyAccepted { .. } => continue,
            }
            holding.get_or_insert(request);
        }
        let Some(request) = holding else {
            return Ok(false);
        };
        self.hold_stage_for_input(stage_name.as_str(), request)?;
        Ok(true)
    }

    /// FOLD one frame of the input wait at `path` — see the module docs for the table.
    ///
    /// # Errors
    ///
    /// A `completed` frame whose output is not this request's [`InputWaitRecord`]; an
    /// orchestrator transition the hold's own state machine refuses.
    pub(super) fn fold_input_wait(
        &self,
        path: &OperationPath,
        outcome: &FoldOutcome,
    ) -> KataResult<()> {
        let request = input_request_at(&self.execution_program, path).ok_or_else(|| {
            KataError::Validation(format!(
                "program operation {} is no blocking request's input wait in this program",
                path.program_operation_stage_id()
            ))
        })?;
        let target = request
            .stage
            .as_ref()
            .map(|stage| stage.0.clone())
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "input wait {} has no target stage",
                    path.program_operation_stage_id()
                ))
            })?;
        match outcome {
            FoldOutcome::InFlight => {
                if self.held_for_input.read().contains(&target) {
                    return Ok(());
                }
                let mut dependencies_complete = true;
                for dependency in self
                    .orchestrator
                    .dag()
                    .dependencies(target.as_str())
                    .unwrap_or_default()
                {
                    if !self.checked_dependency_is_terminal(&StageId(dependency.clone()))? {
                        dependencies_complete = false;
                        break;
                    }
                }
                if dependencies_complete
                    && matches!(
                        self.orchestrator.stage_state(target.as_str()),
                        Some(StageState::Pending)
                    )
                {
                    self.hold_stage_for_input(target.as_str(), request)?;
                }
            }
            FoldOutcome::Completed { output } => {
                let output = output.as_ref().ok_or_else(|| {
                    KataError::Internal(format!(
                        "input wait {} completed with no output",
                        path.program_operation_stage_id()
                    ))
                })?;
                let record = decode_record(path, request, output)?;
                if self.held_for_input.write().remove(&target) {
                    self.orchestrator.release_held_stage(target.as_str())?;
                    info!(
                        execution_id = %self.execution_id,
                        stage = %target,
                        request = %record.request,
                        source = record.source.as_str(),
                        "runner: an accepted input wait released its stage"
                    );
                }
            }
            FoldOutcome::Failed { reason, .. } | FoldOutcome::Cancelled { reason, .. } => {
                self.held_for_input.write().remove(&target);
                self.failed_program_operations
                    .write()
                    .insert(path.program_operation_stage_id(), reason.clone());
                if matches!(
                    self.orchestrator.stage_state(target.as_str()),
                    Some(
                        StageState::Completed { .. }
                            | StageState::Failed { .. }
                            | StageState::Skipped { .. }
                    )
                ) {
                    return Ok(());
                }
                self.replay_promote_if_pending(target.as_str());
                self.orchestrator.fail_stage(
                    target.as_str(),
                    format!(
                        "blocking human request {:?} resolved without an answer: {reason}",
                        request.id
                    ),
                )?;
            }
            FoldOutcome::Orphaned { .. }
            | FoldOutcome::Dispatched { .. }
            | FoldOutcome::AwaitingChildCompletion { .. }
            | FoldOutcome::AwaitingApproval { .. } => {}
        }
        Ok(())
    }

    /// Every ACCEPTED input-wait outcome of this execution, keyed by request id, read off the
    /// accepting transitions — the one source the target's render reads.
    ///
    /// # Errors
    ///
    /// A plane read failure; an accepted output that is not its request's record.
    pub(in crate::runner) fn accepted_input_records(
        &self,
    ) -> KataResult<Vec<(SmolStr, InputWaitRecord)>> {
        self.dispatcher
            .execution_lifecycle()
            .db()
            .accepted_program_operation_outputs(self.execution_id)?
            .into_iter()
            .filter_map(|(path, output)| {
                input_request_at(&self.execution_program, &path).map(|request| {
                    decode_record(&path, request, &output)
                        .map(|record| (request.id.clone(), record))
                })
            })
            .collect()
    }

    /// The input wait of the `index`-th blocking request: its attempt spec at `#op/<path>`,
    /// and its occurrence id.
    fn input_wait_spec(
        &self,
        index: usize,
        request: &ExecutionHumanRequest,
    ) -> KataResult<(MainAttemptSpec, [u8; 32])> {
        let lowered = lower_blocking_request(&self.execution_program, index).map_err(|error| {
            KataError::Validation(format!(
                "blocking human request {:?} does not lower to an input wait: {error:?}",
                request.id
            ))
        })?;
        let occurrence = occurrence_for(
            &self.execution_program,
            ExecutionId(self.execution_id),
            &lowered,
        );
        let occurrence_id = occurrence.id().0.0;
        Ok((
            MainAttemptSpec {
                stage_id: lowered.path.program_operation_stage_id(),
                occurrence: OccurrenceBinding::new(occurrence, None, None),
            },
            occurrence_id,
        ))
    }

    /// Hold `stage` in the orchestrator — `AwaitingApproval`, in flight — and remember it is
    /// held for INPUT, so only an input wait's resolution releases it. Idempotent.
    fn hold_stage_for_input(&self, stage: &str, request: &ExecutionHumanRequest) -> KataResult<()> {
        if self.held_for_input.read().contains(stage) {
            return Ok(());
        }
        self.replay_promote_if_pending(stage);
        self.orchestrator.pause_stage_for_approval(
            stage,
            format!("awaiting input: {} ({})", request.id, request.question),
        )?;
        self.held_for_input.write().insert(SmolStr::new(stage));
        Ok(())
    }
}

fn decode_record(
    path: &OperationPath,
    request: &ExecutionHumanRequest,
    output: &serde_json::Value,
) -> KataResult<InputWaitRecord> {
    let record = InputWaitRecord::from_output(output).map_err(|error| {
        KataError::Storage(format!(
            "the accepted outcome of input wait {} is not an input-wait record: {error}",
            path.program_operation_stage_id()
        ))
    })?;
    if record.request != request.id {
        return Err(KataError::Storage(format!(
            "the accepted outcome of input wait {} answers request {:?}, and the program's \
             request there is {:?}",
            path.program_operation_stage_id(),
            record.request,
            request.id
        )));
    }
    Ok(record)
}

#[cfg(test)]
#[path = "input_wait_tests.rs"]
mod tests;
