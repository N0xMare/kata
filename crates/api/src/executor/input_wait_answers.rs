//! A BLOCKING human request under the `oci` profile: its ANSWER door and its DISCOVERY
//! surface.
//!
//! On this profile the request is a program-level input wait
//! (`kata_workflow::runner`'s input hold), accepted exactly once with an
//! [`InputWaitRecord`]. So an operator answer is not evidence: it RESOLVES that wait
//! (`OperationalDb::resolve_input_wait`), and no `execution_evidence` row is written for
//! it — the accepted outcome is the one source of truth, which the target renders from.
//!
//! And the wait is invisible on the wire (its park is no wire event, so a watcher sees its
//! target merely `pending`); the operator finds it on the execution record instead:
//! [`WorkflowExecutor::overlay_input_waits`] reads the chain — each blocking request whose
//! wait is parked reads `awaiting_input` (with its due time when it has one), and each
//! accepted one reads answered, with the accepted answer — so `kata steer human-requests`,
//! `kata run show` and `GET /executions/{id}` all show what the chain holds.

use super::projections::human_request_projection;
#[allow(clippy::wildcard_imports)]
use super::*;
use kata_core::operational::{InputWaitAnswer, MainAttemptSpec, OccurrenceBinding};
use kata_program::execution_program::input_wait::{InputWaitRecord, input_request_at};
use kata_program::execution_program::{
    blocking_input_requests, lower_blocking_request, occurrence_for,
};
use kata_types::approval::ApprovalPrincipal;
use kata_types::execution_contract::OperationPath;

/// The answer lost: the request's input wait already has its one outcome.
pub const INPUT_REQUEST_ALREADY_RESOLVED: &str = "input_request_already_resolved";
/// No principal was proved for an answer that must record one.
pub const INPUT_ANSWER_PRINCIPAL_UNPROVEN: &str = "input_answer_principal_unproven";
/// A blocking request's evidence status while its input wait is parked.
pub const HUMAN_REQUEST_AWAITING_INPUT_STATUS: &str = "awaiting_input";

impl WorkflowExecutor {
    /// ANSWER a blocking human request of an `oci` execution by resolving its input wait,
    /// with the principal the transport proved.
    ///
    /// # Errors
    ///
    /// [`ExecutorError::InputRequestConflict`] naming [`INPUT_REQUEST_ALREADY_RESOLVED`] and
    /// the winner (the operator answer or the timeout default that was accepted, or the
    /// cancel), naming `main_resolution_execution_terminal` for an execution whose
    /// outcome is published, or naming `input_answer_after_terminal_intent` for one that has
    /// latched its outcome and not published it; [`ExecutorError::PolicyDenied`] naming
    /// [`INPUT_ANSWER_PRINCIPAL_UNPROVEN`]; storage faults.
    pub(super) fn answer_input_wait(
        &self,
        execution_id: Ulid,
        existing: ExecutionHumanRequestEvidence,
        answer_summary: String,
        steering_id: Option<u64>,
        principal: Option<&ApprovalPrincipal>,
    ) -> Result<ExecutionHumanRequestAnswerResponse, ExecutorError> {
        let principal = principal.cloned().ok_or_else(|| {
            ExecutorError::PolicyDenied(format!(
                "{INPUT_ANSWER_PRINCIPAL_UNPROVEN}: the answer to blocking request {:?} is the \
                 accepted outcome of its input wait and records who gave it, and this face \
                 proved no principal; nothing was written",
                existing.id
            ))
        })?;
        let program = self.execution_program_for_execution(execution_id)?;
        let (index, request) = blocking_input_requests(&program)
            .enumerate()
            .find(|(_, request)| request.id.as_str() == existing.id)
            .ok_or_else(|| ExecutorError::HumanRequestNotFound {
                execution_id: execution_id.to_string(),
                request_id: existing.id.clone(),
            })?;
        let spec = input_wait_spec(&program, execution_id, index)?;
        let record = InputWaitRecord::operator(request, answer_summary, principal, steering_id);
        let db = self.execution_lifecycle.db();
        match db
            .resolve_input_wait(Ulid::new(), &spec, &record.to_output())
            .map_err(|error| {
                let message = error.to_string();
                if [
                    kata_core::operational::MAIN_RESOLUTION_EXECUTION_TERMINAL,
                    kata_core::operational::INPUT_ANSWER_AFTER_TERMINAL_INTENT,
                ]
                .iter()
                .any(|code| message.contains(code))
                {
                    ExecutorError::InputRequestConflict(message)
                } else {
                    ExecutorError::DurabilityFailed(format!(
                        "resolve the input wait of request {:?}: {error}",
                        existing.id
                    ))
                }
            })? {
            InputWaitAnswer::Answered { .. } => {
                let mut answered = existing;
                record.apply_to(&mut answered, Some(now_ms()));
                answered.projection = answered_human_request_projection(
                    &answered.id,
                    answered.stage.as_deref(),
                    &answered.question,
                    &record.answer,
                );
                Ok(ExecutionHumanRequestAnswerResponse {
                    status: HUMAN_REQUEST_ANSWER_STATUS.to_string(),
                    human_request: answered,
                })
            }
            InputWaitAnswer::AlreadyResolved { attempt_id, state } => {
                let winner = self
                    .accepted_input_records(execution_id, &program)?
                    .into_iter()
                    .find(|(id, _, _)| id.as_str() == existing.id)
                    .map_or_else(
                        || format!("`{}` without an answer", state.as_str()),
                        |(_, record, _)| {
                            format!(
                                "accepted {:?} from {}{}",
                                record.answer,
                                record.source.as_str(),
                                record
                                    .answered_by
                                    .as_ref()
                                    .map(|by| format!(" ({by:?})"))
                                    .unwrap_or_default()
                            )
                        },
                    );
                Err(ExecutorError::InputRequestConflict(format!(
                    "{INPUT_REQUEST_ALREADY_RESOLVED}: blocking request {:?} of execution \
                     {execution_id} was already resolved by attempt {attempt_id}: {winner}; this \
                     answer was not recorded",
                    existing.id
                )))
            }
        }
    }

    /// Overlay what the CHAIN holds for each blocking request onto the execution record's
    /// human-request rows: `awaiting_input` while its input wait is parked (the due time in
    /// the row's projection), and answered — with the accepted answer, its source and the
    /// acceptance instant — once accepted. A request with neither keeps its row.
    ///
    /// # Errors
    ///
    /// A plane read failure, or an accepted outcome that is not its request's record.
    pub(super) fn overlay_input_waits(
        &self,
        execution_id: Ulid,
        program: &ExecutionProgram,
        rows: &mut [ExecutionHumanRequestEvidence],
    ) -> Result<(), ExecutorError> {
        if blocking_input_requests(program).next().is_none() {
            return Ok(());
        }
        let durability = |error: kata_types::error::KataError| {
            ExecutorError::DurabilityFailed(format!(
                "read the input waits of execution {execution_id}: {error}"
            ))
        };
        let parked = self
            .execution_lifecycle
            .db()
            .parked_main_waits(kata_core::operational::ParkedMainWaitScope::Execution(
                execution_id,
            ))
            .map_err(durability)?;
        for wait in parked {
            if wait.state != kata_core::operational::AttemptLifecycle::AwaitingInput {
                continue;
            }
            let Some(request) = OperationPath::from_program_operation_stage_id(&wait.stage_id)
                .and_then(|path| input_request_at(program, &path))
            else {
                continue;
            };
            if let Some(row) = rows.iter_mut().find(|row| row.id == request.id.as_str()) {
                row.status = HUMAN_REQUEST_AWAITING_INPUT_STATUS.to_string();
                row.projection = format!(
                    "{} Awaiting input: parked until answered{}.",
                    human_request_projection(
                        &row.id,
                        row.stage.as_deref(),
                        &row.question,
                        &row.default_assumption,
                    ),
                    wait.wait_deadline_ms
                        .map_or_else(String::new, |deadline| format!(
                            ", or until {} when the default applies",
                            chrono::DateTime::from_timestamp_millis(deadline)
                                .map_or_else(|| deadline.to_string(), |at| at.to_rfc3339())
                        )),
                );
            }
        }
        for (id, record, accepted_at_ms) in self.accepted_input_records(execution_id, program)? {
            if let Some(row) = rows.iter_mut().find(|row| row.id == id.as_str()) {
                record.apply_to(row, accepted_at_ms);
                row.projection = answered_human_request_projection(
                    &row.id,
                    row.stage.as_deref(),
                    &row.question,
                    &record.answer,
                );
            }
        }
        Ok(())
    }

    /// Every accepted input-wait record of `execution_id`, with its request id and its
    /// acceptance instant.
    fn accepted_input_records(
        &self,
        execution_id: Ulid,
        program: &ExecutionProgram,
    ) -> Result<Vec<(SmolStr, InputWaitRecord, Option<u64>)>, ExecutorError> {
        let db = self.execution_lifecycle.db();
        let durability = |error: kata_types::error::KataError| {
            ExecutorError::DurabilityFailed(format!(
                "read the accepted input waits of execution {execution_id}: {error}"
            ))
        };
        let mut records = Vec::new();
        for (path, output) in db
            .accepted_program_operation_outputs(execution_id)
            .map_err(durability)?
        {
            let Some(request) = input_request_at(program, &path) else {
                continue;
            };
            let record = InputWaitRecord::from_output(&output).map_err(|error| {
                ExecutorError::DurabilityFailed(format!(
                    "the accepted outcome of input wait {} is not an input-wait record: {error}",
                    path.program_operation_stage_id()
                ))
            })?;
            let index = blocking_input_requests(program)
                .position(|candidate| candidate.id == request.id)
                .expect("input_request_at answered a blocking request of this program");
            let occurrence = input_wait_spec(program, execution_id, index)?
                .occurrence
                .occurrence_id();
            let accepted_at_ms = db
                .occurrence(occurrence)
                .map_err(durability)?
                .and_then(|row| row.accepted)
                .and_then(|accepted| u64::try_from(accepted.at_ms).ok());
            records.push((request.id.clone(), record, accepted_at_ms));
        }
        Ok(records)
    }
}

/// The input wait of the `index`-th blocking request — derived through the lowering the
/// runtime claims it by, so the answer door and the hold name one occurrence.
fn input_wait_spec(
    program: &ExecutionProgram,
    execution_id: Ulid,
    index: usize,
) -> Result<MainAttemptSpec, ExecutorError> {
    let lowered = lower_blocking_request(program, index).map_err(|error| {
        ExecutorError::InvalidDefinition(format!(
            "blocking human request {index} does not lower to an input wait: {error:?}"
        ))
    })?;
    Ok(MainAttemptSpec {
        stage_id: lowered.path.program_operation_stage_id(),
        occurrence: OccurrenceBinding::new(
            occurrence_for(
                program,
                kata_types::workflow::ExecutionId(execution_id),
                &lowered,
            ),
            None,
            None,
        ),
    })
}
