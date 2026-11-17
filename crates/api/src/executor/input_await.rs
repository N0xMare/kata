//! Human / external-input await machinery: answering a human request (a
//! blocking one resolves its main-side input wait) and appending an external
//! input row.

#[allow(clippy::wildcard_imports)]
use super::*;

impl WorkflowExecutor {
    /// Attach a compact operator answer to one active human-request row.
    /// Matching is exact by request id; unknown ids return an error without
    /// appending evidence.
    ///
    /// A BLOCKING request is a program-level input wait: its answer
    /// RESOLVES that wait (`answer_input_wait`), recorded with `principal` — the one the
    /// transport proved, refused without one — and writes NO evidence row; the accepted
    /// outcome is the one source of truth. A second answer, or one after the timeout
    /// default was accepted, is refused `input_request_already_resolved`, naming the
    /// winner. A non-blocking request is answered as evidence only.
    pub fn answer_human_request(
        &self,
        execution_id: Ulid,
        answer: ExecutionHumanRequestAnswerRequest,
        principal: Option<&kata_types::approval::ApprovalPrincipal>,
    ) -> Result<ExecutionHumanRequestAnswerResponse, ExecutorError> {
        let _admission = self.enter_admission()?;
        if answer.request_id.is_empty() {
            return Err(ExecutorError::InvalidDefinition(
                "human request answer requires non-empty request_id".to_string(),
            ));
        }
        let answer_summary = bounded_human_request_answer_summary(&answer.answer_summary);
        if answer_summary.is_empty() {
            return Err(ExecutorError::InvalidDefinition(
                "human request answer requires non-empty answer_summary".to_string(),
            ));
        }
        let record = self
            .try_get_execution_by_ulid(execution_id)?
            .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
        let existing = record
            .evidence
            .human_requests
            .iter()
            .find(|request| request.id == answer.request_id)
            .cloned()
            .ok_or_else(|| ExecutorError::HumanRequestNotFound {
                execution_id: execution_id.to_string(),
                request_id: answer.request_id.clone(),
            })?;
        if existing.blocking {
            return self.answer_input_wait(
                execution_id,
                existing,
                answer_summary,
                answer.answered_by_steering_id,
                principal,
            );
        }
        let answered = ExecutionHumanRequestEvidence {
            status: HUMAN_REQUEST_ANSWER_STATUS.to_string(),
            projection: answered_human_request_projection(
                &existing.id,
                existing.stage.as_deref(),
                &existing.question,
                &answer_summary,
            ),
            answer_summary: Some(answer_summary),
            answered_by_steering_id: answer.answered_by_steering_id,
            answered_at_ms: Some(now_ms()),
            // Operator-driven answer: never a timeout self-heal.
            auto_defaulted: false,
            ..existing
        };
        persist_human_request_answer_evidence(
            self.dispatcher.ledger(),
            execution_id,
            answered.clone(),
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        // A blocking request's stage never parked here — it waited on a main-side
        // `awaiting_input` attempt and `answer_input_wait` resolved it above.
        Ok(ExecutionHumanRequestAnswerResponse {
            status: HUMAN_REQUEST_ANSWER_STATUS.to_string(),
            human_request: answered,
        })
    }

    /// Append one external side-channel input row after validating that the
    /// execution's checked program declared the channel. The row is prompt
    /// context only; it does not mutate scheduling, approval, sandbox, or DAG
    /// state.
    pub fn append_external_input(
        &self,
        execution_id: Ulid,
        request: ExecutionExternalInputAppendRequest,
    ) -> Result<ExecutionExternalInputAppendResponse, ExecutorError> {
        let _admission = self.enter_admission()?;
        let record = self
            .try_get_execution_by_ulid(execution_id)?
            .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
        let program = self.execution_program_for_execution(execution_id)?;
        let appended = external_input_evidence_from_request(
            execution_id,
            &program,
            &record.evidence.external_inputs,
            request,
        )?;
        let claim_key = external_input_claim_key(&appended.channel, &appended.id);
        let persisted = self
            .dispatcher
            .ledger()
            .append_execution_evidence_claimed(
                execution_id,
                &claim_key,
                ExecutionEvidence {
                    external_inputs: vec![appended.clone()],
                    ..ExecutionEvidence::default()
                },
            )
            .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?
            .is_some();
        let (status, external_input) = if persisted {
            ("appended", appended)
        } else {
            let record = self
                .try_get_execution_by_ulid(execution_id)?
                .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
            let existing = external_input_for_key(
                &record.evidence.external_inputs,
                &appended.channel,
                &appended.id,
            )
            .ok_or_else(|| {
                ExecutorError::RunnerBuildFailed(format!(
                    "external input claim `{claim_key}` exists but no matching evidence row is visible"
                ))
            })?;
            if !external_input_effectively_matches(&appended, existing) {
                return Err(ExecutorError::PolicyDenied(format!(
                    "external input `{}` on channel `{}` was already appended with different content",
                    appended.id, appended.channel
                )));
            }
            ("already_appended", existing.clone())
        };
        // A capsule stage's prompt is frozen at admission — an external input
        // appended mid-run reaches a later dispatch's render, never a parked one.
        Ok(ExecutionExternalInputAppendResponse {
            status: status.to_string(),
            external_input,
        })
    }
}
