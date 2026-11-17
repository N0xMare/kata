//! The ACCEPTED OUTCOME of a blocking human request's input wait.
//!
//! A blocking request is a program-level `Wait(Input)` occurrence
//! ([`super::blocking_input_requests`], the fourth flat segment). It is accepted exactly
//! once, through the one acceptance door, with an [`InputWaitRecord`]: the operator's
//! answer, or — when the request's `timeout_ms` elapsed first — its authored
//! `default_assumption`. That record is the ONE source of truth for the answer under the
//! `oci` profile: the target stage renders from it, and the operator surfaces read it; no
//! `execution_evidence` row is written for a blocking answer on this route.
//!
//! The shape is `{"request", "answer", "source": "operator" | "timeout_default",
//! "answered_by"?, "steering_id"?}`. `answered_by` is the principal the API TRANSPORT
//! proved for an operator answer ([`ApprovalPrincipal`]) and is absent for a timeout,
//! which no principal decided: kata records what was proved and invents nothing.

use kata_types::approval::ApprovalPrincipal;
use kata_types::execution::{ExecutionHumanRequestEvidence, HUMAN_REQUEST_ANSWER_STATUS};
use kata_types::execution_contract::OperationPath;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use super::{ExecutionHumanRequest, ExecutionProgram, ProgramOperationAt, program_operation_at};

/// Who resolved an input wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputAnswerSource {
    /// An operator answered through the API.
    Operator,
    /// The request's `timeout_ms` elapsed first; the answer is its `default_assumption`.
    TimeoutDefault,
}

impl InputAnswerSource {
    /// The stable name, identical to the serde representation and to the
    /// `answer_source` a stage template reads.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::TimeoutDefault => "timeout_default",
        }
    }
}

/// The accepted outcome of one input wait.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputWaitRecord {
    /// The request id.
    pub request: SmolStr,
    /// The effective answer.
    pub answer: String,
    /// Who resolved it.
    pub source: InputAnswerSource,
    /// The principal the transport proved, for an operator answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_by: Option<ApprovalPrincipal>,
    /// The external steering row that supplied an operator answer, if one was named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steering_id: Option<u64>,
}

impl InputWaitRecord {
    /// An operator's answer, attributed to the principal the transport proved.
    #[must_use]
    pub fn operator(
        request: &ExecutionHumanRequest,
        answer: String,
        answered_by: ApprovalPrincipal,
        steering_id: Option<u64>,
    ) -> Self {
        Self {
            request: request.id.clone(),
            answer,
            source: InputAnswerSource::Operator,
            answered_by: Some(answered_by),
            steering_id,
        }
    }

    /// The timeout's resolution: the request's authored `default_assumption`.
    #[must_use]
    pub fn timeout_default(request: &ExecutionHumanRequest) -> Self {
        Self {
            request: request.id.clone(),
            answer: request.default_assumption.clone(),
            source: InputAnswerSource::TimeoutDefault,
            answered_by: None,
            steering_id: None,
        }
    }

    /// The accepted output this record is committed as.
    ///
    /// # Panics
    ///
    /// Never: every field serializes.
    #[must_use]
    pub fn to_output(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("an input-wait record serializes")
    }

    /// Decode an accepted output.
    ///
    /// # Errors
    ///
    /// An output that is not an input-wait record.
    pub fn from_output(output: &serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(output.clone())
    }

    /// Overlay this ACCEPTED outcome onto the request's evidence row: answered, with this
    /// answer, and — for a timeout — the `auto_defaulted` mark a self-heal sets,
    /// so every reader of the row ([`ExecutionHumanRequestEvidence::is_resolved`], the
    /// template's `answer_source`) reads one resolution whichever profile produced it.
    pub fn apply_to(
        &self,
        evidence: &mut ExecutionHumanRequestEvidence,
        accepted_at_ms: Option<u64>,
    ) {
        HUMAN_REQUEST_ANSWER_STATUS.clone_into(&mut evidence.status);
        evidence.answer_summary = Some(self.answer.clone());
        evidence.answered_by_steering_id = self.steering_id;
        evidence.answered_at_ms = accepted_at_ms;
        evidence.auto_defaulted = self.source == InputAnswerSource::TimeoutDefault;
    }
}

/// The blocking request whose input wait sits at `path`, or `None` when `path` is no
/// input wait of `program` — through [`program_operation_at`], the one inverse.
#[must_use]
pub fn input_request_at<'a>(
    program: &'a ExecutionProgram,
    path: &OperationPath,
) -> Option<&'a ExecutionHumanRequest> {
    match program_operation_at(program, path)? {
        ProgramOperationAt::Input(index) => super::blocking_input_requests(program).nth(index),
        ProgramOperationAt::Select(_) | ProgramOperationAt::Expansion(_) => None,
    }
}
