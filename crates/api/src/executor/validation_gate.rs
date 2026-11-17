//! The operator/factory promotion route's adapter onto the SHARED promotion
//! gate.
//!
//! The rule itself lives in [`kata_workflow::promotion_gate`], shared with the
//! in-graph `workspace_effect op = "promote"` stage: the runner that resolves
//! the in-graph verdict lives in `kata-workflow`, and a second copy of the rule
//! here could drift from its twin.
//!
//! What is left is the one thing the two routes genuinely do not share: this
//! route reads an [`ExecutionRecord`], the in-graph route reads the ledger's
//! evidence rows directly, and [`validation_criteria_gate`] below is the
//! record-shaped door onto the shared function.

use kata_program::execution_program::ExecutionProgram;
use kata_types::execution::{ExecutionRecord, ExecutionValidationCandidateEvidence};

pub(super) use kata_workflow::promotion_gate::{
    ValidationCriteriaGate, validation_criterion_satisfies_policy,
};

/// The shared gate, entered with an [`ExecutionRecord`]'s recorded validation
/// reports. Byte-identical semantics to calling
/// [`kata_workflow::promotion_gate::validation_criteria_gate`] directly; the
/// only thing this adds is the projection out of the record.
pub(super) fn validation_criteria_gate(
    record: &ExecutionRecord,
    program: Option<&ExecutionProgram>,
    expected_candidate: Option<&ExecutionValidationCandidateEvidence>,
) -> ValidationCriteriaGate {
    kata_workflow::promotion_gate::validation_criteria_gate(
        program,
        &record.evidence.validation_reports,
        expected_candidate,
    )
}
