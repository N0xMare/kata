//! Pre-dispatch authority checks over the retained checked program.
//!
//! Crate-local guards the runner uses to prove a ready runtime stage (static,
//! synthetic-derived, or validation-retry) is still covered by the checked
//! execution program before it becomes a worker assignment. Uses the checked IR
//! as a local pre-dispatch guard without widening the persisted workflow schema
//! or worker wire contract.

use kata_types::review_loop::ReviewLoop;
use kata_types::workflow::StageId;
use smol_str::SmolStr;

use super::{
    ExecutionProgram, ExecutionProgramStage, VerifierSeverity, VerifierStatus,
    prompt_template_hash, stage_contract_hash,
};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DispatchPreflightError {
    message: String,
}

impl DispatchPreflightError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Verify that a ready runtime stage is still covered by the checked execution
/// program before it is translated into a worker assignment.
///
/// Public so `kata-workflow`'s runner can use the checked IR as its
/// pre-dispatch guard; it widens neither the persisted workflow schema nor the
/// worker wire contract.
pub fn preflight_stage_dispatch<'a>(
    program: &'a ExecutionProgram,
    stage_id: &StageId,
) -> Result<&'a ExecutionProgramStage, DispatchPreflightError> {
    if program.verifier.status == VerifierStatus::Error {
        let errors = program
            .verifier
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == VerifierSeverity::Error)
            .map(|diagnostic| {
                diagnostic.stage.as_ref().map_or_else(
                    || diagnostic.code.to_string(),
                    |stage| format!("{}({})", diagnostic.code, stage.0),
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(DispatchPreflightError::new(format!(
            "checked execution program verifier failed before dispatch: {errors}"
        )));
    }

    let checked = program.stages.get(stage_id).ok_or_else(|| {
        DispatchPreflightError::new(format!(
            "stage \"{}\" is missing from the checked execution program",
            stage_id.0
        ))
    })?;

    if checked.stage_id != *stage_id {
        return Err(dispatch_contract_mismatch(stage_id, "stage_id"));
    }
    let prompt_present = !checked.op.prompt_template.trim().is_empty();
    if checked.op.prompt_present != prompt_present {
        return Err(dispatch_contract_mismatch(stage_id, "prompt presence"));
    }
    if checked.op.prompt_hash
        != prompt_template_hash(&checked.op.prompt_template, checked.op.prompt_rendering)
    {
        return Err(dispatch_contract_mismatch(stage_id, "prompt hash"));
    }
    let expected_contract_hash = stage_contract_hash(
        stage_id,
        &checked.op,
        &checked.depends_on,
        &checked.outputs,
        &checked.policies,
        &checked.invocation_envelope,
        checked.execution_class,
    );
    if checked.contract_hash != expected_contract_hash {
        return Err(dispatch_contract_mismatch(stage_id, "contract hash"));
    }

    Ok(checked)
}

/// Semantic authority for runtime assignments derived from a checked base
/// stage.
#[derive(Debug)]
pub struct DerivedDispatchPreflight<'a> {
    pub checked_stage: &'a ExecutionProgramStage,
    pub expected_stage_name: SmolStr,
}

/// The derived runtime assignment shape that needs checked-program authority.
pub enum DerivedDispatchKind<'a> {
    ValidationRetry {
        /// The loop iteration N that dispatched the failing assignment
        /// (0 for non-loop / iteration-0). Embedded into the synthetic
        /// retry name as `<base>#iter-N#validate-M` so the retry's
        /// ledger row carries a stable iteration identity.
        dispatch_iter: u32,
        attempt: u32,
    },
    ExecutableChild {
        role: &'a SmolStr,
    },
    DynamicChild {
        role: &'a SmolStr,
        derived_stage: &'a SmolStr,
    },
    ReviewLoopIteration {
        participant: ReviewLoopParticipant,
        iteration: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewLoopParticipant {
    Worker,
    Reviewer,
    /// A NON-EXIT member of a multi-stage loop
    /// body sub-DAG. The exit member is the `Worker`; intermediate/entry body
    /// stages are re-dispatched per refine iteration as `BodyMember`s.
    BodyMember,
}

/// Verify that a synthetic runtime assignment is authorized by the retained
/// checked execution program for its base stage.
pub fn preflight_derived_dispatch<'a>(
    program: &'a ExecutionProgram,
    stage_id: &StageId,
    kind: DerivedDispatchKind<'_>,
) -> Result<DerivedDispatchPreflight<'a>, DispatchPreflightError> {
    let checked_stage = preflight_stage_dispatch(program, stage_id)?;
    let expected_stage_name = match kind {
        DerivedDispatchKind::ValidationRetry {
            dispatch_iter,
            attempt,
        } => {
            if attempt == 0 || attempt > checked_stage.policies.validate_retries {
                return Err(DispatchPreflightError::new(format!(
                    "stage \"{}\" checked execution program validation retry budget {} does not authorize attempt {}",
                    stage_id.0, checked_stage.policies.validate_retries, attempt
                )));
            }
            // A retry dispatched at loop iteration
            // N≥1 carries the iteration-stable name
            // `<base>#iter-N#validate-M`. Resolve + carry the loop's
            // max_iterations so the dispatcher's shape check can verify N
            // against the checked authority (mirrors the
            // ReviewLoopIteration arm); and reject an iteration the
            // checked loop does not authorize at dispatch-derivation time.
            if dispatch_iter >= 1 {
                let max_iterations = review_loop_max_iterations_for_stage(program, stage_id)
                    .ok_or_else(|| {
                        DispatchPreflightError::new(format!(
                            "stage \"{}\" checked execution program validation retry carries iteration {} but the stage is not a checked review-loop participant",
                            stage_id.0, dispatch_iter
                        ))
                    })?;
                if dispatch_iter >= max_iterations {
                    return Err(DispatchPreflightError::new(format!(
                        "stage \"{}\" checked execution program review-loop max_iterations={} does not authorize validation retry at iteration {}",
                        stage_id.0, max_iterations, dispatch_iter
                    )));
                }
            }
            crate::loops::validate_retry_name(&stage_id.0, dispatch_iter, attempt)
        }
        DerivedDispatchKind::ExecutableChild { role } => {
            if checked_stage.invocation_envelope.dynamic_fanout {
                return Err(DispatchPreflightError::new(format!(
                    "stage \"{}\" checked execution program dynamic_fanout does not authorize static executable child role \"{}\"",
                    stage_id.0, role
                )));
            }
            require_child_role(checked_stage, stage_id, role, "executable child")?;
            SmolStr::new(kata_types::execution_contract::child_invocation_stage_name(
                &stage_id.0,
                role,
            ))
        }
        DerivedDispatchKind::DynamicChild {
            role,
            derived_stage,
        } => {
            if !checked_stage.invocation_envelope.dynamic_fanout {
                return Err(DispatchPreflightError::new(format!(
                    "stage \"{}\" checked execution program does not authorize dynamic child role \"{}\"",
                    stage_id.0, role
                )));
            }
            require_child_role(checked_stage, stage_id, role, "dynamic child")?;
            let expected_prefix = format!("{}#child-{}-", stage_id.0, role);
            if !derived_stage.as_str().starts_with(&expected_prefix)
                || derived_stage.as_str().len() == expected_prefix.len()
            {
                return Err(DispatchPreflightError::new(format!(
                    "stage \"{}\" checked execution program dynamic child role \"{}\" does not authorize derived stage \"{}\"",
                    stage_id.0, role, derived_stage
                )));
            }
            derived_stage.clone()
        }
        DerivedDispatchKind::ReviewLoopIteration {
            participant,
            iteration,
        } => {
            let loop_cfg = require_review_loop_participant(program, stage_id, participant)?;
            if matches!(
                participant,
                ReviewLoopParticipant::Worker | ReviewLoopParticipant::BodyMember
            ) && iteration == 0
            {
                return Err(DispatchPreflightError::new(format!(
                    "stage \"{}\" checked execution program review-loop body iteration 0 must use the static dispatch path",
                    stage_id.0
                )));
            }
            if iteration >= loop_cfg.max_iterations {
                return Err(DispatchPreflightError::new(format!(
                    "stage \"{}\" checked execution program review-loop max_iterations={} does not authorize iteration {}",
                    stage_id.0, loop_cfg.max_iterations, iteration
                )));
            }
            crate::loops::iteration_stage_name(&stage_id.0, iteration)
        }
    };

    Ok(DerivedDispatchPreflight {
        checked_stage,
        expected_stage_name,
    })
}

fn require_child_role(
    checked_stage: &ExecutionProgramStage,
    stage_id: &StageId,
    role: &SmolStr,
    label: &str,
) -> Result<(), DispatchPreflightError> {
    if checked_stage
        .invocation_envelope
        .children
        .iter()
        .any(|child| child.role == *role)
    {
        Ok(())
    } else {
        Err(DispatchPreflightError::new(format!(
            "stage \"{}\" checked execution program does not authorize {label} role \"{}\"",
            stage_id.0, role
        )))
    }
}

/// The `max_iterations` of the review loop this
/// stage participates in (as worker, reviewer, or a body member), or
/// `None` if the stage is not a loop participant. Used to authorize a
/// loop stage's iteration-stable validation-retry name at dispatch
/// derivation time.
fn review_loop_max_iterations_for_stage(
    program: &ExecutionProgram,
    stage_id: &StageId,
) -> Option<u32> {
    program
        .review_loops
        .iter()
        .find(|loop_cfg| {
            loop_cfg.worker_stage == stage_id.0
                || loop_cfg.reviewer_stage == stage_id.0
                || loop_cfg.body_stages.iter().any(|m| m.0 == stage_id.0)
        })
        .map(|loop_cfg| loop_cfg.max_iterations)
}

fn require_review_loop_participant<'a>(
    program: &'a ExecutionProgram,
    stage_id: &StageId,
    participant: ReviewLoopParticipant,
) -> Result<&'a ReviewLoop, DispatchPreflightError> {
    program
        .review_loops
        .iter()
        .find(|loop_cfg| match participant {
            ReviewLoopParticipant::Worker => loop_cfg.worker_stage == stage_id.0,
            ReviewLoopParticipant::Reviewer => loop_cfg.reviewer_stage == stage_id.0,
            // A non-exit body member: any body_stages entry that is NOT the
            // exit (the exit is the Worker). The exit also appears in
            // body_stages, but it is dispatched via the Worker participant.
            ReviewLoopParticipant::BodyMember => {
                loop_cfg.body_stages.iter().any(|m| m.0 == stage_id.0)
                    && loop_cfg.worker_stage != stage_id.0
            }
        })
        .ok_or_else(|| {
            DispatchPreflightError::new(format!(
            "stage \"{}\" checked execution program does not authorize review-loop {participant:?} iteration",
            stage_id.0
        ))
        })
}

/// Verify that schema-validation retry eligibility is covered by the retained
/// checked execution program.
///
/// Retry assignment construction stays runtime-owned; this guard only decides
/// whether the checked program authorizes another validation retry for the
/// base stage.
pub fn preflight_validation_retry_authority<'a>(
    program: &'a ExecutionProgram,
    stage_id: &StageId,
) -> Result<&'a ExecutionProgramStage, DispatchPreflightError> {
    if program.verifier.status == VerifierStatus::Error {
        let errors = program
            .verifier
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == VerifierSeverity::Error)
            .map(|diagnostic| {
                diagnostic.stage.as_ref().map_or_else(
                    || diagnostic.code.to_string(),
                    |stage| format!("{}({})", diagnostic.code, stage.0),
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(DispatchPreflightError::new(format!(
            "checked execution program verifier failed before validation retry: {errors}"
        )));
    }

    let checked = program.stages.get(stage_id).ok_or_else(|| {
        DispatchPreflightError::new(format!(
            "stage \"{}\" is missing from the checked execution program for validation retry",
            stage_id.0
        ))
    })?;
    let prompt_present = !checked.op.prompt_template.trim().is_empty();
    if checked.op.prompt_present != prompt_present {
        return Err(dispatch_contract_mismatch(stage_id, "prompt presence"));
    }
    if checked.op.prompt_hash
        != prompt_template_hash(&checked.op.prompt_template, checked.op.prompt_rendering)
    {
        return Err(dispatch_contract_mismatch(stage_id, "prompt hash"));
    }
    let expected_contract_hash = stage_contract_hash(
        stage_id,
        &checked.op,
        &checked.depends_on,
        &checked.outputs,
        &checked.policies,
        &checked.invocation_envelope,
        checked.execution_class,
    );
    if checked.contract_hash != expected_contract_hash {
        return Err(dispatch_contract_mismatch(stage_id, "contract hash"));
    }

    Ok(checked)
}

/// Test-only wrappers for integration tests that need to pin retained-program
/// behavior without exposing runner internals.
#[doc(hidden)]
pub mod testing {
    use kata_types::workflow::StageId;

    use super::ExecutionProgram;

    pub fn validation_retry_authority_budget(
        program: &ExecutionProgram,
        stage_id: &StageId,
    ) -> Result<u32, String> {
        super::preflight_validation_retry_authority(program, stage_id)
            .map(|stage| stage.policies.validate_retries)
            .map_err(|err| err.to_string())
    }
}

fn dispatch_contract_mismatch(stage_id: &StageId, field: &str) -> DispatchPreflightError {
    DispatchPreflightError::new(format!(
        "stage \"{}\" checked execution program {field} does not match the normalized workflow definition",
        stage_id.0
    ))
}
