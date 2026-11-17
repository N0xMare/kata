//! Verifier: load-time diagnostics for the checked execution program.
//!
//! Walks the normalized definition, invocation-plan preview, and extensions to
//! produce the [`VerifierReport`] carried by every compiled program (clause-1
//! orchestration purity, topology/isolation advisories, extension notices).

use std::collections::BTreeMap;

use kata_types::workflow::{
    EdgeCondition, MutationPolicy, ProgressVisibility, StageId, WorkflowDefinition,
};
use smol_str::SmolStr;

use super::{
    ExecutionProgramStage, VerifierDiagnostic, VerifierReport, VerifierSeverity, VerifierStatus,
};
use crate::invocation_plan::WorkflowInvocationPlanPreview;
use crate::policy::WorkflowExtensions;

/// Clause-1 (orchestration purity): whether an edge-routing condition reads ONLY
/// recorded stage verdicts/outputs — never wall-clock, RNG, or host state. The match
/// is EXHAUSTIVE on purpose: a new `EdgeCondition` variant forces a contributor to
/// classify its purity here, turning "routing is pure by IR construction" from a
/// documented argument into a compile-enforced + verified invariant. Every current variant routes
/// purely: `Always` is unconditional; `OnPass`/`OnRefine`/`OnBlock`/`Custom(tag)` route on the
/// upstream stage's recorded verdict. (Walk-away time/cost BOUNDS read the wall clock, but those
/// are recorded `StageHaltTrip` Effects, not routing — they are routed through the command log.)
pub(super) fn edge_condition_routes_purely(condition: &EdgeCondition) -> bool {
    match condition {
        EdgeCondition::Always
        | EdgeCondition::OnPass
        | EdgeCondition::OnRefine
        | EdgeCondition::OnBlock
        | EdgeCondition::Custom(_) => true,
    }
}

pub(super) fn verify_program(
    definition: &WorkflowDefinition,
    invocation_plan: &WorkflowInvocationPlanPreview,
    extensions: &WorkflowExtensions,
    stages: &BTreeMap<StageId, ExecutionProgramStage>,
) -> VerifierReport {
    let mut diagnostics = Vec::new();

    // Clause-1 orchestration purity: control-flow routing must read ONLY
    // recorded stage verdicts/outputs. The routing surface is edge conditions
    // (classified exhaustively by `edge_condition_routes_purely`) + branch routes
    // (pure BY CONSTRUCTION — a `BranchRoute` routes on its `condition_stage`'s
    // declared `verdict_field`, a recorded stage output). An impure edge condition is
    // unreachable with today's closed `EdgeCondition` set; the exhaustive classifier
    // + this check make purity a CHECKED invariant rather than a documented argument:
    // a future impure variant either fails to compile (the exhaustive match) or trips
    // this error.
    for edge in &definition.edges {
        if let Some(condition) = edge.condition.as_ref()
            && !edge_condition_routes_purely(condition)
        {
            diagnostics.push(VerifierDiagnostic {
                severity: VerifierSeverity::Error,
                code: SmolStr::new("clause1_orchestration_impurity"),
                stage: Some(edge.from.clone()),
                message: format!(
                    "edge {} -> {} routes on a condition that is not a recorded stage verdict; \
                     clause-1 orchestration purity forbids routing on wall-clock/RNG/host state",
                    edge.from.0, edge.to.0
                ),
                span: None,
            });
        }
    }

    if !definition.worktree_isolated
        && definition.stages.values().any(|stage| {
            stage
                .topology
                .as_ref()
                .is_some_and(topology_may_write_concurrently)
        })
    {
        diagnostics.push(VerifierDiagnostic {
            severity: VerifierSeverity::Warning,
            code: SmolStr::new("multi_agent_without_worktree_isolation"),
            stage: None,
            message: "workflow declares multi-agent topology while worktree_isolated=false"
                .to_string(),
            span: None,
        });
    }

    for (stage_id, stage) in &definition.stages {
        if stage.outputs.is_empty() {
            diagnostics.push(VerifierDiagnostic {
                severity: VerifierSeverity::Info,
                code: SmolStr::new("unstructured_stage_output"),
                stage: Some(stage_id.clone()),
                message: format!(
                    "stage {} declares no structured outputs; validators cannot machine-check its envelope",
                    stage_id.0
                ),
                span: None,
            });
        }
        if matches!(stage.progress_visibility, ProgressVisibility::Full) {
            diagnostics.push(VerifierDiagnostic {
                severity: VerifierSeverity::Warning,
                code: SmolStr::new("full_progress_visibility"),
                stage: Some(stage_id.clone()),
                message: format!(
                    "stage {} uses full progress visibility; streamed model text is exposed to subscribers",
                    stage_id.0
                ),
                span: None,
            });
        }
        if let Some(topology) = stage.topology.as_ref() {
            if topology_has_mutating_dynamic_fanout(topology)
                && topology.mutation_policy != MutationPolicy::OwnedPaths
            {
                diagnostics.push(VerifierDiagnostic {
                    severity: VerifierSeverity::Error,
                    code: SmolStr::new("dynamic_fanout_without_owned_paths"),
                    stage: Some(stage_id.clone()),
                    message: format!(
                        "stage {} enables mutating dynamic fanout without mutation_policy=owned_paths",
                        stage_id.0
                    ),
                    span: None,
                });
            }
            if !topology.reviewers.is_empty() && topology.review_quorum.is_none() {
                diagnostics.push(VerifierDiagnostic {
                    severity: VerifierSeverity::Warning,
                    code: SmolStr::new("reviewers_without_quorum"),
                    stage: Some(stage_id.clone()),
                    message: format!(
                        "stage {} declares reviewer roles but no review_quorum",
                        stage_id.0
                    ),
                    span: None,
                });
            }
        }
        if !stages.contains_key(stage_id) {
            diagnostics.push(VerifierDiagnostic {
                severity: VerifierSeverity::Error,
                code: SmolStr::new("stage_missing_from_execution_program"),
                stage: Some(stage_id.clone()),
                message: format!(
                    "stage {} was normalized but not lowered into the execution program",
                    stage_id.0
                ),
                span: None,
            });
        }
    }

    for stage_id in invocation_plan.stages.keys() {
        if !definition.stages.contains_key(stage_id) {
            diagnostics.push(VerifierDiagnostic {
                severity: VerifierSeverity::Error,
                code: SmolStr::new("invocation_plan_stage_without_definition"),
                stage: Some(stage_id.clone()),
                message: format!(
                    "stage {} is present in the invocation-plan preview but missing from the normalized definition",
                    stage_id.0
                ),
                span: None,
            });
        }
    }

    let blocking_request_count = extensions
        .human_request_queue
        .requests
        .iter()
        .filter(|request| request.blocking)
        .count();
    let nonblocking_request_count = extensions
        .human_request_queue
        .requests
        .len()
        .saturating_sub(blocking_request_count);
    if nonblocking_request_count > 0 {
        diagnostics.push(VerifierDiagnostic {
            severity: VerifierSeverity::Info,
            code: SmolStr::new("human_request_queue_nonblocking"),
            stage: None,
            message: format!(
                "human_request_queue carries {} nonblocking request(s) with max_items={}",
                nonblocking_request_count, extensions.human_request_queue.max_items
            ),
            span: None,
        });
    }
    if blocking_request_count > 0 {
        diagnostics.push(VerifierDiagnostic {
            severity: VerifierSeverity::Info,
            code: SmolStr::new("human_request_queue_blocking"),
            stage: None,
            message: format!(
                "human_request_queue carries {} blocking request(s) that durably park their scoped stage, with max_items={}",
                blocking_request_count, extensions.human_request_queue.max_items
            ),
            span: None,
        });
    }

    if !extensions.external_input_channels.channels.is_empty() {
        diagnostics.push(VerifierDiagnostic {
            severity: VerifierSeverity::Info,
            code: SmolStr::new("external_input_channels_prompt_context"),
            stage: None,
            message: format!(
                "external_input_channels declares {} prompt/context channel(s) with max_channels={}",
                extensions.external_input_channels.channels.len(),
                extensions.external_input_channels.max_channels
            ),
            span: None,
        });
    }

    if !extensions.memory_selectors.selectors.is_empty() {
        diagnostics.push(VerifierDiagnostic {
            severity: VerifierSeverity::Info,
            code: SmolStr::new("memory_selectors_declared"),
            stage: None,
            message: format!(
                "memory_selectors declares {} checked native-memory selector(s) with max_selectors={}",
                extensions.memory_selectors.selectors.len(),
                extensions.memory_selectors.max_selectors
            ),
            span: None,
        });
    }

    if !extensions.memory_writebacks.writebacks.is_empty() {
        diagnostics.push(VerifierDiagnostic {
            severity: VerifierSeverity::Info,
            code: SmolStr::new("memory_writebacks_declared"),
            stage: None,
            message: format!(
                "memory_writebacks declares {} checked native-memory writeback(s) with max_writebacks={}",
                extensions.memory_writebacks.writebacks.len(),
                extensions.memory_writebacks.max_writebacks
            ),
            span: None,
        });
    }

    if !extensions.validation_criteria.criteria.is_empty() {
        diagnostics.push(VerifierDiagnostic {
            severity: VerifierSeverity::Info,
            code: SmolStr::new("validation_criteria_declared"),
            stage: None,
            message: format!(
                "validation_criteria declares {} completion criterion/criteria for operator and preflight evidence",
                extensions.validation_criteria.criteria.len()
            ),
            span: None,
        });
        for criterion in &extensions.validation_criteria.criteria {
            if criterion.commands.is_empty() && criterion.evidence.is_empty() {
                diagnostics.push(VerifierDiagnostic {
                    severity: VerifierSeverity::Warning,
                    code: SmolStr::new("validation_criterion_without_evidence"),
                    stage: criterion.stage.as_ref().map(|stage| StageId(stage.clone())),
                    message: format!(
                        "validation criterion {} declares no command or evidence hint",
                        criterion.id
                    ),
                    span: None,
                });
            }
        }
    }

    if let Some(pattern) = extensions.workflow_pattern.as_ref()
        && pattern.escape_hatch
    {
        diagnostics.push(VerifierDiagnostic {
            severity: VerifierSeverity::Warning,
            code: SmolStr::new("workflow_pattern_escape_hatch"),
            stage: None,
            message: format!(
                "workflow pattern {} uses an explicit escape hatch; its checked defaults are advisory",
                pattern.name
            ),
            span: None,
        });
        if pattern
            .escape_reason
            .as_deref()
            .is_none_or(|reason| reason.trim().is_empty())
        {
            diagnostics.push(VerifierDiagnostic {
                severity: VerifierSeverity::Warning,
                code: SmolStr::new("workflow_pattern_escape_hatch_without_reason"),
                stage: None,
                message: format!(
                    "workflow pattern {} enables escape_hatch without escape_reason",
                    pattern.name
                ),
                span: None,
            });
        }
    }

    verify_params(extensions, &mut diagnostics);

    let status = if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == VerifierSeverity::Error)
    {
        VerifierStatus::Error
    } else if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == VerifierSeverity::Warning)
    {
        VerifierStatus::Warn
    } else {
        VerifierStatus::Pass
    };

    VerifierReport {
        status,
        diagnostics,
    }
}

/// Verify the declared typed invocation params as a checked-IR invariant.
///
/// The author-time DSL decode (`decode_params`) already fails closed for the
/// Starlark path; this is the belt-and-suspenders that also guards a
/// programmatically-constructed program. Each violation is an Error diagnostic,
/// so the program is rejected (fail-closed) at preflight:
///
/// * a param name must be UNIQUE within the workflow;
/// * a param's declared SCHEMA must be within the supported subset;
/// * a param is REQUIRED XOR DEFAULTED (a default is the value used when the
///   param is omitted, so a required param must not carry one);
/// * a SECRET param must not carry a default (no plaintext secret in source);
/// * a DEFAULT value must satisfy the param's declared schema.
fn verify_params(extensions: &WorkflowExtensions, diagnostics: &mut Vec<VerifierDiagnostic>) {
    // Bound the DECLARED param count (mirrors the resolver's submit-time bound
    // and the author-time DSL decode) so a programmatically-built over-declared
    // program is rejected at verify, before it can ever be admitted.
    if extensions.params.params.len() > kata_types::params::MAX_INVOCATION_PARAMS {
        diagnostics.push(VerifierDiagnostic {
            severity: VerifierSeverity::Error,
            code: SmolStr::new("too_many_params"),
            stage: None,
            message: format!(
                "workflow declares {} params; maximum is {}",
                extensions.params.params.len(),
                kata_types::params::MAX_INVOCATION_PARAMS
            ),
            span: None,
        });
    }
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for spec in &extensions.params.params {
        let name = spec.name.as_str();
        let mut error = |code: &str, message: String| {
            diagnostics.push(VerifierDiagnostic {
                severity: VerifierSeverity::Error,
                code: SmolStr::new(code),
                stage: None,
                message,
                span: None,
            });
        };
        if !seen.insert(name) {
            error(
                "duplicate_param_name",
                format!("workflow declares param {name:?} more than once"),
            );
        }
        if let Err(detail) = kata_types::agent_run::validate_param_schema(&spec.schema) {
            error(
                "invalid_param_schema",
                format!("workflow param {name:?} declares an invalid type schema: {detail}"),
            );
        }
        if spec.required && spec.default.is_some() {
            error(
                "param_required_with_default",
                format!(
                    "workflow param {name:?} is required and also declares a default; a param is \
                     required XOR defaulted"
                ),
            );
        }
        if spec.secret && spec.default.is_some() {
            error(
                "secret_param_with_default",
                format!(
                    "workflow param {name:?} is secret and declares a default; a secret must never \
                     carry a plaintext default"
                ),
            );
        }
        if let Some(default) = &spec.default
            && let Err(detail) =
                kata_types::agent_run::validate_param_value_against_schema(default, &spec.schema)
        {
            error(
                "param_default_type_mismatch",
                format!(
                    "workflow param {name:?} default does not satisfy its declared type: {detail}"
                ),
            );
        }
    }
}

fn topology_may_write_concurrently(topology: &kata_types::workflow::StageTopology) -> bool {
    topology.dynamic_fanout || topology.workers.len() + topology.reviewers.len() > 1
}

fn topology_has_mutating_dynamic_fanout(topology: &kata_types::workflow::StageTopology) -> bool {
    topology.dynamic_fanout && !topology.workers.is_empty()
}
