//! Execution evidence extraction + merge (closeout/controller/validation).

use kata_types::execution::{
    CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION, ExecutionCheckArtifactEvidence,
    ExecutionCloseoutEvidence, ExecutionControllerApplicationEvidence,
    ExecutionControllerCompletionEvidence, ExecutionControllerDecisionEvidence,
    ExecutionControllerDecisionScopeEvidence, ExecutionControllerMemoryPolicyEvidence,
    ExecutionControllerMemoryProposalEvidence, ExecutionControllerRuntimePolicyEvidence,
    ExecutionEvidence, ExecutionHumanRequestEvidence, ExecutionMemoryWritebackEvidence,
    ExecutionValidationEvidence,
};

use kata_program::execution_program::ExecutionProgram;

use super::memory_writeback::parsed_stage_output;

pub(super) fn execution_evidence_from_records(
    typed_records: &[kata_core::ExecutionEvidenceRecord],
) -> ExecutionEvidence {
    let mut evidence_rows = typed_records
        .iter()
        .map(|record| (record.created_at_ms, record.id, record.evidence.clone()))
        .collect::<Vec<_>>();
    evidence_rows.sort_by_key(|(at_ms, id, _)| (*at_ms, *id));

    let mut evidence = ExecutionEvidence::default();
    for (_, _, next) in evidence_rows {
        merge_execution_evidence(&mut evidence, next);
    }
    evidence
}

pub(super) fn merge_execution_evidence(target: &mut ExecutionEvidence, next: ExecutionEvidence) {
    if next.execution_program.is_some() {
        target.execution_program = next.execution_program;
    }
    if next.checked_runtime_authority.is_some() {
        target.checked_runtime_authority = next.checked_runtime_authority;
    }
    if next.parked_candidate.is_some() {
        target.parked_candidate = next.parked_candidate;
    }
    target.auto_parked |= next.auto_parked;
    if next.closeout_park_refusal.is_some() {
        target.closeout_park_refusal = next.closeout_park_refusal;
    }
    for report in next.validation_reports {
        merge_validation_report_evidence(&mut target.validation_reports, report);
    }
    target.closeout_reports.extend(next.closeout_reports);
    for request in next.human_requests {
        if let Some(existing) = target
            .human_requests
            .iter_mut()
            .find(|existing| existing.id == request.id && existing.stage == request.stage)
        {
            if human_request_evidence_rank(&request) >= human_request_evidence_rank(existing) {
                *existing = request;
            }
        } else {
            target.human_requests.push(request);
        }
    }
    for input in next.external_inputs {
        if let Some(existing) = target
            .external_inputs
            .iter_mut()
            .find(|existing| existing.channel == input.channel && existing.id == input.id)
        {
            if input.appended_at_ms >= existing.appended_at_ms {
                *existing = input;
            }
        } else {
            target.external_inputs.push(input);
        }
    }
    // Per-param provenance rows. The admission-evidence claim makes the
    // admission row unique per execution, so rows merge keyed by param name with
    // the FIRST (original-admission) row winning — a later recovery republish
    // never overwrites the original submitting face.
    for row in next.param_provenance {
        if !target
            .param_provenance
            .iter()
            .any(|existing| existing.name == row.name)
        {
            target.param_provenance.push(row);
        }
    }
    for selector in next.memory_selectors {
        if let Some(existing) = target.memory_selectors.iter_mut().find(|existing| {
            existing.selector_id == selector.selector_id && existing.stage == selector.stage
        }) {
            if selector.materialized_at_ms >= existing.materialized_at_ms {
                *existing = selector;
            }
        } else {
            target.memory_selectors.push(selector);
        }
    }
    for artifact in next.check_artifacts {
        merge_check_artifact_evidence(&mut target.check_artifacts, artifact);
    }
    for writeback in next.memory_writebacks {
        merge_memory_writeback_evidence(&mut target.memory_writebacks, writeback);
    }
    for decision in next.controller_decisions {
        merge_controller_decision_evidence(&mut target.controller_decisions, decision);
    }
    for application in next.controller_applications {
        merge_controller_application_evidence(&mut target.controller_applications, application);
    }
    target
        .checked_dispatch_guards
        .extend(next.checked_dispatch_guards);
    // Per-stage output-closure observations. Rows arrive
    // time-sorted (line 27), so replacing the row for an existing stage keeps the
    // latest recorded observation; a new stage is appended.
    for observation in next.output_closures {
        if let Some(existing) = target
            .output_closures
            .iter_mut()
            .find(|existing| existing.stage_name == observation.stage_name)
        {
            *existing = observation;
        } else {
            target.output_closures.push(observation);
        }
    }
    // Egress-refusal rows: written once per ACCEPTED attempt inside the
    // accepting transaction, so `(attempt_id, seq)` is a stable identity — the
    // same refusal can never arrive carrying a different payload, and a
    // re-projected row folds to itself rather than a duplicate.
    for refusal in next.egress_refusals {
        if !target.egress_refusals.iter().any(|existing| {
            existing.attempt_id == refusal.attempt_id && existing.seq == refusal.seq
        }) {
            target.egress_refusals.push(refusal);
        }
    }
    // Agent-turn rows on the same terms: one row is written per accepted
    // attempt's turn inside the accepting transaction, so `attempt_id` is the
    // stable identity and a re-projected row folds to itself.
    for turn in next.agent_turns {
        if !target
            .agent_turns
            .iter()
            .any(|existing| existing.attempt_id == turn.attempt_id)
        {
            target.agent_turns.push(turn);
        }
    }
}

pub(super) fn human_request_evidence_rank(request: &ExecutionHumanRequestEvidence) -> u8 {
    u8::from(request.is_resolved())
}

pub(super) fn merge_validation_report_evidence(
    target: &mut Vec<ExecutionValidationEvidence>,
    report: ExecutionValidationEvidence,
) {
    if !target.iter().any(|existing| existing == &report) {
        target.push(report);
    }
}

pub(super) fn merge_check_artifact_evidence(
    target: &mut Vec<ExecutionCheckArtifactEvidence>,
    artifact: ExecutionCheckArtifactEvidence,
) {
    if let Some(existing) = target.iter_mut().find(|existing| {
        existing.artifact_id == artifact.artifact_id && existing.stage_name == artifact.stage_name
    }) {
        *existing = artifact;
    } else {
        target.push(artifact);
    }
}

pub(super) fn merge_memory_writeback_evidence(
    target: &mut Vec<ExecutionMemoryWritebackEvidence>,
    writeback: ExecutionMemoryWritebackEvidence,
) {
    if let Some(existing) = target.iter_mut().find(|existing| {
        existing.writeback_id == writeback.writeback_id
            && existing.stage_name == writeback.stage_name
            && existing.object_id == writeback.object_id
    }) {
        if memory_writeback_evidence_rank(&writeback) >= memory_writeback_evidence_rank(existing) {
            *existing = writeback;
        }
    } else {
        target.push(writeback);
    }
}

pub(super) fn memory_writeback_evidence_rank(evidence: &ExecutionMemoryWritebackEvidence) -> u8 {
    match evidence.action.as_str() {
        "pending" => 0,
        "applied" | "skipped_idempotent" => 2,
        _ => 1,
    }
}

pub(super) fn merge_controller_decision_evidence(
    target: &mut Vec<ExecutionControllerDecisionEvidence>,
    decision: ExecutionControllerDecisionEvidence,
) {
    if let Some(existing) = target.iter_mut().find(|existing| {
        existing.stage_name == decision.stage_name && existing.decision_id == decision.decision_id
    }) {
        *existing = decision;
    } else {
        target.push(decision);
    }
}

pub(super) fn merge_controller_application_evidence(
    target: &mut Vec<ExecutionControllerApplicationEvidence>,
    application: ExecutionControllerApplicationEvidence,
) {
    if let Some(existing) = target
        .iter_mut()
        .find(|existing| existing.application_id == application.application_id)
    {
        *existing = application;
    } else {
        target.push(application);
    }
}

/// The ONE rule that turns a COMPLETED validation stage's output into evidence.
///
/// Two projections call it and there is exactly one of it. The
/// `ExecutionRecord` aggregator walks `ChainAssignmentState` rows; the memory
/// writeback walks the authority chain. Splitting this into a per-plane copy
/// would put the stage filter and the output decode in two places for one rule
/// — and the two would be read by the same operator as one evidence list.
///
/// BOUND BY DECLARATION. The filter is
/// `ExecutionProgram::stage_records_validation_evidence` — the checked program's
/// own `validation_criterion(stage = ..)` list — never a stage-name
/// convention. `program` is `None` only when the checked program could not be read for
/// this execution; that answers `None` (fail-closed: an unreadable program
/// declares no proof stage we can honour, and the durable evidence rows the
/// runner wrote are unaffected because they are merged from a different source).
///
/// The filter, the missing-program case and the absent-output case all answer
/// `None`, and the caller cannot tell them apart on purpose: none produces
/// evidence, and no caller acts differently on which.
pub(super) fn validation_evidence_for_stage(
    program: Option<&ExecutionProgram>,
    stage_name: &str,
    output: Option<&serde_json::Value>,
) -> Option<ExecutionValidationEvidence> {
    if !program?.stage_records_validation_evidence(stage_name) {
        return None;
    }
    ExecutionValidationEvidence::from_stage_output(stage_name.to_string(), output?)
}

/// The assignment-plane projection of [`validation_evidence_for_stage`].
pub(super) fn validation_evidence_from_assignments(
    program: Option<&ExecutionProgram>,
    assignments: &[kata_workflow::attempt_delivery::ChainAssignmentState],
) -> Vec<ExecutionValidationEvidence> {
    assignments
        .iter()
        .filter(|s| {
            matches!(
                s.status,
                kata_types::ledger::AssignmentStatus::Completed { .. }
            )
        })
        .filter_map(|s| {
            validation_evidence_for_stage(program, s.stage_name.as_str(), s.output.as_ref())
        })
        .collect()
}

/// The AUTHORITY-CHAIN projection of [`validation_evidence_for_stage`].
pub(super) fn chain_validation_evidence(
    program: &ExecutionProgram,
    facts: &[super::memory_writeback::CompletedStageFact],
) -> Vec<ExecutionValidationEvidence> {
    facts
        .iter()
        .filter_map(|fact| {
            validation_evidence_for_stage(
                Some(program),
                fact.base_stage.as_str(),
                fact.output.as_ref(),
            )
        })
        .collect()
}

pub(super) fn closeout_evidence_from_assignments(
    assignments: &[kata_workflow::attempt_delivery::ChainAssignmentState],
) -> Vec<ExecutionCloseoutEvidence> {
    assignments
        .iter()
        .filter(|s| {
            matches!(
                s.status,
                kata_types::ledger::AssignmentStatus::Completed { .. }
            )
        })
        .filter(|s| is_closeout_stage_name(s.stage_name.as_str()))
        .filter_map(closeout_evidence_from_assignment)
        .collect()
}

pub(super) fn closeout_evidence_from_assignment(
    state: &kata_workflow::attempt_delivery::ChainAssignmentState,
) -> Option<ExecutionCloseoutEvidence> {
    closeout_evidence_for_stage(state.stage_name.as_str(), state.output.as_ref())
}

/// The (stage, output) core of [`closeout_evidence_from_assignment`] — the
/// execution-record projection feeds an accepted occurrence output through the
/// same rule, for a stage the assignment population does not carry.
pub(super) fn closeout_evidence_for_stage(
    stage_name: &str,
    output: Option<&serde_json::Value>,
) -> Option<ExecutionCloseoutEvidence> {
    let parsed = parsed_stage_output(output)?;
    let outcome = string_field(&parsed, "outcome");
    let evidence = string_array_field(&parsed, "evidence");
    let remaining = string_array_field(&parsed, "remaining");
    let next_action = string_field(&parsed, "next_action");
    if outcome.is_none() && evidence.is_empty() && remaining.is_empty() && next_action.is_none() {
        return None;
    }
    Some(ExecutionCloseoutEvidence {
        stage_name: stage_name.to_string(),
        outcome,
        evidence,
        remaining,
        next_action,
    })
}

pub(super) fn is_closeout_stage_name(stage_name: &str) -> bool {
    let base = stage_name.split('#').next().unwrap_or(stage_name);
    base == "closeout" || base.ends_with("_closeout")
}

pub(super) fn controller_decision_evidence_from_assignments(
    assignments: &[kata_workflow::attempt_delivery::ChainAssignmentState],
) -> Vec<ExecutionControllerDecisionEvidence> {
    assignments
        .iter()
        .filter(|s| {
            matches!(
                s.status,
                kata_types::ledger::AssignmentStatus::Completed { .. }
            )
        })
        .filter(|s| is_controller_stage_name(s.stage_name.as_str()))
        .filter_map(controller_decision_evidence_from_assignment)
        .collect()
}

pub(super) fn controller_decision_evidence_from_assignment(
    state: &kata_workflow::attempt_delivery::ChainAssignmentState,
) -> Option<ExecutionControllerDecisionEvidence> {
    controller_decision_evidence_for_stage(state.stage_name.as_str(), state.output.as_ref())
}

/// The (stage, output) core of [`controller_decision_evidence_from_assignment`]
/// — the execution-record projection feeds an accepted occurrence output
/// through the same rule, for a stage the assignment population does not carry.
pub(super) fn controller_decision_evidence_for_stage(
    stage_name: &str,
    output: Option<&serde_json::Value>,
) -> Option<ExecutionControllerDecisionEvidence> {
    let parsed = parsed_stage_output(output)?;
    let decision = string_field(&parsed, "decision")?;
    let decision_id = string_field(&parsed, "decision_id")
        .or_else(|| string_field(&parsed, "id"))
        .unwrap_or_else(|| format!("{}:{decision}", stage_name));
    Some(ExecutionControllerDecisionEvidence {
        schema_version: parsed
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|version| u32::try_from(version).ok())
            .unwrap_or(CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION),
        stage_name: stage_name.to_string(),
        decision_id,
        wave_id: string_field(&parsed, "wave_id"),
        decision,
        next_action: string_field(&parsed, "next_action"),
        reason: string_field(&parsed, "reason"),
        evidence: string_array_field(&parsed, "evidence"),
        alternatives: string_array_field(&parsed, "alternatives"),
        human_required: parsed
            .get("human_required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        scope: controller_decision_scope_evidence(&parsed),
        completion: controller_completion_evidence(&parsed),
        memory_policy: controller_memory_policy_evidence(&parsed),
        runtime_policy: controller_runtime_policy_evidence(&parsed),
    })
}

pub(super) fn is_controller_stage_name(stage_name: &str) -> bool {
    let base = stage_name.split('#').next().unwrap_or(stage_name);
    base == "controller" || base.ends_with("_controller") || base.ends_with("_controller_decision")
}

pub(super) fn controller_decision_scope_evidence(
    value: &serde_json::Value,
) -> Option<ExecutionControllerDecisionScopeEvidence> {
    let scope = value.get("scope")?;
    let focus_areas = string_array_field(scope, "focus_areas")
        .into_iter()
        .chain(string_array_field(scope, "focus"))
        .collect::<Vec<_>>();
    let evidence = ExecutionControllerDecisionScopeEvidence {
        summary: string_field(scope, "summary"),
        focus_areas,
        owned_paths: string_array_field(scope, "owned_paths"),
        // Membrane coercion: strip LLM "no blocker" sentinels (e.g. `["none"]`)
        // so a sentinel-only list normalizes to the canonical empty form and a
        // correct controller park decision is not forced to validation-failed.
        validation_blockers: kata_types::execution::filter_sentinel_blockers(string_array_field(
            scope,
            "validation_blockers",
        )),
        rationale: string_field(scope, "rationale").or_else(|| string_field(scope, "reason")),
    };
    if evidence.summary.is_none()
        && evidence.focus_areas.is_empty()
        && evidence.owned_paths.is_empty()
        && evidence.validation_blockers.is_empty()
        && evidence.rationale.is_none()
    {
        None
    } else {
        Some(evidence)
    }
}

pub(super) fn controller_completion_evidence(
    value: &serde_json::Value,
) -> Option<ExecutionControllerCompletionEvidence> {
    let completion = value.get("completion")?;
    let status = string_field(completion, "status")?;
    Some(ExecutionControllerCompletionEvidence {
        status,
        validation_passed: bool_field(completion, "validation_passed").unwrap_or(false),
        // `remaining` is free-text next-steps, not a pass/fail gate — leave it
        // untouched. `blockers` is the same LLM artifact as scope's list, so
        // apply the identical sentinel coercion.
        remaining: string_array_field(completion, "remaining"),
        blockers: kata_types::execution::filter_sentinel_blockers(string_array_field(
            completion, "blockers",
        )),
        rationale: string_field(completion, "rationale")
            .or_else(|| string_field(completion, "reason")),
    })
}

pub(super) fn controller_memory_policy_evidence(
    value: &serde_json::Value,
) -> Option<ExecutionControllerMemoryPolicyEvidence> {
    let policy = value.get("memory_policy")?;
    let evidence = ExecutionControllerMemoryPolicyEvidence {
        selectors: string_array_field(policy, "selectors"),
        writebacks: string_array_field(policy, "writebacks"),
        context_queries: string_array_field(policy, "context_queries")
            .into_iter()
            .chain(string_array_field(policy, "queries"))
            .collect(),
        proposals: controller_memory_proposal_evidence(policy),
        rationale: string_field(policy, "rationale").or_else(|| string_field(policy, "reason")),
    };
    if evidence.selectors.is_empty()
        && evidence.writebacks.is_empty()
        && evidence.context_queries.is_empty()
        && evidence.proposals.is_empty()
        && evidence.rationale.is_none()
    {
        None
    } else {
        Some(evidence)
    }
}

pub(super) fn controller_memory_proposal_evidence(
    policy: &serde_json::Value,
) -> Vec<ExecutionControllerMemoryProposalEvidence> {
    let Some(items) = policy
        .get("proposals")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    // Keep malformed items (missing object_id/kind) rather than silently
    // dropping them: an empty object_id/kind fails the lowering's validation
    // closed instead of vanishing from a fat-fingered controller decision.
    items
        .iter()
        .map(|item| ExecutionControllerMemoryProposalEvidence {
            object_id: string_field(item, "object_id")
                .or_else(|| string_field(item, "id"))
                .unwrap_or_default(),
            kind: string_field(item, "kind").unwrap_or_default(),
            title: string_field(item, "title"),
            summary: string_field(item, "summary").or_else(|| string_field(item, "body")),
            tags: string_array_field(item, "tags"),
        })
        .collect()
}

pub(super) fn controller_runtime_policy_evidence(
    value: &serde_json::Value,
) -> Option<ExecutionControllerRuntimePolicyEvidence> {
    let policy = value.get("runtime_policy")?;
    let cost_limit_micro_usd = u64_field(policy, "cost_limit_micro_usd")
        .or_else(|| u64_field(policy, "budget_micro_usd"))
        .or_else(|| usd_to_micro_usd_field(policy, "cost_limit_usd"))
        .or_else(|| usd_to_micro_usd_field(policy, "budget_usd"));
    let evidence = ExecutionControllerRuntimePolicyEvidence {
        cost_limit_micro_usd,
        deadline_at_ms: u64_field(policy, "deadline_at_ms"),
        next_wave_stage_timeout_ms: positive_u64_field(policy, "next_wave_stage_timeout_ms")
            .or_else(|| positive_u64_field(policy, "stage_timeout_ms"))
            .or_else(|| positive_u64_field(policy, "timeout_ms")),
        recommended_max_waves: u64_field(policy, "recommended_max_waves")
            .or_else(|| u64_field(policy, "max_waves"))
            .and_then(|value| u32::try_from(value).ok()),
        rationale: string_field(policy, "rationale").or_else(|| string_field(policy, "reason")),
    };
    if evidence.cost_limit_micro_usd.is_none()
        && evidence.deadline_at_ms.is_none()
        && evidence.next_wave_stage_timeout_ms.is_none()
        && evidence.recommended_max_waves.is_none()
        && evidence.rationale.is_none()
    {
        None
    } else {
        Some(evidence)
    }
}

pub(super) fn string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

pub(super) fn u64_field(value: &serde_json::Value, field: &str) -> Option<u64> {
    value.get(field).and_then(serde_json::Value::as_u64)
}

pub(super) fn positive_u64_field(value: &serde_json::Value, field: &str) -> Option<u64> {
    u64_field(value, field).filter(|value| *value > 0)
}

pub(super) fn usd_to_micro_usd_field(value: &serde_json::Value, field: &str) -> Option<u64> {
    let amount = value.get(field).and_then(serde_json::Value::as_f64)?;
    if !amount.is_finite() || amount < 0.0 {
        return None;
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some((amount * 1_000_000.0) as u64)
}

pub(super) fn bool_field(value: &serde_json::Value, field: &str) -> Option<bool> {
    value.get(field).and_then(serde_json::Value::as_bool)
}

pub(super) fn string_array_field(value: &serde_json::Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect()
}
