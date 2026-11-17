//! The promotion gate's DECLARED-CRITERIA half: does the checked program's
//! declared REQUIRED validation criteria set actually hold for this execution?
//!
//! # One rule, two routes
//!
//! kata has two ways to land a candidate on the operator's trunk.
//!
//! * The OPERATOR route — `kata_api::executor::WorkflowExecutor::promote` and the
//!   factory apply path — reads an `ExecutionRecord` and calls this.
//! * The IN-GRAPH route — a pack authoring
//!   `stage(agent = "workspace_effect", op = "promote")` — is resolved by
//!   [`authorize_promote_directive`], from the frozen IR and the execution's
//!   recorded validation reports, and calls this. Every writer of a dispatchable
//!   promote directive calls THAT; today the only one is the runner
//!   (`WorkflowRunner::authorize_promote_dispatch`, a thin adapter), because a
//!   capsule stage's prompt is frozen at admission and nothing rewrites a
//!   parked directive afterwards.
//!
//! Both use [`candidate_coherent_promotion_gate`], directly or through the
//! [`validation_criteria_gate`] projection. That is the point of the module
//! existing here rather than in `kata-api`: the in-graph route runs in
//! `kata-workflow`, which cannot reach `kata-api` and must not acquire it, and a
//! second copy of this rule in this crate would drift from its twin.
//!
//! # What this gate does NOT decide
//!
//! * **Whether the tree that lands is the tree that was judged.** That is
//!   [`kata_types::execution::CandidateTreePin`], compared by the provider after
//!   settling the candidate. This gate is about the VERDICT; that one is about
//!   IDENTITY, and neither implies the other.
//! * **Whether the execution's lifecycle is terminal.** The operator route asks
//!   that separately and the in-graph route deliberately does not — see
//!   [`authorize_promote_directive`].
//! * **Whether the workspace exists or is clean.** That is the provider's, at
//!   the mutation.
//!
//! The observed criteria arrive as `&[ExecutionValidationEvidence]` rather than
//! inside an execution record, because the runner holds reports and has no record.

use kata_types::execution::{
    CandidateTreePin, ExecutionValidationCandidateEvidence, ExecutionValidationCriterionEvidence,
    ExecutionValidationCriterionStatus, ExecutionValidationEvidence,
};
use kata_types::workflow::StageId;
use smol_str::SmolStr;

use kata_program::execution_program::ExecutionProgram;

/// The verdict, and enough of the working to explain it to an operator.
///
/// `active` is "this program declares at least one REQUIRED criterion";
/// `passed` is "and none of them blocked". A caller authorizes ONLY on
/// `active && passed` — `passed` alone is `false` for a zero-criterion program
/// and reading it in isolation would invert the gate.
#[derive(Debug, Clone, Default)]
pub struct ValidationCriteriaGate {
    /// The program declares at least one `required = True` criterion.
    pub active: bool,
    /// Every declared required criterion is satisfied. Meaningless without
    /// `active`.
    pub passed: bool,
    /// One `validation_criterion:<id>:<label>` entry per unsatisfied criterion,
    /// sorted and deduplicated.
    pub blockers: Vec<String>,
    /// Operator-facing sentence, `None` exactly when `active && passed`.
    pub reason: Option<String>,
}

/// A criterion as the frozen IR DECLARES it — id plus the proof stage it names.
/// Distinct from `ExecutionValidationCriterionEvidence`, which is what a stage
/// REPORTED; the gate's whole job is to match the second against the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredValidationCriterionPolicy {
    id: String,
    stage: Option<String>,
}

/// Verify that a required validation criterion's declared proof stage routes
/// to a backend whose self-reported verdict may be trusted as promotion proof.
///
/// Fail-closed: an unbound (`stage = None`), unknown, or proof-ineligible
/// stage all return `Err`, so such a criterion can never be marked satisfied.
/// Trusting a `passed` verdict from an LLM-backed proof stage would let the
/// agent self-certify promotion; a `workspace_effect` stage is deterministic
/// but emits no validation report, so it too is ineligible. Only a backend for
/// which `is_validation_proof_eligible` holds (today: `shell`) produces an
/// acceptable mechanical verdict. See
/// `ExecutionProgramStage::is_validation_proof_eligible`.
pub fn validation_proof_stage_determinism(
    program: &ExecutionProgram,
    declared_stage: Option<&str>,
) -> Result<(), &'static str> {
    let Some(stage_name) = declared_stage else {
        return Err("proof_stage_unbound");
    };
    let Some(stage) = program.stages.get(&StageId(SmolStr::new(stage_name))) else {
        return Err("proof_stage_unknown");
    };
    if stage.is_validation_proof_eligible() {
        Ok(())
    } else {
        Err("proof_stage_not_deterministic")
    }
}

/// True if the stage that actually PRODUCED a validation report routes to a
/// backend whose verdict may be trusted as promotion proof.
///
/// `report.stage_name` is the dispatcher-trusted producing stage (set by the
/// runtime when it persists a validation report, not by the agent). The
/// per-criterion `criterion.stage_name` is parsed from agent JSON and must never
/// be trusted to identify the producing stage — otherwise an LLM stage could
/// self-certify by emitting a criterion that spoofs `stage_name` to name a shell
/// stage. Resolves the runtime stage name to its checked stage id (handling
/// `#`-suffixed invocation names) and fails closed if the stage is unknown.
/// Uses the validation-proof-eligibility predicate (which excludes
/// `workspace_effect`), not raw determinism.
pub fn validation_evidence_producing_stage_is_deterministic(
    program: &ExecutionProgram,
    runtime_stage: &str,
) -> bool {
    match program
        .checked_stage_id_for_runtime_stage(runtime_stage)
        .and_then(|stage_id| program.stages.get(&stage_id))
    {
        Some(stage) => stage.is_validation_proof_eligible(),
        None => false,
    }
}

/// THE PROMOTION VERDICT. Does every REQUIRED criterion this program declares
/// hold, in the reports this execution recorded?
///
/// # Refused set, exactly
///
/// A caller authorizing on `active && passed` refuses these and nothing else:
///
/// 1. the program declares no `required = True` criterion, or is unreadable
///    (`active == false`);
/// 2. a required criterion's declared proof stage is unbound, unknown, or
///    routes to a backend that may not be trusted with a verdict
///    (`proof_stage_unbound` / `proof_stage_unknown` /
///    `proof_stage_not_deterministic`);
/// 3. no recorded report carries that criterion id from that declared stage
///    (`missing`);
/// 4. a report does carry it, but the stage that PRODUCED the report is not
///    proof-eligible (`proof_stage_not_deterministic` — the anti-spoofing arm:
///    `criterion.stage_name` is agent JSON, `report.stage_name` is not);
/// 5. the criterion's status is `failed`, `unknown` or `insufficient_evidence`;
/// 6. the status is `waived_by_policy` with a missing or unauthorized waiver
///    (`waiver_missing` / `waiver_unauthorized`);
/// 7. and ONLY when `expected_candidate` is `Some`: the criterion carries no
///    candidate (`candidate_missing`) or one whose execution id or fingerprint
///    differs (`candidate_mismatch`);
/// 8. when a required passed proof pins a tree: a required criterion has no
///    satisfying observation binding that same tree (`candidate_tree_mismatch`).
///
/// # What it does NOT ask
///
/// OPTIONAL criteria never authorize and never block — they appear in `reason`
/// only, so an author who marked the wrong one optional is told why nothing
/// passed. Nothing here reads the execution's LIFECYCLE, the workspace, or the
/// tree that is about to land.
///
/// # `expected_candidate`
///
/// `Some` on the operator/factory route, which recomputes a live candidate
/// binding from `workspace_status` and can therefore compare fingerprints.
/// `None` on the in-graph route, deliberately: the fingerprint was
/// backend-divergent while the `git_worktree` provider existed, so it was never
/// that route's identity question. That route asks the identity question in
/// `kata_types::execution::CandidateTreePin`'s currency instead.
pub fn validation_criteria_gate(
    program: Option<&ExecutionProgram>,
    reports: &[ExecutionValidationEvidence],
    expected_candidate: Option<&ExecutionValidationCandidateEvidence>,
) -> ValidationCriteriaGate {
    match program {
        Some(program) => candidate_coherent_promotion_gate(program, reports, expected_candidate).0,
        None => validation_criteria_gate_for_tree(None, reports, expected_candidate, None),
    }
}

/// Resolve the verdict and pin from one view of the evidence. Every authorizing
/// required observation must bind the selected tree; an operator's live
/// candidate binding adds a fingerprint check without replacing that invariant.
pub fn candidate_coherent_promotion_gate(
    program: &ExecutionProgram,
    reports: &[ExecutionValidationEvidence],
    expected_candidate: Option<&ExecutionValidationCandidateEvidence>,
) -> (ValidationCriteriaGate, CandidateTreePin) {
    let pin = required_proof_candidate_tree_pin(program, reports);
    let gate = validation_criteria_gate_for_tree(
        Some(program),
        reports,
        expected_candidate,
        pin.pinned_tree_id(),
    );
    (gate, pin)
}

fn validation_criteria_gate_for_tree(
    program: Option<&ExecutionProgram>,
    reports: &[ExecutionValidationEvidence],
    expected_candidate: Option<&ExecutionValidationCandidateEvidence>,
    expected_tree: Option<&str>,
) -> ValidationCriteriaGate {
    let declared_required = program
        .map(|program| {
            program
                .validation_criteria
                .criteria
                .iter()
                .filter(|criterion| criterion.required)
                .map(|criterion| DeclaredValidationCriterionPolicy {
                    id: criterion.id.to_string(),
                    stage: criterion.stage.as_ref().map(|stage| stage.0.to_string()),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let declared_optional = program
        .map(|program| {
            program
                .validation_criteria
                .criteria
                .iter()
                .filter(|criterion| !criterion.required)
                .map(|criterion| DeclaredValidationCriterionPolicy {
                    id: criterion.id.to_string(),
                    stage: criterion.stage.as_ref().map(|stage| stage.0.to_string()),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let observed = reports
        .iter()
        .flat_map(|report| {
            report
                .criteria
                .iter()
                .map(move |criterion| (report, criterion))
        })
        .collect::<Vec<_>>();

    let mut blockers = Vec::new();
    for declared in &declared_required {
        // Fail-closed determinism precheck: a required criterion can only be
        // proved by a deterministic (non-LLM) proof stage. Resolve the
        // declared proof stage and verify before any observed-criteria
        // matching, so an unbound / unknown / non-deterministic proof stage
        // can never be satisfied — even if an LLM-backed stage self-reports
        // `passed`.
        match program.map_or(Err("proof_stage_unknown"), |program| {
            validation_proof_stage_determinism(program, declared.stage.as_deref())
        }) {
            Ok(()) => {}
            Err(label) => {
                blockers.push(format!("validation_criterion:{}:{label}", declared.id));
                continue;
            }
        }
        let mut blocker = None;
        let mut satisfied = false;
        if let Some(program) = program {
            for (report, criterion) in &observed {
                if criterion.criterion_id == declared.id
                    && validation_criterion_stage_matches_declaration(
                        program,
                        declared.stage.as_deref(),
                        validation_criterion_evidence_stage(report, criterion),
                    )
                {
                    // TRUST: the stage that actually PRODUCED this report
                    // (`report.stage_name`, dispatcher-trusted) must be a
                    // deterministic executor. `criterion.stage_name` is
                    // agent-controlled JSON, so an LLM stage could otherwise
                    // self-certify by spoofing it to name the shell proof stage;
                    // verifying the producing stage closes that bypass.
                    if !validation_evidence_producing_stage_is_deterministic(
                        program,
                        report.stage_name.as_str(),
                    ) {
                        blocker.get_or_insert("proof_stage_not_deterministic");
                        continue;
                    }
                    // An eligible shell is not authority for another shell's
                    // declared proof. The producing stage is runtime metadata;
                    // the criterion's stage name came from its output JSON.
                    if !validation_criterion_stage_matches_declaration(
                        program,
                        declared.stage.as_deref(),
                        &report.stage_name,
                    ) {
                        continue;
                    }
                    match validation_criterion_policy_state(criterion, expected_candidate) {
                        Ok(()) => {
                            if let Some(expected_tree) = expected_tree {
                                let observed_tree = criterion
                                    .candidate
                                    .as_ref()
                                    .and_then(|candidate| candidate.tree_id.as_deref());
                                if observed_tree != Some(expected_tree) {
                                    blocker.get_or_insert("candidate_tree_mismatch");
                                    continue;
                                }
                            }
                            satisfied = true;
                            break;
                        }
                        Err(label) => {
                            blocker.get_or_insert(label);
                        }
                    }
                }
            }
        }
        if satisfied {
            continue;
        }
        match blocker {
            Some(label) => blockers.push(format!("validation_criterion:{}:{label}", declared.id)),
            // `missing` is the WHOLE truth of this arm, as a consequence of the
            // declaration binding: the stage a criterion DECLARES is the stage
            // that records, so the only way to reach this arm is that the declared
            // proof stage has not produced a report for this criterion, which a
            // rerun CAN fix.
            None => blockers.push(format!("validation_criterion:{}:missing", declared.id)),
        }
    }

    blockers.sort();
    blockers.dedup();
    let active = !declared_required.is_empty();
    let passed = active && blockers.is_empty();
    let reason = if declared_required.is_empty() {
        let optional_note = if declared_optional.is_empty() {
            String::new()
        } else {
            format!(
                "; optional criterion/criteria do not authorize promotion: {}",
                declared_optional
                    .iter()
                    .map(validation_criterion_policy_label)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        Some(format!(
            "promotion requires at least one required validation criterion declared by the checked ExecutionProgram{optional_note}"
        ))
    } else if blockers.is_empty() {
        None
    } else {
        Some(format!(
            "promotion requires declared required validation criteria to pass or be waived against the current candidate; blocker(s): {}",
            blockers.join(", ")
        ))
    };
    ValidationCriteriaGate {
        active,
        passed,
        blockers,
        reason,
    }
}

/// Resolve identity only from passed observations of declared REQUIRED proofs.
/// Optional or undeclared rows, and reports from ineligible producers, cannot
/// rotate the tree a promotion is permitted to land. Waivers keep their existing
/// policy: they may satisfy a required criterion but do not create a passed pin.
pub fn required_proof_candidate_tree_pin(
    program: &ExecutionProgram,
    reports: &[ExecutionValidationEvidence],
) -> CandidateTreePin {
    CandidateTreePin::from_validation_criteria(reports.iter().flat_map(|report| {
        report.criteria.iter().filter(move |criterion| {
            validation_evidence_producing_stage_is_deterministic(program, &report.stage_name)
                && program.validation_criteria.criteria.iter().any(|declared| {
                    declared.required
                        && declared.id.as_str() == criterion.criterion_id
                        && validation_proof_stage_determinism(
                            program,
                            declared.stage.as_ref().map(|stage| stage.0.as_str()),
                        )
                        .is_ok()
                        && validation_criterion_stage_matches_declaration(
                            program,
                            declared.stage.as_ref().map(|stage| stage.0.as_str()),
                            validation_criterion_evidence_stage(report, criterion),
                        )
                        && validation_criterion_stage_matches_declaration(
                            program,
                            declared.stage.as_ref().map(|stage| stage.0.as_str()),
                            &report.stage_name,
                        )
                })
        })
    }))
}

pub fn validation_criterion_policy_state(
    criterion: &ExecutionValidationCriterionEvidence,
    expected_candidate: Option<&ExecutionValidationCandidateEvidence>,
) -> Result<(), &'static str> {
    if !validation_criterion_satisfies_policy(criterion) {
        return Err(validation_criterion_policy_blocker_label(criterion));
    }
    let Some(expected_candidate) = expected_candidate else {
        return Ok(());
    };
    let Some(candidate) = criterion.candidate.as_ref() else {
        return Err("candidate_missing");
    };
    if candidate.execution_id != expected_candidate.execution_id
        || candidate.fingerprint != expected_candidate.fingerprint
    {
        return Err("candidate_mismatch");
    }
    Ok(())
}

pub fn validation_criterion_policy_label(criterion: &DeclaredValidationCriterionPolicy) -> String {
    criterion.stage.as_deref().map_or_else(
        || criterion.id.clone(),
        |stage| format!("{}@{}", criterion.id, stage),
    )
}

pub fn validation_criterion_evidence_stage<'a>(
    report: &'a ExecutionValidationEvidence,
    criterion: &'a ExecutionValidationCriterionEvidence,
) -> &'a str {
    criterion
        .stage_name
        .as_deref()
        .unwrap_or(report.stage_name.as_str())
}

pub fn validation_criterion_stage_matches_declaration(
    program: &ExecutionProgram,
    declared_stage: Option<&str>,
    runtime_stage: &str,
) -> bool {
    let Some(declared_stage) = declared_stage else {
        return true;
    };
    runtime_stage == declared_stage
        || program
            .checked_stage_id_for_runtime_stage(runtime_stage)
            .is_some_and(|stage_id| stage_id.0.as_str() == declared_stage)
}

pub fn validation_criterion_satisfies_policy(
    criterion: &ExecutionValidationCriterionEvidence,
) -> bool {
    match criterion.status {
        ExecutionValidationCriterionStatus::Passed => true,
        ExecutionValidationCriterionStatus::WaivedByPolicy => {
            validation_criterion_has_policy_waiver(criterion)
        }
        ExecutionValidationCriterionStatus::Failed
        | ExecutionValidationCriterionStatus::Unknown
        | ExecutionValidationCriterionStatus::InsufficientEvidence => false,
    }
}

pub fn validation_criterion_has_policy_waiver(
    criterion: &ExecutionValidationCriterionEvidence,
) -> bool {
    matches!(
        validation_criterion_waiver_policy_state(criterion),
        ValidationCriterionWaiverPolicyState::Accepted
    )
}

pub fn validation_criterion_policy_blocker_label(
    criterion: &ExecutionValidationCriterionEvidence,
) -> &'static str {
    if criterion.status == ExecutionValidationCriterionStatus::WaivedByPolicy {
        match validation_criterion_waiver_policy_state(criterion) {
            ValidationCriterionWaiverPolicyState::Accepted => "waived_by_policy",
            ValidationCriterionWaiverPolicyState::Missing => "waiver_missing",
            ValidationCriterionWaiverPolicyState::Unauthorized => "waiver_unauthorized",
        }
    } else {
        validation_criterion_status_label(criterion.status)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationCriterionWaiverPolicyState {
    Accepted,
    Missing,
    Unauthorized,
}

pub fn validation_criterion_waiver_policy_state(
    criterion: &ExecutionValidationCriterionEvidence,
) -> ValidationCriterionWaiverPolicyState {
    let Some(waiver) = criterion.waiver.as_ref() else {
        return ValidationCriterionWaiverPolicyState::Missing;
    };
    if waiver.source.trim().is_empty() || waiver.reason.trim().is_empty() {
        return ValidationCriterionWaiverPolicyState::Missing;
    }
    match waiver.source.as_str() {
        "operator" => {
            if waiver
                .approved_by
                .as_deref()
                .is_some_and(|approved_by| !approved_by.trim().is_empty())
                && waiver.approved_at_ms.is_some()
            {
                ValidationCriterionWaiverPolicyState::Accepted
            } else {
                ValidationCriterionWaiverPolicyState::Unauthorized
            }
        }
        "controller_policy" | "checked_policy" => {
            if waiver
                .authority_id
                .as_deref()
                .is_some_and(|authority_id| !authority_id.trim().is_empty())
            {
                ValidationCriterionWaiverPolicyState::Accepted
            } else {
                ValidationCriterionWaiverPolicyState::Unauthorized
            }
        }
        _ => ValidationCriterionWaiverPolicyState::Unauthorized,
    }
}

pub fn validation_criterion_status_label(
    status: ExecutionValidationCriterionStatus,
) -> &'static str {
    match status {
        ExecutionValidationCriterionStatus::Passed => "passed",
        ExecutionValidationCriterionStatus::Failed => "failed",
        ExecutionValidationCriterionStatus::Unknown => "unknown",
        ExecutionValidationCriterionStatus::InsufficientEvidence => "insufficient_evidence",
        ExecutionValidationCriterionStatus::WaivedByPolicy => "waived_by_policy",
    }
}

// Whether a completed stage's output becomes validation evidence is read from
// the declaration in the frozen IR
// (`ExecutionProgram::stage_records_validation_evidence`), which both crates
// call — never a stage-NAME convention, which would be a proxy that could
// disagree with the declaration it stands for.

/// THE IN-GRAPH PROMOTE'S RUNTIME AUTHORITY, resolved onto a rendered directive.
///
/// Returns `rendered` unchanged for every stage that is not a `workspace_effect`
/// stage, for every effect op other than `promote`, and for a promote directive
/// this cannot parse — the effect backend fails that one with its own clear
/// error, and inventing an authority for a directive we could not read would be
/// worse than passing it through.
///
/// For a promote it does three things, in this order:
///
/// 1. **REFUSES** unless every REQUIRED validation criterion the checked program
///    declares has passed (or carries an authorized waiver) against the SAME tree
///    selected by [`required_proof_candidate_tree_pin`]. The policy checks are
///    shared with [`validation_criteria_gate`]; this route compares tree ids
///    instead of backend-dependent candidate fingerprints.
/// 2. **REFUSES** when those criteria bound NO candidate
///    ([`kata_types::execution::CandidateTreePin::Unpinned`]), because the fence admits `Unpinned` and
///    would then land a tree nothing measured.
/// 3. **STAMPS** the candidate tree pin, overwriting whatever the directive
///    carried, so the effect backend hands the provider a tree the pack could not
///    name and an agent could not forge.
///
/// # Why this is a free function and not a `WorkflowRunner` method
///
/// Because it must be callable by everything that writes a dispatchable prompt,
/// so the funnel's totality is a property of this function's call sites rather
/// than of one type's methods. Today the runner's `render_checked_prompt` is the
/// one production caller; a writer that re-renders a parked assignment's prompt
/// outside the runner must call it too, or a promote parked behind
/// `approval = True` would lose its pin when its prompt is rewritten.
///
/// # Why the VERDICT refuses HERE and is not stamped like the pin
///
/// The pin is a COURIER because its comparison has a far-side operand: the tree
/// of the SETTLED candidate, which exists only after the provider snapshots the
/// working copy. Neither end holds both values, so one has to travel. This
/// verdict has no far-side operand — it is a total function of the frozen IR
/// (the declared criteria) and the durable evidence (the recorded reports), and
/// every caller of this function holds both. Stamping it would add a wire field,
/// a parse, and a second place to get the refusal wrong, purely so the far side
/// could obey an already-decided boolean; it would put a POLICY verdict on the
/// DIRECTIVE, which an operator reads as the stage's authored intent; and it
/// would refuse LATER. Refusing here means no attempt row, no worker
/// involvement and no claim to reconcile — strictly earlier than both the
/// mutation and the teardown, which is what the refusal owes.
///
/// A policy seam injected beside the provider (the third shape considered) was
/// rejected for a sharper reason: the seam would have to be OPTIONAL the way
/// `WorkspaceEffectBackend`'s `forge` is, so a node could be booted with the
/// promotion gate simply absent. A gate that can be unwired is not a gate.
///
/// # The verdict is re-run against the selected tree
///
/// The latest passed REQUIRED proof selects the pin. Every required criterion
/// must then have a satisfying observation on that tree. Partial revalidation
/// on a new tree can therefore revoke an earlier authorization; only revalidating
/// the full required set restores it. Optional and undeclared observations cannot
/// rotate the pin. A failed report still cannot authorize its failed tree.
/// Resolving both halves from one report slice means a directive can never pair
/// a new tree identity with an authorization earned on an old one.
///
/// # What is deliberately NOT asked here
///
/// The candidate FINGERPRINT comparison
/// ([`validation_criterion_policy_state`]'s `candidate_mismatch`, reached by
/// passing `Some(expected_candidate)`) stays on the operator route. It was
/// recipe-DIVERGENT while the `git_worktree` provider existed (its disk reader
/// folded a HEAD commit on git and not on jj), which is why it was never this
/// route's identity question. That question is answered for
/// this route by [`kata_types::execution::CandidateTreePin`], which is compared AFTER the candidate settles (the last instant at which it
/// means anything), and refuses a conflicted tree without comparing.
///
/// Likewise NOT asked: whether the execution's lifecycle is terminal (an in-graph
/// promote dispatches while it is `Running` BY CONSTRUCTION, so
/// `kata_api`'s `require_completed_lifecycle_for_promotion` would refuse every one
/// of them), and whether the execution workspace exists and is registered — which
/// is already answered where the mutation happens, since `promote_workspace` opens
/// with `lookup_workspace` and fails typed when there is nothing to promote.
pub fn authorize_promote_directive(
    program: &ExecutionProgram,
    reports: &[ExecutionValidationEvidence],
    execution_id: ulid::Ulid,
    stage_name: &str,
    checked_stage: &kata_program::execution_program::ExecutionProgramStage,
    rendered: String,
) -> kata_types::KataResult<String> {
    use kata_types::workflow::{WorkspaceEffect, WorkspaceEffectOp};

    if !kata_program::execution_program::stage_routes_to_workspace_effect(checked_stage) {
        return Ok(rendered);
    }
    let Some(mut effect) = WorkspaceEffect::from_directive_prompt(&rendered) else {
        return Ok(rendered);
    };
    if effect.op != WorkspaceEffectOp::Promote {
        return Ok(rendered);
    }
    authorize_promote_effect(program, reports, execution_id, stage_name, &mut effect)?;
    Ok(effect.directive_prompt())
}

/// THE PROMOTE RULE on an already-parsed effect — the same authorization
/// [`authorize_promote_directive`] runs, for a caller that holds the parsed
/// `WorkspaceEffect` rather than the rendered prompt. ONE rule, two doors:
/// the submit funnel's directive round-trip parses, authorizes, and re-emits;
/// the `oci` workspace-effect arm owns its parse (`submit_workspace_effect`)
/// and authorizes it in place so the pin it stamps is the one the claim
/// spec records.
pub fn authorize_promote_effect(
    program: &kata_program::execution_program::ExecutionProgram,
    reports: &[kata_types::execution::ExecutionValidationEvidence],
    execution_id: ulid::Ulid,
    stage_name: &str,
    effect: &mut kata_types::workflow::WorkspaceEffect,
) -> kata_types::KataResult<()> {
    use kata_types::workflow::WorkspaceEffectOp;

    if effect.op != WorkspaceEffectOp::Promote {
        return Ok(());
    }
    let (gate, pin) = candidate_coherent_promotion_gate(program, reports, None);
    if !(gate.active && gate.passed) {
        let reason = gate.reason.unwrap_or_else(|| {
            "promotion requires at least one required validation criterion declared by the \
             checked ExecutionProgram"
                .to_string()
        });
        return Err(kata_types::KataError::Validation(format!(
            "in-graph promote stage \"{stage_name}\" for execution {execution_id} REFUSED \
             before dispatch: {reason}"
        )));
    }
    // CONJUNCT B — the criteria that authorized this promote must have BOUND a
    // candidate. `CandidateTreePin::Unpinned` means no recorded criterion bound
    // one, and the fence admits `Unpinned` because refusing it there would be "a
    // promote requires validation criteria" — which is THIS gate. So the refusal
    // belongs here, not there: a gated promote that reached the provider unpinned
    // would have passed a verdict gate and then landed a tree nothing measured.
    //
    // This is the PRESENCE half of the candidate question only. The COMPARISON
    // half stays at the fence, after the candidate settles, where it is
    // backend-uniform and where refusing is still non-destructive.
    if pin.is_unpinned() {
        return Err(kata_types::KataError::Validation(format!(
            "in-graph promote stage \"{stage_name}\" for execution {execution_id} REFUSED \
             before dispatch: the required validation criteria passed but none of them bound \
             a candidate, so the tree about to land was never measured against the tree that \
             was judged. A promote needs an execution workspace \
             (`workflow(worktree_isolated = True)`) and a proof stage that runs inside it"
        )));
    }
    effect.candidate_tree = pin;
    Ok(())
}
