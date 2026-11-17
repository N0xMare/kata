//! Controller-decision application state machine.
//!
//! Visibility is `pub(super)` only where a caller in `mod.rs` crosses the
//! module boundary.
//!
//! ## Claim-before-effect / observe-first
//!
//! This module is the CONTROLLER half of kata's unified claim-before-effect
//! discipline: `claim_controller_application` persists an `applied == false`
//! claim BEFORE the workspace side effect (park / promote), the effect flips it
//! `applied == true`, and `reconcile_claimed_controller_application` (plus the
//! boot sweep) OBSERVE-FIRST on resume — re-checking already-visible durable
//! evidence rather than blindly re-applying. The WORKER half of the same
//! discipline is the idempotency membrane the capsule execution path consults:
//! it latches a durable claim
//! before every model / effect call and, on an orphaned claim, either replays a
//! recorded outcome, re-executes a deterministic effect (observe-first), or
//! surfaces a non-deterministic call as issued-but-unconfirmed. Keep the two
//! halves in lockstep — a change to one membrane's orphan policy should be
//! mirrored in the other.

#[allow(clippy::wildcard_imports)]
use super::*;

impl WorkflowExecutor {
    /// Apply one recorded controller decision exactly once on this main.
    ///
    /// This is the server-owned primitive behind `kata factory apply`.
    /// Existing durable `controller_applications` evidence wins over retries,
    /// so a client can repeat the request after interruption without re-running
    /// workspace side effects.
    pub fn apply_controller_decision_once(
        &self,
        execution_id: Ulid,
        request: ExecutionControllerApplyRequest,
    ) -> Result<ExecutionControllerApplyResponse, ExecutorError> {
        let _admission = self.enter_admission()?;
        if request.decision_id.trim().is_empty() {
            return Err(ExecutorError::InvalidDefinition(
                "controller apply requires a non-empty decision_id".to_string(),
            ));
        }
        let decision_id = request.decision_id.trim().to_string();
        let lock = self.controller_application_lock(execution_id, &decision_id);
        let _guard = lock.lock().map_err(|_| {
            ExecutorError::RunnerBuildFailed(format!(
                "controller application lock poisoned for decision `{decision_id}`"
            ))
        })?;
        let decision = self.recorded_controller_decision(execution_id, &decision_id)?;
        let action = match request.action.as_deref().map(str::trim) {
            Some("") => {
                return Err(ExecutorError::InvalidDefinition(
                    "controller apply action cannot be empty".to_string(),
                ));
            }
            Some(action) => action.to_string(),
            None => controller_application_action_for_decision(&decision.decision)?,
        };
        if !controller_application_action_matches_decision(&action, &decision.decision) {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller decision `{decision_id}` requested `{}`, not application action `{action}`",
                decision.decision
            )));
        }
        let application_id = default_controller_application_id(&action, &decision_id);
        if let Some(requested_application_id) = request
            .application_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            && requested_application_id != application_id
        {
            return Err(ExecutorError::InvalidDefinition(format!(
                "controller apply application_id is server-derived as `{application_id}`"
            )));
        }
        if let Some(existing) =
            self.applied_controller_application_for_decision(execution_id, &decision_id)?
        {
            if existing.action != action {
                return Err(ExecutorError::PolicyDenied(format!(
                    "controller decision `{decision_id}` was already applied by `{}`, not `{action}`",
                    existing.action
                )));
            }
            return Ok(controller_apply_response_from_application(
                execution_id,
                "already_applied",
                false,
                existing,
                request.workflow_ref.clone(),
                request.external_input_channel.clone(),
                request.external_input_id.clone(),
                Vec::new(),
            ));
        }
        if request.resume_claimed_side_effect
            && self
                .controller_application_for_application_id(execution_id, &application_id)?
                .is_none()
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "resume_claimed_side_effect requires existing durable claim `{application_id}`"
            )));
        }

        let context = ExecutionControllerApplicationContext {
            decision_id: decision_id.clone(),
            decision: decision.decision.clone(),
            application_id: Some(application_id.clone()),
            source: request.source.clone(),
            reason: request.reason.clone(),
        };
        self.validate_controller_application_context(execution_id, &context, &action)?;
        validate_no_factory_advance_source_for_action(&request, &action)?;

        match ControllerApplicationAction::try_from(action.as_str()) {
            Ok(ControllerApplicationAction::Park) => self.apply_park_controller_decision(
                execution_id,
                context,
                action,
                decision_id,
                application_id,
                &request,
            ),
            Ok(ControllerApplicationAction::Promote) => self.apply_promote_controller_decision(
                execution_id,
                context,
                action,
                decision_id,
                application_id,
                &request,
            ),
            Ok(
                ControllerApplicationAction::Advance
                | ControllerApplicationAction::PromoteThenAdvance,
            )
            | Err(_) => Err(ExecutorError::InvalidDefinition(format!(
                "unsupported controller application action `{action}`"
            ))),
        }
    }

    fn apply_park_controller_decision(
        &self,
        execution_id: Ulid,
        context: ExecutionControllerApplicationContext,
        action: String,
        decision_id: String,
        application_id: String,
        request: &ExecutionControllerApplyRequest,
    ) -> Result<ExecutionControllerApplyResponse, ExecutorError> {
        self.require_terminal_lifecycle_for_parking(execution_id)?;
        let label = request
            .park_ref_name
            .as_deref()
            .filter(|value| !value.trim().is_empty());
        if self
            .controller_application_for_application_id(execution_id, &application_id)?
            .is_some()
        {
            if let Some(application) = self.reconcile_claimed_controller_application(
                execution_id,
                &context,
                &action,
                &application_id,
            )? {
                return Ok(controller_apply_response_from_application(
                    execution_id,
                    "already_applied",
                    false,
                    application,
                    None,
                    None,
                    None,
                    Vec::new(),
                ));
            }
            if request.resume_claimed_side_effect {
                return self.resume_claimed_park_controller_application(
                    execution_id,
                    context,
                    &application_id,
                    label,
                );
            }
            return self.claimed_controller_application_response(
                execution_id,
                &default_controller_application_id("park", &decision_id),
                None,
                None,
                None,
                Vec::new(),
            );
        }
        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            ExecutorError::worktree(
                WorktreeFailure::Unavailable,
                "no workspace provider attached to this executor; \
                         candidate parking is unavailable on stateless nodes"
                    .to_string(),
            )
        })?;
        let claim = self.controller_application_claim_evidence(
            execution_id,
            context.clone(),
            "park",
            None,
            None,
            None,
            None,
            Some(park_controller_application_side_effect(execution_id, label)),
        )?;
        if !self.claim_controller_application(execution_id, claim)? {
            if let Some(application) = self.reconcile_claimed_controller_application(
                execution_id,
                &context,
                &action,
                &application_id,
            )? {
                return Ok(controller_apply_response_from_application(
                    execution_id,
                    "already_applied",
                    false,
                    application,
                    None,
                    None,
                    None,
                    Vec::new(),
                ));
            }
            if request.resume_claimed_side_effect {
                return self.resume_claimed_park_controller_application(
                    execution_id,
                    context,
                    &application_id,
                    label,
                );
            }
            return self.claimed_controller_application_response(
                execution_id,
                &default_controller_application_id("park", &decision_id),
                None,
                None,
                None,
                Vec::new(),
            );
        }
        require_standing_workspace(provider.as_ref(), execution_id)?;
        let candidate = provider
            .park_workspace(&ExecutionWorkspaceKey::execution(execution_id), label)
            .map_err(|e| ExecutorError::worktree(WorktreeFailure::Internal, e.to_string()))?;
        persist_parked_candidate_evidence(
            self.dispatcher.ledger(),
            execution_id,
            &candidate,
            false,
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        let parked = parked_execution_from_workspace(&candidate);
        let application = self.controller_application_evidence(
            execution_id,
            context,
            "park",
            None,
            Some(parked.clone()),
            None,
            None,
            None,
        )?;
        persist_controller_application_evidence(
            self.dispatcher.ledger(),
            execution_id,
            application.clone(),
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        Ok(controller_apply_response_from_application(
            execution_id,
            "applied",
            true,
            application,
            None,
            None,
            None,
            Vec::new(),
        ))
    }

    fn apply_promote_controller_decision(
        &self,
        execution_id: Ulid,
        context: ExecutionControllerApplicationContext,
        action: String,
        decision_id: String,
        application_id: String,
        request: &ExecutionControllerApplyRequest,
    ) -> Result<ExecutionControllerApplyResponse, ExecutorError> {
        self.require_completed_lifecycle_for_promotion(execution_id)?;
        // When a durable promote claim already exists
        // (crash after `claim_controller_application` but before
        // `promote_workspace` flipped it applied, or a concurrent
        // claimant), recover IN-BAND rather than dead-ending. Mirror the
        // `park` branch: first reconcile OBSERVE-ONLY (no side effect); if
        // still unreconciled and the operator asked to resume, re-drive
        // the promote idempotently (observe-first).
        if self
            .controller_application_for_application_id(execution_id, &application_id)?
            .is_some()
        {
            if let Some(application) = self.reconcile_claimed_controller_application(
                execution_id,
                &context,
                &action,
                &application_id,
            )? {
                return Ok(controller_apply_response_from_application(
                    execution_id,
                    "already_applied",
                    false,
                    application,
                    None,
                    None,
                    None,
                    Vec::new(),
                ));
            }
            if request.resume_claimed_side_effect {
                return self.resume_claimed_promote_controller_application(
                    execution_id,
                    context,
                    &application_id,
                );
            }
            return self.claimed_controller_application_response(
                execution_id,
                &default_controller_application_id("promote", &decision_id),
                None,
                None,
                None,
                Vec::new(),
            );
        }
        self.require_validation_criteria_for_promotion(execution_id)?;
        let promotion = Some(self.execution_workspace_snapshot(execution_id)?.promotion);
        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            ExecutorError::worktree(
                WorktreeFailure::Unavailable,
                "no workspace provider attached to this executor; \
                         promotion is unavailable on stateless nodes"
                    .to_string(),
            )
        })?;
        let candidate_tree =
            self.require_promotable_workspace_for_promotion(execution_id, provider.as_ref())?;
        // Refused BEFORE the durable claim: a target with no landable branch, or
        // an unreadable invocation, claims no side effect it cannot perform.
        let landing_branch = self.frozen_landing_branch(execution_id)?;
        let claim = self.controller_application_claim_evidence(
            execution_id,
            context.clone(),
            "promote",
            None,
            None,
            promotion.clone(),
            None,
            None,
        )?;
        if !self.claim_controller_application(execution_id, claim)? {
            if let Some(application) = self.reconcile_claimed_controller_application(
                execution_id,
                &context,
                &action,
                &application_id,
            )? {
                return Ok(controller_apply_response_from_application(
                    execution_id,
                    "already_applied",
                    false,
                    application,
                    None,
                    None,
                    None,
                    Vec::new(),
                ));
            }
            if request.resume_claimed_side_effect {
                return self.resume_claimed_promote_controller_application(
                    execution_id,
                    context,
                    &application_id,
                );
            }
            return self.claimed_controller_application_response(
                execution_id,
                &default_controller_application_id("promote", &decision_id),
                None,
                None,
                None,
                Vec::new(),
            );
        }
        let promoted = provider
            .promote_workspace(
                &ExecutionWorkspaceKey::execution(execution_id),
                &candidate_tree,
                landing_branch.as_deref(),
            )
            .map_err(Self::operator_promote_error)?;
        let promotion =
            promotion.map(|promotion| promotion_with_promoted_workspace(promotion, &promoted));
        let application = self.controller_application_evidence(
            execution_id,
            context,
            "promote",
            None,
            None,
            promotion.clone(),
            None,
            None,
        )?;
        persist_controller_application_evidence(
            self.dispatcher.ledger(),
            execution_id,
            application.clone(),
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        Ok(controller_apply_response_from_application(
            execution_id,
            "applied",
            true,
            application,
            None,
            None,
            None,
            Vec::new(),
        ))
    }

    /// Finalize a previously claimed controller application after an operator
    /// has independently verified the side effect. This never retries the
    /// side effect; it only turns a durable non-applied claim into final applied
    /// evidence.
    pub fn finalize_controller_application_claim(
        &self,
        execution_id: Ulid,
        request: ExecutionControllerApplyFinalizeRequest,
    ) -> Result<ExecutionControllerApplyResponse, ExecutorError> {
        let _admission = self.enter_admission()?;
        if request.decision_id.trim().is_empty() {
            return Err(ExecutorError::InvalidDefinition(
                "controller claim finalization requires a non-empty decision_id".to_string(),
            ));
        }
        if !request.confirm_side_effect {
            return Err(ExecutorError::InvalidDefinition(
                "controller claim finalization requires confirm_side_effect=true".to_string(),
            ));
        }
        let (reason, recovery_evidence) = Self::validate_finalize_reason_and_evidence(&request)?;
        let decision_id = request.decision_id.trim().to_string();
        let lock = self.controller_application_lock(execution_id, &decision_id);
        let _guard = lock.lock().map_err(|_| {
            ExecutorError::RunnerBuildFailed(format!(
                "controller application lock poisoned for decision `{decision_id}`"
            ))
        })?;
        let decision = self.recorded_controller_decision(execution_id, &decision_id)?;
        let action = match request.action.as_deref().map(str::trim) {
            Some("") => {
                return Err(ExecutorError::InvalidDefinition(
                    "controller claim finalization action cannot be empty".to_string(),
                ));
            }
            Some(action) => action.to_string(),
            None => controller_application_action_for_decision(&decision.decision)?,
        };
        if !controller_application_action_matches_decision(&action, &decision.decision) {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller decision `{decision_id}` requested `{}`, not application action `{action}`",
                decision.decision
            )));
        }
        let application_id = default_controller_application_id(&action, &decision_id);
        if let Some(requested_application_id) = request
            .application_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            && requested_application_id != application_id
        {
            return Err(ExecutorError::InvalidDefinition(format!(
                "controller claim finalization application_id is server-derived as `{application_id}`"
            )));
        }
        if let Some(existing) =
            self.applied_controller_application_for_decision(execution_id, &decision_id)?
        {
            if existing.action != action {
                return Err(ExecutorError::PolicyDenied(format!(
                    "controller decision `{decision_id}` was already applied by `{}`, not `{action}`",
                    existing.action
                )));
            }
            return Ok(controller_apply_response_from_application(
                execution_id,
                "already_applied",
                false,
                existing,
                None,
                None,
                None,
                Vec::new(),
            ));
        }
        let Some(claim) =
            self.controller_application_for_application_id(execution_id, &application_id)?
        else {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller application `{application_id}` has no durable claim to finalize"
            )));
        };
        if claim.applied {
            return Ok(controller_apply_response_from_application(
                execution_id,
                "already_applied",
                false,
                claim,
                None,
                None,
                None,
                Vec::new(),
            ));
        }
        if claim.decision_id != decision_id
            || claim.action != action
            || claim.decision != decision.decision
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller application `{application_id}` claim does not match decision `{decision_id}`"
            )));
        }
        if let (Some(requested), Some(claimed)) = (
            request.next_execution_id.as_deref(),
            claim.next_execution_id.as_deref(),
        ) && requested.trim() != claimed
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "advance claim recorded next_execution_id `{claimed}`, not `{}`",
                requested.trim()
            )));
        }

        let next_execution_id = request
            .next_execution_id
            .clone()
            .or_else(|| claim.next_execution_id.clone());
        let parked_candidate = request
            .parked_candidate
            .clone()
            .or_else(|| claim.parked_candidate.clone());
        let promotion = request
            .promotion
            .clone()
            .or_else(|| claim.promotion.clone());
        Self::validate_finalize_claim_action_requirements(
            &action,
            parked_candidate.as_ref(),
            promotion.as_ref(),
        )?;
        validate_finalized_controller_claim_matches_side_effect(
            execution_id,
            &application_id,
            &action,
            &claim,
            parked_candidate.as_ref(),
            promotion.as_ref(),
        )?;

        let context = ExecutionControllerApplicationContext {
            decision_id,
            decision: decision.decision,
            application_id: Some(application_id),
            source: request.source.or_else(|| claim.source.clone()),
            reason: Some(reason.clone()),
        };
        self.finalize_controller_application_evidence(
            execution_id,
            context,
            &action,
            next_execution_id,
            parked_candidate,
            promotion,
            claim.memory_policy.clone(),
            claim.side_effect.clone(),
            reason,
            recovery_evidence,
        )
    }

    fn validate_finalize_reason_and_evidence(
        request: &ExecutionControllerApplyFinalizeRequest,
    ) -> Result<(String, Vec<String>), ExecutorError> {
        let reason = request
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ExecutorError::InvalidDefinition(
                    "controller claim finalization requires a non-empty reason".to_string(),
                )
            })?
            .to_string();
        let recovery_evidence = request
            .evidence
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if recovery_evidence.is_empty() {
            return Err(ExecutorError::InvalidDefinition(
                "controller claim finalization requires at least one evidence string".to_string(),
            ));
        }
        Ok((reason, recovery_evidence))
    }

    fn validate_finalize_claim_action_requirements(
        action: &str,
        parked_candidate: Option<&kata_types::execution::ParkedExecution>,
        promotion: Option<&ExecutionWorkspacePromotion>,
    ) -> Result<(), ExecutorError> {
        match ControllerApplicationAction::try_from(action) {
            Ok(ControllerApplicationAction::Park) => {
                let parked = parked_candidate.ok_or_else(|| {
                    ExecutorError::InvalidDefinition(
                        "park claim finalization requires parked_candidate".to_string(),
                    )
                })?;
                if parked.parked_ref.trim().is_empty() || parked.commit_sha.trim().is_empty() {
                    return Err(ExecutorError::InvalidDefinition(
                        "parked_candidate requires non-empty parked_ref and commit_sha".to_string(),
                    ));
                }
            }
            Ok(ControllerApplicationAction::Promote) => {
                if promotion.is_none() {
                    return Err(ExecutorError::InvalidDefinition(
                        "promote claim finalization requires promotion".to_string(),
                    ));
                }
            }
            Ok(
                ControllerApplicationAction::Advance
                | ControllerApplicationAction::PromoteThenAdvance,
            )
            | Err(_) => {
                return Err(ExecutorError::InvalidDefinition(format!(
                    "unsupported controller application action `{action}`"
                )));
            }
        }
        Ok(())
    }

    fn finalize_controller_application_evidence(
        &self,
        execution_id: Ulid,
        context: ExecutionControllerApplicationContext,
        action: &str,
        next_execution_id: Option<String>,
        parked_candidate: Option<kata_types::execution::ParkedExecution>,
        promotion: Option<ExecutionWorkspacePromotion>,
        memory_policy: Option<ExecutionControllerMemoryPolicyApplicationEvidence>,
        side_effect: Option<ExecutionControllerApplicationSideEffectEvidence>,
        reason: String,
        recovery_evidence: Vec<String>,
    ) -> Result<ExecutionControllerApplyResponse, ExecutorError> {
        let mut application = self.controller_application_evidence(
            execution_id,
            context,
            action,
            next_execution_id,
            parked_candidate,
            promotion,
            memory_policy,
            side_effect,
        )?;
        application.recovery = Some(ExecutionControllerApplicationRecoveryEvidence {
            mode: "finalize_observed".to_string(),
            source: application.source.clone(),
            reason,
            evidence: recovery_evidence,
        });
        persist_controller_application_evidence(
            self.dispatcher.ledger(),
            execution_id,
            application.clone(),
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        Ok(controller_apply_response_from_application(
            execution_id,
            "finalized",
            true,
            application,
            None,
            None,
            None,
            Vec::new(),
        ))
    }

    pub(super) fn require_validation_criteria_for_promotion(
        &self,
        execution_id: Ulid,
    ) -> Result<(), ExecutorError> {
        let record = self
            .try_get_execution_by_ulid(execution_id)?
            .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
        let (gate, _) = self.checked_promotion_evidence_for_record(execution_id, &record, None)?;
        if gate.active && gate.passed {
            return Ok(());
        }
        Err(ExecutorError::PolicyDenied(gate.reason.unwrap_or_else(
            || {
                "promotion requires at least one required validation criterion declared by the checked ExecutionProgram"
                    .to_string()
            },
        )))
    }

    /// Authorize the current candidate and return its identity fence from the
    /// same checked program and evidence. A failed authority read cannot become
    /// an `Unpinned` mutation, and callers need no separate permissive reread.
    pub(super) fn require_promotable_workspace_for_promotion(
        &self,
        execution_id: Ulid,
        provider: &dyn ExecutionWorkspaceProvider,
    ) -> Result<CandidateTreePin, ExecutorError> {
        let key = ExecutionWorkspaceKey::execution(execution_id);
        let status = require_standing_workspace(provider, execution_id)?;
        // The reports bind the RECORDED candidate — mint the expected side from
        // the same producer (see executor/mod.rs's snapshot site: a live-read
        // expected candidate reports `candidate_mismatch` on a promote the gate
        // would authorize).
        let recorded = provider
            .recorded_workspace_status(&key)
            .map_err(|e| ExecutorError::worktree(WorktreeFailure::Internal, e.to_string()))?
            .ok_or_else(|| {
                ExecutorError::worktree(
                    WorktreeFailure::Internal,
                    format!(
                        "execution workspace {execution_id} carries no recorded candidate status"
                    ),
                )
            })?;
        let expected_candidate =
            kata_workflow::worktree_isolation::validation_candidate_binding_for_recorded(
                execution_id,
                Some(provider.backend().as_str()),
                &recorded,
            )
            .map_err(|e| ExecutorError::worktree(WorktreeFailure::Internal, e.to_string()))?;
        let record = self
            .try_get_execution_by_ulid(execution_id)?
            .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
        let (gate, candidate_tree) = self.checked_promotion_evidence_for_record(
            execution_id,
            &record,
            Some(&expected_candidate),
        )?;
        if !(gate.active && gate.passed) {
            return Err(ExecutorError::PolicyDenied(gate.reason.unwrap_or_else(
                || {
                    "promotion requires validation evidence bound to the current execution workspace candidate"
                        .to_string()
                },
            )));
        }
        match status.dirty {
            Some(false) => Ok(candidate_tree),
            Some(true) if provider.promotion_snapshots_dirty() => Ok(candidate_tree),
            Some(true) => {
                let changed_paths = status
                    .changed_paths
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                let changed = if changed_paths.is_empty() {
                    "unknown changed paths".to_string()
                } else {
                    changed_paths.join(", ")
                };
                Err(ExecutorError::PolicyDenied(format!(
                    "promotion requires a clean execution workspace for provider {}; changed path(s): {changed}",
                    provider.backend().as_str()
                )))
            }
            None => Err(ExecutorError::PolicyDenied(
                "promotion requires readable execution workspace status".to_string(),
            )),
        }
    }

    pub(super) fn validation_criteria_gate_for_record_with_candidate(
        &self,
        execution_id: Ulid,
        record: &ExecutionRecord,
        expected_candidate: Option<&ExecutionValidationCandidateEvidence>,
    ) -> ValidationCriteriaGate {
        let program = match self.execution_program_for_execution(execution_id) {
            Ok(program) => Some(program),
            Err(error) => {
                warn!(
                    %execution_id,
                    error = %error,
                    "validation_criteria: checked execution program unavailable for read-only projection; mutation gates still require durable checked program authority"
                );
                None
            }
        };
        validation_criteria_gate(record, program.as_ref(), expected_candidate)
    }

    fn checked_promotion_evidence_for_record(
        &self,
        execution_id: Ulid,
        record: &ExecutionRecord,
        expected_candidate: Option<&ExecutionValidationCandidateEvidence>,
    ) -> Result<(ValidationCriteriaGate, CandidateTreePin), ExecutorError> {
        let program = self.execution_program_for_execution(execution_id).map_err(|err| {
            ExecutorError::PolicyDenied(format!(
                "promotion requires durable checked execution-program authority for execution {execution_id}; {err}"
            ))
        })?;
        Ok(
            kata_workflow::promotion_gate::candidate_coherent_promotion_gate(
                &program,
                &record.evidence.validation_reports,
                expected_candidate,
            ),
        )
    }

    fn controller_application_claim_evidence(
        &self,
        execution_id: Ulid,
        context: ExecutionControllerApplicationContext,
        action: &str,
        next_execution_id: Option<String>,
        parked_candidate: Option<kata_types::execution::ParkedExecution>,
        promotion: Option<ExecutionWorkspacePromotion>,
        memory_policy: Option<ExecutionControllerMemoryPolicyApplicationEvidence>,
        side_effect: Option<ExecutionControllerApplicationSideEffectEvidence>,
    ) -> Result<ExecutionControllerApplicationEvidence, ExecutorError> {
        let decision =
            self.validate_controller_application_context(execution_id, &context, action)?;
        let application_id = context
            .application_id
            .unwrap_or_else(|| default_controller_application_id(action, &context.decision_id));
        Ok(ExecutionControllerApplicationEvidence {
            schema_version: CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION,
            application_id,
            decision_id: context.decision_id,
            decision: context.decision,
            action: action.to_string(),
            applied: false,
            applied_at_ms: now_ms(),
            source: context
                .source
                .or_else(|| Some("factory_controller".to_string())),
            reason: context.reason.or(decision.reason),
            error: None,
            next_execution_id,
            parked_candidate,
            promotion,
            memory_policy,
            side_effect,
            recovery: None,
        })
    }

    fn claim_controller_application(
        &self,
        execution_id: Ulid,
        application: ExecutionControllerApplicationEvidence,
    ) -> Result<bool, ExecutorError> {
        let claim_key = controller_application_claim_key(&application.application_id);
        let evidence = ExecutionEvidence {
            controller_applications: vec![application],
            ..ExecutionEvidence::default()
        };
        self.dispatcher
            .ledger()
            .append_execution_evidence_claimed(execution_id, &claim_key, evidence)
            .map(|record| record.is_some())
            .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))
    }

    fn controller_application_for_application_id(
        &self,
        execution_id: Ulid,
        application_id: &str,
    ) -> Result<Option<ExecutionControllerApplicationEvidence>, ExecutorError> {
        let record = self
            .try_get_execution_by_ulid(execution_id)?
            .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
        Ok(record
            .evidence
            .controller_applications
            .into_iter()
            .find(|application| application.application_id == application_id))
    }

    fn claimed_controller_application_response(
        &self,
        execution_id: Ulid,
        application_id: &str,
        workflow_ref: Option<String>,
        initial_external_input_channel: Option<String>,
        initial_external_input_id: Option<String>,
        validation_blockers: Vec<String>,
    ) -> Result<ExecutionControllerApplyResponse, ExecutorError> {
        if let Some(existing) =
            self.controller_application_for_application_id(execution_id, application_id)?
        {
            let status = if existing.applied {
                "already_applied"
            } else {
                "apply_claimed"
            };
            return Ok(controller_apply_response_from_application(
                execution_id,
                status,
                false,
                existing,
                workflow_ref,
                initial_external_input_channel,
                initial_external_input_id,
                validation_blockers,
            ));
        }
        Err(ExecutorError::PolicyDenied(format!(
            "controller application `{application_id}` is already claimed but no evidence row is visible"
        )))
    }

    fn resume_claimed_park_controller_application(
        &self,
        execution_id: Ulid,
        context: ExecutionControllerApplicationContext,
        application_id: &str,
        label: Option<&str>,
    ) -> Result<ExecutionControllerApplyResponse, ExecutorError> {
        let Some(claim) =
            self.controller_application_for_application_id(execution_id, application_id)?
        else {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller application `{application_id}` has no durable claim to resume"
            )));
        };
        if claim.applied {
            return Ok(controller_apply_response_from_application(
                execution_id,
                "already_applied",
                false,
                claim,
                None,
                None,
                None,
                Vec::new(),
            ));
        }
        if claim.decision_id != context.decision_id
            || claim.decision != context.decision
            || claim.action != "park"
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller application `{application_id}` claim does not match decision `{}`",
                context.decision_id
            )));
        }
        let Some(side_effect) = claim.side_effect.as_ref() else {
            return Err(ExecutorError::PolicyDenied(
                "resume_claimed_side_effect for `park` requires side-effect claim metadata; use factory finalize for older claims".to_string(),
            ));
        };
        if side_effect.kind != "park" {
            return Err(ExecutorError::PolicyDenied(
                "resume_claimed_side_effect for `park` requires a park side-effect claim"
                    .to_string(),
            ));
        }
        let Some(claimed_parked_ref) = side_effect
            .parked_ref
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        else {
            return Err(ExecutorError::PolicyDenied(
                "resume_claimed_side_effect for `park` requires side-effect parked_ref metadata; use factory finalize for older claims".to_string(),
            ));
        };
        if let Some(value) = label.filter(|value| !value.trim().is_empty()) {
            let requested_ref = parked_ref_name_for_label(execution_id, Some(value));
            if requested_ref != claimed_parked_ref {
                return Err(ExecutorError::PolicyDenied(format!(
                    "resume_claimed_side_effect for `park` must use claimed parked ref `{claimed_parked_ref}`, not `{requested_ref}`"
                )));
            }
        }

        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            ExecutorError::worktree(
                WorktreeFailure::Unavailable,
                "no workspace provider attached to this executor; \
                 claimed candidate parking cannot be resumed on stateless nodes"
                    .to_string(),
            )
        })?;
        let claimed_label = claimed_parked_ref.strip_prefix("parked/");
        let candidate = if let Some(parked) =
            self.observed_parked_workspace_for_claim(execution_id, &claim)?
        {
            ParkedWorkspace {
                ref_name: parked.parked_ref,
                commit_sha: parked.commit_sha,
                identity: parked.identity,
            }
        } else {
            require_standing_workspace(provider.as_ref(), execution_id)?;
            provider
                .park_workspace(
                    &ExecutionWorkspaceKey::execution(execution_id),
                    claimed_label,
                )
                .map_err(|e| ExecutorError::worktree(WorktreeFailure::Internal, e.to_string()))?
        };
        persist_parked_candidate_evidence(
            self.dispatcher.ledger(),
            execution_id,
            &candidate,
            false,
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        let parked = parked_execution_from_workspace(&candidate);
        let resumed_context = ExecutionControllerApplicationContext {
            decision_id: context.decision_id,
            decision: context.decision,
            application_id: Some(claim.application_id.clone()),
            source: context
                .source
                .or_else(|| claim.source.clone())
                .or_else(|| Some("factory_controller_resume".to_string())),
            reason: context.reason.or_else(|| claim.reason.clone()).or_else(|| {
                Some(
                    "operator requested retry of claimed park side effect after no durable parked-candidate evidence was visible"
                        .to_string(),
                )
            }),
        };
        let mut application = self.controller_application_evidence(
            execution_id,
            resumed_context,
            "park",
            None,
            Some(parked.clone()),
            None,
            claim.memory_policy.clone(),
            claim.side_effect.clone(),
        )?;
        application.recovery = Some(ExecutionControllerApplicationRecoveryEvidence {
            mode: "resume_claimed_side_effect".to_string(),
            source: application.source.clone(),
            reason: "operator requested retry of claimed park side effect".to_string(),
            evidence: vec![
                format!("application_id={application_id}"),
                "action=park".to_string(),
                format!("parked_ref={}", parked.parked_ref),
                format!("commit_sha={}", parked.commit_sha),
            ],
        });
        persist_controller_application_evidence(
            self.dispatcher.ledger(),
            execution_id,
            application.clone(),
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        Ok(controller_apply_response_from_application(
            execution_id,
            "resumed",
            true,
            application,
            None,
            None,
            None,
            Vec::new(),
        ))
    }

    fn observed_parked_workspace_for_claim(
        &self,
        execution_id: Ulid,
        claim: &ExecutionControllerApplicationEvidence,
    ) -> Result<Option<kata_types::execution::ParkedExecution>, ExecutorError> {
        if let Some(parked) = claim.parked_candidate.as_ref()
            && !parked.parked_ref.trim().is_empty()
            && !parked.commit_sha.trim().is_empty()
        {
            return Ok(Some(parked.clone()));
        }
        let Some(ref_name) = claim
            .side_effect
            .as_ref()
            .filter(|side_effect| side_effect.kind == "park")
            .and_then(|side_effect| side_effect.parked_ref.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let Some(provider) = self.workspace_provider.as_ref() else {
            return Ok(None);
        };
        let Some(candidate) = provider
            .lookup_parked_workspace(&ExecutionWorkspaceKey::execution(execution_id), ref_name)
            .map_err(|e| ExecutorError::worktree(WorktreeFailure::Internal, e.to_string()))?
        else {
            return Ok(None);
        };
        if candidate.ref_name != ref_name {
            return Err(ExecutorError::worktree(
                WorktreeFailure::Internal,
                format!(
                    "workspace provider returned parked ref `{}`, expected `{ref_name}`",
                    candidate.ref_name
                ),
            ));
        }
        if candidate.commit_sha.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(parked_execution_from_workspace(&candidate)))
    }

    /// OBSERVE-ONLY: has this promote claim's side effect DURABLY LANDED?
    /// Mirrors [`Self::observed_parked_workspace_for_claim`] for promote. Two
    /// observation sources, in order:
    ///
    /// 1. Durable promotion evidence already on the claim — `promoted_ref` +
    ///    `promoted_commit_sha` populated means the promotion completed (only
    ///    [`promotion_with_promoted_workspace`] sets them). Surfaced directly,
    ///    no provider probe needed.
    /// 2. Otherwise probe the provider: has the trusted base ref (from the
    ///    claim's promotion identity) advanced to the candidate workspace
    ///    commit? This is the durable, provider-observable landed signal.
    ///
    /// Returns `None` when the promotion is not yet observable — the caller then
    /// leaves the claim `apply_claimed` (reconcile) or re-drives it (resume).
    /// NEVER runs a side effect.
    fn observed_promoted_workspace_for_claim(
        &self,
        execution_id: Ulid,
        claim: &ExecutionControllerApplicationEvidence,
    ) -> Result<Option<PromotedWorkspace>, ExecutorError> {
        let Some(promotion) = claim.promotion.as_ref() else {
            return Ok(None);
        };
        // (1) Durable promotion evidence already recorded on the claim.
        if let (Some(ref_name), Some(commit_sha)) = (
            promotion
                .promoted_ref
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
            promotion
                .promoted_commit_sha
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        ) {
            return Ok(Some(PromotedWorkspace {
                ref_name: ref_name.to_string(),
                commit_sha: commit_sha.to_string(),
                identity: promotion.identity.clone(),
            }));
        }
        // (2) Provider-observable base-ref advancement to the candidate commit.
        let Some(identity) = promotion.identity.as_ref() else {
            return Ok(None);
        };
        let base_ref = identity
            .base_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        // The candidate the promote fast-forwards the base onto: prefer an
        // explicit target commit, else the workspace HEAD recorded at claim time.
        let candidate = identity
            .target_commit_sha
            .as_deref()
            .or(identity.workspace_commit_sha.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let (Some(base_ref), Some(candidate)) = (base_ref, candidate) else {
            return Ok(None);
        };
        let Some(provider) = self.workspace_provider.as_ref() else {
            return Ok(None);
        };
        provider
            .lookup_promoted_workspace(
                &ExecutionWorkspaceKey::execution(execution_id),
                base_ref,
                candidate,
            )
            .map_err(|e| ExecutorError::worktree(WorktreeFailure::Internal, e.to_string()))
    }

    /// Operator/factory-gated in-band retry of a claimed-but-unapplied PROMOTE
    /// side effect. The counterpart to
    /// [`Self::resume_claimed_park_controller_application`]. OBSERVE-FIRST for
    /// idempotency: [`ExecutionWorkspaceProvider::promote_workspace`] is NOT
    /// idempotent (it ff-merges the base then removes the workspace, so a
    /// re-drive after removal fails), so this only re-drives when the promotion
    /// demonstrably did NOT land; if it already landed it reconciles from the
    /// observed evidence WITHOUT re-driving.
    ///
    /// This re-drive belongs ONLY to this operator-gated resume path — the boot
    /// sweep and the shared reconcile arm stay observe-only.
    fn resume_claimed_promote_controller_application(
        &self,
        execution_id: Ulid,
        context: ExecutionControllerApplicationContext,
        application_id: &str,
    ) -> Result<ExecutionControllerApplyResponse, ExecutorError> {
        let Some(claim) =
            self.controller_application_for_application_id(execution_id, application_id)?
        else {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller application `{application_id}` has no durable claim to resume"
            )));
        };
        if claim.applied {
            return Ok(controller_apply_response_from_application(
                execution_id,
                "already_applied",
                false,
                claim,
                None,
                None,
                None,
                Vec::new(),
            ));
        }
        if claim.decision_id != context.decision_id
            || claim.decision != context.decision
            || claim.action != "promote"
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller application `{application_id}` claim does not match decision `{}`",
                context.decision_id
            )));
        }
        let Some(base_promotion) = claim.promotion.clone() else {
            return Err(ExecutorError::PolicyDenied(
                "resume_claimed_side_effect for `promote` requires promotion claim metadata; use factory finalize for older claims".to_string(),
            ));
        };
        let provider = self.workspace_provider.as_ref().ok_or_else(|| {
            ExecutorError::worktree(
                WorktreeFailure::Unavailable,
                "no workspace provider attached to this executor; \
                 claimed promotion cannot be resumed on stateless nodes"
                    .to_string(),
            )
        })?;

        // OBSERVE-FIRST: only re-drive when the promotion demonstrably did NOT
        // land. If it already landed (base ref advanced / durable evidence),
        // reconcile from the observed promotion instead of re-driving a
        // non-idempotent promote_workspace against an already-removed workspace.
        let (promoted, redriven) = if let Some(promoted) =
            self.observed_promoted_workspace_for_claim(execution_id, &claim)?
        {
            (promoted, false)
        } else {
            // The durable claim records an earlier authorization. A surviving
            // candidate may have changed since that attempt; re-drive only after
            // every required proof authorizes its current contents again.
            let candidate_tree =
                self.require_promotable_workspace_for_promotion(execution_id, provider.as_ref())?;
            let landing_branch = self.frozen_landing_branch(execution_id)?;
            let promoted = provider
                .promote_workspace(
                    &ExecutionWorkspaceKey::execution(execution_id),
                    &candidate_tree,
                    landing_branch.as_deref(),
                )
                .map_err(Self::operator_promote_error)?;
            (promoted, true)
        };
        let promotion = promotion_with_promoted_workspace(base_promotion, &promoted);
        let resumed_context = ExecutionControllerApplicationContext {
            decision_id: context.decision_id,
            decision: context.decision,
            application_id: Some(claim.application_id.clone()),
            source: context
                .source
                .or_else(|| claim.source.clone())
                .or_else(|| Some("factory_controller_resume".to_string())),
            reason: context.reason.or_else(|| claim.reason.clone()).or_else(|| {
                Some("operator requested retry of claimed promote side effect".to_string())
            }),
        };
        let mut application = self.controller_application_evidence(
            execution_id,
            resumed_context,
            "promote",
            None,
            None,
            Some(promotion.clone()),
            claim.memory_policy.clone(),
            claim.side_effect.clone(),
        )?;
        application.recovery = Some(ExecutionControllerApplicationRecoveryEvidence {
            mode: "resume_claimed_side_effect".to_string(),
            source: application.source.clone(),
            reason: if redriven {
                "operator requested retry of claimed promote side effect; \
                 promotion was not observable, so it was re-driven"
                    .to_string()
            } else {
                "operator requested retry of claimed promote side effect; \
                 promotion was already observable, so it was reconciled without re-driving"
                    .to_string()
            },
            evidence: vec![
                format!("application_id={application_id}"),
                "action=promote".to_string(),
                format!("redriven={redriven}"),
                format!(
                    "promoted_ref={}",
                    promotion.promoted_ref.clone().unwrap_or_default()
                ),
                format!(
                    "promoted_commit_sha={}",
                    promotion.promoted_commit_sha.clone().unwrap_or_default()
                ),
            ],
        });
        persist_controller_application_evidence(
            self.dispatcher.ledger(),
            execution_id,
            application.clone(),
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        Ok(controller_apply_response_from_application(
            execution_id,
            "resumed",
            true,
            application,
            None,
            None,
            None,
            Vec::new(),
        ))
    }

    fn reconcile_claimed_controller_application(
        &self,
        execution_id: Ulid,
        context: &ExecutionControllerApplicationContext,
        action: &str,
        application_id: &str,
    ) -> Result<Option<ExecutionControllerApplicationEvidence>, ExecutorError> {
        let Some(claim) =
            self.controller_application_for_application_id(execution_id, application_id)?
        else {
            return Ok(None);
        };
        if claim.applied {
            return Ok(Some(claim));
        }
        if claim.decision_id != context.decision_id
            || claim.decision != context.decision
            || claim.action != action
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller application `{application_id}` claim does not match decision `{}`",
                context.decision_id
            )));
        }

        match action {
            "advance" | "promote_then_advance" => {
                let Some(next_execution_id) = claim.next_execution_id.as_deref() else {
                    return Ok(None);
                };
                let Ok(next_ulid) = Ulid::from_string(next_execution_id) else {
                    return Ok(None);
                };
                if self.try_get_execution_by_ulid(next_ulid)?.is_none() {
                    return Ok(None);
                }
                if action == "promote_then_advance" && claim.promotion.is_none() {
                    return Ok(None);
                }
                let mut evidence = vec![format!("next_execution_id={next_execution_id}")];
                if let Some(promotion) = claim.promotion.as_ref() {
                    evidence.push(format!("promotion_status={}", promotion.status));
                }
                self.reconcile_observed_controller_application(
                    execution_id,
                    context,
                    &claim,
                    Some(next_execution_id.to_string()),
                    None,
                    claim.promotion.clone(),
                    if action == "promote_then_advance" {
                        "claimed promotion and next execution are visible in controller application evidence"
                    } else {
                        "claimed next execution is visible in the executor ledger"
                    },
                    evidence,
                )
                .map(Some)
            }
            "park" => {
                let record = self
                    .try_get_execution_by_ulid(execution_id)?
                    .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
                let parked_from_evidence = record.evidence.parked_candidate.clone();
                let parked = match parked_from_evidence.clone() {
                    Some(parked) => Some(parked),
                    None => self.observed_parked_workspace_for_claim(execution_id, &claim)?,
                };
                let Some(parked) = parked else {
                    return Ok(None);
                };
                if parked.parked_ref.trim().is_empty() || parked.commit_sha.trim().is_empty() {
                    return Ok(None);
                }
                if parked_from_evidence.is_none() {
                    persist_parked_candidate_evidence(
                        self.dispatcher.ledger(),
                        execution_id,
                        &ParkedWorkspace {
                            ref_name: parked.parked_ref.clone(),
                            commit_sha: parked.commit_sha.clone(),
                            identity: parked.identity.clone(),
                        },
                        false,
                    )
                    .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
                }
                let reason = if parked_from_evidence.is_some() {
                    "durable parked-candidate evidence is visible in the execution record"
                } else {
                    "claimed parked ref is visible in the workspace provider"
                };
                self.reconcile_observed_controller_application(
                    execution_id,
                    context,
                    &claim,
                    None,
                    Some(parked.clone()),
                    None,
                    reason,
                    vec![
                        format!("parked_ref={}", parked.parked_ref),
                        format!("commit_sha={}", parked.commit_sha),
                    ],
                )
                .map(Some)
            }
            "promote" => {
                // The promote reconcile arm. OBSERVE-ONLY (honors the fail-closed / reconcile-only
                // contract shared with the boot sweep — NO re-drive here): if the
                // promotion is already durably visible (durable promotion
                // evidence on the claim, or the trusted base ref observably
                // advanced to the candidate commit), append `reconcile_observed`
                // evidence and flip the claim applied. Otherwise `Ok(None)` — the
                // claim stays `apply_claimed` for an operator-driven resume.
                let Some(promoted) =
                    self.observed_promoted_workspace_for_claim(execution_id, &claim)?
                else {
                    return Ok(None);
                };
                let Some(base_promotion) = claim.promotion.clone() else {
                    return Ok(None);
                };
                let promotion = promotion_with_promoted_workspace(base_promotion, &promoted);
                self.reconcile_observed_controller_application(
                    execution_id,
                    context,
                    &claim,
                    None,
                    None,
                    Some(promotion),
                    "trusted base ref is observably advanced to the promoted candidate commit",
                    vec![
                        format!("promoted_ref={}", promoted.ref_name),
                        format!("promoted_commit_sha={}", promoted.commit_sha),
                    ],
                )
                .map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Boot-time durability sweep: reconcile every interrupted (`apply_claimed`)
    /// controller-application claim from already-visible evidence.
    ///
    /// When the main crashes after a controller decision's side effect was
    /// durably *claimed* (`applied == false`) but before the application
    /// evidence could be flipped to `applied == true`, the claim is left
    /// dangling. [`Self::resume_in_flight_runs`] only re-drives non-terminal
    /// *stage* state; it never inspects controller-application evidence, so
    /// without this sweep such a claim would only reconcile on an explicit
    /// operator `--resume-claimed-side-effect` / finalize retry. This method
    /// runs the same reconcile-only convergence automatically at boot.
    ///
    /// **Reconcile-only and fail-closed.** It delegates entirely to
    /// [`Self::reconcile_claimed_controller_application`], which NEVER submits a
    /// wave, parks a workspace, or runs a promotion — it only appends
    /// `reconcile_observed` evidence when the side effect is *already* visible
    /// (next execution present / parked ref present in the
    /// workspace / durable parked-candidate evidence present). A claim whose
    /// side effect is not yet observable stays `apply_claimed` and is counted in
    /// `left_claimed`; it is never marked applied. Re-running every boot is a
    /// no-op for already-applied claims (the inner reconcile early-returns the
    /// existing claim when `claim.applied` is already true).
    ///
    /// **Boot-non-fatal.** Each per-execution / per-claim step is isolated: an
    /// error is logged and counted in `errored`, then the sweep continues. The
    /// method never panics and never returns `Err`, so a single bad row cannot
    /// abort boot.
    ///
    /// # THE DISCOVERY IS THE NUCLEUS
    ///
    /// A discovery that answered EMPTY while the nucleus still holds every
    /// execution would make this sweep scan zero executions and reconcile nothing.
    /// Its whole product is the reconcile, so the leg would not degrade, it would
    /// go **DARK**, with the tell that the summary reports `scanned: 0` and reads
    /// exactly like a clean boot.
    ///
    /// [`Self::try_known_execution_ids`] is the construction that already exists
    /// for this question — the nucleus's `lifecycle_execution_ids()` — and it is
    /// what `list_executions` already discovers through.
    /// Reusing it rather than spelling a second enumeration here is the point: two
    /// enumerations of "every execution this daemon knows" is how the two come to
    /// disagree. An id with nothing to reconcile costs nothing but a
    /// `get_execution` that answers `None` or a record with no unapplied claim —
    /// both already `continue` arms.
    ///
    /// **An unreadable nucleus is FAIL-CLOSED, and it is the one path that does
    /// not "log and continue".** Candidate discovery IS lifecycle authority: a
    /// sweep that silently scans an empty set is indistinguishable from a boot
    /// with nothing to reconcile, which is the failure this section exists to
    /// remove. So the error is counted in `errored` — and `boot.rs` refuses
    /// readiness on `errors > 0`, exactly as it already does for the recovery
    /// scan one call earlier. The method still never returns `Err`.
    #[tracing::instrument(
        name = "workflow.reconcile_claimed_controller_applications_at_boot",
        skip_all
    )]
    pub fn reconcile_claimed_controller_applications_at_boot(
        &self,
    ) -> BootControllerApplicationReconcileSummary {
        let mut summary = BootControllerApplicationReconcileSummary::default();
        let execution_ids = match self.try_known_execution_ids() {
            Ok(ids) => {
                // Deterministic sweep order. The ids arrive as a `HashSet`, and
                // a boot summary whose per-execution log lines reorder run to run
                // is harder to diff than one that does not; nothing here depends
                // on the order, because every claim is reconciled independently.
                let mut ids: Vec<Ulid> = ids.into_iter().collect();
                ids.sort_unstable();
                ids
            }
            Err(error) => {
                summary.errored += 1;
                error!(
                    %error,
                    "boot reconcile: could not enumerate the executions to reconcile; \
                     refusing to report a clean sweep over a set that could not be read"
                );
                return summary;
            }
        };
        for execution_id in execution_ids {
            let Some(record) = self.get_execution(&execution_id.to_string()) else {
                continue;
            };
            for claim in &record.evidence.controller_applications {
                if claim.applied {
                    continue;
                }
                summary.scanned += 1;
                let application_id = claim.application_id.clone();
                // Reconstruct the application context from the durable claim so
                // the reconcile path can re-validate it against the recorded
                // controller decision. `source`/`reason` fall back to a stable
                // boot marker when the claim carried none.
                let context = ExecutionControllerApplicationContext {
                    decision_id: claim.decision_id.clone(),
                    decision: claim.decision.clone(),
                    application_id: Some(application_id.clone()),
                    source: claim
                        .source
                        .clone()
                        .or_else(|| Some("factory_boot_reconcile".to_string())),
                    reason: claim.reason.clone(),
                };
                match self.reconcile_claimed_controller_application(
                    execution_id,
                    &context,
                    &claim.action,
                    &application_id,
                ) {
                    Ok(Some(_application)) => {
                        summary.reconciled += 1;
                        info!(
                            %execution_id,
                            application_id = %application_id,
                            action = %claim.action,
                            decision_id = %claim.decision_id,
                            "boot reconcile: claimed controller application reconciled from \
                             already-visible side effect"
                        );
                    }
                    Ok(None) => {
                        summary.left_claimed += 1;
                        info!(
                            %execution_id,
                            application_id = %application_id,
                            action = %claim.action,
                            decision_id = %claim.decision_id,
                            "boot reconcile: claimed controller application side effect not yet \
                             visible; leaving apply_claimed for a later operator-driven retry"
                        );
                    }
                    Err(e) => {
                        summary.errored += 1;
                        warn!(
                            %execution_id,
                            application_id = %application_id,
                            action = %claim.action,
                            decision_id = %claim.decision_id,
                            error = %e,
                            "boot reconcile: claimed controller application reconcile errored; \
                             leaving apply_claimed and continuing boot"
                        );
                    }
                }
            }
        }
        if summary.scanned > 0 {
            info!(
                scanned = summary.scanned,
                reconciled = summary.reconciled,
                left_claimed = summary.left_claimed,
                errored = summary.errored,
                "boot reconcile: claimed controller-application sweep complete"
            );
        }
        summary
    }

    fn reconcile_observed_controller_application(
        &self,
        execution_id: Ulid,
        context: &ExecutionControllerApplicationContext,
        claim: &ExecutionControllerApplicationEvidence,
        next_execution_id: Option<String>,
        parked_candidate: Option<kata_types::execution::ParkedExecution>,
        promotion: Option<ExecutionWorkspacePromotion>,
        reason: &str,
        evidence: Vec<String>,
    ) -> Result<ExecutionControllerApplicationEvidence, ExecutorError> {
        if let Some(candidate) = parked_candidate.as_ref() {
            validate_parked_execution_identity(execution_id, &claim.application_id, candidate)?;
        }
        if let Some(promotion) = promotion.as_ref() {
            validate_promotion_identity(execution_id, &claim.application_id, promotion)?;
        }
        let reconciled_context = ExecutionControllerApplicationContext {
            decision_id: context.decision_id.clone(),
            decision: context.decision.clone(),
            application_id: Some(claim.application_id.clone()),
            source: claim
                .source
                .clone()
                .or_else(|| Some("factory_controller_reconcile".to_string())),
            reason: claim.reason.clone().or_else(|| Some(reason.to_string())),
        };
        let mut application = self.controller_application_evidence(
            execution_id,
            reconciled_context,
            &claim.action,
            next_execution_id.or_else(|| claim.next_execution_id.clone()),
            parked_candidate.or_else(|| claim.parked_candidate.clone()),
            promotion.or_else(|| claim.promotion.clone()),
            claim.memory_policy.clone(),
            claim.side_effect.clone(),
        )?;
        application.recovery = Some(ExecutionControllerApplicationRecoveryEvidence {
            mode: "reconcile_observed".to_string(),
            source: application.source.clone(),
            reason: reason.to_string(),
            evidence,
        });
        persist_controller_application_evidence(
            self.dispatcher.ledger(),
            execution_id,
            application.clone(),
        )
        .map_err(|e| ExecutorError::RunnerBuildFailed(e.to_string()))?;
        Ok(application)
    }

    fn controller_application_evidence(
        &self,
        execution_id: Ulid,
        context: ExecutionControllerApplicationContext,
        action: &str,
        next_execution_id: Option<String>,
        parked_candidate: Option<kata_types::execution::ParkedExecution>,
        promotion: Option<ExecutionWorkspacePromotion>,
        memory_policy: Option<ExecutionControllerMemoryPolicyApplicationEvidence>,
        side_effect: Option<ExecutionControllerApplicationSideEffectEvidence>,
    ) -> Result<ExecutionControllerApplicationEvidence, ExecutorError> {
        let decision =
            self.validate_controller_application_context(execution_id, &context, action)?;
        let application_id = context
            .application_id
            .unwrap_or_else(|| default_controller_application_id(action, &context.decision_id));
        Ok(ExecutionControllerApplicationEvidence {
            schema_version: CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION,
            application_id,
            decision_id: context.decision_id,
            decision: context.decision,
            action: action.to_string(),
            applied: true,
            applied_at_ms: now_ms(),
            source: context
                .source
                .or_else(|| Some("factory_controller".to_string())),
            reason: context.reason.or(decision.reason),
            error: None,
            next_execution_id,
            parked_candidate,
            promotion,
            memory_policy,
            side_effect,
            recovery: None,
        })
    }

    fn validate_controller_application_context(
        &self,
        execution_id: Ulid,
        context: &ExecutionControllerApplicationContext,
        action: &str,
    ) -> Result<ExecutionControllerDecisionEvidence, ExecutorError> {
        if context.decision_id.trim().is_empty() {
            return Err(ExecutorError::InvalidDefinition(
                "controller application requires a non-empty decision_id".to_string(),
            ));
        }
        if context.decision.trim().is_empty() {
            return Err(ExecutorError::InvalidDefinition(
                "controller application requires a non-empty decision".to_string(),
            ));
        }
        let decision = self.recorded_controller_decision(execution_id, &context.decision_id)?;
        if decision.decision != context.decision {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller application decision `{}` does not match recorded decision `{}` for `{}`",
                context.decision, decision.decision, context.decision_id
            )));
        }
        if !controller_application_action_matches_decision(action, &decision.decision) {
            return Err(ExecutorError::PolicyDenied(format!(
                "controller decision `{}` requested `{}`, not application action `{action}`",
                context.decision_id, decision.decision
            )));
        }
        Ok(decision)
    }

    fn recorded_controller_decision(
        &self,
        execution_id: Ulid,
        decision_id: &str,
    ) -> Result<ExecutionControllerDecisionEvidence, ExecutorError> {
        let record = self
            .try_get_execution_by_ulid(execution_id)?
            .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
        record
            .evidence
            .controller_decisions
            .into_iter()
            .find(|decision| decision.decision_id == decision_id)
            .ok_or_else(|| {
                ExecutorError::PolicyDenied(format!(
                    "controller decision `{decision_id}` was not recorded on execution `{execution_id}`"
                ))
            })
    }

    fn controller_application_lock(&self, execution_id: Ulid, decision_id: &str) -> Arc<Mutex<()>> {
        self.controller_application_locks
            .entry(format!("{execution_id}:{decision_id}"))
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn applied_controller_application_for_decision(
        &self,
        execution_id: Ulid,
        decision_id: &str,
    ) -> Result<Option<ExecutionControllerApplicationEvidence>, ExecutorError> {
        let record = self
            .try_get_execution_by_ulid(execution_id)?
            .ok_or_else(|| ExecutorError::ExecutionNotFound(execution_id.to_string()))?;
        Ok(record
            .evidence
            .controller_applications
            .into_iter()
            .rev()
            .find(|application| application.decision_id == decision_id && application.applied))
    }
}

/// The execution's workspace as the provider reports it, refused
/// [`WorktreeFailure::Missing`] when the provider registers none for the
/// execution — the check a promote and every park door that asks the provider to
/// write a park make before acting on the workspace. The jj provider registers
/// no workspace whose `.jj` directory is gone
/// ([`ExecutionWorkspaceProvider::lookup_workspace`]), so a workspace directory
/// removed outside kata is `Missing` here too. A failed read is
/// [`WorktreeFailure::Internal`].
pub(super) fn require_standing_workspace(
    provider: &dyn ExecutionWorkspaceProvider,
    execution_id: Ulid,
) -> Result<kata_effects_contract::ExecutionWorkspaceStatus, ExecutorError> {
    provider
        .workspace_status(&ExecutionWorkspaceKey::execution(execution_id))
        .map_err(|e| ExecutorError::worktree(WorktreeFailure::Internal, e.to_string()))?
        .ok_or_else(|| {
            ExecutorError::worktree(
                WorktreeFailure::Missing,
                format!("execution workspace {execution_id} is not registered"),
            )
        })
}

#[cfg(test)]
mod controller_decision_evidence_tests {
    use super::super::evidence_merge::{
        controller_completion_evidence, controller_decision_scope_evidence,
    };

    /// An LLM controller can emit
    /// `scope.validation_blockers = ["none", "N/A", ""]` — natural-language
    /// sentinels meaning "no blocker". The parse must coerce these to the
    /// canonical empty list so they never count as real blockers downstream.
    #[test]
    fn controller_decision_scope_evidence_strips_sentinel_validation_blockers() {
        let value = serde_json::json!({
            "decision": "park",
            "scope": {
                "summary": "park: protected-properties doc",
                "owned_paths": ["docs/architecture/protected-properties.md"],
                "validation_blockers": ["none", "N/A", ""],
            },
        });
        let scope = controller_decision_scope_evidence(&value)
            .expect("scope evidence present (owned_paths is non-empty)");
        assert!(
            scope.validation_blockers.is_empty(),
            "sentinel-only blockers must normalize to empty, got {:?}",
            scope.validation_blockers
        );
    }

    /// Companion to the sentinel-stripping test: a genuine blocker survives the
    /// coercion so a real validation failure is still surfaced.
    #[test]
    fn controller_decision_scope_evidence_retains_real_validation_blocker() {
        let value = serde_json::json!({
            "decision": "repair",
            "scope": {
                "owned_paths": ["crates/api"],
                "validation_blockers": ["none", "missing test coverage"],
            },
        });
        let scope = controller_decision_scope_evidence(&value).expect("scope evidence present");
        assert_eq!(
            scope.validation_blockers,
            vec!["missing test coverage".to_string()]
        );
    }

    /// Completion `blockers` is the same LLM artifact as scope's list and must
    /// receive the identical sentinel coercion; `remaining` (free-text next
    /// steps) must be left untouched.
    #[test]
    fn controller_completion_evidence_strips_sentinel_blockers_but_keeps_remaining() {
        let value = serde_json::json!({
            "completion": {
                "status": "complete",
                "validation_passed": true,
                "remaining": ["none"],
                "blockers": ["none"],
            },
        });
        let completion =
            controller_completion_evidence(&value).expect("completion evidence present");
        assert!(
            completion.blockers.is_empty(),
            "sentinel blockers normalize to empty"
        );
        assert_eq!(
            completion.remaining,
            vec!["none".to_string()],
            "remaining is free-text and must not be coerced"
        );
    }
}
