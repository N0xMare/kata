//! The `oci` `workspace_effect` submit arm.
//!
//! A `stage(agent = "workspace_effect", op = …)` under `oci` is MAIN-RESOLVED:
//! its claim is the double-spend guard, its jj verbs run at the main between
//! claim and resolve, and a `promote`/`park`/`commit`/`forge_export` needs no
//! container at all — the capsule profile's `Executor::Effect` arm dispatches
//! here instead of `submit_stage_as_capsule`.
//!
//! # The claim's operands
//!
//! * `expected_candidate` — the head row's `candidate_commit_id`; the verbs
//!   fence on it (`oci_candidate_diverged`) so a candidate that moved under a
//!   parked gate or a swept apply refuses rather than mutate the wrong commit.
//! * `delivered_commit` — what `promote` lands and `forge_export` pushes: the
//!   head row's `committed_commit_id` when the candidate is the empty `@` a
//!   `commit` left on top of it, else the candidate
//!   (`workspace_effect_delivered_commit`). Without it both would deliver that
//!   empty, undescribed `@`.
//! * `candidate_tree_id` — the candidate's jj tree id, read off the workspace
//!   at claim; the approval payload binds it and the `promote` pin fences it.
//! * `pin` — `required_proof_candidate_tree_pin`'s answer, resolved from the
//!   durable validation criteria exactly as the operator promote's
//!   authorization does — the recorded spec carries it so the sweep re-performs with the pin
//!   the claim judged, not a re-derivation.
//! * `target` — the ref/branch the op moves: `exec-<id>` (commit),
//!   `parked/<exec>` (park), the trunk bookmark (promote), `kata/<exec>`
//!   (forge_export). Recorded, so the gate reads what approving authorizes.
//!
//! `approval_required` parks the fresh claim `awaiting_approval` with the
//! scope in the park payload (`Dispatcher::decide_workspace_effect_gate` is
//! its door); under terminal intent the claim settles `cancelled` in its own
//! transaction, mirroring `claim_work_apply_attempt`.

use kata_core::operational::{
    MainAttemptSpec, OccurrenceBinding, WorkspaceEffectClaimOutcome, WorkspaceEffectSpec,
};
use kata_types::error::{KataError, KataResult};
use kata_types::execution::CandidateTreePin;
use kata_types::workflow::ExecutionId;
use kata_types::workflow::{WorkspaceEffect, WorkspaceEffectOp};
use smol_str::SmolStr;
use ulid::Ulid;

use crate::runner::WorkflowRunner;
use crate::runner::dispatch::main_resolved::CapsuleProfileRoute;
use kata_program::execution_program::{LoweredOperation, occurrence_for};

impl WorkflowRunner {
    /// THE WORKSPACE-EFFECT ARM — claim the main attempt, run the verb through
    /// the dispatcher, resolve. Returns `Resolved` for every outcome — the
    /// effect never produces a capsule and never holds a worker; a parked gate
    /// or a recorded answer both end the dispatch leg.
    pub(in crate::runner) fn submit_workspace_effect(
        &self,
        stage_name: &SmolStr,
        lowered: &LoweredOperation,
    ) -> KataResult<CapsuleProfileRoute> {
        let checked_stage = self
            .execution_program
            .stages
            .get(&kata_types::workflow::StageId(stage_name.clone()))
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "workspace_effect stage {stage_name} is no stage of this program"
                ))
            })?;
        let provider = self.workspace_provider.clone().ok_or_else(|| {
            KataError::Internal(format!(
                "workspace_effect stage {stage_name} dispatched under `oci` with no \
                 execution-workspace provider — the worktree-isolated admission is what wires \
                 one, and the CHECK's rule should have refused this pack already"
            ))
        })?;
        let lifecycle = self.dispatcher.execution_lifecycle();
        let db = lifecycle.db();

        let mut effect = WorkspaceEffect::from_directive_prompt(&checked_stage.op.prompt_template)
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "workspace_effect stage {stage_name} carries no parseable directive — the \
                 checked stage's prompt is the frontend's own synthesized directive, so a \
                 parse failure here is load-time drift, not a dispatch refusal"
                ))
            })?;

        // The recorded candidate: the head row's commit the verbs fence on, and
        // the workspace's tree for the gate scope + promote pin. The
        // precondition's dirty/diverged checks run at the verbs — the claim's
        // reads are the row's facts plus one status read for the tree id.
        let head = db
            .execution_work_tree_head(self.execution_id)?
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "workspace_effect stage {stage_name} under `oci` holds no /work head row — \
                     worktree isolation records it at admission; a stage that reached dispatch \
                     without it is a rig that skipped admission"
                ))
            })?;
        let key = kata_effects_contract::ExecutionWorkspaceKey::execution(self.execution_id);
        // `forge_export` is the terminal SINK the load-time rule orders AFTER
        // `promote` — and a landed promote tears the execution workspace
        // down, so the live-workspace reads the other ops fence on have no
        // answer for it. Its candidate is the commit the head row still names
        // (`promote` does not move the row); its tree is that commit's, read
        // from the repository.
        let (candidate_commit, candidate_tree_id) = if effect.op == WorkspaceEffectOp::ForgeExport {
            (
                head.candidate_commit_id.clone(),
                provider.commit_tree_id(&head.candidate_commit_id)?,
            )
        } else {
            provider.workspace_status(&key)?.ok_or_else(|| {
                KataError::Internal(format!(
                    "workspace_effect stage {stage_name}: the execution workspace is gone — \
                         for a `commit` it must still be live; terminal ops follow `commit` at \
                         load time and cannot depend on it"
                ))
            })?;
            let candidate_commit = provider
                .workspace_effect_candidate_commit(&key)?
                .ok_or_else(|| {
                    KataError::Internal(format!(
                        "workspace_effect stage {stage_name}: the execution workspace \
                             reports no candidate commit — the head row names {}",
                        head.candidate_commit_id
                    ))
                })?;
            if candidate_commit != head.candidate_commit_id {
                return Err(KataError::Validation(format!(
                    "oci_candidate_diverged: the execution workspace's @ is \
                         {candidate_commit} but the recorded head names {} — the candidate moved \
                         before the effect claimed",
                    head.candidate_commit_id
                )));
            }
            let candidate_tree_id =
                provider
                    .workspace_effect_candidate_tree(&key)?
                    .ok_or_else(|| {
                        KataError::Internal(format!(
                            "workspace_effect stage {stage_name}: no candidate tree read for \
                             {candidate_commit}"
                        ))
                    })?;
            (candidate_commit, candidate_tree_id)
        };

        let target = match effect.op {
            WorkspaceEffectOp::Commit => format!("exec-{}", self.execution_id),
            // The park's ref is execution-scoped (`parked/<exec-id>`) — the
            // authored `label` rides the spec as metadata, never the ref name.
            WorkspaceEffectOp::Park => provider.parked_ref_name(&key, None),
            // The branch the perform lands on or refuses: the FROZEN landable
            // branch, never the host's trunk answer now. Without one (no
            // target froze a landable branch — admission refuses such a
            // promoting program first) the landing ladder resolves the trunk
            // at the land, which the placeholder says.
            WorkspaceEffectOp::Promote => self
                .dispatcher
                .frozen_landing_branch(self.execution_id)?
                .unwrap_or_else(|| "<trunk>".to_owned()),
            WorkspaceEffectOp::ForgeExport => format!(
                "{}{}",
                kata_vcs::trunk::FORGE_BRANCH_PREFIX,
                self.execution_id
            ),
        };
        // THE PROMOTION GATE — the same authorization `submit_stage`'s shared
        // funnel runs (`authorize_promote_directive` → this), on the effect
        // this arm already parsed: the required validation criteria must have
        // recorded a PASSING observation, and those criteria must have bound
        // a candidate — both refuse before dispatch. The gate's own pin is
        // the one the spec carries, so a promote can never land a tree no
        // criterion measured.
        if effect.op == WorkspaceEffectOp::Promote {
            crate::promotion_gate::authorize_promote_effect(
                &self.execution_program,
                &self.recorded_validation_reports(),
                self.execution_id,
                stage_name,
                &mut effect,
            )?;
        }
        let pin = if effect.op == WorkspaceEffectOp::Promote {
            effect.candidate_tree
        } else {
            CandidateTreePin::default()
        };
        let delivered_commit = provider.workspace_effect_delivered_commit(
            effect.op,
            &candidate_commit,
            &head.committed_commit_id,
        )?;
        // The export's push remote is resolved HERE, before the claim, and
        // recorded: every later leg pushes to the remote the claim named.
        let forge_remote = if effect.op == WorkspaceEffectOp::ForgeExport {
            Some(
                self.dispatcher
                    .forge_export_claim_remote(self.execution_id, &provider)?,
            )
        } else {
            None
        };
        let spec = WorkspaceEffectSpec {
            op: effect.op,
            label: effect.label.clone(),
            target,
            candidate_commit,
            delivered_commit,
            candidate_tree_id,
            pin,
            forge: effect.forge.clone(),
            forge_remote,
        };

        let attempt_id = Ulid::new();
        let claim_spec = MainAttemptSpec {
            stage_id: stage_name.to_string(),
            occurrence: OccurrenceBinding::new(
                occurrence_for(
                    &self.execution_program,
                    ExecutionId(self.execution_id),
                    lowered,
                ),
                None,
                None,
            ),
        };
        let approval = crate::authorization::approval_gate_reason(checked_stage);
        match db.claim_workspace_effect_attempt(
            attempt_id,
            &claim_spec,
            &spec,
            approval.as_deref(),
        )? {
            WorkspaceEffectClaimOutcome::Claimed { .. } => {
                kata_core::fault_inject::operational_crash_point(
                    "after_workspace_effect_claimed_before_jj_publish",
                );
                self.dispatcher.perform_workspace_effect(
                    self.execution_id,
                    attempt_id,
                    stage_name.as_str(),
                    &spec,
                    &provider,
                    self.forge.as_ref(),
                )?;
                Ok(CapsuleProfileRoute::Resolved)
            }
            // A re-presented live attempt is the sweep's own question — drive
            // it now (the claim just proved the attempt exists `pending` or
            // parked).
            WorkspaceEffectClaimOutcome::AlreadyLive { state, .. } if state == "pending" => {
                self.dispatcher.drive_pending_workspace_effects(
                    self.execution_id,
                    Some(&provider),
                    self.forge.as_ref(),
                )?;
                Ok(CapsuleProfileRoute::Resolved)
            }
            WorkspaceEffectClaimOutcome::AlreadyLive { .. }
            | WorkspaceEffectClaimOutcome::ParkedForApproval { .. }
            | WorkspaceEffectClaimOutcome::AlreadyAccepted { .. }
            | WorkspaceEffectClaimOutcome::RecordedTerminal { .. } => {
                Ok(CapsuleProfileRoute::Resolved)
            }
        }
    }
}

impl WorkflowRunner {
    /// The pass-loop sweep leg — pending `workspace_effect` main attempts,
    /// classified and re-performed or resolved from repository facts. Same
    /// slot as `drive_pending_work_applies`: a pending row exists only where
    /// the effect was claimed, which only happens on a `worktree_isolated`
    /// `oci` run — the sweep is a no-op otherwise.
    pub(in crate::runner) fn drive_pending_workspace_effects(&self) -> KataResult<()> {
        if !self.execution_program.summary.worktree_isolated {
            return Ok(());
        }
        self.dispatcher.drive_pending_workspace_effects(
            self.execution_id,
            self.workspace_provider.as_ref(),
            self.forge.as_ref(),
        )?;
        Ok(())
    }
}
