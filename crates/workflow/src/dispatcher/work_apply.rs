//! The `/work` apply driver: after a
//! capsule's delta is adopted and its occurrence accepted, the dispatcher
//! applies the recorded delta to the durable `/work` head AT THE STAGE'S OWN
//! `parallel()` coordinate through a main-resolved `work_apply` attempt
//! (`#apply/<stage>`), and advances that head in the resolving transaction.
//! Successors are released only once that attempt is accepted — the head a
//! later capsule maps is the one its apply landed.
//!
//! # Two apply legs, chosen by the HEAD — not by the execution
//!
//! Which leg an apply takes is a property of the row it advances: a head
//! whose `candidate_commit_id` is set is an ISOLATED execution's root head —
//! the jj leg drives `ExecutionWorkspaceProvider::apply_work_delta`, tags the
//! op `kata.effect:<attempt>`, and advances head and candidate together. A
//! head with no candidate — every `parallel()` branch row, and every head of
//! a non-isolated execution — has no checkout to rewrite: the CAS-only leg
//! publishes the delta-applied manifest and the resolve advances the row.
//!
//! # Legs of the sweep
//!
//! [`Dispatcher::drive_pending_work_applies`] is the one driver for every
//! pending row [`OperationalDb::pending_work_applies`] enumerates, run at the
//! top of each runner pass and again from the post-completion sweep:
//!
//! * a row with NO apply occurrence — the live leg: claim, apply, resolve;
//! * a row whose apply attempt is `pending` (a crash between claim and
//!   resolve) — the sweep leg: a jj head's reconcile is `classify_work_apply`
//!   (the `kata.effect` op tag, or the candidate's predecessor chain after a
//!   GC): `NotApplied` re-applies, `Applied` resolves and advances,
//!   `Diverged` records `work_apply_candidate_diverged`. A CAS head has no
//!   workspace to classify: the row still reading the delta's base is the
//!   whole question — re-publish is a content-identical no-op where the first
//!   drive already published;
//! * a row whose apply is already accepted — nothing (the enumeration's
//!   `NOT EXISTS` already filtered it; convergence is the backstop).
//!
//! Empty deltas resolve without touching either leg and leave the head row
//! byte-equal — head_seq does not advance for a delta that changed nothing.

use std::sync::Arc;

use kata_core::OperationalDb;
use kata_core::operational::OccurrenceBinding;
use kata_core::operational::{
    MainAttemptSpec, PendingWorkApply, WorkApplyClaimOutcome, WorkTreeHeadAdvance,
};
use kata_effects_contract::{
    ExecutionWorkspaceHandle, ExecutionWorkspaceKey, ExecutionWorkspaceProvider,
};
use kata_types::error::{KataError, KataResult};
use kata_types::execution_contract::{
    OccurrenceRef, OperationContractId, OperationPath, work_apply_operation_contract,
    work_apply_stage_id,
};
use kata_types::primitives::{ContentHash, FixedBytes, ObjectId};
use kata_types::tree_artifact::TreeManifest;
use kata_types::tree_delta::TreeDelta;
use kata_types::workflow::{ExecutionId, StageId};
use smol_str::SmolStr;
use tracing::{info, warn};
use ulid::Ulid;

use super::Dispatcher;

impl Dispatcher {
    /// Drive every pending `/work` apply for `execution_id`, in acceptance
    /// order — the live leg after a capsule acceptance AND the resume sweep.
    ///
    /// `program` is the execution's checked program — each row's head
    /// coordinate is DERIVED from its stage through
    /// [`kata_program::execution_program::work_head_coordinate`], never trusted from
    /// the row itself. `provider` is the executor's workspace provider,
    /// demanded only by the jj leg; `cas` the node's content store, demanded
    /// by both. A driver asked to run with no CAS — an execution whose
    /// applies exist without one — fails fast rather than apply partially.
    ///
    /// # Errors
    ///
    /// A provider or CAS fault propagates (the attempt stays `pending` for the
    /// sweep to re-drive); a `work_apply_candidate_diverged` or stale-base
    /// classification is RECORDED as the apply attempt's failure and the drive
    /// continues so a later stage's own apply is not blocked behind it.
    pub fn drive_pending_work_applies(
        &self,
        execution_id: Ulid,
        program: &kata_program::execution_program::ExecutionProgram,
        provider: Option<&dyn ExecutionWorkspaceProvider>,
        cas: Option<&kata_core::store::cas::CasStore>,
    ) -> KataResult<()> {
        let db = Arc::clone(self.execution_lifecycle().db());
        let pending = db.pending_work_applies(execution_id)?;
        if pending.is_empty() {
            return Ok(());
        }
        let cas = cas.ok_or_else(|| {
            KataError::Storage(format!(
                "execution {execution_id} owes {} /work appl(ies) and this node has no \
                 content store attached to settle them — a /work delta exists only where a \
                 capsule produced it, and a capsule exists only where the CAS does",
                pending.len(),
            ))
        })?;
        for row in &pending {
            Self::drive_one_work_apply(&db, program, provider, cas, execution_id, row)?;
        }
        Ok(())
    }

    /// The execution's workspace provider and jj handle — demanded by the jj
    /// leg and only the jj leg, so a CAS-only execution owes no checkout at
    /// all. The provider returns alongside: the caller's `Option` is a
    /// demanded-by-construction fact this leg has just established.
    fn jj_workspace(
        provider: Option<&dyn ExecutionWorkspaceProvider>,
        execution_id: Ulid,
    ) -> KataResult<(&dyn ExecutionWorkspaceProvider, ExecutionWorkspaceHandle)> {
        let provider = provider.ok_or_else(|| {
            KataError::Storage(format!(
                "execution {execution_id} owes a /work apply onto a checkout-recorded head \
                 and no workspace provider is attached — a head with a candidate commit can \
                 only have been recorded where the provider was",
            ))
        })?;
        let handle = provider
            .lookup_workspace(&ExecutionWorkspaceKey::execution(execution_id))?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "execution {execution_id} owes a /work apply and has no live execution \
                     workspace for the provider to apply it to"
                ))
            })?;
        Ok((provider, handle))
    }

    /// Drive ONE pending apply — the claim's fences first, then the live leg's
    /// apply or the sweep leg's reconcile, on the leg the head picks.
    fn drive_one_work_apply(
        db: &Arc<OperationalDb>,
        program: &kata_program::execution_program::ExecutionProgram,
        provider: Option<&dyn ExecutionWorkspaceProvider>,
        cas: &kata_core::store::cas::CasStore,
        execution_id: Ulid,
        row: &PendingWorkApply,
    ) -> KataResult<()> {
        let operation_path =
            OperationPath::from_canonical_bytes(&row.operation_path).ok_or_else(|| {
                KataError::Storage(format!(
                    "occurrence {}'s stored operation_path does not decode canonically",
                    ContentHash::new(row.occurrence_id),
                ))
            })?;
        let (head_stage, coordinate) = apply_head(program, row, &operation_path)?;
        let branch = coordinate.spelling();
        let delta = load_work_delta(db, cas, row.work_delta_artifact_id)?;
        let attempt_id = Ulid::new();
        let spec = MainAttemptSpec {
            stage_id: work_apply_stage_id(&head_stage),
            occurrence: OccurrenceBinding::new(
                OccurrenceRef::new(
                    ExecutionId(execution_id),
                    ContentHash::new(row.program_hash),
                    work_apply_operation_contract(OperationContractId(FixedBytes(
                        row.operation_contract_id,
                    ))),
                    operation_path,
                ),
                None,
                None,
            ),
        };
        match db.claim_work_apply_attempt(attempt_id, &spec, &branch, delta_base_id(&delta))? {
            WorkApplyClaimOutcome::Claimed { head, .. } => {
                Self::apply_and_resolve(db, provider, cas, row, attempt_id, &delta, &head)
            }
            WorkApplyClaimOutcome::AlreadyLive { attempt_id, .. } => {
                // The sweep leg: reconcile before resolving anything — the
                // head's own kind decides what reconcile means.
                Self::reconcile_live_work_apply(db, provider, cas, attempt_id, &branch, &delta)
            }
            WorkApplyClaimOutcome::AlreadyAccepted { .. } => Ok(()),
            WorkApplyClaimOutcome::RecordedTerminal { attempt_id, state } => {
                // The apply's recorded answer stands — a stale base, a
                // diverged candidate, a refused classification — and a
                // re-drive does not re-run a settled effect.
                info!(
                    %execution_id,
                    stage = %row.stage_id,
                    %attempt_id,
                    %state,
                    "work_apply: the apply is already recorded terminal — nothing re-runs"
                );
                Ok(())
            }
            WorkApplyClaimOutcome::StaleBase { reason, .. } => {
                warn!(
                    %execution_id,
                    stage = %row.stage_id,
                    %reason,
                    "work_apply: delta base is stale — apply attempt recorded failed"
                );
                Ok(())
            }
        }
    }

    /// The live leg: run the apply's effect on the leg the head picks, then
    /// resolve the attempt with the head advance in one transaction.
    ///
    /// An EMPTY delta resolves `completed` without an apply and advances
    /// nothing.
    fn apply_and_resolve(
        db: &Arc<OperationalDb>,
        provider: Option<&dyn ExecutionWorkspaceProvider>,
        cas: &kata_core::store::cas::CasStore,
        row: &PendingWorkApply,
        attempt_id: Ulid,
        delta: &TreeDelta,
        head: &kata_core::operational::ExecutionWorkTreeHead,
    ) -> KataResult<()> {
        let execution_id = head.execution_id;
        if delta.changes().is_empty() {
            let output = serde_json::json!({
                "work_apply": {"applied": false, "reason": "empty delta"}
            });
            db.resolve_work_apply_attempt(attempt_id, &head.branch, None, &output)?;
            info!(
                %execution_id,
                stage = %row.stage_id,
                "work_apply: empty delta resolved with the head unchanged"
            );
            return Ok(());
        }
        // Crash boundary: the claim committed, the apply leg's effect has
        // not run. The pending attempt is exactly the sweep's enumeration
        // input.
        kata_core::fault_inject::operational_crash_point("after_work_apply_claimed_before_apply");
        if head.candidate_commit_id.is_empty() {
            // THE CAS-ONLY LEG — a branch head, or a non-isolated execution's
            // root: there is no checkout to rewrite, so the effect IS the
            // applied manifest's publication. The resolve's compare-and-swap
            // (`expected_head_seq`/`expected_artifact_id`, claimed above) is
            // the whole fence.
            let new_tree_ref = publish_applied_tree(db, cas, execution_id, head, delta)?;
            // Crash boundary: the manifest is durable and declared; the
            // resolve has not committed. The sweep leg re-publishes the same
            // content and resolves.
            kata_core::fault_inject::operational_crash_point(
                "after_work_apply_published_before_resolve",
            );
            let advance = WorkTreeHeadAdvance {
                work_tree_artifact_id: new_tree_ref.id().0.0,
                candidate_commit_id: String::new(),
                expected_head_seq: head.head_seq,
                expected_artifact_id: head.work_tree_artifact_id,
            };
            let output = serde_json::json!({
                "work_apply": {
                    "applied": true,
                    "leg": "cas",
                    "head_artifact": new_tree_ref.id().0.to_string(),
                    "head_seq": head.head_seq + 1,
                }
            });
            db.resolve_work_apply_attempt(attempt_id, &head.branch, Some(&advance), &output)?;
            kata_core::fault_inject::operational_crash_point(
                "after_work_apply_acceptance_before_successor_release",
            );
            info!(
                %execution_id,
                stage = %row.stage_id,
                branch = %head.branch,
                "work_apply: delta applied CAS-only; head advanced"
            );
            return Ok(());
        }
        // THE JJ LEG — the isolated root head: rewrite the candidate, tag the
        // op, and the manifest's declare names what the checkout now is.
        let (provider, handle) = Self::jj_workspace(provider, execution_id)?;
        let members = |object_id: ObjectId, size: u64| -> KataResult<Vec<u8>> {
            cas.get_verified(
                &object_id,
                size,
                kata_types::tree_artifact::MAX_MEMBER_BYTES,
            )
        };
        let applied = match provider.apply_work_delta(
            &handle,
            &head.candidate_commit_id,
            delta,
            &members,
            &attempt_id.to_string(),
        ) {
            Ok(applied) => applied,
            Err(error) => {
                if matches!(error, KataError::Validation(_)) {
                    // A typed refusal — candidate divergence, a member that did
                    // not survive — is the effect's outcome, recorded, so the
                    // sweep does not re-drive a settled question.
                    db.fail_work_apply_attempt(attempt_id, &error.to_string())?;
                    warn!(
                        %execution_id,
                        stage = %row.stage_id,
                        error = %error,
                        "work_apply: apply refused; attempt recorded failed"
                    );
                    return Ok(());
                }
                return Err(error);
            }
        };
        // Crash boundary: the jj apply PUBLISHED (the `kata.effect` op is
        // the reconcile evidence), the resolve — and with it the head advance —
        // has not committed. The sweep leg's `classify_work_apply` answers
        // `Applied` for exactly this window.
        kata_core::fault_inject::operational_crash_point(
            "after_work_apply_published_before_resolve",
        );
        // The applied manifest: the delta applied to the head's own manifest,
        // published and declared before the resolving transaction names it.
        let new_tree_ref = publish_applied_tree(db, cas, execution_id, head, delta)?;
        let advance = WorkTreeHeadAdvance {
            work_tree_artifact_id: new_tree_ref.id().0.0,
            candidate_commit_id: applied.commit_id.clone(),
            expected_head_seq: head.head_seq,
            expected_artifact_id: head.work_tree_artifact_id,
        };
        let output = serde_json::json!({
            "work_apply": {
                "applied": true,
                "candidate_commit": applied.commit_id,
                "tree_id": applied.tree_id,
                "head_artifact": new_tree_ref.id().0.to_string(),
                "head_seq": head.head_seq + 1,
            }
        });
        db.resolve_work_apply_attempt(attempt_id, &head.branch, Some(&advance), &output)?;
        // Crash boundary: the acceptance AND the head advance committed —
        // the pass's successor release has not run yet. Recovery is the gate's
        // own read: `pending_work_apply_for_stage` answers false and the
        // successor promotes on the next advance, no apply state needed.
        kata_core::fault_inject::operational_crash_point(
            "after_work_apply_acceptance_before_successor_release",
        );
        info!(
            %execution_id,
            stage = %row.stage_id,
            commit = %applied.commit_id,
            "work_apply: delta applied; head advanced"
        );
        Ok(())
    }

    /// The sweep leg: the attempt is `pending` — what reconcile means is the
    /// head's own kind: a jj head classifies the workspace; a CAS head's row
    /// still reading the delta's base is the whole question.
    fn reconcile_live_work_apply(
        db: &Arc<OperationalDb>,
        provider: Option<&dyn ExecutionWorkspaceProvider>,
        cas: &kata_core::store::cas::CasStore,
        attempt_id: Ulid,
        branch: &str,
        delta: &TreeDelta,
    ) -> KataResult<()> {
        let attempt = db.attempt(attempt_id)?.ok_or_else(|| {
            KataError::Storage(format!(
                "converged work-apply attempt {attempt_id} has no row"
            ))
        })?;
        let head = db
            .work_tree_head_at(attempt.execution_id, branch)?
            .ok_or_else(|| {
                KataError::Storage(format!(
                    "pending work-apply attempt {attempt_id} and no head row for execution {} \
                     at {branch:?} — the claim fenced on the row, so its absence is a plane \
                     divergence",
                    attempt.execution_id,
                ))
            })?;
        if head.candidate_commit_id.is_empty() {
            // THE CAS-ONLY SWEEP: no checkout exists to classify. The head
            // still reading the delta's base is the whole reconcile — the
            // claim's own fence answered it at claim time and nothing between
            // then and now may have moved it (a successor's apply cannot
            // enumerate ahead of this one's acceptance), so a moved row is
            // the durable stale-base refusal, and a still-base row re-drives
            // the publish (content-identical where the first drive's bytes
            // already landed) and resolves.
            if head.work_tree_artifact_id != delta_base_id(delta) {
                db.fail_work_apply_attempt(
                    attempt_id,
                    &format!(
                        "{}: the recorded /work head at {branch:?} no longer names the delta's \
                         base artifact — the pending apply's base is spent",
                        kata_core::operational::WORK_DELTA_BASE_STALE,
                    ),
                )?;
                return Ok(());
            }
            let new_tree_ref = publish_applied_tree(db, cas, attempt.execution_id, &head, delta)?;
            kata_core::fault_inject::operational_crash_point(
                "after_work_apply_published_before_resolve",
            );
            let advance = WorkTreeHeadAdvance {
                work_tree_artifact_id: new_tree_ref.id().0.0,
                candidate_commit_id: String::new(),
                expected_head_seq: head.head_seq,
                expected_artifact_id: head.work_tree_artifact_id,
            };
            let output = serde_json::json!({
                "work_apply": {
                    "applied": true,
                    "leg": "cas",
                    "recovered": true,
                    "head_artifact": new_tree_ref.id().0.to_string(),
                    "head_seq": head.head_seq + 1,
                }
            });
            db.resolve_work_apply_attempt(attempt_id, branch, Some(&advance), &output)?;
            return Ok(());
        }
        let (provider, handle) = Self::jj_workspace(provider, attempt.execution_id)?;
        provider.repair_stale_checkout(&handle)?;
        // Bounded op-log walk: no op older than the apply's CLAIM can carry
        // its `kata.effect` tag, so `find_effect_tag` stops at
        // `created_at_ms` rather than walking the whole log on every pass.
        // An op GC'd past the bound degrades to the predecessor + delta-nodes
        // fallback — a typed path, not a wrong answer.
        let claimed_at_ms = db.work_apply_claimed_at_ms(attempt_id)?.ok_or_else(|| {
            KataError::Storage(format!(
                "pending work-apply attempt {attempt_id} has no row"
            ))
        })?;
        let classified = provider.classify_work_apply(
            &handle,
            &head.candidate_commit_id,
            &attempt_id.to_string(),
            delta,
            claimed_at_ms,
        )?;
        match classified {
            kata_effects_contract::WorkApplyState::Applied { commit_id, tree_id } => {
                let new_tree_ref =
                    publish_applied_tree(db, cas, attempt.execution_id, &head, delta)?;
                let advance = WorkTreeHeadAdvance {
                    work_tree_artifact_id: new_tree_ref.id().0.0,
                    candidate_commit_id: commit_id.clone(),
                    expected_head_seq: head.head_seq,
                    expected_artifact_id: head.work_tree_artifact_id,
                };
                let output = serde_json::json!({
                    "work_apply": {
                        "applied": true,
                        "recovered": true,
                        "candidate_commit": commit_id,
                        "tree_id": tree_id,
                        "head_artifact": new_tree_ref.id().0.to_string(),
                        "head_seq": head.head_seq + 1,
                    }
                });
                db.resolve_work_apply_attempt(attempt_id, branch, Some(&advance), &output)?;
            }
            kata_effects_contract::WorkApplyState::NotApplied => {
                // Publish never landed: the jj transaction died before commit.
                // Re-drive the apply itself — the fence is the recorded head's
                // candidate, which is still what `@` names.
                let members = |object_id: ObjectId, size: u64| -> KataResult<Vec<u8>> {
                    cas.get_verified(
                        &object_id,
                        size,
                        kata_types::tree_artifact::MAX_MEMBER_BYTES,
                    )
                };
                match provider.apply_work_delta(
                    &handle,
                    &head.candidate_commit_id,
                    delta,
                    &members,
                    &attempt_id.to_string(),
                ) {
                    Ok(applied) => {
                        let new_tree_ref =
                            publish_applied_tree(db, cas, attempt.execution_id, &head, delta)?;
                        let advance = WorkTreeHeadAdvance {
                            work_tree_artifact_id: new_tree_ref.id().0.0,
                            candidate_commit_id: applied.commit_id.clone(),
                            expected_head_seq: head.head_seq,
                            expected_artifact_id: head.work_tree_artifact_id,
                        };
                        let output = serde_json::json!({
                            "work_apply": {
                                "applied": true,
                                "reapplied_after_crash": true,
                                "candidate_commit": applied.commit_id,
                                "tree_id": applied.tree_id,
                                "head_artifact": new_tree_ref.id().0.to_string(),
                                "head_seq": head.head_seq + 1,
                            }
                        });
                        db.resolve_work_apply_attempt(attempt_id, branch, Some(&advance), &output)?;
                    }
                    Err(error) if matches!(error, KataError::Validation(_)) => {
                        db.fail_work_apply_attempt(attempt_id, &error.to_string())?;
                    }
                    Err(error) => return Err(error),
                }
            }
            kata_effects_contract::WorkApplyState::Diverged { reason } => {
                db.fail_work_apply_attempt(
                    attempt_id,
                    &format!("work_apply_candidate_diverged: {reason}"),
                )?;
            }
        }
        Ok(())
    }
}

/// Load and decode the recorded `/work` delta artifact — the verified read the
/// claim path never re-does: the row's own object id and length bound it.
pub(crate) fn load_work_delta(
    db: &Arc<OperationalDb>,
    cas: &kata_core::store::cas::CasStore,
    artifact_id: [u8; 32],
) -> KataResult<TreeDelta> {
    let row = db.artifact(artifact_id)?.ok_or_else(|| {
        KataError::Storage(format!(
            "accepted outcome records /work delta artifact {} and the artifacts row is gone",
            ContentHash::new(artifact_id),
        ))
    })?;
    let bytes = cas.get_verified(
        &ObjectId::new(row.object_id),
        row.size_bytes,
        TreeDelta::MAXIMUM_ENCODED_BYTES,
    )?;
    serde_json::from_slice(&bytes).map_err(|error| {
        KataError::Storage(format!(
            "the recorded /work delta artifact {} does not decode: {error}",
            ContentHash::new(artifact_id),
        ))
    })
}

/// Publish the manifest the delta produces over the head's manifest and declare it
/// the execution's work-tree artifact — what the advanced head row names.
fn publish_applied_tree(
    db: &Arc<OperationalDb>,
    cas: &kata_core::store::cas::CasStore,
    execution_id: Ulid,
    head: &kata_core::operational::ExecutionWorkTreeHead,
    delta: &TreeDelta,
) -> KataResult<kata_types::execution_contract::ArtifactRef> {
    let row = db.artifact(head.work_tree_artifact_id)?.ok_or_else(|| {
        KataError::Storage(format!(
            "the head's /work artifact {} has no artifacts row",
            ContentHash::new(head.work_tree_artifact_id),
        ))
    })?;
    let base_bytes = cas.get_verified(
        &ObjectId::new(row.object_id),
        row.size_bytes,
        TreeManifest::MAXIMUM_ENCODED_BYTES,
    )?;
    let base: TreeManifest = serde_json::from_slice(&base_bytes).map_err(|error| {
        KataError::Storage(format!(
            "the head's recorded /work manifest does not decode: {error}"
        ))
    })?;
    let manifest = delta.apply(&base)?;
    let bytes = manifest.manifest_bytes()?;
    let durable = cas.put_durable(&bytes)?;
    let reference =
        kata_core::work_tree::declare_work_tree(db, cas, execution_id, &manifest, &durable)?;
    Ok(reference)
}

/// The delta's base artifact id — the head the claim's fence compares.
fn delta_base_id(delta: &TreeDelta) -> [u8; 32] {
    delta.base().id().0.0
}

/// Which head `row`'s apply advances, and the AUTHORED stage its
/// `#apply/<stage>` spelling names (the fold checks it against the program).
/// Derived from the program and the row alone:
///
/// * a stage EXPANSION's merged delta (`row.stage_id` is the expansion's own
///   `#op/<path>`) lands on the expanding stage's head;
/// * a stage-expansion MEMBER's delta (`row`'s path is a child of one; its
///   stage id may be the synthetic `<base>#child-<role>`) lands on the member's
///   own `/work` branch — never the parent head, which only the expansion's
///   merge advances;
/// * every other row — a plain stage, a review-loop member, a `parallel()`
///   join — lands on its stage's own coordinate (a join's is the barrier's, so
///   a fan-in's merged delta lands on exactly the head its inputs forked from).
///
/// # Errors
///
/// `Storage` for an `#op/` row that names no stage expansion of the program
/// (only a topology settle records a delta under an `#op` coordinate);
/// `work_head_coordinate`'s refusals otherwise.
fn apply_head(
    program: &kata_program::execution_program::ExecutionProgram,
    row: &PendingWorkApply,
    operation_path: &OperationPath,
) -> KataResult<(SmolStr, kata_types::work_tree_head::WorkTreeHeadCoordinate)> {
    if OperationPath::from_program_operation_stage_id(row.stage_id.as_str()).is_some() {
        let Some((stage, coordinate)) =
            kata_program::execution_program::expansion_settle_head(program, operation_path)?
        else {
            return Err(KataError::Storage(format!(
                "an accepted outcome at program operation {} records a /work delta, and only a \
                 topology settle may — this program maps the coordinate to no topology",
                row.stage_id
            )));
        };
        return Ok((stage.0, coordinate));
    }
    let head_stage =
        kata_types::execution_contract::parse_child_invocation_stage_name(row.stage_id.as_str())
            .map_or_else(|| SmolStr::new(row.stage_id.as_str()), |(base, _)| base);
    if let Some(branch) = kata_program::execution_program::expansion_member_work_coordinate(
        program,
        operation_path,
        row.stage_id.as_str(),
    )? {
        return Ok((head_stage, branch));
    }
    let coordinate = kata_program::execution_program::work_head_coordinate(
        program,
        &StageId(head_stage.clone()),
    )?;
    Ok((head_stage, coordinate))
}
