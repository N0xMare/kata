//! The `oci` `workspace_effect` driver.
//!
//! A `stage(agent = "workspace_effect", op = …)` under `oci` resolves at the
//! main as a durable main attempt, never on a worker:
//!
//! * the RUNNER claims it (`OperationalDb::claim_workspace_effect_attempt`) at
//!   the stage's own occurrence — the claim is the double-spend guard, and its
//!   blob carries the whole spec (`WorkspaceEffectSpec`) the verbs and the
//!   recovery legs read;
//! * the PERFORM runs here — [`Dispatcher::perform_workspace_effect`] — between
//!   the claim and the resolve, the jj verbs fencing on the recorded candidate
//!   (`oci_candidate_diverged` / `oci_candidate_disk_diverged`);
//! * the RESOLVE is the attempt's terminal — for `commit` the head row's
//!   `candidate_commit_id` (onto the empty `@` the commit leaves) and
//!   `committed_commit_id` (onto the finalized commit) advance
//!   compare-and-swapped in the resolving transaction itself;
//! * `promote` and `forge_export` fence on the recorded candidate but DELIVER
//!   the spec's `delivered_commit` — after a `commit`, the committed commit
//!   beneath the empty `@`, so trunk and the PR head are the described commit;
//! * a crash between claim and resolve leaves `pending`, and the sweep —
//!   [`Dispatcher::drive_pending_workspace_effects`], run on every pass —
//!   classifies the mutation from repository facts rather than re-driving
//!   blindly;
//! * `forge_export` issues its push and its pull request each under an intent
//!   row, and its recovery reads the REMOTE through each intent's observer
//!   (`forge_export`, [`Dispatcher::drive_forge_export`]).
//!
//! The approval gate: `approval_required` claims park `awaiting_approval` with
//! the scope in the park payload; [`Dispatcher::decide_workspace_effect_gate`]
//! approves (→ `pending`, the sweep performs) or rejects (→ `failed`, proven
//! not performed).

use std::sync::Arc;

use kata_core::operational::{
    HeadCommitAdvance, MainResolution, PendingWorkspaceEffect, WorkspaceEffectSpec,
};
use kata_effects_contract::WorkspaceEffectClass;
use kata_effects_contract::{
    ExecutionWorkspaceHandle, ExecutionWorkspaceKey, ExecutionWorkspaceProvider, Forge,
};
use kata_types::error::{KataError, KataResult};
use kata_types::target::{TARGET_NOT_LANDABLE, TargetRefusal};
use kata_types::workflow::WorkspaceEffectOp;
use kata_vcs::jj::FORGE_EXPORT_UNCOMMITTED_CANDIDATE;
use ulid::Ulid;

use crate::dispatcher::Dispatcher;

mod forge_export;

pub use forge_export::{
    FORGE_OBSERVER_ASK_SPACING, FORGE_OBSERVER_UNANSWERED_BOUND, ForgeReconcile,
};

/// The code of a pending attempt the sweep recorded `failed` because its
/// classify phase returned an error (`Dispatcher::resolve_unclassified_effect`):
/// the facts that answer whether the effect ran could not be read, so the
/// record claims neither answer.
const WORKSPACE_EFFECT_UNCLASSIFIED: &str = "workspace_effect_unclassified";

/// Why a Running isolated execution's workspace is gone though its run has
/// not ended: one of its own `park`/`promote` effects removed it — both verbs
/// tear the workspace down on every success path, and on a landing park — so
/// recovery resumes the execution without one. Only these two ops remove a
/// workspace: `commit` leaves it live and `forge_export` never touches it, so
/// neither accounts for an absent one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkspaceTeardown {
    /// A `park` or `promote` attempt resolved `completed`: its verb returned,
    /// teardown included, or the sweep resolved it off a published ref after
    /// finishing the teardown.
    Completed {
        /// The effect's stage.
        stage_id: String,
        /// `park` or `promote`.
        op: WorkspaceEffectOp,
    },
    /// A `park` or `promote` attempt is still `pending` and the repository
    /// shows its verb published — `parked/<exec>` at the delivered commit (`Parked`),
    /// trunk holding the delivered commit (`Promoted`), or the landing's own
    /// revalidation park (`LandingParked`). The pre-fold sweep resolves it
    /// from the same classification before anything dispatches.
    Published {
        /// The effect's stage.
        stage_id: String,
        /// `park` or `promote`.
        op: WorkspaceEffectOp,
    },
}

/// The ops whose verb removes the execution workspace: `park` and `promote`
/// (`ExecutionWorkspaceProvider::park_workspace_effect` /
/// `promote_workspace_effect`). `commit` finalizes in place and `forge_export`
/// is a sink that never touches the workspace.
const fn removes_workspace(op: WorkspaceEffectOp) -> bool {
    matches!(op, WorkspaceEffectOp::Park | WorkspaceEffectOp::Promote)
}

/// What [`Dispatcher::perform_workspace_effect`] produced — the outcome the
/// resolving transition records.
pub enum EffectPerformed {
    /// The op landed: the stage's output envelope.
    Output(serde_json::Value),
    /// `commit` additionally advances the head row — the candidate and the
    /// committed commit `resolve_workspace_effect_attempt` compare-and-swaps
    /// in the resolving transaction.
    Commit {
        /// The stage's output envelope.
        output: serde_json::Value,
        /// The recorded candidate the head still names.
        expected_candidate: String,
        /// The new empty `@` `jj commit` left.
        new_candidate: String,
        /// The finalized commit — the head row's new `committed_commit_id`.
        committed_commit: String,
    },
}

/// The envelope one `workspace_effect` stage's recorded output carries —
/// `{"content": "<envelope>", "stop_reason": "effect_applied", …}` — the
/// document a downstream `stages.<x>` read sees.
fn effect_output(stage_name: &str, envelope: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "content": envelope.to_string(),
        "stop_reason": "effect_applied",
        "stage": stage_name,
    })
}

/// The operation-envelope JSON the content carries — `{"operation": …, …}`.
fn effect_envelope(
    op: WorkspaceEffectOp,
    extra: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    let mut envelope = serde_json::Map::new();
    envelope.insert(
        "operation".to_owned(),
        serde_json::Value::String(op.as_str().to_owned()),
    );
    envelope.extend(extra);
    serde_json::Value::Object(envelope)
}

/// What a `forge_export` pushes and asks the forge for — derived by
/// [`Dispatcher::forge_export_plan`] on every drive from the claim's recorded
/// spec and the frozen invocation, immutable facts, so no two drives of one
/// export disagree.
struct ForgeExportPlan {
    /// `kata/<exec>` — the branch written and pushed.
    branch: String,
    /// The git remote the branch is pushed to.
    remote: String,
    /// The pull request's base branch.
    base: String,
    /// The pull request's title.
    title: String,
    /// The pull request's body.
    body: String,
}

impl Dispatcher {
    /// The execution's FROZEN landable branch, read off the immutable
    /// invocation: the branch admission resolved, never a name resolved now.
    /// `None` when the invocation froze no target, or a target with no
    /// landable branch (an unborn trunk, a pull request). A `promote`'s claim
    /// records it as the spec's `target` (what its approval gate shows), its
    /// perform lands on it and its classify — the sweep's and the perform's
    /// reconcile-first — judges it, so all of them read one branch.
    pub(crate) fn frozen_landing_branch(&self, execution_id: Ulid) -> KataResult<Option<String>> {
        Ok(self
            .execution_lifecycle()
            .invocation(execution_id)?
            .and_then(|stored| stored.invocation.target)
            .and_then(|target| target.branch))
    }

    /// A `forge_export`'s pull request base: [`Self::frozen_landing_branch`].
    ///
    /// # Errors
    ///
    /// `target_not_landable` when the invocation froze none (admission
    /// refuses a program that exports under such a target first; this is its
    /// run-time restatement, never a default).
    fn forge_export_base(&self, execution_id: Ulid) -> KataResult<String> {
        self.frozen_landing_branch(execution_id)?.ok_or_else(|| {
            KataError::from(TargetRefusal::new(
                TARGET_NOT_LANDABLE,
                format!(
                    "forge_export for execution {execution_id}: its invocation froze no \
                         landable branch to open a pull request into; nothing is pushed"
                ),
            ))
        })
    }

    /// The push remote a `forge_export` CLAIM records
    /// (`WorkspaceEffectSpec::forge_remote`): the one the repository names for
    /// the frozen landable branch (`forge_export_remote`), resolved once,
    /// before the claim, so every later drive — the live claim, a recovery
    /// after a crash, an approval decided later — pushes to and reads back the
    /// remote the claim named, whatever the host's git config says by then.
    ///
    /// # Errors
    ///
    /// `target_not_landable` ([`Self::forge_export_base`]) and
    /// `forge_remote_unresolved` (the repository names no single remote),
    /// both before anything is claimed or pushed.
    pub fn forge_export_claim_remote(
        &self,
        execution_id: Ulid,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
    ) -> KataResult<String> {
        provider.forge_export_remote(&self.forge_export_base(execution_id)?)
    }

    /// The plan of a claimed `forge_export`, or its refusal before anything is
    /// pushed.
    ///
    /// The pull request's base is [`Self::forge_export_base`]; the push remote
    /// is the one the claim RECORDED ([`Self::forge_export_claim_remote`]).
    /// Neither is pack text, and neither is re-resolved here: every drive of
    /// the export pushes to and asks for the same thing.
    ///
    /// Refuses `target_not_landable` when the invocation froze no landable
    /// branch — a fact of the immutable invocation, so a refusal here means
    /// nothing of the export was ever issued.
    fn forge_export_plan(
        &self,
        execution_id: Ulid,
        spec: &WorkspaceEffectSpec,
    ) -> KataResult<ForgeExportPlan> {
        let base = self.forge_export_base(execution_id)?;
        let remote = spec.forge_remote.clone().ok_or_else(|| {
            KataError::Internal(format!(
                "forge_export for execution {execution_id} carries no claimed remote — the \
                 claim records one for every export"
            ))
        })?;
        let forge_spec = spec.forge.clone().unwrap_or_default();
        Ok(ForgeExportPlan {
            branch: format!("{}{}", kata_vcs::trunk::FORGE_BRANCH_PREFIX, execution_id),
            remote,
            base,
            title: forge_spec
                .title
                .unwrap_or_else(|| format!("kata: land execution {execution_id}")),
            body: forge_spec
                .body
                .unwrap_or_else(|| format!("Exported by kata execution {execution_id}")),
        })
    }

    /// Refuse `forge_export_uncommitted_candidate`, before the push's intent,
    /// exactly when a `commit` ran (the head row's `committed_commit_id` is
    /// set) and the claim's delivered commit is neither that commit nor one a
    /// completed `promote` of this execution landed (`landed_promote_commits`)
    /// — the candidate changed after the commit and nothing recorded the
    /// change, so the export would publish edits no boundary named.
    /// `commit → promote → forge_export` and a read-only stage between
    /// `commit` and the export deliver the committed commit, and `commit →
    /// shell(rw) → promote → forge_export` delivers the commit its promote
    /// landed: all three pass. Nothing writes `/work` after a `promote` (it is
    /// terminal for every dependent but the export), so no candidate can
    /// change after one.
    fn refuse_uncommitted_export(
        &self,
        execution_id: Ulid,
        spec: &WorkspaceEffectSpec,
    ) -> KataResult<()> {
        let head = self
            .execution_lifecycle()
            .db()
            .execution_work_tree_head(execution_id)?
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "forge_export for execution {execution_id} found no /work head row — a \
                     claimed effect always has one"
                ))
            })?;
        if !head.committed_commit_id.is_empty()
            && spec.delivered_commit != head.committed_commit_id
            && !self
                .execution_lifecycle()
                .db()
                .landed_promote_commits(execution_id)?
                .contains(&spec.delivered_commit)
        {
            return Err(KataError::Validation(format!(
                "{FORGE_EXPORT_UNCOMMITTED_CANDIDATE}: forge_export for execution \
                 {execution_id} would push {}, but the execution's latest `commit` finalized \
                 {} and no `promote` of this execution landed it — the candidate changed after \
                 the commit, so the export would publish edits no `commit` or `promote` \
                 recorded; nothing is pushed. Put a `commit` after the last stage that writes \
                 /work",
                spec.delivered_commit, head.committed_commit_id
            )));
        }
        Ok(())
    }

    /// PERFORM the claimed `workspace_effect` attempt and resolve it — one
    /// driver step for the live claim leg and for the sweep's `NotPerformed`
    /// leg. Refusals from the verbs (the divergence precondition, a stale
    /// promote pin) record the attempt `failed` — a refused effect is a typed
    /// answer, not a retry. A `forge_export` is handed to its own driver,
    /// [`Self::drive_forge_export`].
    ///
    /// # Errors
    ///
    /// The store's own failures surface; a refused or failed effect is
    /// recorded on the attempt and returned `Ok`.
    pub fn perform_workspace_effect(
        &self,
        execution_id: Ulid,
        attempt_id: Ulid,
        stage_name: &str,
        spec: &WorkspaceEffectSpec,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        forge: Option<&Arc<dyn Forge>>,
    ) -> KataResult<()> {
        if spec.op == WorkspaceEffectOp::ForgeExport {
            return self.drive_forge_export(
                execution_id,
                attempt_id,
                stage_name,
                spec,
                provider,
                forge,
                forge_export::ObserverAsk::Scheduled,
            );
        }
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        // Two drivers can reach this perform — the runner's pass loop and the
        // approval-gate decision path — on separate Dispatcher handles over
        // one db. The lock serializes them, and the re-check inside it proves
        // the attempt is still `pending` on a still-`running` execution before
        // any jj op runs: a cancel that beat us settled the attempt
        // `cancelled`, and performing after that would land a mutation the
        // record cannot resolve.
        let _permit = db.effect_perform_lock();
        if !db.workspace_effect_attempt_drivable(attempt_id)? {
            return Ok(());
        }
        // The landable branch the execution's target froze — a promote lands
        // on the trunk admission named or refuses.
        let landing_branch = self.frozen_landing_branch(execution_id)?;
        let performed = Self::perform_workspace_effect_inner(
            execution_id,
            attempt_id,
            stage_name,
            spec,
            provider,
            landing_branch.as_deref(),
        );
        kata_core::fault_inject::operational_crash_point(
            "after_workspace_effect_jj_publish_before_resolution",
        );
        // Owned values outlive the borrowed resolution — `MainResolution`
        // borrows its output/reason, so the owned envelope and failure text
        // are bound first.
        // A typed REFUSAL (`Validation`) is the effect's own pre-publish
        // answer — settle `failed` with it. Every other error is ambiguous: an
        // `Internal`/`OutcomeUnknown` can follow a jj publish that landed
        // (the `commit` verb's post-publish checkout failure is exactly that),
        // so it propagates and leaves the attempt `pending` for the sweep's
        // repository-facts classify — the same shape `apply_and_resolve` uses.
        let (output_value, reason_value, update) = match performed {
            Ok(EffectPerformed::Output(output)) => (Some(output), None, None),
            Ok(EffectPerformed::Commit {
                output,
                expected_candidate,
                new_candidate,
                committed_commit,
            }) => (
                Some(output),
                None,
                Some((expected_candidate, new_candidate, committed_commit)),
            ),
            Err(KataError::Validation(reason)) => (None, Some(reason), None),
            Err(error) => return Err(error),
        };
        let resolution = if let Some(output) = output_value.as_ref() {
            MainResolution::Complete { output }
        } else {
            MainResolution::Fail {
                reason: reason_value.as_deref().unwrap_or("effect refused"),
                terminal_charge: None,
            }
        };
        let update_ref = update
            .as_ref()
            .map(|(expected, new, committed)| HeadCommitAdvance {
                expected_candidate: expected,
                new_candidate: new,
                committed_commit: committed,
            });
        // A crash AFTER the resolve commits and before this returns is benign —
        // the attempt is terminal and the sweep drains nothing.
        if db
            .resolve_workspace_effect_attempt(attempt_id, update_ref.as_ref(), &resolution)?
            .is_none()
        {
            // Premise lapsed between the drivable re-check and the resolve:
            // under the perform lock the only other settler is the outcome's
            // terminalization drain, which marks the attempt `cancelled` in
            // the publication commit — the record wins, and the mutation the
            // perform may have landed is itself durable (the tagged op, the
            // written ref), so nothing here is dropped: the effect's evidence
            // survives the cancelled row exactly as recovery reads it.
        }
        Ok(())
    }

    /// The effect's perform leg — the verbs and their envelopes, no resolving.
    /// A `forge_export` never reaches it ([`Self::drive_forge_export`]).
    fn perform_workspace_effect_inner(
        execution_id: Ulid,
        attempt_id: Ulid,
        stage_name: &str,
        spec: &WorkspaceEffectSpec,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        landing_branch: Option<&str>,
    ) -> KataResult<EffectPerformed> {
        let key = ExecutionWorkspaceKey::execution(execution_id);
        let tag = attempt_id.to_string();
        // The publish-checkpoint repair precedes every verb: a crash between a
        // jj publish and its checkout leaves the working copy stale, and the
        // precondition's clean-check would misread that as divergence.
        if let Some(handle) = provider.lookup_workspace(&key)? {
            provider.repair_stale_checkout(&handle)?;
        }
        match spec.op {
            WorkspaceEffectOp::Commit => {
                let committed =
                    provider.commit_workspace_effect(&key, &spec.candidate_commit, &tag)?;
                let output = effect_output(
                    stage_name,
                    effect_envelope(
                        spec.op,
                        serde_json::json!({
                            "ref_name": committed.ref_name,
                            "commit_sha": committed.commit_sha,
                        })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    ),
                );
                Ok(EffectPerformed::Commit {
                    output,
                    expected_candidate: spec.candidate_commit.clone(),
                    new_candidate: committed.new_wc_commit_id,
                    committed_commit: committed.commit_sha,
                })
            }
            WorkspaceEffectOp::Park => {
                // Reconcile-first: the execution-scoped parked ref already at the
                // delivered commit is this effect's own earlier performance —
                // resolve off it, never re-run (and never double-write).
                // The ref is always `parked/<exec-id>` — the authored label is
                // spec metadata, never the ref name (execution-scoped refs are
                // unambiguous under recovery and cannot collide cross-execution).
                let ref_name = provider.parked_ref_name(&key, None);
                if let Some(sha) = Self::parked_ref_commit(provider, &key, &ref_name)?
                    && sha == spec.delivered_commit
                {
                    Self::finish_owed_teardown(provider, &key, &tag)?;
                    return Ok(EffectPerformed::Output(effect_output(
                        stage_name,
                        effect_envelope(
                            spec.op,
                            serde_json::json!({
                                "ref_name": ref_name,
                                "commit_sha": sha,
                            })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                        ),
                    )));
                }
                let parked = provider.park_workspace_effect(
                    &key,
                    &spec.candidate_commit,
                    &spec.delivered_commit,
                    &tag,
                )?;
                Ok(EffectPerformed::Output(effect_output(
                    stage_name,
                    effect_envelope(
                        spec.op,
                        serde_json::json!({
                            "ref_name": parked.ref_name,
                            "commit_sha": parked.commit_sha,
                        })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    ),
                )))
            }
            WorkspaceEffectOp::Promote => {
                // Reconcile-first: a promote whose landing already ran classifies
                // `Promoted` off the frozen branch — the sweep leg answers it; the
                // live leg gets here only on a fresh claim, but the same check
                // makes a re-drive after a mid-land crash idempotent.
                let handle = provider.lookup_workspace(&key)?;
                match provider.classify_workspace_effect(
                    &key,
                    handle.as_ref(),
                    spec.op,
                    &spec.candidate_commit,
                    &spec.delivered_commit,
                    landing_branch,
                )? {
                    WorkspaceEffectClass::Promoted {
                        ref_name,
                        commit_sha,
                    } => {
                        Self::finish_owed_teardown(provider, &key, &tag)?;
                        return Ok(EffectPerformed::Output(effect_output(
                            stage_name,
                            effect_envelope(
                                spec.op,
                                serde_json::json!({
                                    "ref_moved": ref_name,
                                    "commit_sha": commit_sha,
                                })
                                .as_object()
                                .cloned()
                                .unwrap_or_default(),
                            ),
                        )));
                    }
                    // The landing already answered: the refusal the verb
                    // returns, recorded the way the verb's is, after the
                    // teardown it still owed.
                    WorkspaceEffectClass::LandingParked { reason } => {
                        Self::finish_owed_teardown(provider, &key, &tag)?;
                        return Err(KataError::Validation(reason));
                    }
                    WorkspaceEffectClass::Diverged { reason } => {
                        return Err(KataError::Validation(reason));
                    }
                    // `NotPerformed` and the other op's shapes fall through to
                    // the verb's own precondition, which re-derives the
                    // divergence before it moves a ref.
                    _ => {}
                }
                let promoted = provider.promote_workspace_effect(
                    &key,
                    &spec.pin,
                    &spec.candidate_commit,
                    &spec.delivered_commit,
                    &tag,
                    landing_branch,
                )?;
                Ok(EffectPerformed::Output(effect_output(
                    stage_name,
                    effect_envelope(
                        spec.op,
                        serde_json::json!({
                            "ref_moved": promoted.ref_name,
                            "commit_sha": promoted.commit_sha,
                        })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    ),
                )))
            }
            WorkspaceEffectOp::ForgeExport => Err(KataError::Internal(format!(
                "forge_export attempt {attempt_id} reached the verbs' perform; its driver is \
                 drive_forge_export"
            ))),
        }
    }

    /// The parked ref's commit, if it resolves — the park reconcile-first's read.
    fn parked_ref_commit(
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        key: &ExecutionWorkspaceKey,
        ref_name: &str,
    ) -> KataResult<Option<String>> {
        Ok(provider
            .lookup_parked_workspace(key, ref_name)?
            .map(|parked| parked.commit_sha))
    }

    /// The teardown a performed `park` or `promote` still owes. Both verbs
    /// publish (the parked ref, the land, the landing's park) and THEN remove
    /// the workspace, so a crash between the two (kata-vcs's
    /// `after_jj_publish_before_teardown` and `after_landing_park_before_teardown`
    /// windows) leaves the effect answered and its workspace standing, and a
    /// crash inside the teardown (`after_wc_removal_before_forget`,
    /// `after_forget_before_remove_dir`, or inside the directory's removal)
    /// leaves it partly removed. Every leg that answers such an effect from
    /// repository facts instead of re-running the verb (the sweep's
    /// `Parked`/`Promoted`/`LandingParked` arms, the perform's reconcile-first
    /// `park` and `Promoted`/`LandingParked` arms) runs the teardown here
    /// whatever `lookup_workspace` reports — a partly done teardown is no live
    /// workspace to it — because the provider's teardown is idempotent step by
    /// step.
    fn finish_owed_teardown(
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        key: &ExecutionWorkspaceKey,
        effect_tag: &str,
    ) -> KataResult<()> {
        provider.teardown_workspace_effect(key, effect_tag)
    }

    /// THE SWEEP — every pass re-drives the execution's `pending`
    /// `workspace_effect` attempts. Non-isolated executions record no provider
    /// and no effects, so this is a `provider.is_none()` → `Ok(0)` early-out;
    /// a pending row on a non-isolated run is a rig inconsistency, surfaced.
    ///
    /// Per pending attempt: classify from repository facts —
    ///
    /// * performed (the verb's durable mark exists — `Committed`, `Parked`,
    ///   `Promoted`) → resolve `completed` off the
    ///   classification, never re-driving — a `Parked`/`Promoted` first
    ///   finishes the workspace teardown a crash inside the verb left owed,
    ///   whole or partly done;
    /// * `LandingParked` (the promote's landing parked its rebase for
    ///   revalidation) → finish that owed teardown, then resolve `failed` with
    ///   the refusal the verb returns for that park;
    /// * `NotPerformed` → perform it (the verbs are idempotent over their own
    ///   ref names);
    /// * `Diverged` → resolve `failed` with the classified reason — named
    ///   uncertainty, never a blind redo;
    /// * `forge_export` → [`Self::drive_forge_export`]: the step its intents
    ///   leave owed — the push from the start when none was issued, otherwise
    ///   the owed effect's observer over the remote;
    /// * an error out of the classify phase itself (the workspace lookup, the
    ///   op's classify) → resolve `failed` under `workspace_effect_unclassified`
    ///   naming it ([`Self::resolve_unclassified_effect`]), never out of the
    ///   sweep. A store failure, and an error after the classify (the
    ///   stale-checkout repair, the re-perform, the ref write, the teardown)
    ///   still propagate.
    ///
    /// The classify reads refs and the view (it loads a live workspace only to
    /// name its `@`; it never snapshots or checks out), so it runs on the
    /// workspace as found. The stale-checkout repair waits for a step that
    /// uses the working copy ([`Self::repair_live_workspace`]), so a working
    /// copy that cannot be repaired never hides the ref that answers a
    /// published `park` or `promote`.
    pub fn drive_pending_workspace_effects(
        &self,
        execution_id: Ulid,
        provider: Option<&Arc<dyn ExecutionWorkspaceProvider>>,
        forge: Option<&Arc<dyn Forge>>,
    ) -> KataResult<usize> {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        let pending = db.pending_workspace_effects(execution_id)?;
        if pending.is_empty() {
            return Ok(0);
        }
        let Some(provider) = provider else {
            return Err(KataError::Internal(format!(
                "execution {execution_id} holds {} pending workspace_effect attempts but no \
                 workspace provider is attached — the `oci` main-resolved effect cannot classify \
                 without one",
                pending.len()
            )));
        };
        let mut progressed = 0;
        for attempt in pending {
            self.drive_one_workspace_effect(execution_id, &attempt, provider, forge)?;
            progressed += 1;
        }
        Ok(progressed)
    }

    /// Converge the live workspace's working copy a crash left stale
    /// (`repair_stale_checkout`) — after the classify, and only before a step
    /// that uses the working copy: the `Committed` arm (the run goes on in the
    /// workspace); the re-perform and a `forge_export`'s push repair inside
    /// their own legs. Nothing here when the workspace is not live.
    fn repair_live_workspace(
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        handle: Option<&ExecutionWorkspaceHandle>,
    ) -> KataResult<()> {
        if let Some(handle) = handle {
            provider.repair_stale_checkout(handle)?;
        }
        Ok(())
    }

    /// Record a pending attempt the sweep could not classify as `failed`
    /// under [`WORKSPACE_EFFECT_UNCLASSIFIED`], naming `error`, which came out
    /// of the classify phase — the workspace lookup or the op's classify. The
    /// facts that answer whether the effect
    /// ran could not be read, so the record says so and claims neither answer:
    /// a typed error there (the promote classify's `Validation` for a frozen
    /// branch it cannot find) is a fact the classify could not read, not the
    /// verb's refusal, and is recorded under the same code. Like `Diverged`,
    /// the attempt is never re-driven and nothing is torn down. An error left
    /// to propagate out of the sweep would instead fail the whole run in the
    /// pre-fold slot (`run_replay`), the attempt cancelled with no reason of
    /// its own.
    fn resolve_unclassified_effect(
        &self,
        attempt: &PendingWorkspaceEffect,
        error: &KataError,
    ) -> KataResult<()> {
        let reason = format!(
            "{WORKSPACE_EFFECT_UNCLASSIFIED}: recovery could not classify the pending {} attempt \
             {} — {error}. Whether it ran is unknown: it is recorded failed, never re-driven, and \
             nothing is torn down",
            attempt.spec.op.as_str(),
            attempt.attempt_id,
        );
        self.execution_lifecycle()
            .db()
            .resolve_workspace_effect_attempt(
                attempt.attempt_id,
                None,
                &MainResolution::Fail {
                    reason: reason.as_str(),
                    terminal_charge: None,
                },
            )?;
        Ok(())
    }

    /// The [`WorkspaceTeardown`] that accounts for `execution_id`'s missing
    /// workspace, or `None` when nothing on its chain does. The caller asks it
    /// only once the provider reports no live workspace.
    ///
    /// Accepted, and only these: a `park`/`promote` attempt `completed`; a
    /// `park`/`promote` attempt `pending` that the repository classifies
    /// `Parked`, `Promoted` or `LandingParked` with the workspace gone.
    ///
    /// Not accepted: any `commit` or `forge_export` attempt in any state; a
    /// `failed` or `cancelled` `park`/`promote` (a refused verb removed
    /// nothing; the landing park's failure is answered by the parked-candidate
    /// proof instead); a `pending` `park`/`promote` that classifies
    /// `Diverged` — a workspace torn down without the effect's mark is a
    /// foreign removal — or `NotPerformed`. The classify is asked with no
    /// handle, and the jj provider answers `NotPerformed` only for a standing
    /// workspace at the candidate, so no jj run reaches that arm here; it
    /// refuses should a provider answer it.
    ///
    /// # Errors
    ///
    /// The chain's and the provider's read refusals, a pending `park`/`promote`'s
    /// classify error among them (the frozen trunk renamed away). An error is no
    /// answer for the missing workspace: boot refuses the restart naming it and
    /// records nothing, where the sweep of a run boot resumed records the same
    /// error `workspace_effect_unclassified` (`resolve_unclassified_effect`).
    pub fn workspace_teardown(
        &self,
        execution_id: Ulid,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
    ) -> KataResult<Option<WorkspaceTeardown>> {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        if let Some(effect) = db
            .completed_workspace_effects(execution_id)?
            .into_iter()
            .find(|effect| removes_workspace(effect.spec.op))
        {
            return Ok(Some(WorkspaceTeardown::Completed {
                stage_id: effect.stage_id,
                op: effect.spec.op,
            }));
        }
        let key = ExecutionWorkspaceKey::execution(execution_id);
        for attempt in db.pending_workspace_effects(execution_id)? {
            let op = attempt.spec.op;
            if !removes_workspace(op) {
                continue;
            }
            let landing_branch = if op == WorkspaceEffectOp::Promote {
                self.frozen_landing_branch(execution_id)?
            } else {
                None
            };
            match provider.classify_workspace_effect(
                &key,
                None,
                op,
                &attempt.spec.candidate_commit,
                &attempt.spec.delivered_commit,
                landing_branch.as_deref(),
            )? {
                WorkspaceEffectClass::Parked { .. }
                | WorkspaceEffectClass::Promoted { .. }
                | WorkspaceEffectClass::LandingParked { .. } => {
                    return Ok(Some(WorkspaceTeardown::Published {
                        stage_id: attempt.stage_id,
                        op,
                    }));
                }
                WorkspaceEffectClass::NotPerformed
                | WorkspaceEffectClass::Committed { .. }
                | WorkspaceEffectClass::Diverged { .. } => {}
            }
        }
        Ok(None)
    }

    /// One sweep row: classify from facts, then resolve or perform. Never a
    /// blind redo — `Diverged` is recorded `failed` with the reason, and so is
    /// an error the classify phase returned
    /// ([`Self::resolve_unclassified_effect`]).
    fn drive_one_workspace_effect(
        &self,
        execution_id: Ulid,
        attempt: &PendingWorkspaceEffect,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        forge: Option<&Arc<dyn Forge>>,
    ) -> KataResult<()> {
        if attempt.spec.op == WorkspaceEffectOp::ForgeExport {
            return self.drive_forge_export(
                execution_id,
                attempt.attempt_id,
                &attempt.stage_id,
                &attempt.spec,
                provider,
                forge,
                forge_export::ObserverAsk::Scheduled,
            );
        }
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        let key = ExecutionWorkspaceKey::execution(execution_id);
        let handle = match provider.lookup_workspace(&key) {
            Ok(handle) => handle,
            Err(error) => return self.resolve_unclassified_effect(attempt, &error),
        };
        let op = attempt.spec.op;
        // The branch the perform lands a `promote` on — judged here,
        // not the trunk the repository resolves after a crash. Only a
        // promote reads it: `commit` and `park` never judge a branch.
        let landing_branch = if op == WorkspaceEffectOp::Promote {
            self.frozen_landing_branch(execution_id)?
        } else {
            None
        };
        let class = match provider.classify_workspace_effect(
            &key,
            handle.as_ref(),
            op,
            &attempt.spec.candidate_commit,
            &attempt.spec.delivered_commit,
            landing_branch.as_deref(),
        ) {
            Ok(class) => class,
            Err(error) => return self.resolve_unclassified_effect(attempt, &error),
        };
        match class {
            WorkspaceEffectClass::NotPerformed => {
                kata_core::fault_inject::operational_crash_point(
                    "after_workspace_effect_claimed_before_jj_publish",
                );
                self.perform_workspace_effect(
                    execution_id,
                    attempt.attempt_id,
                    &attempt.stage_id,
                    &attempt.spec,
                    provider,
                    forge,
                )
            }
            WorkspaceEffectClass::Committed {
                commit_sha,
                new_wc_commit_id,
            } => {
                // The finalize landed; the `exec-<id>` bookmark is the
                // second publish — ensure it (the crash window between
                // them is exactly this leg's), then resolve with the
                // head-row candidate advance. The run goes on in this
                // workspace, so its working copy is converged first.
                Self::repair_live_workspace(provider, handle.as_ref())?;
                provider.ensure_workspace_ref(
                    &key,
                    &format!("exec-{execution_id}"),
                    &commit_sha,
                    &attempt.attempt_id.to_string(),
                )?;
                let output = effect_output(
                    &attempt.stage_id,
                    effect_envelope(
                        attempt.spec.op,
                        serde_json::json!({
                            "ref_name": format!("exec-{execution_id}"),
                            "commit_sha": commit_sha,
                        })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    ),
                );
                db.resolve_workspace_effect_attempt(
                    attempt.attempt_id,
                    Some(&HeadCommitAdvance {
                        expected_candidate: &attempt.spec.candidate_commit,
                        new_candidate: &new_wc_commit_id,
                        committed_commit: &commit_sha,
                    }),
                    &MainResolution::Complete { output: &output },
                )?;
                Ok(())
            }
            WorkspaceEffectClass::Parked {
                ref_name,
                commit_sha,
            } => {
                Self::finish_owed_teardown(provider, &key, &attempt.attempt_id.to_string())?;
                let output = effect_output(
                    &attempt.stage_id,
                    effect_envelope(
                        attempt.spec.op,
                        serde_json::json!({
                            "ref_name": ref_name,
                            "commit_sha": commit_sha,
                        })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    ),
                );
                db.resolve_workspace_effect_attempt(
                    attempt.attempt_id,
                    None,
                    &MainResolution::Complete { output: &output },
                )?;
                Ok(())
            }
            WorkspaceEffectClass::Promoted {
                ref_name,
                commit_sha,
            } => {
                Self::finish_owed_teardown(provider, &key, &attempt.attempt_id.to_string())?;
                let output = effect_output(
                    &attempt.stage_id,
                    effect_envelope(
                        attempt.spec.op,
                        serde_json::json!({
                            "ref_moved": ref_name,
                            "commit_sha": commit_sha,
                        })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    ),
                );
                db.resolve_workspace_effect_attempt(
                    attempt.attempt_id,
                    None,
                    &MainResolution::Complete { output: &output },
                )?;
                Ok(())
            }
            WorkspaceEffectClass::LandingParked { reason } => {
                Self::finish_owed_teardown(provider, &key, &attempt.attempt_id.to_string())?;
                db.resolve_workspace_effect_attempt(
                    attempt.attempt_id,
                    None,
                    &MainResolution::Fail {
                        reason: reason.as_str(),
                        terminal_charge: None,
                    },
                )?;
                Ok(())
            }
            WorkspaceEffectClass::Diverged { reason } => {
                db.resolve_workspace_effect_attempt(
                    attempt.attempt_id,
                    None,
                    &MainResolution::Fail {
                        reason: reason.as_str(),
                        terminal_charge: None,
                    },
                )?;
                Ok(())
            }
        }
    }

    /// CANCEL an execution's parked `workspace_effect` gates — the
    /// cancel-propagation arm, mirroring `cancel_parked_capsule_gates`: a
    /// parked effect gate resolves `cancelled` proven-not-performed (the
    /// attempt never left the park — no jj write ever ran for it).
    pub fn cancel_parked_workspace_effect_gates(
        &self,
        execution_id: Ulid,
        reason: &str,
    ) -> KataResult<usize> {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        let mut settled = 0;
        for gate in db.parked_workspace_effect_gates(execution_id)? {
            let cancel_reason = format!(
                "cancelled: {reason}. The workspace_effect was parked awaiting approval and no \
                 mutation for it ever ran — proven not performed"
            );
            if db
                .resolve_workspace_effect_attempt_parked(
                    gate.attempt_id,
                    &MainResolution::Cancel {
                        reason: cancel_reason.as_str(),
                        terminal_charge: None,
                    },
                )?
                .is_some()
            {
                settled += 1;
            }
        }
        Ok(settled)
    }
}

impl Dispatcher {
    /// What `GET /approvals` shows for one parked `workspace_effect` gate —
    /// `(reason, awaiting_since_ms, scope)` off the park's own payload, or
    /// `None` when `attempt_id` is not a parked workspace-effect gate. A
    /// `forge_export` gate also names where the push goes, derived here from
    /// stored facts rather than written into the park: the remote its claim
    /// recorded and the landable branch the invocation froze.
    pub(crate) fn workspace_effect_gate_view(
        &self,
        attempt_id: Ulid,
    ) -> KataResult<
        Option<(
            String,
            Option<u64>,
            kata_types::approval::PendingWorkspaceEffectGate,
        )>,
    > {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        let Some(execution_id) = db.workspace_effect_attempt(attempt_id)? else {
            return Ok(None);
        };
        let Some(gate) = db
            .parked_workspace_effect_gates(execution_id)?
            .into_iter()
            .find(|gate| gate.attempt_id == attempt_id)
        else {
            return Ok(None);
        };
        let forge_base = if gate.scope.op == WorkspaceEffectOp::ForgeExport.as_str() {
            self.frozen_landing_branch(execution_id)?
        } else {
            None
        };
        Ok(Some((
            gate.reason,
            u64::try_from(gate.parked_at_ms).ok(),
            kata_types::approval::PendingWorkspaceEffectGate {
                op: gate.scope.op.clone(),
                target: gate.scope.target,
                candidate_commit: gate.scope.candidate_commit,
                candidate_tree_id: gate.scope.candidate_tree_id,
                forge_remote: gate.forge_remote,
                forge_base,
            },
        )))
    }

    /// THE OPERATOR DOOR on a parked `workspace_effect` gate — the decision
    /// write (`OperationalDb::decide_workspace_effect_approval`) plus, on
    /// approve, the sweep's own drive so the un-parked attempt performs under
    /// this call rather than waiting on a pass. Provider + forge are the
    /// node-attached ones the `oci` route wires.
    ///
    /// # Errors
    ///
    /// `decide_workspace_effect_approval`'s refused set, verbatim; a storage or
    /// perform fault propagates.
    pub fn decide_workspace_effect_gate(
        &self,
        attempt_id: Ulid,
        principal: &kata_types::approval::ApprovalPrincipal,
        verdict: kata_core::operational::WorkspaceEffectVerdict<'_>,
        provider: &Arc<dyn ExecutionWorkspaceProvider>,
        forge: Option<&Arc<dyn Forge>>,
    ) -> KataResult<()> {
        let lifecycle = self.execution_lifecycle();
        let db = lifecycle.db();
        let execution_id = db.workspace_effect_attempt(attempt_id)?.ok_or_else(|| {
            KataError::Validation(format!(
                "approval_gate_not_parked: attempt {attempt_id} is no workspace_effect attempt"
            ))
        })?;
        let scope = db
            .parked_workspace_effect_gates(execution_id)?
            .into_iter()
            .find(|gate| gate.attempt_id == attempt_id)
            .map(|gate| kata_core::operational::WorkspaceEffectGateScope {
                op: gate.scope.op.clone(),
                target: gate.scope.target.clone(),
                candidate_commit: gate.scope.candidate_commit.clone(),
                candidate_tree_id: gate.scope.candidate_tree_id.clone(),
            })
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "approval_gate_not_parked: attempt {attempt_id} is not parked \
                     awaiting_approval"
                ))
            })?;
        let decision =
            kata_core::operational::WorkspaceEffectApprovalDecision { principal, verdict };
        match db.decide_workspace_effect_approval(attempt_id, &decision, &scope)? {
            kata_core::operational::CapsuleApprovalOutcome::Approved { .. }
            | kata_core::operational::CapsuleApprovalOutcome::AlreadyApproved => {
                self.drive_pending_workspace_effects(execution_id, Some(provider), forge)?;
            }
            _ => {}
        }
        Ok(())
    }
}
