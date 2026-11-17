//! The `oci` `workspace_effect` ops. A
//! `stage(agent = "workspace_effect", op = …)` under `oci` runs AT THE MAIN as a
//! durable main-resolved attempt, never on a worker: these are the
//! jj-side verbs and the recovery classifiers for that path.
//!
//! # The shared precondition
//!
//! Every verb is fenced on the head row: the workspace's `@` must BE the
//! recorded candidate commit and the on-disk working copy must be clean —
//! a snapshot finding edits means the working copy carries work nobody
//! recorded (`oci_candidate_disk_diverged`; under `oci` no worker writes that
//! disk, so an edit there is foreign). The driver runs `repair_stale_checkout`
//! FIRST, so a publish-checkpoint lag is repaired, not refused.
//!
//! # Recovery
//!
//! [`JjBackend::classify_workspace_effect`] answers, from repository facts
//! alone (the `kata.effect` op tag is corroborating evidence only — the op log
//! can be garbage-collected), whether a pending effect attempt's mutation
//! landed:
//!
//! * `commit`: the wc commit's PARENT is the recorded candidate (the finalize
//!   landed and `@` is the new empty commit) → `Committed`; `@` is still the
//!   candidate → `NotPerformed`.
//! * `park`: the execution's `parked/<exec>` bookmark resolves to the
//!   DELIVERED commit → `Parked`; the workspace still live with `@` the
//!   recorded candidate → `NotPerformed`.
//! * `promote`: the FROZEN landable branch's head IS or CONTAINS the
//!   DELIVERED commit (jj ancestry — the same fact `land_committed_candidate`
//!   decides `AlreadyLanded` from) → `Promoted`; the workspace still live with
//!   `@` the recorded candidate → `NotPerformed`. The branch is the one the
//!   execution's target froze — the branch the perform lands on — never the
//!   repository's trunk answer at recovery. `parked/<exec>` naming the
//!   landing's OWN rebase of the delivered commit (its revalidation park),
//!   with the workspace gone or still at the recorded candidate →
//!   `LandingParked`, the refusal that landing gave; a conflict park leaves
//!   the delivered commit itself at that ref, a shape a `park` effect of the
//!   same execution also writes, so it stays `NotPerformed` and re-drives.
//! * `forge_export` is classified by the caller from the remote's own head
//!   (`JjBackend::remote_branch_head`) and the forge's pull requests — remote
//!   facts, not repository ones; this module owns only the local side.
//!
//! Anything else is `Diverged`, recorded as the attempt's failure — never
//! re-driven, and nothing torn down.
//!
//! Every jj transaction an effect op runs carries `kata.effect` = the attempt
//! id (`tx.set_tag`), so a published-but-unresolved mutation is reconstructible
//! from the op log as corroboration of the repository facts.
//!
//! # The fence and the delivered commit
//!
//! `park`, `promote` and `forge_export` carry two commits. The recorded
//! candidate is the FENCE: `@` must still be it. The delivered commit is what
//! they park, land and push: after a `commit` effect the candidate is the empty
//! `@` the commit left, and delivering it would put an empty, undescribed
//! commit at `parked/<exec>`, on trunk and on the remote, so
//! [`JjBackend::workspace_effect_delivered_commit`] names the committed commit
//! beneath it instead.

use jj_lib::object_id::ObjectId as _;
use jj_lib::ref_name::RefNameBuf;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use jj_lib::workspace_store::{SimpleWorkspaceStore, WorkspaceStore as _};
use kata_types::error::{KataError, KataResult};
use kata_types::execution::CandidateTreePin;
use kata_types::workflow::WorkspaceEffectOp;

use kata_effects_contract::{
    CommittedEffect, ExecutionWorkspaceHandle, ExecutionWorkspaceKey, ParkedWorkspace,
    PromotedWorkspace, WorkspaceEffectClass,
};

use super::JjBackend;
use super::apply::KATA_EFFECT_TAG;
use super::durability::{RepositoryBarrier, commit_transaction};
use super::merge_queue::LandingOutcome;

/// The execution workspace's `@` is not the commit the head row recorded — the
/// candidate moved under the effect (a foreign rewrite, a stale sweep), so the
/// op refuses rather than mutate the wrong commit.
pub const OCI_CANDIDATE_DIVERGED: &str = "oci_candidate_diverged";

/// The execution workspace's on-disk working copy carries edits. Under `oci`
/// nothing writes that disk but the recorded apply — a `commit`/`park`/`promote`
/// that snapshotted it would publish bytes no delta ever named.
pub const OCI_CANDIDATE_DISK_DIVERGED: &str = "oci_candidate_disk_diverged";

/// A park (the closeout's `park_workspace_recorded`, the operator's
/// `park_workspace`) found its `parked/<…>` ref already naming a commit other
/// than the settled candidate it would write — a landing's revalidation park,
/// an outside write — so it is not the park's own, and the park refuses rather
/// than overwrite that evidence.
pub const PARKED_REF_OCCUPIED: &str = "parked_ref_occupied";

/// The commit `promote` would land does not carry the recorded candidate's
/// tree — the pin fence judged the candidate, so landing a different tree would
/// deliver content no criterion measured.
pub const OCI_DELIVERED_TREE_DIVERGED: &str = "oci_delivered_tree_diverged";

/// A `forge_export` would push a commit that is not the one the execution's
/// latest `commit` effect finalized nor one its `promote` landed: the candidate
/// changed after the commit (a writable stage between them applied a delta)
/// and no boundary recorded the change, so the export would publish edits no
/// `commit` or `promote` named. Refused before anything is pushed. Refused set:
/// a `commit` ran (the head row's `committed_commit_id` is set) and the claim's
/// delivered commit is neither that commit nor the delivered commit of a
/// completed `promote` of the execution. An export after no `commit` (it
/// follows a `promote` alone) is not this refusal's.
pub const FORGE_EXPORT_UNCOMMITTED_CANDIDATE: &str = "forge_export_uncommitted_candidate";

/// The repository names no single git remote to push a `forge_export` to.
/// kata inherits the host's answer and never guesses one: the remote is git's
/// PUSH remote for the landable branch, the one `git push` on it would use
/// (`branch.<branch>.pushRemote`, else `remote.pushDefault`, else
/// `branch.<branch>.remote`), else the repository's ONLY remote. Refused set:
/// the first of those keys that is set names a URL or a name that is no
/// configured remote; or none is set and the repository has no remote or more
/// than one; or the inherited name starts with `-` (it would be read as an
/// option); or the jj store has no git backend to read remotes from. Refused before the export is claimed: the
/// claim records the remote it resolved, and no later leg re-reads it.
pub const FORGE_REMOTE_UNRESOLVED: &str = "forge_remote_unresolved";

/// The export's push remote names no forge repository for the pull request
/// to open in. kata binds every `gh` call of a `forge_export` to the
/// repository the push remote's configured push URL names, read before any
/// `url.*.insteadOf` rewrite, and never lets `gh` pick its default. Refused
/// set: the remote is no configured remote, or has no URL; its URL has no
/// host (a local path, a `file://` URL); its path, one trailing `.git`
/// dropped, is not exactly `OWNER/REPO`; or the jj store has no git backend to
/// read remotes from. Refused before the export writes or pushes anything, and
/// before each later `gh` call. Not refused here: a URL whose literal host the
/// forge client does not address — an SSH host alias (`git@github-work:o/r`
/// reads as host `github-work`), a shorthand only a rewrite expands (`gh:o/r`
/// as host `gh`); the export's confirmation (`Forge::confirm_repository`)
/// refuses those `forge_export_repository_unaddressed`, before the push. A
/// refusal shows a URL by its host and path only, never its user or password.
pub const FORGE_REPOSITORY_UNRESOLVED: &str = "forge_export_repository_unresolved";

/// Test-only crash arms inside the effect verbs, named for the crash-boundary
/// ledger: `KATA_WORKSPACE_EFFECT_CRASH_ARM=before_jj_publish` (every verb) /
/// `between_write_and_publish` (`commit`) / `after_jj_publish_before_return`
/// (`commit`, which owes no teardown) / `after_jj_publish_before_teardown`
/// (`park`, a landed `promote`) / `after_landing_park_before_teardown`
/// (a `promote` whose landing parked) / `after_wc_removal_before_forget` and
/// `after_forget_before_remove_dir` (between the three steps of every
/// teardown, [`JjBackend::remove_workspace_tagged`]). Each is a window inside
/// ONE provider call, which no dispatcher line can sit inside, so a
/// dependent's crash cell (kata-workflow's `workspace_effect`) arms it through
/// `test-support`.
/// Compiled out of the shipped library.
#[cfg(any(test, feature = "test-support"))]
fn workspace_effect_crash_point(boundary: &str) {
    if std::env::var("KATA_WORKSPACE_EFFECT_CRASH_ARM")
        .ok()
        .as_deref()
        == Some(boundary)
    {
        eprintln!("[kata-test] workspace_effect crash arm reached: {boundary}; aborting");
        std::process::abort();
    }
}
#[cfg(not(any(test, feature = "test-support")))]
fn workspace_effect_crash_point(_: &str) {}

/// Set `kata.effect` on the transaction when the call carries an effect tag —
/// every publishing transaction of an effect verb gets the attempt id.
pub(super) fn tag_effect(tx: &mut jj_lib::transaction::Transaction, effect_tag: Option<&str>) {
    if let Some(tag) = effect_tag {
        tx.set_tag(KATA_EFFECT_TAG.to_owned(), tag.to_owned());
    }
}

/// The refusal a `promote` records when its landing parked the rebased
/// delivered commit for revalidation — the verb's own answer, and the answer
/// recovery gives the same park (`WorkspaceEffectClass::LandingParked`); the
/// legacy `promote_workspace` spells its refusal through it too, as it lands
/// through the same ladder.
pub(super) fn revalidation_park_refusal(
    key: &ExecutionWorkspaceKey,
    delivered: &str,
    base: &str,
    rebased: &str,
    parked_ref: &str,
) -> String {
    format!(
        "promote candidate for execution {} PARKED needs-revalidation: base advanced ({delivered} \
         -> {base}), so the rebased tree {rebased} was not the tree validation approved and must \
         be revalidated before it can be trusted; rebased candidate preserved at {parked_ref} \
         (revalidate the rebased tree + re-land)",
        key.execution_id,
    )
}

/// The facts a pending `commit` classify and the shared precondition read:
/// the workspace's `@` commit id and its parents.
pub(super) struct WcPosition {
    /// `@`'s commit id (hex).
    pub(super) wc_commit_id: String,
    /// `@`'s `MergedTree` id (hex) — the candidate tree the promote pin fences
    /// against.
    pub(super) tree_id: String,
}

impl JjBackend {
    /// Load `handle`'s workspace and head — the classify legs need the repo
    /// itself (predecessor and tree facts), not only the `@` position.
    pub(super) fn load_workspace_head(
        &self,
        handle: &ExecutionWorkspaceHandle,
    ) -> KataResult<(
        std::sync::Arc<jj_lib::repo::ReadonlyRepo>,
        jj_lib::commit::Commit,
    )> {
        let settings = self.user_settings()?;
        let workspace = Workspace::load(
            &settings,
            &handle.path,
            &StoreFactories::default(),
            &default_working_copy_factories(),
        )
        .map_err(|err| {
            KataError::Internal(format!("failed to load the execution workspace: {err}"))
        })?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let workspace_name = workspace.workspace_name().to_owned();
        let wc_commit = Self::workspace_commit(repo.as_ref(), &workspace_name)?;
        Ok((repo, wc_commit))
    }

    /// Read `handle`'s wc commit id + parent ids — a read-only load; the
    /// classify legs and the precondition share it.
    pub(super) fn wc_position(&self, handle: &ExecutionWorkspaceHandle) -> KataResult<WcPosition> {
        let (_repo, wc_commit) = self.load_workspace_head(handle)?;
        Ok(WcPosition {
            wc_commit_id: wc_commit.id().hex(),
            tree_id: Self::merged_tree_id_hex(wc_commit.tree_ids()),
        })
    }

    /// The precondition EVERY effect verb runs first, over the workspace status
    /// read: `@` is the recorded candidate (`oci_candidate_diverged` otherwise)
    /// and the working copy is clean (`oci_candidate_disk_diverged`). The
    /// status read is the provider's own `workspace_status` verb — it snapshots
    /// under a dropped lock, so this is still a read.
    pub(super) fn require_clean_recorded_candidate(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
    ) -> KataResult<kata_effects_contract::ExecutionWorkspaceStatus> {
        use kata_effects_contract::ExecutionWorkspaceProvider as _;
        self.require_intact_workspace_candidate(&Self::execution_workspace_agent(key)?)?;
        let Some(status) = self.workspace_status(key)? else {
            return Err(KataError::Internal(format!(
                "no worktree registered for execution {}",
                key.execution_id
            )));
        };
        if !status.handle.path.exists() {
            return Err(KataError::Internal(format!(
                "worktree path {} does not exist",
                status.handle.path.display()
            )));
        }
        if status.dirty == Some(true) {
            return Err(KataError::Validation(format!(
                "{OCI_CANDIDATE_DISK_DIVERGED}: the execution workspace at {} carries on-disk \
                 edits the recorded /work never named — under `oci` no writer but the recorded \
                 apply touches that directory, so the edits are foreign and the effect refuses \
                 rather than publish them",
                status.handle.path.display()
            )));
        }
        // `@` is the working-copy commit — `wc_position`, not
        // `identity.workspace_commit_sha` (which names the workspace's TARGET,
        // the base it was checked out onto, not the candidate).
        let position = self.wc_position(&status.handle)?;
        if position.wc_commit_id != expected_wc_commit {
            return Err(KataError::Validation(format!(
                "{OCI_CANDIDATE_DIVERGED}: the execution workspace's @ is {} but the \
                 recorded candidate is {expected_wc_commit} — the candidate moved under the \
                 effect (a foreign rewrite, a stale apply); nothing runs",
                position.wc_commit_id
            )));
        }
        Ok(status)
    }

    /// The `commit` op: FINALIZE the recorded candidate — `jj commit`'s shape
    /// (rewrite `@` with the op's description, a fresh empty `@` on top, the wc
    /// moved) — then the `exec-<id>` bookmark so the commit stays reachable once
    /// the workspace is eventually reaped. Every transaction is tagged
    /// `kata.effect` = `effect_tag`.
    ///
    /// This always finalizes: the precondition already proved the tree is
    /// exactly the recorded candidate's, so the new `@` is empty by
    /// construction and the finalize is the op itself, not a snapshot.
    pub(super) fn commit_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
        effect_tag: &str,
    ) -> KataResult<CommittedEffect> {
        super::record_vcs_op("workspace_effect_commit", || {
            let status = self.require_clean_recorded_candidate(key, expected_wc_commit)?;
            let handle = status.handle;

            let settings = self.user_settings()?;
            let mut workspace = Workspace::load(
                &settings,
                &handle.path,
                &StoreFactories::default(),
                &default_working_copy_factories(),
            )
            .map_err(|err| {
                KataError::Internal(format!("failed to load the execution workspace: {err}"))
            })?;
            let repo = Self::block_on(workspace.repo_loader().load_at_head()).map_err(|err| {
                KataError::Internal(format!("failed to load jj repo head: {err}"))
            })?;
            let workspace_name = workspace.workspace_name().to_owned();
            let wc_commit = Self::workspace_commit(repo.as_ref(), &workspace_name)?;
            let old_tree = wc_commit.tree();

            let barrier = RepositoryBarrier::for_git_store(repo.store())?;
            let mut tx = repo.start_transaction();
            let committed = Self::block_on(
                tx.repo_mut()
                    .rewrite_commit(&wc_commit)
                    .set_description(format!(
                        "kata workspace_effect commit for execution {}",
                        key.execution_id
                    ))
                    .write(),
            )
            .map_err(|err| {
                KataError::Internal(format!("failed to finalize the candidate commit: {err}"))
            })?;
            let next_wc = Self::block_on(
                tx.repo_mut()
                    .new_commit(vec![committed.id().clone()], committed.tree())
                    .write(),
            )
            .map_err(|err| {
                KataError::Internal(format!("failed to write the next jj wc commit: {err}"))
            })?;
            tx.repo_mut()
                .set_wc_commit(workspace_name.clone(), next_wc.id().clone())
                .map_err(|err| {
                    KataError::Internal(format!("failed to update jj wc commit: {err}"))
                })?;
            Self::block_on(tx.repo_mut().rebase_descendants()).map_err(|err| {
                KataError::Internal(format!("failed to rebase after jj commit: {err}"))
            })?;
            tag_effect(&mut tx, Some(effect_tag));

            workspace_effect_crash_point("before_jj_publish");
            let unpublished =
                Self::block_on(tx.write(format!("kata workspace_effect commit {effect_tag}")))
                    .map_err(|err| {
                        KataError::Internal(format!(
                            "failed to write the workspace_effect op: {err}"
                        ))
                    })?;
            workspace_effect_crash_point("between_write_and_publish");
            barrier.sync("workspace_effect commit publish")?;
            let repo = Self::block_on(unpublished.publish()).map_err(|err| {
                KataError::Internal(format!("failed to publish the workspace_effect op: {err}"))
            })?;
            let operation_id = repo.operation().id().clone();

            // The new `@` is a commit on top of the finalized one with the same
            // tree — the working copy is checked out onto it exactly like an
            // apply's landing, so the disk is never left stale.
            Self::block_on(workspace.check_out(operation_id, Some(&old_tree), &next_wc)).map_err(
                |err| {
                    KataError::Internal(format!(
                        "workspace_effect commit published {effect_tag} but the checkout failed: \
                         {err} — the working copy is stale until `repair_stale_checkout` runs"
                    ))
                },
            )?;

            let committed_sha = committed.id().hex();
            let ref_name = format!("exec-{}", key.execution_id);
            // PUBLISH REFUSAL before the ref exists — `exec-<id>` exports into
            // the colocated `.git`, so this is a commit leaving the workspace.
            self.publishable_author("commit", &committed_sha)?;
            self.set_local_bookmark_tagged(&ref_name, &committed_sha, Some(effect_tag))?;
            workspace_effect_crash_point("after_jj_publish_before_return");
            Ok(CommittedEffect {
                ref_name,
                commit_sha: committed_sha,
                new_wc_commit_id: next_wc.id().hex(),
            })
        })
    }

    /// The commit an `op` claimed against `candidate_commit` delivers. `commit`
    /// acts on the candidate itself; `park`, `promote` and `forge_export`
    /// deliver `committed_commit` when the candidate is its empty child (sole
    /// parent `committed_commit`, same tree: the `@` a `commit` effect leaves),
    /// else the candidate. `committed_commit` is the head row's
    /// `committed_commit_id`, `''` when no commit resolved. The tree check is
    /// what keeps a candidate CHANGED after the commit (a later apply rewrote
    /// the `@`) delivered as itself rather than dropped back to the commit.
    pub(super) fn workspace_effect_delivered_commit(
        &self,
        op: WorkspaceEffectOp,
        candidate_commit: &str,
        committed_commit: &str,
    ) -> KataResult<String> {
        let delivers_beneath = match op {
            WorkspaceEffectOp::Park
            | WorkspaceEffectOp::Promote
            | WorkspaceEffectOp::ForgeExport => true,
            WorkspaceEffectOp::Commit => false,
        };
        if !delivers_beneath || committed_commit.is_empty() || committed_commit == candidate_commit
        {
            return Ok(candidate_commit.to_owned());
        }
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let load = |sha: &str| {
            let id = jj_lib::backend::CommitId::try_from_hex(sha).ok_or_else(|| {
                KataError::Internal(format!("the commit id {sha} is not valid hex"))
            })?;
            repo.store().get_commit(&id).map_err(|err| {
                KataError::Internal(format!(
                    "the commit {sha} is not in the repository's store: {err}"
                ))
            })
        };
        let candidate = load(candidate_commit)?;
        let committed = load(committed_commit)?;
        let empty_child = candidate.parent_ids() == std::slice::from_ref(committed.id())
            && candidate.tree_ids() == committed.tree_ids();
        Ok(if empty_child {
            committed_commit.to_owned()
        } else {
            candidate_commit.to_owned()
        })
    }

    /// The `park` op: the delivered commit's `parked/<exec>` ref + teardown —
    /// the `park_workspace` mutation with `kata.effect` tagging on every
    /// publishing transaction and the recorded-candidate precondition in place
    /// of the dirty settle (under `oci` the wc is clean by precondition; `park`
    /// publishes `delivered_commit` — the recorded candidate, or after a
    /// `commit` the committed commit it is the empty child of — never a
    /// snapshot). The authored
    /// label never names the ref — `parked/<exec-id>` is the only name this
    /// verb writes, which is what `classify_park_effect` reads back and what
    /// keeps two same-label executions off each other's evidence ref.
    pub(super) fn park_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
        barrier: &RepositoryBarrier,
    ) -> KataResult<ParkedWorkspace> {
        super::record_vcs_op("workspace_effect_park", || {
            let agent = Self::execution_workspace_agent(key)?;
            self.require_clean_recorded_candidate(key, expected_wc_commit)?;
            let commit_sha = delivered_commit.to_owned();
            let ref_name = Self::parked_bookmark_name(key.execution_id, None);
            // Refuse BEFORE the ref is written and BEFORE the teardown — a park
            // that refused after `remove_workspace` destroyed the work it
            // refused to publish.
            self.publishable_author("park", &commit_sha)?;
            workspace_effect_crash_point("before_jj_publish");
            self.set_local_bookmark_tagged(&ref_name, &commit_sha, Some(effect_tag))?;
            workspace_effect_crash_point("after_jj_publish_before_teardown");
            self.remove_workspace_tagged(&agent, Some(effect_tag), barrier)?;
            let identity = Some(kata_effects_contract::execution_workspace_identity(
                key,
                kata_effects_contract::ExecutionWorkspaceBackend::Jj,
                Some(format!(
                    "{}{}",
                    crate::EXECUTION_REF_PREFIX,
                    key.execution_id
                )),
                Some(commit_sha.clone()),
                self.trunk_name_for_evidence(),
                None,
                Some(ref_name.clone()),
                Some(commit_sha.clone()),
            ));
            Ok(ParkedWorkspace {
                ref_name,
                commit_sha,
                identity,
            })
        })
    }

    /// The `promote` op: precondition → pin fence → merge-queue land →
    /// teardown, the `promote_workspace` shape with `kata.effect` tagging on
    /// every publishing transaction and the recorded-candidate fence up front
    /// (the settle snapshot is gone — under `oci` the precondition already
    /// proved the tree is the recorded candidate's). The ladder lands
    /// `delivered_commit`: the candidate itself, or — after a `commit` — the
    /// committed commit the candidate is the empty child of, whose tree is the
    /// candidate's, so the pin fence judges the same tree either way.
    pub(super) fn promote_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        pin: &CandidateTreePin,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
        landing_branch: Option<&str>,
        barrier: &RepositoryBarrier,
    ) -> KataResult<PromotedWorkspace> {
        super::record_vcs_op("workspace_effect_promote", || {
            let agent = Self::execution_workspace_agent(key)?;
            let status = self.require_clean_recorded_candidate(key, expected_wc_commit)?;
            let candidate_tree = self.wc_position(&status.handle)?.tree_id;
            // The identity fence — the tree the criteria judged is the tree the
            // ladder lands. The recorded candidate's tree IS what validation
            // measured under `oci` (the head's applied tree).
            pin.require_tree("promote", &key.execution_id.to_string(), &candidate_tree)?;
            // The pin judged the CANDIDATE's tree; the ladder lands the
            // delivered commit, so the two must be one tree or the fence
            // would vouch for content it never saw.
            let delivered_tree = self.commit_tree_id(delivered_commit)?;
            if delivered_tree != candidate_tree {
                return Err(KataError::Validation(format!(
                    "{OCI_DELIVERED_TREE_DIVERGED}: promote for execution {} would land \
                     {delivered_commit} with tree {delivered_tree}, but the recorded candidate's \
                     tree is {candidate_tree} — the tree validation judged is not the tree that \
                     would land; nothing lands",
                    key.execution_id
                )));
            }
            let author = self.publishable_author("promote", delivered_commit)?;
            workspace_effect_crash_point("before_jj_publish");
            match self.land_committed_candidate_tagged(
                key,
                delivered_commit,
                None,
                Some(effect_tag),
                landing_branch,
            )? {
                LandingOutcome::Landed { mut promoted, .. } => {
                    workspace_effect_crash_point("after_jj_publish_before_teardown");
                    self.remove_workspace_tagged(&agent, Some(effect_tag), barrier)?;
                    promoted.identity = promoted
                        .identity
                        .map(|identity| identity.with_author(Some(author)));
                    Ok(promoted)
                }
                LandingOutcome::Parked { parked, conflict } => {
                    workspace_effect_crash_point("after_landing_park_before_teardown");
                    self.remove_workspace_tagged(&agent, Some(effect_tag), barrier)?;
                    Err(KataError::Validation(format!(
                        "promote parked candidate for execution {}: rebase onto {} conflicts in \
                         {:?}; candidate work preserved at {} (revalidate + re-land)",
                        key.execution_id,
                        self.trunk_name_for_evidence()
                            .as_deref()
                            .unwrap_or("<unresolved trunk>"),
                        conflict.conflicted_paths,
                        parked.ref_name,
                    )))
                }
                LandingOutcome::ParkedForRevalidation { parked, rebased } => {
                    workspace_effect_crash_point("after_landing_park_before_teardown");
                    self.remove_workspace_tagged(&agent, Some(effect_tag), barrier)?;
                    Err(KataError::Validation(revalidation_park_refusal(
                        key,
                        &rebased.original_commit_sha,
                        &rebased.base_commit_sha,
                        &rebased.rebased_commit_sha,
                        &parked.ref_name,
                    )))
                }
            }
        })
    }

    /// A `forge_export`'s local half, on every drive before the read that
    /// leases its push: [`Self::refuse_unexportable`], then the `kata/<exec>`
    /// branch write. The pushed commit is `delivered_commit`, named by the
    /// claim from the head row — never re-derived off a live `@`: the workspace
    /// may already be torn down (a landed promote tore it down), and a missing
    /// workspace is fine because the commit is durable.
    pub(super) fn write_exportable_forge_branch(
        &self,
        key: &ExecutionWorkspaceKey,
        branch: &str,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
    ) -> KataResult<()> {
        self.refuse_unexportable(key, expected_wc_commit, delivered_commit)?;
        self.write_forge_branch_tagged(branch, delivered_commit, Some(effect_tag))
    }

    /// What a `forge_export` refuses before it writes `kata/<exec>`,
    /// each a typed `Validation` naming the commit or the workspace:
    ///
    /// * `oci_candidate_disk_diverged` — the execution workspace is live and
    ///   its on-disk working copy carries edits;
    /// * `oci_candidate_diverged` — the workspace is live and its `@` is not
    ///   `expected_wc_commit`, the recorded candidate (the head row lies);
    /// * `forge_export_conflicted_commit` — `delivered_commit`'s tree carries
    ///   a conflict, which has no faithful git form;
    /// * the publish refusal (`forge_export: refusing to publish commit …`) —
    ///   `delivered_commit`'s author or committer is an identity kata will not
    ///   publish ([`Self::publishable_author`]): jj-cli's refusal to push an
    ///   authorless commit never runs, because the push shells `git push` at
    ///   the colocated root, which sends one at exit 0.
    ///
    /// A workspace that is not live (a landed promote tore it down) fences
    /// nothing: the delivered commit is durable without it.
    fn refuse_unexportable(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
        delivered_commit: &str,
    ) -> KataResult<()> {
        use kata_effects_contract::ExecutionWorkspaceProvider as _;
        if let Some(status) = self.workspace_status(key)? {
            if status.dirty == Some(true) {
                return Err(KataError::Validation(format!(
                    "{OCI_CANDIDATE_DISK_DIVERGED}: the execution workspace at {} carries \
                     on-disk edits the recorded /work never named — forge_export refuses \
                     rather than export a candidate whose disk disagrees",
                    status.handle.path.display()
                )));
            }
            let wc_commit = self.wc_position(&status.handle)?.wc_commit_id;
            if wc_commit != expected_wc_commit {
                return Err(KataError::Validation(format!(
                    "{OCI_CANDIDATE_DIVERGED}: the execution workspace's @ is {wc_commit} but \
                     the recorded candidate is {expected_wc_commit} — the candidate moved \
                     under the effect; nothing is exported"
                )));
            }
        }
        self.refuse_conflicted_export(delivered_commit)?;
        self.publishable_author("forge_export", delivered_commit)?;
        Ok(())
    }

    /// Classify a pending `workspace_effect` attempt against repository facts.
    ///
    /// `recorded_candidate` is the head row's `candidate_commit_id` at claim
    /// time — the commit the effect was claimed against, unchanged while its
    /// stage is unresolved (only this execution's apply/commit txs move it,
    /// and they move it in the attempt's own resolving transaction).
    /// `delivered_commit` is the spec's commit a `promote` lands (see the
    /// module doc); `commit` and `park` read only the candidate. `handle`
    /// may be absent — a landed `park`/`promote` tears the workspace down, in
    /// full or (a crash inside the teardown) in part, and `lookup_workspace`
    /// answers neither as live — so the classify legs read refs first and
    /// treat a live `@` as "not yet".
    /// `landing_branch` is the execution's frozen landable branch — the one
    /// the `promote` perform lands on ([`Self::promote_workspace_effect`]) —
    /// and the only branch the `promote` classify reads; `commit` and `park`
    /// ignore it.
    pub(super) fn classify_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        handle: Option<&ExecutionWorkspaceHandle>,
        op: WorkspaceEffectOp,
        recorded_candidate: &str,
        delivered_commit: &str,
        landing_branch: Option<&str>,
    ) -> KataResult<WorkspaceEffectClass> {
        match op {
            WorkspaceEffectOp::Commit => self.classify_commit_effect(handle, recorded_candidate),
            WorkspaceEffectOp::Park => {
                self.classify_park_effect(key, handle, recorded_candidate, delivered_commit)
            }
            WorkspaceEffectOp::Promote => self.classify_promote_effect(
                key,
                handle,
                recorded_candidate,
                delivered_commit,
                landing_branch,
            ),
            WorkspaceEffectOp::ForgeExport => Err(KataError::Internal(
                "classify_workspace_effect does not classify forge_export — the remote is the \
                 authority, read by forge_remote_head, not the local repository"
                    .to_string(),
            )),
        }
    }

    /// `commit`: `@` still the recorded candidate → `NotPerformed`. The
    /// verb's LANDED shape is `@` = `next_wc`, whose single parent is the
    /// commit `rewrite_commit` minted — a rewrite always gets a new id, so the
    /// recorded candidate is never `@`'s parent; it is an edge in that
    /// parent's PREDECESSOR chain (the same mechanism `classify_work_apply`
    /// uses for a GC'd op tag). `Committed` therefore asks: `@` has exactly
    /// one parent, that parent's predecessors carry the recorded candidate,
    /// and the parent's tree IS the candidate's tree (the rewrite changes the
    /// description, never the content — a parent carrying the candidate in
    /// predecessors but a different tree is a foreign rewrite, diverged).
    /// `commit_sha` names that parent — the commit the verb published — which
    /// is also where the sweep's `exec-<id>` ref write must land. Any other
    /// shape (the workspace gone — `commit` never tears it down — a
    /// multi-parent `@`, or neither) is `Diverged`.
    fn classify_commit_effect(
        &self,
        handle: Option<&ExecutionWorkspaceHandle>,
        recorded_candidate: &str,
    ) -> KataResult<WorkspaceEffectClass> {
        let Some(handle) = handle else {
            return Ok(WorkspaceEffectClass::Diverged {
                reason: format!(
                    "{OCI_CANDIDATE_DIVERGED}: the execution workspace is gone, but `commit` \
                     never tears it down — a missing workspace is a foreign teardown, not a \
                     landed commit"
                ),
            });
        };
        let (repo, wc_commit) = self.load_workspace_head(handle)?;
        let wc_commit_id = wc_commit.id().hex();
        if wc_commit_id == recorded_candidate {
            return Ok(WorkspaceEffectClass::NotPerformed);
        }
        let parents = Self::block_on(wc_commit.parents())
            .map_err(|err| {
                KataError::Internal(format!("failed to load jj wc commit parents: {err}"))
            })?
            .clone();
        if let [parent] = parents.as_slice() {
            let recorded_id = jj_lib::backend::CommitId::try_from_hex(recorded_candidate)
                .ok_or_else(|| {
                    KataError::Internal(format!(
                        "recorded candidate commit id {recorded_candidate} is not valid hex"
                    ))
                })?;
            let recorded_commit = repo.store().get_commit(&recorded_id).map_err(|err| {
                KataError::Internal(format!(
                    "workspace_effect commit classify: the recorded candidate {recorded_candidate} \
                     is not in the store: {err}"
                ))
            })?;
            if super::apply::predecessors_contain(&repo, parent, &recorded_id)?
                && parent.tree_ids() == recorded_commit.tree_ids()
            {
                return Ok(WorkspaceEffectClass::Committed {
                    commit_sha: parent.id().hex(),
                    new_wc_commit_id: wc_commit_id,
                });
            }
        }
        Ok(WorkspaceEffectClass::Diverged {
            reason: format!(
                "{OCI_CANDIDATE_DIVERGED}: the workspace's @ is {} (parents {:?}) — neither the \
                 recorded candidate {} nor a rewrite carrying it in predecessors with its tree; \
                 the candidate moved under the pending commit",
                wc_commit_id,
                parents
                    .iter()
                    .map(|commit| commit.id().hex())
                    .collect::<Vec<_>>(),
                recorded_candidate,
            ),
        })
    }

    /// `park`: the `parked/<exec>` ref names the delivered commit → `Parked`
    /// (teardown already ran, or a crash between the ref write and the
    /// teardown — either way the publish landed and only teardown remains,
    /// which the dispatcher's sweep and perform legs complete). The workspace still live with `@` the
    /// candidate → `NotPerformed`. Anything else is `Diverged`.
    fn classify_park_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        handle: Option<&ExecutionWorkspaceHandle>,
        recorded_candidate: &str,
        delivered_commit: &str,
    ) -> KataResult<WorkspaceEffectClass> {
        let ref_name = Self::parked_bookmark_name(key.execution_id, None);
        if let Some(sha) = self.local_bookmark_commit(&ref_name)? {
            if sha == delivered_commit {
                return Ok(WorkspaceEffectClass::Parked {
                    ref_name,
                    commit_sha: sha,
                });
            }
            return Ok(WorkspaceEffectClass::Diverged {
                reason: format!(
                    "{OCI_CANDIDATE_DIVERGED}: the parked ref {ref_name} names {sha}, not the \
                     delivered commit {delivered_commit} — a foreign ref move, not this \
                     park's publish"
                ),
            });
        }
        match handle {
            Some(handle) if handle.path.exists() => {
                let position = self.wc_position(handle)?;
                if position.wc_commit_id == recorded_candidate {
                    return Ok(WorkspaceEffectClass::NotPerformed);
                }
                Ok(WorkspaceEffectClass::Diverged {
                    reason: format!(
                        "{OCI_CANDIDATE_DIVERGED}: the parked ref is absent and the workspace's \
                         @ is {} — not the recorded candidate {recorded_candidate}; the \
                         candidate moved under the pending park",
                        position.wc_commit_id
                    ),
                })
            }
            _ => Ok(WorkspaceEffectClass::Diverged {
                reason: format!(
                    "{OCI_CANDIDATE_DIVERGED}: the parked ref {ref_name} is absent AND the \
                     workspace is gone — a park that neither wrote its ref nor left its \
                     workspace is a foreign teardown"
                ),
            }),
        }
    }

    /// `promote`: the trunk bookmark's head IS or CONTAINS the delivered
    /// commit → `Promoted` (the same ancestry fact
    /// `land_committed_candidate`'s `AlreadyLanded` decides from — a crash
    /// between the land and the workspace teardown is settled by it). The
    /// workspace still live with `@` the recorded candidate → `NotPerformed`.
    /// Trunk not holding the delivered commit AND the workspace gone →
    /// `Diverged` (torn down without landing — foreign).
    ///
    /// `parked/<exec>` at a commit other than the delivered one is
    /// `LandingParked` exactly when it is the landing ladder's revalidation
    /// park of the delivered commit ([`Self::own_revalidation_park`] states the
    /// evidence) AND the workspace is still the landing's — gone (the verb's
    /// teardown ran) or standing with `@` the recorded candidate; an own park
    /// under a moved `@` is `Diverged` (the candidate moved), and any other
    /// commit there is an outside write, `Diverged`. `parked/<exec>` AT the
    /// delivered commit (a conflict park) is not separable by its shape from a
    /// `park` effect of the same execution, which writes that ref at the
    /// delivered commit too; no
    /// rule found refuses the two pending at once, nor proves they can be — so
    /// it is not read: a live
    /// workspace at the candidate is `NotPerformed`, and the re-driven verb
    /// re-derives its answer under its own fences.
    ///
    /// "Trunk" is `landing_branch`, the execution's FROZEN landable branch —
    /// the only branch its perform can have moved, because the landing ladder
    /// refuses `target_trunk_renamed` when the trunk it resolves is not that
    /// name. The repository's trunk answer NOW is never read when a frozen
    /// branch exists: after a crash it may name another branch, and judging
    /// that branch would record a landed promote `Diverged`, or re-drive one.
    /// `None` (an invocation that froze no target) is the ladder's own `None`
    /// arm: the trunk the repository resolves, as the ladder lands on it.
    fn classify_promote_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        handle: Option<&ExecutionWorkspaceHandle>,
        recorded_candidate: &str,
        delivered_commit: &str,
        landing_branch: Option<&str>,
    ) -> KataResult<WorkspaceEffectClass> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let trunk = match landing_branch {
            Some(frozen) => frozen.to_owned(),
            None => self
                .resolve_trunk_in(repo.as_ref())?
                .require("promote")?
                .to_owned(),
        };
        let trunk_head = repo
            .view()
            .get_local_bookmark(RefNameBuf::from(trunk.as_str()).as_ref())
            .as_normal()
            .cloned()
            .ok_or_else(|| {
                KataError::Validation(format!(
                    "landing base bookmark {trunk} is absent or conflicted"
                ))
            })?;
        let delivered_id =
            jj_lib::backend::CommitId::try_from_hex(delivered_commit).ok_or_else(|| {
                KataError::Internal(format!(
                    "delivered commit id {delivered_commit} is not valid hex"
                ))
            })?;
        let landed = trunk_head == delivered_id
            || repo
                .index()
                .is_ancestor(&delivered_id, &trunk_head)
                .map_err(|err| {
                    KataError::Internal(format!("failed to check jj landing ancestry: {err}"))
                })?;
        if landed {
            return Ok(WorkspaceEffectClass::Promoted {
                ref_name: trunk,
                commit_sha: trunk_head.hex(),
            });
        }
        // The workspace's own fact: `Some(@)` while it stands, `None` once gone.
        let standing_wc = || -> KataResult<Option<String>> {
            match handle {
                Some(handle) if handle.path.exists() => {
                    Ok(Some(self.wc_position(handle)?.wc_commit_id))
                }
                _ => Ok(None),
            }
        };
        let candidate_moved = |wc_commit_id: &str| WorkspaceEffectClass::Diverged {
            reason: format!(
                "{OCI_CANDIDATE_DIVERGED}: trunk does not hold the delivered commit \
                 {delivered_commit} and the workspace's @ is {wc_commit_id} — not the recorded \
                 candidate {recorded_candidate}; the candidate moved under the pending promote"
            ),
        };
        let parked_ref = Self::parked_bookmark_name(key.execution_id, None);
        if let Some(sha) = self.local_bookmark_commit(&parked_ref)?
            && sha != delivered_commit
        {
            if let Some(reason) = Self::own_revalidation_park(
                repo.as_ref(),
                key,
                &trunk,
                &trunk_head,
                &delivered_id,
                &parked_ref,
                &sha,
            )? {
                // The park answers for the workspace only while the workspace
                // is still the landing's: gone (the verb's teardown ran), or
                // standing at the recorded candidate. A moved `@` on top of the
                // park is an outside divergence, and moves nothing.
                return Ok(match standing_wc()? {
                    Some(wc) if wc != recorded_candidate => candidate_moved(&wc),
                    _ => WorkspaceEffectClass::LandingParked { reason },
                });
            }
            return Ok(WorkspaceEffectClass::Diverged {
                reason: format!(
                    "the parked ref {parked_ref} names {sha}, which is neither the delivered \
                     commit {delivered_commit} nor this landing's own rebase of it onto {trunk} \
                     — an outside write, not this promote's landing; the pending promote moves \
                     nothing"
                ),
            });
        }
        match standing_wc()? {
            Some(wc) if wc == recorded_candidate => Ok(WorkspaceEffectClass::NotPerformed),
            Some(wc) => Ok(candidate_moved(&wc)),
            None => Ok(WorkspaceEffectClass::Diverged {
                reason: format!(
                    "{OCI_CANDIDATE_DIVERGED}: trunk does not hold the delivered commit \
                     {delivered_commit} and the execution workspace is gone — a torn-down \
                     workspace that never landed is a foreign teardown"
                ),
            }),
        }
    }
}

impl JjBackend {
    /// Whether `parked` (the commit `parked_ref` names) is the landing ladder's
    /// revalidation park of `delivered` onto the branch `trunk` (head
    /// `trunk_head`), and if so the refusal the verb returned for it. The
    /// evidence, every fact of which the ladder's `ParkedForRevalidation` arm
    /// writes in one transaction and reads back from the repository alone:
    ///
    /// * `parked` has exactly one parent, the base, and the base is on `trunk`
    ///   (its head or an ancestor) — the ladder parks onto the head it read;
    /// * `parked` is not on `trunk` — the ladder never moves trunk to it;
    /// * the base is not an ancestor of `delivered` — else the ladder would
    ///   have fast-forwarded, never rebased;
    /// * `parked`'s description is the ladder's for this execution and branch
    ///   ([`Self::revalidation_rebase_description`]) — another execution's
    ///   labelled park cannot name this execution;
    /// * `parked`'s tree is the rebase of `delivered` onto the base,
    ///   recomputed ([`Self::rebased_tree`]) — conflict-free, as the ladder
    ///   writes it, since a conflicting rebase parks `delivered` itself.
    ///
    /// A commit written by anyone else that meets all five is the same rebase
    /// of the same commit under the same name, and is answered as the landing's.
    #[allow(clippy::too_many_arguments)] // The classify's operands plus the parked ref.
    fn own_revalidation_park(
        repo: &dyn jj_lib::repo::Repo,
        key: &ExecutionWorkspaceKey,
        trunk: &str,
        trunk_head: &jj_lib::backend::CommitId,
        delivered: &jj_lib::backend::CommitId,
        parked_ref: &str,
        parked: &str,
    ) -> KataResult<Option<String>> {
        let load = |id: &jj_lib::backend::CommitId| {
            repo.store().get_commit(id).map_err(|err| {
                KataError::Internal(format!(
                    "workspace_effect promote classify: commit {} is not in the store: {err}",
                    id.hex()
                ))
            })
        };
        let on_trunk = |id: &jj_lib::backend::CommitId| -> KataResult<bool> {
            Ok(id == trunk_head
                || repo.index().is_ancestor(id, trunk_head).map_err(|err| {
                    KataError::Internal(format!("failed to check jj landing ancestry: {err}"))
                })?)
        };
        let parked_id = jj_lib::backend::CommitId::try_from_hex(parked).ok_or_else(|| {
            KataError::Internal(format!("parked commit id {parked} is not valid hex"))
        })?;
        let parked_commit = load(&parked_id)?;
        let [base_id] = parked_commit.parent_ids() else {
            return Ok(None);
        };
        if !on_trunk(base_id)? || on_trunk(&parked_id)? {
            return Ok(None);
        }
        let fast_forwardable = repo
            .index()
            .is_ancestor(base_id, delivered)
            .map_err(|err| {
                KataError::Internal(format!("failed to check jj landing ancestry: {err}"))
            })?;
        if fast_forwardable
            || parked_commit.description()
                != Self::revalidation_rebase_description(key.execution_id, trunk)
        {
            return Ok(None);
        }
        let Some(rebased) = Self::rebased_tree(repo, &load(delivered)?, &load(base_id)?)? else {
            return Ok(None);
        };
        if rebased.tree_ids() != parked_commit.tree_ids() {
            return Ok(None);
        }
        Ok(Some(revalidation_park_refusal(
            key,
            &delivered.hex(),
            &base_id.hex(),
            parked,
            parked_ref,
        )))
    }

    /// `VcsBackend::remove_workspace` with `kata.effect` = `effect_tag` on the
    /// working-copy-removal transaction when a tag is given — the `oci`
    /// `workspace_effect` verbs' variant; the trait teardown delegates with
    /// `None`. `barrier` is the calling provider call's, opened before any of
    /// its writes. The removal transaction publishes behind it
    /// (`commit_transaction`), before the workspace store forgets the workspace
    /// and its directory goes: whatever the call wrote first (the parked or
    /// landed ref, its objects, the op naming them) is durable before the
    /// workspace's copy of the candidate is removed, and a writeback error of
    /// any of those writes refuses the teardown `repository_not_durable` with
    /// the workspace standing. A working copy the view no longer names is a
    /// teardown a crash cut off after that transaction; every caller that wrote
    /// the repository first (a park, a landing) still holds a live `@`, so a
    /// resumed teardown has no earlier write of its own call to order.
    ///
    /// Three steps no one transaction spans: the transaction removing the
    /// workspace's working-copy commit from the view, the workspace store's
    /// `forget`, the directory's removal. A crash between them leaves the
    /// directory, `.jj` and all, with no working-copy commit in the view —
    /// which `lookup_workspace` answers as no live workspace — and running
    /// this again finishes it: each step acts only on what remains.
    pub(super) fn remove_workspace_tagged(
        &self,
        agent: &kata_types::AgentId,
        effect_tag: Option<&str>,
        barrier: &RepositoryBarrier,
    ) -> KataResult<()> {
        let settings = self.user_settings()?;
        let workspace_name = Self::workspace_name(agent);
        let workspace_path = self.workspace_path(agent);

        let root_workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(root_workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;

        if repo.view().get_wc_commit_id(&workspace_name).is_some() {
            let mut tx = repo.start_transaction();
            Self::block_on(tx.repo_mut().remove_wc_commit(&workspace_name)).map_err(|err| {
                KataError::Internal(format!("failed to remove jj workspace commit: {err}"))
            })?;
            Self::block_on(tx.repo_mut().rebase_descendants()).map_err(|err| {
                KataError::Internal(format!("failed to rebase after workspace removal: {err}"))
            })?;
            tag_effect(&mut tx, effect_tag);
            commit_transaction(
                barrier,
                tx,
                format!("kata remove workspace {}", agent.0),
                "failed to commit workspace removal",
            )?;
        }
        workspace_effect_crash_point("after_wc_removal_before_forget");

        SimpleWorkspaceStore::load(root_workspace.repo_path())
            .and_then(|store| store.forget(&[&workspace_name]))
            .map_err(|err| {
                KataError::Internal(format!("failed to forget jj workspace metadata: {err}"))
            })?;
        workspace_effect_crash_point("after_forget_before_remove_dir");

        if workspace_path.exists() {
            std::fs::remove_dir_all(&workspace_path)?;
        }

        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
impl JjBackend {
    /// Test support: rewrite `key`'s workspace `@` so its tree carries a
    /// three-sided conflict at `path` — the candidate's own tree as the base
    /// and two sides writing different bytes there, the shape a rebase
    /// conflict leaves — and check it out, under this repository's identity.
    /// Answers the new `@`. jj records the conflict in the commit, so
    /// `commit`, which never asks, finalizes it as it would any candidate.
    pub(crate) fn conflict_the_workspace_candidate(
        &self,
        key: &ExecutionWorkspaceKey,
        path: &str,
    ) -> KataResult<String> {
        use jj_lib::backend::{CopyId, TreeValue};
        use jj_lib::merge::Merge;
        use jj_lib::merged_tree::MergedTree;
        use jj_lib::merged_tree_builder::MergedTreeBuilder;
        use jj_lib::repo_path::{RepoPath, RepoPathBuf};

        let internal = |err: &dyn std::fmt::Display| KataError::Internal(err.to_string());
        let agent = Self::execution_workspace_agent(key)?;
        let settings = self.user_settings()?;
        let mut workspace = Workspace::load(
            &settings,
            &self.workspace_path(&agent),
            &StoreFactories::default(),
            &default_working_copy_factories(),
        )
        .map_err(|err| internal(&err))?;
        let repo =
            Self::block_on(workspace.repo_loader().load_at_head()).map_err(|err| internal(&err))?;
        let workspace_name = workspace.workspace_name().to_owned();
        let wc_commit = Self::workspace_commit(repo.as_ref(), &workspace_name)?;
        let store = repo.store().clone();
        let side = |bytes: &[u8]| -> KataResult<MergedTree> {
            let mut reader = bytes;
            let file = Self::block_on(store.write_file(
                RepoPath::from_internal_string(path).map_err(|err| internal(&err))?,
                &mut reader,
            ))
            .map_err(|err| internal(&err))?;
            let mut builder = MergedTreeBuilder::new(wc_commit.tree());
            builder.set_or_remove(
                RepoPathBuf::from_internal_string(path).map_err(|err| internal(&err))?,
                Merge::resolved(Some(TreeValue::File {
                    id: file,
                    executable: false,
                    copy_id: CopyId::placeholder(),
                })),
            );
            Self::block_on(builder.write_tree()).map_err(|err| internal(&err))
        };
        let conflicted_tree = Self::block_on(MergedTree::merge(Merge::from_vec(vec![
            (wc_commit.tree(), "base".to_owned()),
            (side(b"side a\n")?, "side a".to_owned()),
            (side(b"side b\n")?, "side b".to_owned()),
        ])))
        .map_err(|err| internal(&err))?;
        let mut tx = repo.start_transaction();
        let conflicted = Self::block_on(
            tx.repo_mut()
                .rewrite_commit(&wc_commit)
                .set_tree(conflicted_tree)
                .write(),
        )
        .map_err(|err| internal(&err))?;
        tx.repo_mut()
            .set_wc_commit(workspace_name, conflicted.id().clone())
            .map_err(|err| internal(&err))?;
        Self::block_on(tx.repo_mut().rebase_descendants()).map_err(|err| internal(&err))?;
        let repo = Self::block_on(tx.commit("test support: a conflicted candidate"))
            .map_err(|err| internal(&err))?;
        Self::block_on(workspace.check_out(
            repo.operation().id().clone(),
            Some(&wc_commit.tree()),
            &conflicted,
        ))
        .map_err(|err| internal(&err))?;
        Ok(conflicted.id().hex())
    }
}
