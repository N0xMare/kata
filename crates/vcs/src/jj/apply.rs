//! The `work_apply` effect on the jj backend: apply a
//! recorded [`TreeDelta`] to the execution workspace's candidate commit, as one
//! jj transaction tagged `kata.effect`, followed by a working-copy checkout.
//!
//! # What this owns, and what it deliberately does not
//!
//! This module is the VCS half of the apply effect. The durable half — the
//! `WorkApply` main attempt and the head row — lives in the
//! operational plane and calls IN here; this module never touches it. What it
//! guarantees on the repository:
//!
//! * the workspace's recorded `@` commit is `expected_wc_commit` before a tree
//!   is built (a candidate that has already moved is refused
//!   [`WORK_APPLY_CANDIDATE_DIVERGED`], never silently re-based);
//! * the delta lands as `rewrite_commit(@).set_tree(merged)` — the candidate
//!   CHANGE accumulates, no new commit node — inside a transaction tagged
//!   `kata.effect = <effect_tag>`;
//! * `rebase_descendants` runs before commit: `Transaction::write` refuses a
//!   transaction with un-rebased rewrites (jj-lib 0.39);
//! * the new commit is CHECKED OUT to the on-disk working copy before the call
//!   returns: skipping the checkout leaves the next `snapshot` reading the
//!   PRE-apply disk state and silently reverting the apply into whatever
//!   records that snapshot.
//!
//! # Crash anatomy (asserted by this module's cells)
//!
//! `Transaction::commit` is `write` + `publish`. Between them a crash leaves an
//! op in the store that no head reaches — invisible to `classify_work_apply`'s
//! tag walk, exactly like the never-written case. After publish, before
//! `check_out`, a crash leaves the op published and the disk stale — which
//! `repair_stale_checkout` converges. `classify_work_apply` is the one place
//! "did this apply happen" is answered, because the op-log GC (`op_log_gc.rs`)
//! can prune a tagged op while its commit survives: tag found, OR the current
//! `@` counts the recorded head among its predecessors and carries the delta's
//! nodes on every changed path, means applied; `@` still the recorded head
//! means not applied; anything else is diverged and must not be re-driven.

use std::sync::Arc;

use jj_lib::backend::{CommitId, CopyId, TreeValue};
use jj_lib::merge::Merge;
use jj_lib::merged_tree::MergedTree;
use jj_lib::merged_tree_builder::MergedTreeBuilder;
use jj_lib::object_id::ObjectId as _;
use jj_lib::op_walk;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::repo_path::RepoPathBuf;
use jj_lib::working_copy::WorkingCopyFreshness;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_types::cache::object_id_for_canonical_bytes;
use kata_types::primitives::ObjectId;
use kata_types::tree_artifact::{TreeEntryMode, TreeNode};
use kata_types::tree_delta::{TreeChangeKind, TreeDelta};
use kata_types::{KataError, KataResult};

use kata_effects_contract::{AppliedCandidate, ExecutionWorkspaceHandle, WorkApplyState};

use super::JjBackend;
use super::durability::RepositoryBarrier;

/// The jj operation-metadata tag an apply transaction carries: the work-apply
/// effect's attempt id, the evidence `classify_work_apply` walks for.
pub const KATA_EFFECT_TAG: &str = "kata.effect";

/// The workspace's `@` was not the commit the head row recorded — the apply
/// refuses rather than guess which candidate it should rewrite.
pub const WORK_APPLY_CANDIDATE_DIVERGED: &str = "work_apply_candidate_diverged";

/// The bytes a member fetch returned are not the object the delta named —
/// length or content address disagree, so writing them would record a tree the
/// delta never described.
pub const WORK_APPLY_MEMBER_MISMATCH: &str = "work_apply_member_mismatch";

/// `forge_export` was asked to export a commit whose `MergedTree` still carries
/// a conflict — git cannot express one, so nothing is written or pushed.
pub const FORGE_EXPORT_CONFLICTED_COMMIT: &str = "forge_export_conflicted_commit";

impl JjBackend {
    /// Apply `delta` to the execution workspace `handle`'s candidate commit.
    ///
    /// `expected_wc_commit` is the head row's recorded commit id (hex): the
    /// workspace's `@` must BE it or the call refuses
    /// [`WORK_APPLY_CANDIDATE_DIVERGED`]. `members(object, size_bytes)` fetches
    /// one CAS member's bytes — the caller owns the store. `effect_tag` is the
    /// durable effect id the op log is tagged with.
    pub(super) fn apply_work_delta(
        &self,
        handle: &ExecutionWorkspaceHandle,
        expected_wc_commit: &str,
        delta: &TreeDelta,
        members: &dyn Fn(ObjectId, u64) -> KataResult<Vec<u8>>,
        effect_tag: &str,
    ) -> KataResult<AppliedCandidate> {
        super::record_vcs_op("work_apply", || {
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
            if wc_commit.id().hex() != expected_wc_commit {
                return Err(KataError::Validation(format!(
                    "{WORK_APPLY_CANDIDATE_DIVERGED}: the execution workspace's @ is {} but the \
                     recorded head is {expected_wc_commit} — the candidate moved under the apply \
                     (another apply, a settle, or a repair); nothing is rewritten",
                    wc_commit.id().hex()
                )));
            }
            let old_tree = wc_commit.tree();
            // Opened before the delta's blobs and trees are written: the op
            // published below names them.
            let barrier = RepositoryBarrier::for_git_store(repo.store())?;
            let new_tree = build_delta_tree(&repo, &old_tree, delta, members)?;
            assert_delta_nodes_present(&repo, &new_tree, delta)?;

            // The candidate CHANGE accumulates: rewrite @ onto the delta's
            // tree (same change id), rebase the wc pointer's dependents, tag
            // the op with the effect id, publish, then materialize the new
            // commit so the on-disk working copy is never left stale.
            let mut tx = repo.start_transaction();
            let new_commit = Self::block_on(
                tx.repo_mut()
                    .rewrite_commit(&wc_commit)
                    .set_tree(new_tree)
                    .write(),
            )
            .map_err(|err| {
                KataError::Internal(format!("failed to rewrite the candidate commit: {err}"))
            })?;
            Self::block_on(tx.repo_mut().rebase_descendants()).map_err(|err| {
                KataError::Internal(format!("failed to rebase workspace descendants: {err}"))
            })?;
            tx.set_tag(KATA_EFFECT_TAG.to_owned(), effect_tag.to_owned());

            work_apply_crash_point("before_jj_publish");
            // commit() is write()+publish(); spelled out so the crash window
            // between them is armable — it is the seam where "stored but
            // unreachable" ops live.
            let unpublished = Self::block_on(tx.write(format!("kata work_apply {effect_tag}")))
                .map_err(|err| {
                    KataError::Internal(format!("failed to write the work_apply op: {err}"))
                })?;
            work_apply_crash_point("between_write_and_publish");
            // The op becomes the head only once every object it names is
            // durable, so jj's log never names a torn object.
            barrier.sync("work_apply publish")?;
            let repo = Self::block_on(unpublished.publish()).map_err(|err| {
                KataError::Internal(format!("failed to publish the work_apply op: {err}"))
            })?;
            let operation_id = repo.operation().id().clone();
            work_apply_crash_point("after_publish_before_checkout");

            Self::block_on(workspace.check_out(operation_id, Some(&old_tree), &new_commit))
                .map_err(|err| {
                    KataError::Internal(format!(
                        "work_apply published {tag} but the checkout failed: {err} — the working \
                         copy is stale until `repair_stale_checkout` runs",
                        tag = effect_tag
                    ))
                })?;
            Ok(AppliedCandidate {
                commit_id: new_commit.id().hex(),
                tree_id: Self::merged_tree_id_hex(new_commit.tree_ids()),
            })
        })
    }

    /// Classify whether the `effect_tag` apply landed on `handle`'s workspace.
    ///
    /// The recovery rule, in order: a `@` still equal to `recorded_head_commit` means
    /// nothing landed (a published tag beside it is a contradiction →
    /// [`WorkApplyState::Diverged`]); otherwise a `kata.effect` tag walked from
    /// the op head — bounded at ops older than `since_ms` — or the current `@`
    /// listing the recorded head among its predecessors while carrying the
    /// delta's node on every changed path means [`WorkApplyState::Applied`];
    /// anything else is [`WorkApplyState::Diverged`].
    pub(super) fn classify_work_apply(
        &self,
        handle: &ExecutionWorkspaceHandle,
        recorded_head_commit: &str,
        effect_tag: &str,
        delta: &TreeDelta,
        since_ms: i64,
    ) -> KataResult<WorkApplyState> {
        super::record_vcs_op("classify_work_apply", || {
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
            let repo = Self::block_on(workspace.repo_loader().load_at_head()).map_err(|err| {
                KataError::Internal(format!("failed to load jj repo head: {err}"))
            })?;
            let workspace_name = workspace.workspace_name().to_owned();
            let wc_commit = Self::workspace_commit(repo.as_ref(), &workspace_name)?;
            let wc_hex = wc_commit.id().hex();
            let wc_is_recorded_head = wc_hex == recorded_head_commit;

            let tag_found = find_effect_tag(repo.as_ref(), effect_tag, since_ms)?;

            if wc_is_recorded_head {
                return Ok(if tag_found {
                    // The apply published but the wc pointer is unmoved — a
                    // state neither classification accepts; surface it rather
                    // than re-apply or call it done.
                    WorkApplyState::Diverged {
                        reason: format!(
                            "the kata.effect tag {effect_tag} walks from the op head, yet the \
                             workspace's @ is still the recorded head {recorded_head_commit}"
                        ),
                    }
                } else {
                    WorkApplyState::NotApplied
                });
            }
            if tag_found {
                return Ok(WorkApplyState::Applied {
                    commit_id: wc_hex,
                    tree_id: Self::merged_tree_id_hex(wc_commit.tree_ids()),
                });
            }
            // The tag may be GC'd (op_log_gc prunes by count+age, never by
            // effect resolution) while the commit survives: the rewritten @
            // names its predecessor, and the delta's nodes are the content
            // check that rewrite produced the right tree.
            let recorded_id = CommitId::try_from_hex(recorded_head_commit).ok_or_else(|| {
                KataError::Internal(format!(
                    "work_apply classify: recorded head commit id is not valid hex: {recorded_head_commit}"
                ))
            })?;
            // Each apply rewrite records ONE predecessor — the commit it
            // rewrote — so after several applies the recorded head is an
            // ANCESTOR in the predecessor DAG, not a direct edge. Walk the
            // (linear in practice) chain, bounded, until the head is found or
            // the chain ends.
            if predecessors_contain(&repo, &wc_commit, &recorded_id)?
                && delta_nodes_match(&repo, &wc_commit.tree(), delta)?
            {
                return Ok(WorkApplyState::Applied {
                    commit_id: wc_hex,
                    tree_id: Self::merged_tree_id_hex(wc_commit.tree_ids()),
                });
            }
            Ok(WorkApplyState::Diverged {
                reason: format!(
                    "the workspace's @ is {wc_hex}, neither the recorded head \
                     {recorded_head_commit} nor (absent the kata.effect tag) a commit whose \
                     predecessors carry it with the delta's nodes — the candidate diverged and \
                     the apply must not be re-driven"
                ),
            })
        })
    }

    /// Converge a workspace left stale by a crash between the apply's publish
    /// and its checkout: jj's update-stale — re-materialize the recorded `@`.
    /// A `Fresh` working copy (or one already ahead — `Updated`) is a no-op.
    /// `SiblingOperation` — the wc recorded an op the head does not contain —
    /// refuses rather than guess.
    pub(super) fn repair_stale_checkout(
        &self,
        handle: &ExecutionWorkspaceHandle,
    ) -> KataResult<()> {
        super::record_vcs_op("repair_stale_checkout", || {
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
            let mut locked = workspace.start_working_copy_mutation().map_err(|err| {
                KataError::Internal(format!("failed to lock jj working copy: {err}"))
            })?;
            match WorkingCopyFreshness::check_stale(locked.locked_wc(), &wc_commit, repo.as_ref())
                .map_err(|err| {
                KataError::Internal(format!("failed to check jj workspace freshness: {err}"))
            })? {
                WorkingCopyFreshness::Fresh | WorkingCopyFreshness::Updated(_) => {
                    drop(locked);
                    Ok(())
                }
                WorkingCopyFreshness::WorkingCopyStale => {
                    Self::block_on(locked.locked_wc().check_out(&wc_commit)).map_err(|err| {
                        KataError::Internal(format!(
                            "failed to check out the stale workspace: {err}"
                        ))
                    })?;
                    locked.finish(repo.op_id().clone()).map_err(|err| {
                        KataError::Internal(format!("failed to finish the checkout repair: {err}"))
                    })
                }
                WorkingCopyFreshness::SiblingOperation => Err(KataError::Validation(format!(
                    "{WORK_APPLY_CANDIDATE_DIVERGED}: the working copy recorded an operation the \
                     repo head does not contain — a sibling op, not a stale one; repair will not \
                     guess which side holds the candidate"
                ))),
            }
        })
    }
}

/// Build the delta's `MergedTree` over `base` — write every member blob/link
/// into the store, then materialize the tree. Pure store work: no transaction,
/// no op, nothing published.
fn build_delta_tree(
    repo: &Arc<jj_lib::repo::ReadonlyRepo>,
    base: &MergedTree,
    delta: &TreeDelta,
    members: &dyn Fn(ObjectId, u64) -> KataResult<Vec<u8>>,
) -> KataResult<MergedTree> {
    // `WORK_DELTA_RESERVED_PATH` — jj's RepoPath parser ACCEPTS `.git`/`.jj`
    // components and the store would write them; only CHECKOUT refuses
    // (`CheckoutError::ReservedPathComponent`), which would wedge the apply
    // sweep and every later materialization of this workspace. Refuse here —
    // typed `Validation` before any write — so a delta carrying one settles
    // the attempt `failed` rather than publishing a poison tree. (The worker
    // capture and the adoption judge refuse the same paths by the same token;
    // this is the last door for a delta produced elsewhere.)
    for change in delta.changes() {
        if let Some(component) = change.path.reserved_vcs_component() {
            return Err(KataError::Validation(format!(
                "{token}: the /work delta path {path:?} carries the VCS-internal \
                 component `{component}` — jj can never check it out, so nothing is published",
                token = kata_types::tree_artifact::WORK_DELTA_RESERVED_PATH,
                path = change.path.as_str(),
            )));
        }
    }
    let store = repo.store().clone();
    let mut builder = MergedTreeBuilder::new(base.clone());
    for change in delta.changes() {
        let path = RepoPathBuf::from_internal_string(change.path.as_str()).map_err(|err| {
            KataError::Validation(format!(
                "work_apply: delta path {:?} is not a jj repo path: {err}",
                change.path.as_str()
            ))
        })?;
        let values = match &change.change {
            TreeChangeKind::Write { node } => {
                let value = write_node(&store, &path, node, members)?;
                Merge::resolved(Some(value))
            }
            TreeChangeKind::Delete => Merge::absent(),
        };
        builder.set_or_remove(path, values);
    }
    JjBackend::block_on(builder.write_tree()).map_err(|err| {
        KataError::Internal(format!("work_apply: failed to write the delta tree: {err}"))
    })
}

/// Write one `TreeNode`'s content into the store and return its `TreeValue`.
/// A file's bytes are fetched through `members` and MUST be the object the
/// delta named — size and content address both, so a wrong/missing CAS member
/// refuses rather than writes a tree the delta never described.
fn write_node(
    store: &Arc<jj_lib::store::Store>,
    path: &jj_lib::repo_path::RepoPath,
    node: &TreeNode,
    members: &dyn Fn(ObjectId, u64) -> KataResult<Vec<u8>>,
) -> KataResult<TreeValue> {
    match node {
        TreeNode::File {
            mode,
            object,
            size_bytes,
        } => {
            let bytes = members(*object, *size_bytes)?;
            if bytes.len() as u64 != *size_bytes || object_id_for_canonical_bytes(&bytes) != *object
            {
                return Err(KataError::Validation(format!(
                    "{WORK_APPLY_MEMBER_MISMATCH}: member {object} for {path:?} is not the object \
                     the delta named (declared {size_bytes} bytes, got {})",
                    bytes.len()
                )));
            }
            let mut reader: &[u8] = &bytes;
            let file_id =
                JjBackend::block_on(store.write_file(path, &mut reader)).map_err(|err| {
                    KataError::Internal(format!("work_apply: failed to write blob {object}: {err}"))
                })?;
            Ok(TreeValue::File {
                id: file_id,
                executable: *mode == TreeEntryMode::Executable,
                copy_id: CopyId::placeholder(),
            })
        }
        TreeNode::Symlink { target } => {
            let symlink_id = JjBackend::block_on(store.write_symlink(path, target.as_str()))
                .map_err(|err| {
                    KataError::Internal(format!(
                        "work_apply: failed to write symlink at {path:?}: {err}"
                    ))
                })?;
            Ok(TreeValue::Symlink(symlink_id))
        }
    }
}

/// The cheap per-apply check: every changed path in `tree` names the delta's
/// node — blob content address and exec bit, symlink target, or absence for a
/// delete. Reads each member back from the store; bounded by the delta's
/// change count, not the tree.
fn assert_delta_nodes_present(
    repo: &Arc<jj_lib::repo::ReadonlyRepo>,
    tree: &MergedTree,
    delta: &TreeDelta,
) -> KataResult<()> {
    if delta_nodes_match(repo, tree, delta)? {
        return Ok(());
    }
    Err(KataError::Internal(
        "work_apply: the materialized tree does not carry the delta's node on every changed path — the apply was built wrong, not landed wrong"
            .to_string(),
    ))
}

/// Whether `tree` agrees with `delta` on every changed path (the classify
/// half's content check, shared with the post-build assertion).
fn delta_nodes_match(
    repo: &Arc<jj_lib::repo::ReadonlyRepo>,
    tree: &MergedTree,
    delta: &TreeDelta,
) -> KataResult<bool> {
    let store = repo.store();
    for change in delta.changes() {
        let path = RepoPathBuf::from_internal_string(change.path.as_str()).map_err(|err| {
            KataError::Validation(format!(
                "work_apply: delta path {:?} is not a jj repo path: {err}",
                change.path.as_str()
            ))
        })?;
        let value = tree.path_value(&path).map_err(|err| {
            KataError::Internal(format!(
                "work_apply: failed to read {path:?} from the tree: {err}"
            ))
        })?;
        match &change.change {
            TreeChangeKind::Delete => {
                if value.as_resolved().is_some_and(Option::is_some) {
                    return Ok(false);
                }
            }
            TreeChangeKind::Write { node } => {
                let resolved = value.as_resolved().and_then(|v| v.as_ref());
                match node {
                    TreeNode::Symlink { target } => {
                        let Some(TreeValue::Symlink(symlink_id)) = resolved else {
                            return Ok(false);
                        };
                        let stored = JjBackend::block_on(store.read_symlink(&path, symlink_id))
                            .map_err(|err| {
                                KataError::Internal(format!(
                                    "work_apply: failed to read symlink {path:?}: {err}"
                                ))
                            })?;
                        if stored != target.as_str() {
                            return Ok(false);
                        }
                    }
                    TreeNode::File {
                        mode,
                        object,
                        size_bytes,
                    } => {
                        let Some(TreeValue::File {
                            id: file_id,
                            executable,
                            ..
                        }) = resolved
                        else {
                            return Ok(false);
                        };
                        if *executable != (*mode == TreeEntryMode::Executable) {
                            return Ok(false);
                        }
                        let mut reader = JjBackend::block_on(store.read_file(&path, file_id))
                            .map_err(|err| {
                                KataError::Internal(format!(
                                    "work_apply: failed to open blob at {path:?}: {err}"
                                ))
                            })?;
                        let bytes = JjBackend::block_on(async {
                            use tokio::io::AsyncReadExt as _;
                            let mut bytes = Vec::new();
                            reader.read_to_end(&mut bytes).await.map(|_| bytes)
                        })
                        .map_err(|err| {
                            KataError::Internal(format!(
                                "work_apply: failed to read blob at {path:?}: {err}"
                            ))
                        })?;
                        if bytes.len() as u64 != *size_bytes
                            || object_id_for_canonical_bytes(&bytes) != *object
                        {
                            return Ok(false);
                        }
                    }
                }
            }
        }
    }
    Ok(true)
}

/// Whether `start`'s predecessor DAG reaches `target`, bounded. `rewrite_commit`
/// records exactly the commit it rewrote, so an apply chain is linear — but the
/// walk stays a worklist so a merge-shaped predecessor set cannot wedge it.
pub(super) fn predecessors_contain(
    repo: &Arc<jj_lib::repo::ReadonlyRepo>,
    start: &jj_lib::commit::Commit,
    target: &CommitId,
) -> KataResult<bool> {
    const MAX_HOPS: usize = 4096;
    let mut seen = std::collections::HashSet::new();
    let mut frontier: Vec<CommitId> = start.store_commit().predecessors.clone();
    while let Some(id) = frontier.pop() {
        if id == *target {
            return Ok(true);
        }
        if !seen.insert(id.clone()) || seen.len() > MAX_HOPS {
            continue;
        }
        let commit = repo.store().get_commit(&id).map_err(|err| {
            KataError::Internal(format!(
                "work_apply classify: predecessor unreadable: {err}"
            ))
        })?;
        frontier.extend(commit.store_commit().predecessors.iter().cloned());
    }
    Ok(false)
}

/// Walk the op log from the current head, newest first, stopping at the first
/// op older than `since_ms`, answering whether any reached op carries
/// `kata.effect = effect_tag`.
///
/// The walk is timestamp-ordered lazily (`walk_ancestors`'s heuristic), so the
/// `since_ms` stop is a bound on effort AND on how far back an unresolved
/// effect's evidence is sought — the caller supplies the effect's issue time.
pub(crate) fn find_effect_tag(
    repo: &jj_lib::repo::ReadonlyRepo,
    effect_tag: &str,
    since_ms: i64,
) -> KataResult<bool> {
    let loader = repo.loader();
    let heads = op_walk::get_current_head_ops(loader.op_store(), loader.op_heads_store().as_ref())
        .map_err(|err| KataError::Internal(format!("failed to read jj op heads: {err}")))?;
    for operation in op_walk::walk_ancestors(&heads) {
        let operation = operation
            .map_err(|err| KataError::Internal(format!("failed to walk the jj op log: {err}")))?;
        if operation.metadata().time.end.timestamp.0 < since_ms {
            break;
        }
        if operation
            .metadata()
            .tags
            .get(KATA_EFFECT_TAG)
            .is_some_and(|tag| tag == effect_tag)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Test-only crash arms inside `apply_work_delta`, named for the crash-boundary
/// ledger: `KATA_WORK_APPLY_CRASH_ARM=before_jj_publish` /
/// `between_write_and_publish` / `after_publish_before_checkout`. Compiled out
/// of the shipped library (`cfg(test)`); abort rather than exit so the child
/// leaves whatever was persisted on disk, which is the thing under test.
#[inline]
fn work_apply_crash_point(arm: &str) {
    #[cfg(test)]
    if std::env::var_os("KATA_WORK_APPLY_CRASH_ARM").as_deref() == Some(std::ffi::OsStr::new(arm)) {
        eprintln!("[kata-test] work_apply crash arm reached: {arm}; aborting");
        std::process::abort();
    }
    #[cfg(not(test))]
    let _ = arm;
}
