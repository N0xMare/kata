//! The `/git-history` PUBLISHER: take the git-history
//! artifact an `oci` execution's provider produced for the committed base,
//! declare it retained by the execution, and record the
//! `execution_git_views` row the capsule submit path reads.
//!
//! [`publish_execution_git_view`] is the same publish-declare shape
//! [`crate::work_tree::publish_base_tree_head`] states, over the
//! provider-converted [`CommittedBaseGitView`] rather than the base tree:
//! every member — `objects/pack/pack-*.{pack,idx}`, `index`, a possible
//! `shallow` — is streamed through `put_member` into the CAS, the manifest
//! declares a `kind='tree'` artifact owned by the
//! execution, and the row is recorded LAST, after the
//! `after_git_view_published_before_recorded` boundary — the one window
//! where the artifact is durable and no row names it yet. Re-admission
//! converges through CAS dedup plus `record_execution_git_view`'s
//! converge-or-refuse (`git_view_divergent`), and an artifact left orphaned
//! by the window is an unreferenced row that costs disk, so this function is
//! safe to re-drive end to end.

use kata_types::error::KataResult;
use kata_types::primitives::ObjectId;
use kata_types::tree_artifact::CommittedBaseGitView;
use ulid::Ulid;

use crate::OperationalDb;
use crate::operational::ExecutionGitView;
use crate::store::cas::CasStore;

/// Publish an execution's git-history artifact and record its
/// `execution_git_views` row, admission-side.
///
/// `convert` is the provider's `committed_base_git_history` bound to the
/// execution's workspace: it streams every member through the supplied
/// `put_member` (bytes land in CAS as produced — packs never all held at
/// once) and returns the manifest plus the view metadata the row records.
///
/// # Errors
///
/// The converter's refused set (`git_view_*`, `work_tree_base_*`) passes
/// through unchanged; declaration and storage failures surface as their own
/// `KataError` kinds.
pub fn publish_execution_git_view(
    db: &OperationalDb,
    cas: &CasStore,
    execution: Ulid,
    convert: impl FnOnce(
        &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
    ) -> KataResult<CommittedBaseGitView>,
) -> KataResult<ExecutionGitView> {
    let committed = convert(&mut |bytes: &[u8]| Ok(cas.put_durable(bytes)?.object_id()))?;
    let manifest_durable = cas.put_durable(&committed.manifest_bytes)?;
    let reference = crate::work_tree::declare_work_tree(
        db,
        cas,
        execution,
        &committed.manifest,
        &manifest_durable,
    )?;
    crate::fault_inject::operational_crash_point("after_git_view_published_before_recorded");
    let view = db.record_execution_git_view(
        execution,
        &committed.base_commit,
        committed.branch.as_ref(),
        committed.identity.name.as_str(),
        committed.identity.email.as_str(),
        reference.id().0.0,
    )?;
    Ok(view)
}
