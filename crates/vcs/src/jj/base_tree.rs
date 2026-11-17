//! The COMMITTED base tree of an execution workspace,
//! converted to a [`CommittedBaseTree`] — a [`TreeManifest`] plus the member
//! bytes streamed one blob at a time to the publisher's `put_member`.
//!
//! The tree this converts is the working-copy commit's sole PARENT: the commit
//! `create_workspace` resolved as the base. Reading the parent — never the `@`
//! working-copy commit itself — is what makes "uncommitted operator checkout
//! edits are never inputs" structural rather than a timing promise: the
//! working copy's dirty state lives in `@`'s tree, and this walk never opens
//! it.
//!
//! The refusals are named per rejected SET and share the `work_tree_base_*`
//! family so the admission error states exactly what the committed tree did:
//!
//! - [`WORK_TREE_BASE_CONFLICTED`]: any path still conflicted in the base
//!   commit's `MergedTree`. The refusal is claimed here, by the code that
//!   would otherwise have to pick a side.
//! - [`WORK_TREE_BASE_GITLINK`]: a `TreeValue::GitSubmodule` at any depth. The
//!   census refuses the same base via
//!   `UnsupportedRepositoryFeature::GitSubmodule`, so admission normally never
//!   reaches this; the conversion refuses it regardless of what ran before it.
//! - [`WORK_TREE_BASE_UNREPRESENTABLE`]: a committed entry a `TreeManifest`
//!   cannot carry — a path `TreePath::new` rejects (control bytes, `.`/`..`
//!   components), a symlink target `SymlinkTarget::new` rejects (empty, NUL),
//!   a `@` whose base is not a single commit, or a backend value kind the
//!   schema has no node for.
//! - [`WORK_TREE_BASE_MEMBER_TOO_LARGE`]: one member over
//!   [`kata_types::tree_artifact::MAX_MEMBER_BYTES`] — the same bound the
//!   worker's materializer enforces on the read side.
//! - [`WORK_TREE_BASE_BOUND_EXCEEDED`]: the tree over the
//!   `[node]`-configured input ceiling (`work_tree_max_bytes` /
//!   `work_tree_max_entries`). This is the INPUT bound only — capsule result
//!   budgets stay in their own class.
//!
//! Encoding failures of things the walk MUST read (the workspace, the commit,
//! a blob the store cannot return) are `Internal`, never a silent skip: a
//! silently skipped member would publish a `/work` that disagrees with the
//! commit it claims to be.

use std::sync::Arc;

use jj_lib::backend::TreeValue;
use jj_lib::merged_tree::MergedTree;
use jj_lib::object_id::ObjectId as _;
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::store::Store;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_types::primitives::ObjectId;
use kata_types::tree_artifact::{
    CommittedBaseTree, MAX_MEMBER_BYTES, SymlinkTarget, TreeEntry, TreeEntryMode, TreeManifest,
    TreeNode, TreePath, WorkTreeInputBounds,
};
use kata_types::{KataError, KataResult};
use tokio::io::AsyncReadExt as _;

use kata_effects_contract::{
    ExecutionWorkspaceHandle, WORK_TREE_BASE_BOUND_EXCEEDED, WORK_TREE_BASE_CONFLICTED,
    WORK_TREE_BASE_GITLINK, WORK_TREE_BASE_MEMBER_TOO_LARGE, WORK_TREE_BASE_UNREPRESENTABLE,
};

use super::JjBackend;

impl JjBackend {
    /// Load the workspace `handle` names and resolve its COMMITTED BASE commit —
    /// the working-copy commit's sole parent, which is the commit
    /// `create_workspace` selected (at admission, before any capsule can have
    /// landed, `@`'s parent IS that base). Shared by the base-tree conversion
    /// and the git-history producer so both read the SAME commit — a second
    /// hand-rolled parent pick is how "the /work tree" and "the git view" would
    /// disagree on what they are rooted at.
    ///
    /// `WORK_TREE_BASE_UNREPRESENTABLE` refuses a `@` whose base is not a
    /// single commit — a merge-shaped or parentless `@` means the workspace is
    /// not the shape admission was promised.
    ///
    /// The returned `Arc<ReadonlyRepo>` stays loaded for the caller's own
    /// reads (the git store behind it, the trunk bookmark) rather than being
    /// re-opened.
    pub(super) fn workspace_base_commit(
        &self,
        handle: &ExecutionWorkspaceHandle,
    ) -> KataResult<(
        std::sync::Arc<jj_lib::repo::ReadonlyRepo>,
        jj_lib::commit::Commit,
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
            KataError::Internal(format!(
                "base-commit resolution could not load the execution workspace {}: {err}",
                handle.path.display()
            ))
        })?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head()).map_err(|err| {
            KataError::Internal(format!(
                "base-commit resolution could not load the jj repository: {err}"
            ))
        })?;
        let workspace_name = workspace.workspace_name().to_owned();
        let wc_commit = Self::workspace_commit(repo.as_ref(), &workspace_name)?;
        // `create_workspace` checks a fresh `@` out over the resolved base, so
        // the base is the one parent. A merge-shaped or parentless `@` here
        // means the workspace is not the shape admission was promised — refuse
        // rather than pick one of several possible bases.
        let [base_id] = wc_commit.parent_ids() else {
            return Err(work_tree_base_refusal(
                WORK_TREE_BASE_UNREPRESENTABLE,
                format!(
                    "the execution workspace's @ has {} parents; a committed base must be \
                     the single parent of the workspace commit create_workspace made",
                    wc_commit.parent_ids().len(),
                ),
            ));
        };
        let base_commit = repo.store().get_commit(base_id).map_err(|err| {
            KataError::Internal(format!(
                "base-commit resolution could not load the base commit {base_id}: {err}"
            ))
        })?;
        Ok((repo, wc_commit, base_commit))
    }

    /// Convert the workspace's committed base tree and stream every member to
    /// `put_member`.
    ///
    /// Loads the workspace the handle names, takes the working-copy commit's
    /// sole parent as the base (the commit `create_workspace` selected — at
    /// admission, before any capsule can have landed, `@`'s parent IS that
    /// base), and walks the parent commit's `MergedTree`.
    ///
    /// `put_member` is invoked once per file with the member's full bytes — a
    /// member is bounded by [`MAX_MEMBER_BYTES`] before the call, so the
    /// publisher receives the same bytes it will persist. The callback is how
    /// this stays streaming: the publisher maps them straight into CAS and no
    /// more than one member is held at a time.
    pub(super) fn committed_base_tree(
        &self,
        handle: &ExecutionWorkspaceHandle,
        bounds: WorkTreeInputBounds,
        put_member: &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
    ) -> KataResult<CommittedBaseTree> {
        let (repo, wc_commit, base_commit) = self.workspace_base_commit(handle)?;
        let base_id = base_commit.id();
        let (manifest, manifest_bytes) = convert_tree(
            repo.store().clone(),
            &base_commit.tree(),
            bounds,
            put_member,
        )?;
        Ok(CommittedBaseTree {
            base_commit: jj_lib::object_id::ObjectId::hex(base_id),
            candidate_commit_id: wc_commit.id().hex(),
            manifest,
            manifest_bytes,
        })
    }
}

/// The walk itself: one `MergedTree`'s leaves → manifest entries, members
/// streamed to `put_member` in tree order.
///
/// `tree.entries()` visits every level's leaf values sorted by path; the
/// manifest builder re-sorts on insert, so enumeration order only orders the
/// `put_member` calls.
fn convert_tree(
    store: Arc<Store>,
    tree: &MergedTree,
    bounds: WorkTreeInputBounds,
    put_member: &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
) -> KataResult<(TreeManifest, Vec<u8>)> {
    let mut entries = Vec::new();
    let mut total_bytes: u64 = 0;
    for (path, value) in tree.entries() {
        let path_string = path.as_internal_file_string();
        let value = value.map_err(|err| {
            KataError::Internal(format!(
                "committed-base-tree conversion could not read tree entry `{path_string}`: {err}"
            ))
        })?;
        if !value.is_resolved() {
            return Err(work_tree_base_refusal(
                WORK_TREE_BASE_CONFLICTED,
                format!(
                    "`{path_string}` is conflicted in the base commit's tree; a conflicted \
                     base has no single committed content /work could carry",
                ),
            ));
        }
        if entries.len() as u64 >= bounds.max_entries {
            return Err(work_tree_base_refusal(
                WORK_TREE_BASE_BOUND_EXCEEDED,
                format!(
                    "the committed base tree holds more than the configured \
                     work_tree_max_entries bound of {} entries",
                    bounds.max_entries,
                ),
            ));
        }
        let tree_path = TreePath::new(path_string).map_err(|err| {
            work_tree_base_refusal(
                WORK_TREE_BASE_UNREPRESENTABLE,
                format!("committed path `{path_string}` is not a TreeManifest path: {err}"),
            )
        })?;
        let entry = match value.as_resolved().and_then(Option::as_ref) {
            Some(TreeValue::File { id, executable, .. }) => {
                let bytes = read_member(store.as_ref(), path.as_ref(), id)?;
                let size_bytes = bytes.len() as u64;
                if size_bytes > MAX_MEMBER_BYTES {
                    return Err(work_tree_base_refusal(
                        WORK_TREE_BASE_MEMBER_TOO_LARGE,
                        format!(
                            "`{path_string}` is {size_bytes} bytes — over the {MAX_MEMBER_BYTES}-byte \
                             per-member bound the worker's materializer enforces",
                        ),
                    ));
                }
                let object = put_member(&bytes)?;
                TreeEntry {
                    path: tree_path,
                    node: TreeNode::File {
                        mode: if *executable {
                            TreeEntryMode::Executable
                        } else {
                            TreeEntryMode::Regular
                        },
                        object,
                        size_bytes,
                    },
                }
            }
            Some(TreeValue::Symlink(id)) => {
                let target = JjBackend::block_on(store.read_symlink(path.as_ref(), id)).map_err(|err| {
                    KataError::Internal(format!(
                        "committed-base-tree conversion could not read symlink `{path_string}`: {err}"
                    ))
                })?;
                let target = SymlinkTarget::new(target).map_err(|err| {
                    work_tree_base_refusal(
                        WORK_TREE_BASE_UNREPRESENTABLE,
                        format!(
                            "committed symlink `{path_string}`'s target is not representable \
                             in a TreeManifest: {err}"
                        ),
                    )
                })?;
                TreeEntry {
                    path: tree_path,
                    node: TreeNode::Symlink { target },
                }
            }
            Some(TreeValue::GitSubmodule(_)) => {
                return Err(work_tree_base_refusal(
                    WORK_TREE_BASE_GITLINK,
                    format!(
                        "`{path_string}` is a committed git submodule (gitlink); /work \
                         carries no submodule content",
                    ),
                ));
            }
            // `entries()` yields leaf values only — a Tree here would mean the
            // merged-tree contract changed; a resolved None likewise. Refuse by
            // name rather than silently drop an entry.
            Some(TreeValue::Tree(_)) | None => {
                return Err(work_tree_base_refusal(
                    WORK_TREE_BASE_UNREPRESENTABLE,
                    format!("`{path_string}` resolves to a tree value /work cannot carry"),
                ));
            }
        };
        // The byte budget charges `TreeNode::size_bytes` — a file's length AND
        // a symlink's target length, the same accounting the read side applies.
        total_bytes = total_bytes.saturating_add(entry.node.size_bytes());
        if total_bytes > bounds.max_bytes {
            return Err(work_tree_base_refusal(
                WORK_TREE_BASE_BOUND_EXCEEDED,
                format!(
                    "the committed base tree's members total more than the configured \
                     work_tree_max_bytes bound of {} bytes",
                    bounds.max_bytes,
                ),
            ));
        }
        entries.push(entry);
    }
    let manifest = TreeManifest::new(entries).map_err(|err| {
        work_tree_base_refusal(
            WORK_TREE_BASE_UNREPRESENTABLE,
            format!("the committed base tree built no legal manifest: {err}"),
        )
    })?;
    // `manifest_bytes` propagates TREE_MANIFEST_OVER_CEILING by its own name —
    // the manifest ceiling is the one bound shared with every reader.
    let manifest_bytes = manifest.manifest_bytes()?;
    Ok((manifest, manifest_bytes))
}

/// Read one committed member, capped at [`MAX_MEMBER_BYTES`]: the read stops at
/// the bound plus one byte, so an over-bound member costs the bound, never its
/// full length, and the caller distinguishes "exactly the bound" from "over it"
/// by one byte.
fn read_member(
    store: &Store,
    path: &jj_lib::repo_path::RepoPath,
    id: &jj_lib::backend::FileId,
) -> KataResult<Vec<u8>> {
    let internal = path.as_internal_file_string().to_owned();
    JjBackend::block_on(async {
        let reader = store.read_file(path, id).await.map_err(|err| {
            KataError::Internal(format!(
                "committed-base-tree conversion could not open `{internal}` in the base tree: {err}"
            ))
        })?;
        let mut bytes = Vec::new();
        reader
            .take(MAX_MEMBER_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .await
            .map_err(|err| {
                KataError::Internal(format!(
                    "committed-base-tree conversion could not read `{internal}`: {err}"
                ))
            })?;
        Ok::<_, KataError>(bytes)
    })
}

/// Every refusal this conversion emits is a `KataError::Validation` carrying
/// the stable token and the class detail — the two facts the admission error
/// has to state (the refusal grammar here is a token-prefixed `Validation`,
/// the spelling `oci_unsupported_features_refusal` already uses).
fn work_tree_base_refusal(token: &str, detail: String) -> KataError {
    KataError::Validation(format!("{token}: {detail}"))
}

#[cfg(test)]
#[path = "base_tree_tests.rs"]
mod tests;
