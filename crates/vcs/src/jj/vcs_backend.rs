//! [`VcsBackend`] impl for [`JjBackend`].
//!
//! Shared private helpers live on [`JjBackend`] in the parent module (`jj/mod.rs`)
//! and are reachable here because this is a descendant module.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use futures::StreamExt as _;
use jj_lib::git::{self, GitImportOptions};
use jj_lib::matchers::{EverythingMatcher, NothingMatcher};
use jj_lib::merged_tree::{MergedTree, TreeDiffEntry};
use jj_lib::object_id::ObjectId as _;
use jj_lib::ref_name::{GitRefNameBuf, RefNameBuf, WorkspaceNameBuf};
use jj_lib::repo::{ReadonlyRepo, Repo as _, StoreFactories};
use jj_lib::revset::SymbolResolver;
use jj_lib::working_copy::{SnapshotOptions, WorkingCopyFreshness};
use jj_lib::workspace::{Workspace, default_working_copy_factories, default_working_copy_factory};
use kata_types::target::TargetHead;
use kata_types::{AgentId, KataError, KataResult};

use crate::backend::VcsBackend;
use crate::revset::{RevsetCommit, RevsetDiagnostic, RevsetQueryResult};
use crate::trunk::TrunkResolution;
use crate::workspace::{
    WorkspaceFileStatus, WorkspaceFileStatusKind, WorkspaceHandle, WorkspaceStatus,
};
use kata_effects_contract::{RecordedChangeKind, RecordedPathChange, TARGET_HEAD_ABSENT};

use super::JjBackend;
use super::durability::{RepositoryBarrier, commit_transaction};

impl VcsBackend for JjBackend {
    fn open(path: &Path) -> KataResult<Self> {
        fs::create_dir_all(path)?;
        let repo_path = path.canonicalize()?;
        let settings = Self::user_settings_at(&repo_path)?;

        if repo_path.join(super::JJ_METADATA_DIR_NAME).exists() {
            Workspace::load(
                &settings,
                &repo_path,
                &StoreFactories::default(),
                &default_working_copy_factories(),
            )
            .map_err(|err| KataError::Internal(format!("failed to load jj workspace: {err}")))?;
        } else if repo_path.join(".git").exists() {
            // The root is ALREADY a git repo (the default `vcs.jj_repo =
            // "."` points kata's execution-workspace root at the operator's git
            // project) but has no jj yet. ADOPT the existing `.git` as jj's store
            // so the repo becomes colocated IN PLACE: the pre-existing top-level
            // `.git` stays the single git surface and jj shares its working copy.
            // `init_colocated_git` here would try to CREATE a fresh `.git` and
            // fail ("Failed to initialize git repository") because one already
            // exists, silently dropping the operator to a no-provider fallback.
            let git_repo_path = repo_path.join(".git");
            let (_workspace, repo) = Self::block_on(Workspace::init_external_git(
                &settings,
                &repo_path,
                &git_repo_path,
            ))
            .map_err(|err| {
                KataError::Internal(format!(
                    "failed to initialize jj repo over existing git store: {err}"
                ))
            })?;
            // `init_external_git` only POINTS jj's store at the existing `.git`;
            // it does NOT import refs/HEAD, so jj's view starts at the EMPTY root
            // commit and the operator's git-COMMITTED history is invisible to jj
            // — and to every execution workspace derived from it (a secondary
            // workspace would check out an empty tree, hiding the operator's
            // files from agents). IMPORT the git HEAD + refs so jj's view carries
            // the git HEAD and branches, mirroring what `jj git init --colocate`
            // does on an existing repo. `create_workspace` then bases execution
            // workspaces off the imported head.
            Self::import_adopted_git_history(&repo)?;
        } else {
            // jj-git colocation — initialize a NEW repo COLOCATED: one
            // real top-level `.git` sharing the working copy with `.jj`, so the
            // git CLI works at the repo root. This is the OPERATOR / stage-level
            // git surface (a `validate` stage that shells `git status` in its
            // execution workspace, the forge push) — kata itself never shells
            // git. `init_internal_git` would bury the git store at
            // `.jj/repo/store/git` with NO top-level `.git`, so the git CLI could
            // not reach the repo at all.
            //
            // NARROWING: this only re-shapes NEWLY-created repos. A repo that
            // already carries `.jj` loads unchanged above — a pre-existing
            // INTERNAL-git repo stays internal (no in-place internal→colocated
            // migration). An operator re-colocates such a repo by re-creating it
            // (move the working files aside, delete `.jj`, `open()` afresh) or by
            // running `jj git init --colocate` against it out-of-band.
            Self::block_on(Workspace::init_colocated_git(&settings, &repo_path)).map_err(
                |err| KataError::Internal(format!("failed to initialize jj repo: {err}")),
            )?;
        }

        Ok(Self {
            repo_path,
            op_log_gc: super::op_log_gc::OpLogGcPolicy::default(),
            // NO DEFAULT TRUNK. `open()` deliberately carries `None`: the
            // operator's `vcs.trunk` arrives through
            // `JjBackend::with_configured_trunk` at the boot construction
            // site, and absent means "ask this repository", never "assume
            // `main`".
            configured_trunk: None,
        })
    }

    fn create_workspace(&self, agent: &AgentId) -> KataResult<WorkspaceHandle> {
        self.create_workspace_based(agent, WorkspaceBase::Trunk)
    }

    fn remove_workspace(&self, agent: &AgentId) -> KataResult<()> {
        self.remove_workspace_tagged(agent, None, &self.barrier()?)
    }

    fn commit(&self, agent: &AgentId, message: &str) -> KataResult<String> {
        super::record_vcs_op("commit", || Self::commit_inner(self, agent, message))
    }

    fn workspace_status(&self, agent: &AgentId) -> KataResult<WorkspaceStatus> {
        let settings = self.user_settings()?;
        let workspace_name = Self::workspace_name(agent);
        let workspace = self.load_agent_workspace(&settings, agent)?;
        Self::workspace_status_core(workspace, &workspace_name)
    }
}

/// What a freshly-created workspace is based on.
#[derive(Clone, Copy, Debug)]
pub(super) enum WorkspaceBase<'a> {
    /// Trunk as resolved now — the agent-keyed [`VcsBackend`] surface.
    Trunk,
    /// An execution's FROZEN target head: the commit admission resolved, or the
    /// empty root for an unborn trunk. Never re-resolved.
    Frozen(&'a TargetHead),
}

impl JjBackend {
    /// Create (or re-open) `agent`'s workspace based on `base`.
    ///
    /// Re-opening an existing workspace changes nothing: the base it was
    /// created on is what it keeps.
    pub(super) fn create_workspace_based(
        &self,
        agent: &AgentId,
        base: WorkspaceBase<'_>,
    ) -> KataResult<WorkspaceHandle> {
        super::record_vcs_op("workspace_create", || {
            let settings = self.user_settings()?;
            let workspace_path = self.workspace_path(agent);
            fs::create_dir_all(&workspace_path)?;

            if workspace_path.join(".jj").exists() {
                Workspace::load(
                    &settings,
                    &workspace_path,
                    &StoreFactories::default(),
                    &default_working_copy_factories(),
                )
                .map_err(|err| {
                    KataError::Internal(format!("failed to load agent workspace: {err}"))
                })?;
            } else {
                let root_workspace = self.load_root_workspace(&settings)?;
                let root_repo = Self::block_on(root_workspace.repo_loader().load_at_head())
                    .map_err(|err| {
                        KataError::Internal(format!("failed to load jj repo head: {err}"))
                    })?;

                // Opened before jj-lib's initialization writes anything, so the
                // sync below reports a writeback error of any of its writes.
                let initialization = self.barrier()?;
                let (mut workspace, repo) = Self::block_on(
                    Workspace::init_workspace_with_existing_repo(
                        &workspace_path,
                        root_workspace.repo_path(),
                        &root_repo,
                        &*default_working_copy_factory(),
                        Self::workspace_name(agent),
                    ),
                )
                .map_err(|err| {
                    KataError::Internal(format!("failed to initialize agent jj workspace: {err}"))
                })?;
                // jj-lib's initialization writes the workspace's `.jj/repo` pointer
                // and working-copy files without a sync and publishes its own
                // `add workspace` operation, which kata cannot barrier from inside.
                // Sync them now, before the base checkout — which can take seconds
                // on a large tree — so the window in which a power loss can tear
                // a registered workspace is jj-lib's call alone.
                initialization.sync("after the workspace's initialization")?;

                // A freshly-initialized jj workspace always checks out the EMPTY root
                // commit (jj-lib's `init_working_copy` hardcodes it). Base this
                // execution workspace on TRUNK — the SAME resolved bookmark the
                // merge queue lands against — so the repository's committed
                // files are materialized for the agent AND the candidate can
                // fast-forward. A repository with no trunk at all has nothing to
                // fork, so the empty-root checkout stands unchanged; a
                // repository whose trunk kata cannot identify REFUSES here
                // rather than handing the agent an empty tree.
                match base {
                    WorkspaceBase::Trunk => {
                        self.base_workspace_on_trunk(&mut workspace, repo, agent)?;
                    }
                    // The empty root jj-lib already checked out IS an unborn
                    // trunk's base.
                    WorkspaceBase::Frozen(TargetHead::Unborn) => {}
                    WorkspaceBase::Frozen(TargetHead::Commit(head)) => {
                        Self::base_workspace_on_frozen_head(&mut workspace, repo, agent, head)?;
                    }
                }
            }

            Ok(WorkspaceHandle::new(*agent, workspace_path))
        })
    }

    /// Base a freshly-created execution workspace on the target head admission
    /// FROZE, read straight out of the store — never through a ref that could
    /// have moved since. The head stays reachable between resolution and here
    /// through the execution's target pin (`refs/kata/targets/<id>/head`),
    /// which jj never imports: jj's git import reads only `refs/heads`,
    /// `refs/remotes` and `refs/tags`, and checking the commit out indexes its
    /// ancestry on the way.
    ///
    /// # Errors
    ///
    /// `Validation` (`target_head_absent`) when the store does not hold the
    /// frozen head — the pin was removed and the commit collected — so the run
    /// is refused rather than forked from anything else.
    fn base_workspace_on_frozen_head(
        workspace: &mut Workspace,
        repo: Arc<ReadonlyRepo>,
        agent: &AgentId,
        head: &str,
    ) -> KataResult<()> {
        // `check_structure` already refused a non-hex head, so a miss here is
        // corruption of the frozen target, not a refusal the operator can act on.
        let id = jj_lib::backend::CommitId::try_from_hex(head).ok_or_else(|| {
            KataError::Internal(format!(
                "the frozen target head `{head}` is not a commit id, though its structure was checked"
            ))
        })?;
        // Only a NOT-FOUND is `target_head_absent`: any other store failure says
        // nothing about whether the repository still holds the head.
        let base_commit = repo.store().get_commit(&id).map_err(|err| match err {
            jj_lib::backend::BackendError::ObjectNotFound { .. } => KataError::Validation(format!(
                "{TARGET_HEAD_ABSENT}: the repository no longer holds the frozen target head \
                 `{head}` ({err}); the run is not forked from anything else"
            )),
            other => KataError::Internal(format!(
                "read the frozen target head `{head}` from the repository: {other}"
            )),
        })?;
        Self::check_out_base(
            workspace,
            repo,
            Self::workspace_name(agent),
            &agent.0.to_string(),
            &base_commit,
        )
    }
}

impl JjBackend {
    /// Import an adopted git repo's HEAD + refs into jj's view.
    ///
    /// `Workspace::init_external_git` only POINTS jj's store at the pre-existing
    /// `.git`; it leaves jj's view at the empty root commit. This mirrors what
    /// `jj git init --colocate` does over an existing repo: in one transaction,
    /// import the git HEAD (so jj's `git_head()` and the head commit become
    /// reachable) and the git refs (branches → local bookmarks, so kata's
    /// `main`-bookmark promote/park flow has its base), then rebase descendants
    /// and commit.
    ///
    /// NARROWING: the REFS are what the execution-workspace path rides on —
    /// `refs/heads/<trunk>` becomes the local bookmark that both
    /// [`Self::base_workspace_on_trunk`] forks and the merge queue lands against.
    /// HEAD is imported too so an operator repo whose HEAD is detached off every
    /// branch still has its head commit reachable in jj. On a first adoption jj's
    /// view is empty, so nothing is abandoned.
    fn import_adopted_git_history(repo: &Arc<ReadonlyRepo>) -> KataResult<()> {
        Self::import_git_history_tx(repo.clone(), "kata adopt colocated git history").map(|_| ())
    }

    /// Import the adopted git repo's HEAD + refs into jj's view in ONE
    /// transaction and hand back the resulting repo.
    ///
    /// Shared body of the one-time adoption import at
    /// [`Self::import_adopted_git_history`] (`open()`, first-open visibility) and
    /// the per-workspace refresh at [`Self::refresh_trunk_from_git`]
    /// (`create_workspace`). Import the git HEAD (so jj's `git_head()` and
    /// the head commit become reachable) and the git refs (branches → local
    /// bookmarks) with `abandon_unreachable_commits: false` so nothing already in
    /// jj's view is discarded, then rebase descendants and commit. `description`
    /// is the op-log message so the two call sites stay distinguishable.
    fn import_git_history_tx(
        repo: Arc<ReadonlyRepo>,
        description: &str,
    ) -> KataResult<Arc<ReadonlyRepo>> {
        super::record_vcs_op("import", || {
            Self::import_git_history_tx_inner(repo, description)
        })
    }

    fn import_git_history_tx_inner(
        repo: Arc<ReadonlyRepo>,
        description: &str,
    ) -> KataResult<Arc<ReadonlyRepo>> {
        let import_options = GitImportOptions {
            auto_local_bookmark: true,
            abandon_unreachable_commits: false,
            remote_auto_track_bookmarks: HashMap::new(),
        };
        // An import can write commits (a working-copy commit rebased onto an
        // imported head) and their keep refs before it publishes.
        let barrier = RepositoryBarrier::for_git_store(repo.store())?;
        let mut tx = repo.start_transaction();
        git::import_head(tx.repo_mut()).map_err(|err| {
            KataError::Internal(format!("failed to import git HEAD into jj: {err}"))
        })?;
        git::import_refs(tx.repo_mut(), &import_options).map_err(|err| {
            KataError::Internal(format!("failed to import git refs into jj: {err}"))
        })?;
        Self::block_on(tx.repo_mut().rebase_descendants()).map_err(|err| {
            KataError::Internal(format!("failed to rebase after git import: {err}"))
        })?;
        commit_transaction(
            &barrier,
            tx,
            description.to_owned(),
            "failed to commit jj git import",
        )
    }

    /// The git ref TRUNK lives on - `refs/heads/<trunk>`, for the trunk
    /// [`crate::trunk::resolve_trunk`] resolved. This is the git-side name of
    /// the SAME ref the merge queue lands against (the trunk name as a jj local
    /// bookmark) and the one every ref-moving effect exports to.
    fn trunk_git_ref(trunk: &str) -> GitRefNameBuf {
        GitRefNameBuf::from(format!("refs/heads/{trunk}"))
    }

    /// Re-import git's trunk ref so a NEWLY-created execution workspace bases on
    /// the CURRENT trunk — not trunk as of the last import (node boot / `open()`).
    ///
    /// A long-running node ADOPTS the operator repo exactly once at boot
    /// ([`Self::import_adopted_git_history`]). Without a re-import, operator
    /// commits landed AFTER boot would never reach jj, so every subsequent
    /// execution workspace would base on a STALE trunk and agents would run
    /// against an old tree. Re-run the same HEAD+refs import here so each fresh
    /// workspace picks up live trunk.
    ///
    /// IDEMPOTENCY: peek the on-disk `refs/heads/<trunk>` WITHOUT mutating jj and
    /// skip the whole transaction when it already equals jj's recorded `git_refs`
    /// entry for that ref — jj's own bookkeeping of what it last imported or
    /// exported there, so a ref KATA just exported reads as unchanged and never
    /// round-trips. That skip matters because `Transaction::commit` ALWAYS
    /// publishes a new op-log entry (even for an empty transaction); without the
    /// guard every `create_workspace` on an unchanged repo would grow the op-log.
    ///
    /// This deliberately does NOT key off git's `HEAD`. `HEAD` is not a value kata
    /// maintains and jj-lib actively freezes it: `git::export_some_refs`'
    /// `check_and_detach_head` DETACHES a symbolic `HEAD` at its PRE-move commit
    /// whenever an export moves the bookmark `HEAD` points at. kata's first
    /// `promote` therefore turns `ref: refs/heads/main` into a detached sha that
    /// never moves again — see [`Self::base_workspace_on_trunk_named`].
    ///
    /// FAIL-SOFT only for the no-git case: a store with no git backend (never in
    /// kata's colocated / adopted / internal-git repos) has no git trunk ref to
    /// re-import, so return the repo untouched and let the caller read jj's
    /// bookmark alone. A real import failure on an adopted repo surfaces as the
    /// same `KataError::Internal` class as the adoption import.
    pub(super) fn refresh_trunk_from_git(
        repo: Arc<ReadonlyRepo>,
        trunk: &str,
    ) -> KataResult<Arc<ReadonlyRepo>> {
        let Ok(git_backend) = jj_lib::git::get_git_backend(repo.store()) else {
            return Ok(repo);
        };
        let trunk_ref = Self::trunk_git_ref(trunk);
        let on_disk_trunk = git_backend
            .git_repo()
            .find_reference(trunk_ref.as_str())
            .ok()
            .and_then(|reference| reference.into_fully_peeled_id().ok())
            .map(|oid| jj_lib::backend::CommitId::from_bytes(oid.as_bytes()));
        if repo.view().get_git_ref(&trunk_ref).as_resolved() == Some(&on_disk_trunk) {
            return Ok(repo);
        }
        Self::import_git_history_tx(repo, "kata refresh trunk from git")
    }

    /// Base a freshly-created execution workspace on TRUNK.
    ///
    /// jj-lib's `init_working_copy` (reached via
    /// `init_workspace_with_existing_repo`) always checks out the EMPTY root
    /// commit, so a brand-new workspace starts with an empty tree and the
    /// repository's committed files are invisible to agents. Record `@` as an
    /// empty change on top of trunk and check it out so the committed baseline is
    /// materialized on disk.
    fn base_workspace_on_trunk(
        &self,
        workspace: &mut Workspace,
        repo: Arc<ReadonlyRepo>,
        agent: &AgentId,
    ) -> KataResult<()> {
        self.base_workspace_on_trunk_named(
            workspace,
            repo,
            Self::workspace_name(agent),
            &agent.0.to_string(),
        )
    }

    /// The body of [`Self::base_workspace_on_trunk`], given the workspace name
    /// and the op-log label it derives from the agent id.
    ///
    /// ## Why TRUNK and not git's `HEAD`
    ///
    /// The fork base and the landing base MUST be the same ref:
    /// `JjBackend::run_landing_ladder` lands against the trunk LOCAL BOOKMARK, so
    /// a workspace forked from anything else is a candidate whose base "advanced"
    /// the moment it was created, and the fail-closed base-advance fence PARKS it
    /// needs-revalidation instead of landing it.
    ///
    /// `repo.view().git_head()` equals trunk only by accident, on the first
    /// execution of an adopted repo, and kata itself destroys that accident:
    /// jj-lib's `git::export_some_refs` runs `check_and_detach_head`, which
    /// DETACHES a symbolic `.git/HEAD` at its PRE-move commit whenever the export
    /// moves the bookmark it points at. The first `promote` exports
    /// `refs/heads/main`, so `.git/HEAD` flips from `ref: refs/heads/main` to a
    /// raw pre-promote sha and stays frozen there forever: a second execution
    /// forking `git_head()` would fork the PRE-promote commit, not see the landed
    /// files, and park `needs-revalidation: base advanced`. On a kata-`init`ed
    /// colocated repo `git_head()` is absent, so every workspace would fork the
    /// empty root.
    ///
    /// ## An absent trunk is TWO states, not one
    ///
    /// A single silent `Ok(())` on an absent trunk bookmark would conflate:
    ///
    /// * **nothing to fork** - a fresh `init_colocated_git` before anything has
    ///   landed, where jj's empty-root checkout genuinely IS the right base;
    /// * **this repository's trunk is called something else** - where the
    ///   empty-root checkout hands the agent NONE of the repository, and
    ///   nothing anywhere reports a problem until the last stage fails.
    ///
    /// [`crate::trunk::TrunkResolution`] is the split:
    /// [`crate::trunk::TrunkResolution::NoTrunkYet`] is the first state and is
    /// `Ok`; the second state cannot arise, because the resolver FINDS the trunk
    /// whatever it is called - and where it genuinely cannot
    /// tell, it returns `Err` here rather than forking an agent from nothing.
    fn base_workspace_on_trunk_named(
        &self,
        workspace: &mut Workspace,
        repo: Arc<ReadonlyRepo>,
        workspace_name: WorkspaceNameBuf,
        label: &str,
    ) -> KataResult<()> {
        // Resolve BEFORE the re-import: the import below is scoped to trunk's
        // own git ref, so it needs the name. `observe_trunk` reads git's
        // `refs/heads/*` as well as jj's bookmarks for exactly this ordering.
        let TrunkResolution::Resolved { name: trunk, .. } = self.resolve_trunk_in(repo.as_ref())?
        else {
            // NOTHING TO FORK - and only this state. The empty-root checkout
            // jj-lib already performed is the correct base for a repository
            // with no history.
            return Ok(());
        };

        // Re-import git's trunk ref FIRST so this NEW execution workspace
        // bases on the CURRENT trunk, not trunk as of the import at node boot
        // (`open()`). Cheap no-op (no transaction) when the ref hasn't moved.
        let repo = Self::refresh_trunk_from_git(repo, &trunk)?;

        let trunk_bookmark = RefNameBuf::from(trunk.clone());
        let Some(base_id) = repo
            .view()
            .get_local_bookmark(&trunk_bookmark)
            .as_normal()
            .cloned()
        else {
            // The resolver named `trunk` FROM this repository's own refs, so an
            // absence here is not "no trunk" - it is the bookmark being
            // conflicted, or the ref moving under us between the resolve and
            // this read. Either way, forking silently from the empty root is
            // the behaviour this whole change exists to delete.
            return Err(KataError::Validation(format!(
                "the resolved trunk bookmark `{trunk}` is absent or conflicted in this \
                 repository, so there is no single commit to fork the execution workspace \
                 from. Resolve the conflict, or name the trunk explicitly with `vcs.trunk`"
            )));
        };
        let base_commit = repo.store().get_commit(&base_id).map_err(|err| {
            KataError::Internal(format!("failed to load trunk base commit: {err}"))
        })?;
        Self::check_out_base(workspace, repo, workspace_name, label, &base_commit)
    }

    /// Record `@` as an empty change on top of `base_commit` in `workspace_name`
    /// and check it out, so the base's committed files are materialized.
    fn check_out_base(
        workspace: &mut Workspace,
        repo: Arc<ReadonlyRepo>,
        workspace_name: WorkspaceNameBuf,
        label: &str,
        base_commit: &jj_lib::commit::Commit,
    ) -> KataResult<()> {
        // The freshly-inited working copy sits at the empty root tree; capture it
        // as the expected on-disk state so the checkout below is guarded against a
        // concurrent divergence.
        let old_tree = Self::workspace_commit(repo.as_ref(), &workspace_name)?.tree();

        let barrier = RepositoryBarrier::for_git_store(repo.store())?;
        let mut tx = repo.start_transaction();
        let new_wc_commit = Self::block_on(tx.repo_mut().check_out(workspace_name, base_commit))
            .map_err(|err| KataError::Internal(format!("failed to base jj workspace: {err}")))?;
        Self::block_on(tx.repo_mut().rebase_descendants()).map_err(|err| {
            KataError::Internal(format!(
                "failed to rebase after basing the workspace: {err}"
            ))
        })?;
        let repo = commit_transaction(
            &barrier,
            tx,
            format!("kata base workspace {label}"),
            "failed to commit jj workspace base",
        )?;

        Self::block_on(workspace.check_out(repo.op_id().clone(), Some(&old_tree), &new_wc_commit))
            .map_err(|err| {
                KataError::Internal(format!(
                    "failed to check out the base into jj workspace: {err}"
                ))
            })?;
        Ok(())
    }

    fn commit_inner(&self, agent: &AgentId, message: &str) -> KataResult<String> {
        let settings = self.user_settings()?;
        let workspace_name = Self::workspace_name(agent);
        let workspace_path = self.workspace_path(agent);
        let mut workspace = Workspace::load(
            &settings,
            &workspace_path,
            &StoreFactories::default(),
            &default_working_copy_factories(),
        )
        .map_err(|err| KataError::Internal(format!("failed to load agent workspace: {err}")))?;

        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let wc_commit = Self::workspace_commit(repo.as_ref(), &workspace_name)?;
        // Opened before the snapshot writes its trees and blobs: the commit
        // below names them.
        let barrier = RepositoryBarrier::for_git_store(repo.store())?;

        let base_ignores = Self::base_ignores(workspace.workspace_root());
        let mut locked_workspace = workspace
            .start_working_copy_mutation()
            .map_err(|err| KataError::Internal(format!("failed to lock jj working copy: {err}")))?;
        let matcher = EverythingMatcher;
        let force_matcher = NothingMatcher;
        let snapshot_options = SnapshotOptions {
            base_ignores,
            progress: None,
            start_tracking_matcher: &matcher,
            force_tracking_matcher: &force_matcher,
            max_new_file_size: u64::MAX,
        };
        let (snapshot_tree, _stats) = Self::block_on(
            locked_workspace.locked_wc().snapshot(&snapshot_options),
        )
        .map_err(|err| KataError::Internal(format!("failed to snapshot jj workspace: {err}")))?;

        let mut tx = repo.start_transaction();
        let committed_change = Self::block_on(
            tx.repo_mut()
                .rewrite_commit(&wc_commit)
                .set_tree(snapshot_tree)
                .set_description(message)
                .write(),
        )
        .map_err(|err| KataError::Internal(format!("failed to write jj commit: {err}")))?;
        let committed_id = committed_change.id().hex();
        let next_wc_commit = Self::block_on(
            tx.repo_mut()
                .new_commit(vec![committed_change.id().clone()], committed_change.tree())
                .write(),
        )
        .map_err(|err| KataError::Internal(format!("failed to write next jj wc commit: {err}")))?;
        tx.repo_mut()
            .set_wc_commit(workspace_name, next_wc_commit.id().clone())
            .map_err(|err| KataError::Internal(format!("failed to update jj wc commit: {err}")))?;
        Self::block_on(tx.repo_mut().rebase_descendants()).map_err(|err| {
            KataError::Internal(format!("failed to rebase after jj commit: {err}"))
        })?;
        let repo = commit_transaction(
            &barrier,
            tx,
            format!("kata commit {}", agent.0),
            "failed to commit jj operation",
        )?;

        Self::block_on(locked_workspace.locked_wc().reset(&next_wc_commit)).map_err(|err| {
            KataError::Internal(format!("failed to reset jj working copy: {err}"))
        })?;
        locked_workspace
            .finish(repo.op_id().clone())
            .map_err(|err| {
                KataError::Internal(format!("failed to finish jj working copy mutation: {err}"))
            })?;

        Ok(committed_id)
    }
}

impl JjBackend {
    /// Evaluate a bounded revset against the jj workspace rooted directly at
    /// `path`, WITHOUT going through the agent-keyed `agents/<id>` layout.
    ///
    /// This is the read surface the workflow layer's `{{ workspace.query(...) }}`
    /// role-prompt builtin uses for jj-backed execution worktrees: the
    /// runner only knows the worktree path on disk, and a jj-backed worktree has
    /// `.jj` but no top-level `.git`. Loading the workspace at its own root and
    /// reading its own [`Workspace::workspace_name`] recovers the correct
    /// working-copy scope for `@`/`<workspace>@` resolution. Rides the
    /// full-language revset parser via [`Self::query_revset_core`], so any
    /// jj revset expression the operator writes is accepted.
    pub fn query_revset_at_path(
        path: &Path,
        query: &str,
        limit: usize,
    ) -> KataResult<RevsetQueryResult> {
        let settings = Self::user_settings_at(path)?;
        let workspace = Workspace::load(
            &settings,
            path,
            &StoreFactories::default(),
            &default_working_copy_factories(),
        )
        .map_err(|err| {
            KataError::Internal(format!(
                "failed to load jj workspace at {}: {err}",
                path.display()
            ))
        })?;
        let workspace_name = workspace.workspace_name().to_owned();
        Self::query_revset_core(workspace, &workspace_name, query, limit)
    }

    /// The body of [`Self::query_revset_at_path`]: given a loaded [`Workspace`]
    /// and its working-copy name, parse + resolve + evaluate a bounded revset
    /// into a typed [`RevsetQueryResult`].
    fn query_revset_core(
        workspace: Workspace,
        workspace_name: &WorkspaceNameBuf,
        query: &str,
        limit: usize,
    ) -> KataResult<RevsetQueryResult> {
        let settings = Self::user_settings_at(workspace.workspace_root())?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let limit = limit.max(1);
        let mut diagnostics = Vec::new();
        let workspace_root = workspace.workspace_root().to_path_buf();
        let Some(expression) = (match Self::revset_expression(
            query,
            &workspace_root,
            workspace_name,
            settings.user_email(),
        ) {
            Ok(expression) => Some(expression),
            Err(diagnostic) => {
                diagnostics.push(diagnostic);
                None
            }
        }) else {
            return Ok(RevsetQueryResult {
                query: query.to_owned(),
                limit,
                commits: Vec::new(),
                diagnostics,
            });
        };

        let symbol_resolver = SymbolResolver::new(
            repo.as_ref(),
            &[] as &[Box<dyn jj_lib::revset::SymbolResolverExtension>],
        );
        let resolved = match expression.resolve_user_expression(repo.as_ref(), &symbol_resolver) {
            Ok(resolved) => resolved,
            Err(err) => {
                let message = err.to_string();
                diagnostics.push(if message.contains("ambiguous") {
                    RevsetDiagnostic::Ambiguous { message }
                } else {
                    RevsetDiagnostic::Invalid { message }
                });
                return Ok(RevsetQueryResult {
                    query: query.to_owned(),
                    limit,
                    commits: Vec::new(),
                    diagnostics,
                });
            }
        };

        let revset = match resolved.evaluate(repo.as_ref()) {
            Ok(revset) => revset,
            Err(err) => {
                diagnostics.push(RevsetDiagnostic::Evaluation {
                    message: err.to_string(),
                });
                return Ok(RevsetQueryResult {
                    query: query.to_owned(),
                    limit,
                    commits: Vec::new(),
                    diagnostics,
                });
            }
        };

        let mut commits = Vec::new();
        for item in revset.commit_change_ids() {
            match item {
                Ok((commit_id, change_id)) if commits.len() < limit => commits.push(RevsetCommit {
                    commit_id: commit_id.hex(),
                    change_id: change_id.hex(),
                }),
                Ok(_) => {
                    diagnostics.push(RevsetDiagnostic::Truncated { limit });
                    break;
                }
                Err(err) => {
                    diagnostics.push(RevsetDiagnostic::Evaluation {
                        message: err.to_string(),
                    });
                    break;
                }
            }
        }

        if commits.is_empty() && diagnostics.is_empty() {
            diagnostics.push(RevsetDiagnostic::EmptyResult);
        }

        Ok(RevsetQueryResult {
            query: query.to_owned(),
            limit,
            commits,
            diagnostics,
        })
    }
}

impl JjBackend {
    /// Every path whose value differs between `before` and `after`, in the
    /// stream's path order, with how it changed — the one tree-diff walk the
    /// workspace status and the recorded commit diff share. `what` names the
    /// diff in a fault.
    fn tree_changes(
        before: &MergedTree,
        after: &MergedTree,
        what: &str,
    ) -> KataResult<Vec<RecordedPathChange>> {
        let matcher = EverythingMatcher;
        let mut out = Vec::new();
        let mut diff_stream = before.diff_stream(after, &matcher);
        while let Some(TreeDiffEntry { path, values }) = Self::block_on(diff_stream.next()) {
            let values = values
                .map_err(|err| KataError::Internal(format!("failed to diff {what}: {err}")))?;
            // The stream yields only paths whose value differs, so at least
            // one side is present: a path on neither side never reaches here.
            let kind = match (values.before.is_present(), values.after.is_present()) {
                (false, _) => RecordedChangeKind::Added,
                (true, false) => RecordedChangeKind::Deleted,
                (true, true) => RecordedChangeKind::Modified,
            };
            out.push(RecordedPathChange {
                path: path.into_internal_string().into(),
                kind,
            });
        }
        Ok(out)
    }

    /// [`crate::ExecutionWorkspaceProvider::recorded_commit_diff`]: both commits
    /// load from the store through the shared repo view (the ROOT workspace,
    /// never the execution workspace's working copy) and their trees diff path
    /// by path, in the stream's path order.
    pub(super) fn recorded_commit_diff(
        &self,
        base_commit: &str,
        head_commit: &str,
    ) -> KataResult<Vec<RecordedPathChange>> {
        let (_, base, head) = self.recorded_commit_trees(base_commit, head_commit)?;
        Self::tree_changes(&base, &head, &format!("{base_commit}..{head_commit}"))
    }

    /// The trees of two commits in the repository store, loaded through the
    /// shared repo view (the ROOT workspace, never an execution workspace's
    /// working copy), with the store that reads their files.
    ///
    /// # Errors
    ///
    /// `Internal` when either id is not valid hex or names no commit in the
    /// store, and the store's own read refusal.
    pub(super) fn recorded_commit_trees(
        &self,
        base_commit: &str,
        head_commit: &str,
    ) -> KataResult<(Arc<jj_lib::store::Store>, MergedTree, MergedTree)> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let tree = |hex: &str| -> KataResult<MergedTree> {
            let id = jj_lib::backend::CommitId::try_from_hex(hex).ok_or_else(|| {
                KataError::Internal(format!("the commit id {hex:?} is not valid hex"))
            })?;
            let commit = repo.store().get_commit(&id).map_err(|err| {
                KataError::Internal(format!(
                    "the commit {hex} is not in the repository's store: {err}"
                ))
            })?;
            Ok(commit.tree())
        };
        let (base, head) = (tree(base_commit)?, tree(head_commit)?);
        Ok((Arc::clone(repo.store()), base, head))
    }

    /// The body of [`VcsBackend::workspace_status`]: given a loaded
    /// [`Workspace`] and its working-copy name, snapshot + diff the working
    /// copy into a typed [`WorkspaceStatus`].
    fn workspace_status_core(
        mut workspace: Workspace,
        workspace_name: &WorkspaceNameBuf,
    ) -> KataResult<WorkspaceStatus> {
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let wc_commit = Self::workspace_commit(repo.as_ref(), workspace_name)?;
        let workspace_root = workspace.workspace_root().to_owned();
        let disk_files = Self::collect_disk_files(&workspace_root)?;
        let mut locked_workspace = workspace
            .start_working_copy_mutation()
            .map_err(|err| KataError::Internal(format!("failed to lock jj working copy: {err}")))?;
        let freshness =
            WorkingCopyFreshness::check_stale(locked_workspace.locked_wc(), &wc_commit, &repo)
                .map_err(|err| {
                    KataError::Internal(format!("failed to check jj workspace freshness: {err}"))
                })?;
        let stale = !matches!(freshness, WorkingCopyFreshness::Fresh);
        let mut head = Self::head_metadata_from_repo(repo.as_ref(), workspace_name, stale)?;
        let matcher = EverythingMatcher;
        let force_matcher = NothingMatcher;
        let snapshot_options = SnapshotOptions {
            base_ignores: Self::base_ignores(&workspace_root),
            progress: None,
            start_tracking_matcher: &matcher,
            force_tracking_matcher: &force_matcher,
            max_new_file_size: u64::MAX,
        };
        let snapshot_result = super::record_vcs_op("snapshot", || {
            Self::block_on(locked_workspace.locked_wc().snapshot(&snapshot_options))
        });
        let (snapshot_tree, _stats) = snapshot_result.map_err(|err| {
            KataError::Internal(format!("failed to snapshot jj workspace: {err}"))
        })?;
        // Status reflects the LIVE working copy, not just the recorded `@`
        // commit: the snapshot tree already folds in the stage's dirty edits, so
        // key the head tree_id off it. This is the content address the effect
        // model dedups on — a stage that produced files rotates it BEFORE any
        // commit.
        //
        // THE SNAPSHOT IS NOT PERSISTED INTO `@`, AND THAT IS DELIBERATE. Unlike
        // the `jj` CLI — which snapshots and REWRITES `@` as a side effect of
        // most commands — this drops the locked working-copy mutation without
        // finishing it, so `workspace_status` stays a pure READ and `dirty` stays
        // LEVEL-triggered (a diff of `@` against the live disk, reported
        // identically on every read). Folding the snapshot into `@` here would
        // make `dirty` edge-triggered: the first read would report the change and
        // every later read would say clean, silently emptying the human gate's
        // `"dirty" / "changed_paths"` and the promote guard that keys on them.
        // The consequence is that `@` NEVER contains uncommitted work, which is
        // why every effect that publishes a commit settles the candidate first
        // (`JjBackend::settle_candidate`) instead of reading `@`; reading `@`
        // would make `commit`/`park`/`promote` publish empty commits.
        head.tree_id = Self::merged_tree_id_hex(snapshot_tree.tree_ids());
        let wc_tree = wc_commit.tree();
        let tracked_files = Self::collect_tree_files(&wc_tree)?;
        let snapshot_files = Self::collect_tree_files(&snapshot_tree)?;
        let ignored_files = Self::collect_ignored_disk_files(&workspace_root, &tracked_files)?;
        let mut files = Vec::new();

        for change in Self::tree_changes(&wc_tree, &snapshot_tree, "jj workspace status")? {
            files.push(WorkspaceFileStatus {
                path: change.path.to_string(),
                kind: match change.kind {
                    RecordedChangeKind::Added => WorkspaceFileStatusKind::Untracked,
                    RecordedChangeKind::Modified => WorkspaceFileStatusKind::Modified,
                    RecordedChangeKind::Deleted => WorkspaceFileStatusKind::Deleted,
                },
            });
        }

        for path in disk_files.difference(&snapshot_files) {
            if ignored_files.contains(path) {
                files.push(WorkspaceFileStatus {
                    path: path.clone(),
                    kind: WorkspaceFileStatusKind::Ignored,
                });
            }
        }

        files.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| format!("{:?}", left.kind).cmp(&format!("{:?}", right.kind)))
        });

        Ok(WorkspaceStatus {
            workspace_root,
            head,
            files,
        })
    }
}
