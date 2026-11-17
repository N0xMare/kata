//! [`ExecutionWorkspaceProvider`] impl for [`JjBackend`].
//!
//! Shared private helpers live on [`JjBackend`] in the parent module (`jj/mod.rs`)
//! and are reachable here because this is a descendant module.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kata_types::execution::CandidateTreePin;
use kata_types::primitives::ObjectId;
use kata_types::target::{ExecutionTarget, TargetSpec};
use kata_types::tree_artifact::{CommittedBaseGitView, CommittedBaseTree, WorkTreeInputBounds};
use kata_types::{KataError, KataResult};
use smol_str::SmolStr;
use ulid::Ulid;

use crate::backend::VcsBackend;
use crate::workspace::WorkspaceFileStatusKind;
use kata_effects_contract::{
    ExecutionLiveness, ExecutionWorkspaceBackend, ExecutionWorkspaceHandle, ExecutionWorkspaceKey,
    ExecutionWorkspaceProvider, ExecutionWorkspaceStatus, ParkedWorkspace, PromotedWorkspace,
    TerminalWorkspaceReapPolicy, execution_workspace_identity,
};

use super::durability::RepositoryBarrier;
use super::merge_queue::LandingOutcome;
use super::workspace_effect::{PARKED_REF_OCCUPIED, revalidation_park_refusal};
use super::{JJ_METADATA_DIR_NAME, JjBackend};
use crate::trunk::EXECUTION_REF_PREFIX;

impl JjBackend {
    /// A park never writes over a `parked/<…>` naming another commit than the
    /// one it would write (`commit_sha`): such a ref is not the park's own
    /// write — a landing's revalidation park, another execution's park, an
    /// outside write — so it refuses `parked_ref_occupied`, naming both
    /// commits, and the caller writes and removes nothing. A ref already AT
    /// `commit_sha` (the park's own write whose teardown never ran, or any
    /// write of that same commit) passes, and the park completes over it.
    fn refuse_occupied_parked_ref(
        &self,
        key: &ExecutionWorkspaceKey,
        park: &str,
        ref_name: &str,
        commit_sha: &str,
    ) -> KataResult<()> {
        match self.local_bookmark_commit(ref_name)? {
            Some(standing) if standing != commit_sha => Err(KataError::Validation(format!(
                "{PARKED_REF_OCCUPIED}: the {park} of execution {} refused: {ref_name} \
                 already names {standing}, not the candidate {commit_sha} this park would write \
                 — a commit this park did not write (a landing's revalidation park, an outside \
                 write) is kept as it stands, and the workspace stands for inspection; park \
                 under a label to keep the candidate",
                key.execution_id
            ))),
            _ => Ok(()),
        }
    }

    /// THE single point at which a candidate execution workspace's live disk
    /// state becomes a durable commit. Every effect that publishes a commit —
    /// `commit`, `park`, `promote` — goes through it, and none of them snapshots
    /// on its own.
    ///
    /// ## Why this exists
    ///
    /// Publishing `@` after [`VcsBackend::workspace_status`] would rest on the
    /// belief that "jj snapshots the working copy into the `@` commit on status".
    /// That is true of the `jj` CLI and FALSE of `jj_lib`, which kata drives: the CLI
    /// snapshots and REWRITES `@` as a side effect of most commands, whereas
    /// `workspace_status_core` snapshots only to compute a `tree_id` and a
    /// changeset and then DROPS the locked working-copy mutation without
    /// finishing it. `@` therefore stays at the empty commit `create_workspace`
    /// checked out, and every on-disk edit an agent made would be invisible to
    /// all three effects: an empty commit would land on trunk and the agent's
    /// work would be destroyed with the torn-down worktree.
    ///
    /// ## What it does
    ///
    /// Dirty disk state is committed (jj's own `jj commit` shape: finalize `@`,
    /// check out a fresh empty `@`); a clean workspace commits nothing. Either
    /// way the returned status's `head.target_commit_id` is the commit that
    /// HOLDS the candidate's content — see `JjBackend::settled_candidate_commit`
    /// for why that is not the same thing as `@`.
    ///
    /// IDEMPOTENT: re-driving against an already-settled workspace finds it
    /// clean, writes nothing, and resolves to the SAME commit, so a crash-window
    /// re-dispatch reconciles instead of stacking empty commits.
    fn settle_candidate(
        &self,
        agent: &kata_types::AgentId,
        message: &str,
    ) -> KataResult<crate::workspace::WorkspaceStatus> {
        let status = <Self as VcsBackend>::workspace_status(self, agent)?;
        if !status.is_dirty() {
            return Ok(status);
        }
        <Self as VcsBackend>::commit(self, agent, message)?;
        <Self as VcsBackend>::workspace_status(self, agent)
    }

    /// Reclaim leaked `<repo>/agents/<exec-id>`
    /// execution workspaces.
    ///
    /// ## The leak this reclaims, measured rather than assumed
    ///
    /// `promote_workspace` and `park_workspace` are TERMINAL and already tear
    /// their own workspace down — verified by driving all four paths against a
    /// real repository and observing the repository, not kata's records. What
    /// is left standing afterwards is exactly the runs that reached a terminal
    /// state through NEITHER: an execution whose graph ends in a NON-terminal
    /// `commit` effect, and an execution with no `workspace_effect` stage at
    /// all. Both leave `<repo>/agents/<exec-id>/` on disk AND a live jj
    /// working-copy registration (`view().wc_commit_ids()` plus the workspace
    /// store's `agent-<exec-id>` entry) in the shared repo. Both accumulate
    /// once per run, forever, on a long-running node.
    ///
    /// ## What it reclaims
    ///
    /// The directory and the registration, through the ordinary
    /// [`VcsBackend::remove_workspace`] teardown — the SAME body the terminal
    /// effects use, so a reaped workspace is indistinguishable from a promoted
    /// one and there is no second removal path to keep in step.
    ///
    /// ## What it deliberately does NOT reclaim
    ///
    /// **No ref, ever** — see the [`ExecutionWorkspaceProvider::reap_terminal_workspaces`]
    /// trait doc. Concretely, a reaped workspace whose run published an
    /// `exec-<id>` commit keeps that bookmark: the bookmark is the only thing
    /// keeping the commit reachable once the workspace is gone, which is the
    /// entire reason the `commit` effect creates it.
    ///
    /// **Any entry that is not ULID-named** — an operator's directory. It is
    /// excluded structurally, not by a name check: the entry never reaches the
    /// classifier, and a per-execution liveness verdict cannot speak for it.
    ///
    /// **A `<agents>/<ULID>` directory with no `.jj`** — kata cannot prove it
    /// created it, and the removal path ends in `remove_dir_all`. Refusing costs
    /// an empty directory left by a crash between `create_dir_all` and workspace
    /// init, or what a crash inside a teardown's `remove_dir_all` left once
    /// `.jj` was gone (the recovery leg that answers that `park`/`promote`
    /// finishes the removal; nothing else does); reaping could delete something
    /// an operator put there. Fail safe.
    ///
    /// ## Failure handling
    ///
    /// `Err` only when the `<agents>` root itself cannot be listed. A missing
    /// root is `Ok(0)` (a node that has never run an isolated workflow). Every
    /// per-entry failure — an unreadable stat, a jj transaction that lost a race
    /// with a concurrent execution — is SKIPPED, leaking one cycle rather than
    /// aborting the sweep and leaving later entries unexamined.
    fn reap_terminal_execution_workspaces(
        &self,
        policy: TerminalWorkspaceReapPolicy,
        classify: &dyn Fn(Ulid) -> ExecutionLiveness,
    ) -> KataResult<usize> {
        let now = SystemTime::now();
        let now_ms = u64::try_from(
            now.duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let min_ttl = policy.min_ttl();
        let agents_root = self.agents_root();
        let entries = match std::fs::read_dir(&agents_root) {
            Ok(entries) => entries,
            // A node that has never created an execution workspace has no
            // `<agents>` root. Nothing to reap is not a failure.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => {
                return Err(KataError::Internal(format!(
                    "failed to read jj agents root {} for the terminal-workspace reap: {e}",
                    agents_root.display()
                )));
            }
        };

        let mut reaped = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            // Only a ULID-named entry is an execution workspace.
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Ok(execution_id) = Ulid::from_string(name) else {
                continue;
            };
            // ...and only one carrying jj's metadata dir is one kata created.
            // The teardown ends in `remove_dir_all`; refuse anything this
            // cannot prove kata owns. Ownership, not liveness: a directory
            // whose working-copy commit the view no longer names (a teardown
            // partly done) is no workspace to `lookup_workspace`, and is still
            // reaped here.
            if !path.join(JJ_METADATA_DIR_NAME).is_dir() {
                continue;
            }
            // Cheapest gate FIRST: below the shortest reap window across all
            // verdicts nothing is reapable, so skip the durable classifier for
            // entries too young to reap under any of them.
            let Ok(age) = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .map(|mtime| now.duration_since(mtime).unwrap_or(Duration::ZERO))
            else {
                continue;
            };
            if age < min_ttl {
                continue;
            }
            // The durable lifecycle verdict is the authority; the filesystem
            // contributed only `age`. An in-flight (or about-to-be-replayed)
            // execution is NEVER reaped, at any age.
            if !policy.permits_reap(classify(execution_id), age, now_ms) {
                continue;
            }
            let key = ExecutionWorkspaceKey::execution(execution_id);
            // Skip a per-entry failure rather than abort the sweep: a jj
            // transaction can lose a race with a concurrent execution, and one
            // contended entry must not hide every later leak.
            if <Self as ExecutionWorkspaceProvider>::remove_workspace(self, &key).is_ok() {
                reaped += 1;
            }
        }
        Ok(reaped)
    }

    /// [`ExecutionWorkspaceProvider::park_workspace`]'s body; the trait method
    /// runs it behind the repository's durability barrier.
    fn park_live_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        label: Option<&str>,
        barrier: &RepositoryBarrier,
    ) -> KataResult<ParkedWorkspace> {
        let agent = Self::execution_workspace_agent(key)?;
        let Some(handle) = self.lookup_workspace(key)? else {
            return Err(KataError::Internal(format!(
                "no worktree registered for execution {}",
                key.execution_id
            )));
        };
        if !handle.path.exists() {
            return Err(KataError::Internal(format!(
                "worktree path {} does not exist",
                handle.path.display()
            )));
        }

        self.require_intact_workspace_candidate(&agent)?;
        // Same one snapshot point as commit/promote. This arm ALREADY committed
        // dirty state, which is why a park preserved real work while a promote
        // of the same workspace landed nothing — but it then published `@` when
        // clean, which after its own commit is the content-free child.
        let status = self.settle_candidate(
            &agent,
            &format!("park candidate for execution {}", key.execution_id),
        )?;
        let commit_sha = status.head.target_commit_id.clone();
        let ref_name = Self::parked_bookmark_name(key.execution_id, label);
        // Refuse BEFORE the ref is written and BEFORE the worktree is torn
        // down: a park that refused after `remove_workspace` would destroy the
        // work it refused to publish.
        self.refuse_occupied_parked_ref(key, "park", &ref_name, &commit_sha)?;
        let author = self.publishable_author("park", &commit_sha)?;
        self.set_local_bookmark(&ref_name, &commit_sha)?;
        self.remove_workspace_tagged(&agent, None, barrier)?;

        Ok(ParkedWorkspace {
            identity: Some(
                Self::execution_workspace_identity_from_head(
                    key,
                    Some(format!("{EXECUTION_REF_PREFIX}{}", key.execution_id)),
                    &status.head,
                    self.trunk_name_for_evidence(),
                    Some(ref_name.clone()),
                    Some(commit_sha.clone()),
                )
                .with_author(Some(author)),
            ),
            ref_name,
            commit_sha,
        })
    }

    /// [`ExecutionWorkspaceProvider::promote_workspace`]'s body; the trait
    /// method runs it behind the repository's durability barrier, which the
    /// teardown syncs before it removes anything.
    fn promote_live_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        pin: &CandidateTreePin,
        landing_branch: Option<&str>,
        barrier: &RepositoryBarrier,
    ) -> KataResult<PromotedWorkspace> {
        let agent = Self::execution_workspace_agent(key)?;
        let Some(handle) = self.lookup_workspace(key)? else {
            return Err(KataError::Internal(format!(
                "no worktree registered for execution {}",
                key.execution_id
            )));
        };
        if !handle.path.exists() {
            return Err(KataError::Internal(format!(
                "worktree path {} does not exist",
                handle.path.display()
            )));
        }

        self.require_intact_workspace_candidate(&agent)?;
        // Settle the candidate into a durable commit FIRST (the one snapshot
        // point — see `JjBackend::settle_candidate`), so `target_commit_id`
        // is the exact commit the queue lands/parks. Reading `@` here
        // instead would land an empty commit on trunk.
        let status = self.settle_candidate(
            &agent,
            &format!("promote candidate for execution {}", key.execution_id),
        )?;
        let candidate_commit = status.head.target_commit_id.clone();
        // Refuse BEFORE the landing ladder runs — every one of its arms
        // either moves trunk or tears the worktree down, and both are past
        // the point where refusing is non-destructive.
        //
        // THE IDENTITY FENCE: what validation judged is what lands. The
        // observed value is read off the SETTLED status above, so it is the
        // tree of the commit the ladder is about to publish — measured
        // byte-identical to the live pre-settle tree id,
        // which is what the validation stamp recorded. Ahead of
        // `publishable_author` only because a missing identity and an
        // unvalidated tree are both non-destructive refusals and this one
        // is the cheaper read.
        pin.require_tree(
            "promote",
            &key.execution_id.to_string(),
            &status.head.tree_id,
        )?;
        let author = self.publishable_author("promote", &candidate_commit)?;

        // Land through the serialized MergeQueue by DEFAULT. A candidate whose
        // base is still trunk fast-forwards and lands (its validated tree IS the
        // landed tree). A candidate whose base ADVANCED since it forked is NOT
        // landed: per the fail-closed revalidation fence its (conflict-free) rebased tree
        // is PARKED needs-revalidation (it is not the tree validation approved),
        // and a genuine-conflict rebase is PARKED conflict — either way trunk is
        // untouched, the work is preserved, and the promote FAILS typed so no
        // caller records an unvalidated tree as a landed promotion. Landing/park
        // is terminal, so the execution workspace is torn down afterward.
        match self.land_committed_candidate_tagged(
            key,
            &candidate_commit,
            None,
            None,
            landing_branch,
        )? {
            LandingOutcome::Landed { mut promoted, .. } => {
                self.remove_workspace_tagged(&agent, None, barrier)?;
                promoted.identity = promoted
                    .identity
                    .map(|identity| identity.with_author(Some(author)));
                Ok(promoted)
            }
            LandingOutcome::Parked { parked, conflict } => {
                self.remove_workspace_tagged(&agent, None, barrier)?;
                Err(KataError::Validation(format!(
                    "promote parked candidate for execution {}: rebase onto {} conflicts in {:?}; \
                 candidate work preserved at {} (revalidate + re-land)",
                    key.execution_id,
                    self.trunk_name_for_evidence()
                        .as_deref()
                        .unwrap_or("<unresolved trunk>"),
                    conflict.conflicted_paths,
                    parked.ref_name,
                )))
            }
            // Fail-closed floor: the base advanced, so the rebased tree is
            // NOT the tree validation approved. It is PARKED needs-revalidation
            // and trunk is left untouched — never trusted/landed-as-validated.
            // Fail the promote (typed, non-corrupting) so no caller records this
            // as a landed promotion; the parked rebased tree is revalidated +
            // re-landed by an operator/runner.
            LandingOutcome::ParkedForRevalidation { parked, rebased } => {
                self.remove_workspace_tagged(&agent, None, barrier)?;
                Err(KataError::Validation(revalidation_park_refusal(
                    key,
                    &rebased.original_commit_sha,
                    &rebased.base_commit_sha,
                    &rebased.rebased_commit_sha,
                    &parked.ref_name,
                )))
            }
        }
    }

    /// [`ExecutionWorkspaceProvider::park_workspace_recorded`]'s body; the
    /// trait method runs it behind the repository's durability barrier.
    fn park_recorded_candidate(
        &self,
        key: &ExecutionWorkspaceKey,
        label: Option<&str>,
        expected_wc_commit: &str,
        barrier: &RepositoryBarrier,
    ) -> KataResult<ParkedWorkspace> {
        let agent = Self::execution_workspace_agent(key)?;
        let Some(handle) = self.lookup_workspace(key)? else {
            return Err(KataError::Internal(format!(
                "no worktree registered for execution {}",
                key.execution_id
            )));
        };
        if !handle.path.exists() {
            return Err(KataError::Internal(format!(
                "worktree path {} does not exist",
                handle.path.display()
            )));
        }
        <Self as ExecutionWorkspaceProvider>::require_clean_recorded_candidate(
            self,
            key,
            expected_wc_commit,
        )?;
        // The settled target from the repo's recorded view — `wc_position`'s
        // load_at_head reads recorded state; `head_metadata_from_repo`'s
        // `target_commit_id` applies the settle rule without touching the
        // working copy's files a second time.
        let settings = self.user_settings()?;
        let root_workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(root_workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let workspace_name = Self::workspace_name(&agent);
        let head = Self::head_metadata_from_repo(repo.as_ref(), &workspace_name, false)?;
        let commit_sha = head.target_commit_id.clone();
        let ref_name = Self::parked_bookmark_name(key.execution_id, label);
        self.refuse_occupied_parked_ref(key, "closeout park", &ref_name, &commit_sha)?;
        // Refuse BEFORE the ref is written and BEFORE the worktree is torn
        // down — same order `park_workspace` holds.
        let author = self.publishable_author("park", &commit_sha)?;
        self.set_local_bookmark(&ref_name, &commit_sha)?;
        self.remove_workspace_tagged(&agent, None, barrier)?;
        Ok(ParkedWorkspace {
            identity: Some(
                Self::execution_workspace_identity_from_head(
                    key,
                    Some(format!("{EXECUTION_REF_PREFIX}{}", key.execution_id)),
                    &head,
                    self.trunk_name_for_evidence(),
                    Some(ref_name.clone()),
                    Some(commit_sha.clone()),
                )
                .with_author(Some(author)),
            ),
            ref_name,
            commit_sha,
        })
    }
}

impl ExecutionWorkspaceProvider for JjBackend {
    fn backend(&self) -> ExecutionWorkspaceBackend {
        ExecutionWorkspaceBackend::Jj
    }

    /// TRUE: `promote_workspace` settles dirty disk state into a real commit
    /// before landing it (see [`JjBackend::settle_candidate`]). The orchestration
    /// boundary that rejects a dirty promotion is only consulted on the OPERATOR
    /// apply-gate route, never on the in-graph `workspace_effect` stage, so a
    /// promote that published the untouched `@` would be catastrophic there.
    fn promotion_snapshots_dirty(&self) -> bool {
        true
    }

    /// # The ADMISSION half of the identity remedy
    ///
    /// This is where a `worktree_isolated` workflow's candidate is materialized,
    /// BEFORE a single stage is dispatched and before a single token is spent.
    /// It is therefore where a host that cannot answer *who am I* must be told
    /// so — the same place, and for the same reason, that
    /// [`crate::trunk::resolve_trunk`] refuses a repository whose trunk kata
    /// cannot tell.
    ///
    /// BOTH this and the publish-path refusal in [`JjBackend::publishable_author`]
    /// are required, because a commit-time refusal alone lets an empty identity
    /// leave the host. Neither alone
    /// discharges it: admission refuses before the spend, publish refuses a
    /// commit admission never saw.
    fn resolve_target(
        &self,
        execution_id: Ulid,
        spec: &TargetSpec,
        forge: Option<&dyn kata_effects_contract::Forge>,
    ) -> KataResult<ExecutionTarget> {
        super::record_vcs_op("resolve_target", || {
            self.durably("resolve_target", |_| {
                self.resolve_and_pin_target(execution_id, spec, forge)
            })
        })
    }

    fn release_target_pins(&self, execution_id: Ulid) -> KataResult<()> {
        self.durably("release_target_pins", |_| {
            self.delete_target_pins(execution_id)
        })
    }

    fn sweep_target_pins(
        &self,
        claim: &dyn Fn(Ulid) -> kata_effects_contract::TargetPinClaim,
    ) -> KataResult<kata_effects_contract::TargetPinSweep> {
        self.durably("sweep_target_pins", |_| {
            self.sweep_claimed_target_pins(claim)
        })
    }

    fn create_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        target: &ExecutionTarget,
    ) -> KataResult<ExecutionWorkspaceHandle> {
        let agent = Self::execution_workspace_agent(key)?;
        crate::identity::resolve_commit_identity(&crate::identity::observe_identity_at(
            self.repo_root(),
        ))?;
        let handle = self.durably("create_workspace", |_| {
            self.create_workspace_based(
                &agent,
                super::vcs_backend::WorkspaceBase::Frozen(&target.head),
            )
        })?;
        Ok(ExecutionWorkspaceHandle {
            key: key.clone(),
            path: handle.workspace_path,
            backend: ExecutionWorkspaceBackend::Jj,
        })
    }

    /// The `oci` admission repository census over the
    /// workspace's base tree and the git store behind it. The census is timed
    /// as `kata_vcs_operation_duration_seconds{operation="census"}` so its
    /// admission cost is operator-visible the same way every other jj op's
    /// is.
    fn refuse_unsupported_repository_features(
        &self,
        handle: &ExecutionWorkspaceHandle,
    ) -> KataResult<()> {
        let findings = super::record_vcs_op("census", || {
            self.census_execution_workspace_repository(handle)
        })?;
        if findings.is_empty() {
            return Ok(());
        }
        Err(kata_effects_contract::oci_unsupported_features_refusal(
            &findings,
        ))
    }

    /// The committed base tree the execution's `/work` is
    /// published from. Delegates to `jj::base_tree`; timed as
    /// `kata_vcs_operation_duration_seconds{operation="base_tree"}` so the
    /// admission walk's cost is operator-visible like every other jj op's.
    fn committed_base_tree(
        &self,
        handle: &ExecutionWorkspaceHandle,
        bounds: WorkTreeInputBounds,
        put_member: &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
    ) -> KataResult<CommittedBaseTree> {
        super::record_vcs_op("base_tree", || {
            JjBackend::committed_base_tree(self, handle, bounds, put_member)
        })
    }

    /// The committed base's git HISTORY the `/git-history`
    /// artifact is published from. Delegates to `jj::git_view`; timed as
    /// `kata_vcs_operation_duration_seconds{operation="git_history"}`.
    fn committed_base_git_history(
        &self,
        handle: &ExecutionWorkspaceHandle,
        target: &ExecutionTarget,
        history_depth: Option<u32>,
        history_bytes_ceiling: u64,
        put_member: &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
    ) -> KataResult<CommittedBaseGitView> {
        super::record_vcs_op("git_history", || {
            JjBackend::committed_base_git_history(
                self,
                handle,
                target,
                history_depth,
                history_bytes_ceiling,
                put_member,
            )
        })
    }

    /// A LIVE workspace: its directory carries `.jj` AND the repository's view
    /// still names its working-copy commit. A directory whose working-copy
    /// commit the view no longer names is a teardown partly done — a crash
    /// between `remove_workspace_tagged`'s three steps left it — which nothing
    /// can load, repair or classify the `@` of, so it is no workspace; the
    /// recovery that finishes the teardown removes it.
    fn lookup_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<ExecutionWorkspaceHandle>> {
        let agent = Self::execution_workspace_agent(key)?;
        let handle = self.execution_workspace_handle(key, agent);
        if !handle.path.join(JJ_METADATA_DIR_NAME).is_dir() {
            return Ok(None);
        }
        let settings = self.user_settings()?;
        let root_workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(root_workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let registered = repo
            .view()
            .get_wc_commit_id(&Self::workspace_name(&agent))
            .is_some();
        Ok(registered.then_some(handle))
    }

    fn workspace_status(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<ExecutionWorkspaceStatus>> {
        let Some(handle) = self.lookup_workspace(key)? else {
            return Ok(None);
        };
        let agent = Self::execution_workspace_agent(key)?;
        let status = <Self as VcsBackend>::workspace_status(self, &agent)?;
        let changed_paths = status
            .files
            .iter()
            .filter(|file| file.kind != WorkspaceFileStatusKind::Ignored)
            .map(|file| SmolStr::new(file.path.as_str()))
            .collect();

        Ok(Some(ExecutionWorkspaceStatus {
            handle,
            exists: status.workspace_root.exists(),
            dirty: Some(status.is_dirty()),
            changed_paths,
            status_error: None,
            identity: Some(Self::execution_workspace_identity_from_head(
                key,
                Some(format!("{EXECUTION_REF_PREFIX}{}", key.execution_id)),
                &status.head,
                self.trunk_name_for_evidence(),
                None,
                None,
            )),
        }))
    }

    fn remove_workspace(&self, key: &ExecutionWorkspaceKey) -> KataResult<()> {
        let agent = Self::execution_workspace_agent(key)?;
        <Self as VcsBackend>::remove_workspace(self, &agent)
    }

    /// Reclaim leaked `<repo>/agents/<exec-id>` execution workspaces on the
    /// DEFAULT backend. See the trait doc for what a reaper must not touch;
    /// [`JjBackend::reap_terminal_execution_workspaces`] for the mechanism.
    fn reap_terminal_workspaces(
        &self,
        policy: TerminalWorkspaceReapPolicy,
        classify: &dyn Fn(ulid::Ulid) -> ExecutionLiveness,
    ) -> KataResult<usize> {
        self.reap_terminal_execution_workspaces(policy, classify)
    }

    fn promote_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        pin: &CandidateTreePin,
        landing_branch: Option<&str>,
    ) -> KataResult<PromotedWorkspace> {
        super::record_vcs_op("promote", || {
            self.durably("promote", |barrier| {
                self.promote_live_workspace(key, pin, landing_branch, barrier)
            })
        })
    }

    fn park_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        label: Option<&str>,
    ) -> KataResult<ParkedWorkspace> {
        self.durably("park", |barrier| {
            self.park_live_workspace(key, label, barrier)
        })
    }

    /// The `oci` closeout park: NO `settle_candidate`
    /// snapshot-publish. The parked ref names the RECORDED candidate
    /// (`expected_wc_commit` is the head row's `candidate_commit_id`) after
    /// the `oci_candidate_disk_diverged`/`oci_candidate_diverged` fence: a
    /// workspace the recorded state cannot account for refuses and nothing is
    /// torn down. The ref lands on the SETTLED candidate — the repo view's
    /// `target_commit_id`, which steps a content-free `@` down to its parent —
    /// and the workspace is removed
    /// only after the ref is durable. A ref already at another commit refuses
    /// `parked_ref_occupied`, writing and removing nothing
    /// (`refuse_occupied_parked_ref`).
    fn park_workspace_recorded(
        &self,
        key: &ExecutionWorkspaceKey,
        label: Option<&str>,
        expected_wc_commit: &str,
    ) -> KataResult<ParkedWorkspace> {
        self.durably("closeout park", |barrier| {
            self.park_recorded_candidate(key, label, expected_wc_commit, barrier)
        })
    }

    fn parked_ref_name(&self, key: &ExecutionWorkspaceKey, label: Option<&str>) -> String {
        Self::parked_bookmark_name(key.execution_id, label)
    }

    fn lookup_parked_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        ref_name: &str,
    ) -> KataResult<Option<ParkedWorkspace>> {
        let ref_name = ref_name.trim().to_string();
        if ref_name.is_empty() {
            return Ok(None);
        }
        Ok(self
            .local_bookmark_commit(&ref_name)?
            .map(|commit_sha| ParkedWorkspace {
                identity: Some(execution_workspace_identity(
                    key,
                    ExecutionWorkspaceBackend::Jj,
                    None,
                    None,
                    None,
                    None,
                    Some(ref_name.clone()),
                    Some(commit_sha.clone()),
                )),
                ref_name,
                commit_sha,
            }))
    }

    fn lookup_promoted_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        base_ref: &str,
        candidate_commit_sha: &str,
    ) -> KataResult<Option<PromotedWorkspace>> {
        let base_ref = base_ref.trim();
        let candidate = candidate_commit_sha.trim();
        if base_ref.is_empty() || candidate.is_empty() {
            return Ok(None);
        }
        // A landed promotion ff-merges `base_ref` onto the candidate HEAD, so the
        // base bookmark pointing AT the candidate commit is a NECESSARY condition
        // for "the promote landed" — and NOT a sufficient one. "The candidate sha is unique to
        // this execution's work" is false for a candidate that HAS no work: it
        // resolves to the base commit it forked from, so the base bookmark holds
        // it vacuously and this returns `Some` for an execution that promoted
        // nothing. See the trait doc. Anything else — a different commit — means
        // the promote did NOT land, so we observe `None` and the caller re-drives
        // (or leaves the claim `apply_claimed`).
        let Some(base_commit) = self.local_bookmark_commit(base_ref)? else {
            return Ok(None);
        };
        if base_commit != candidate {
            return Ok(None);
        }
        Ok(Some(PromotedWorkspace {
            identity: Some(execution_workspace_identity(
                key,
                ExecutionWorkspaceBackend::Jj,
                None,
                None,
                Some(base_ref.to_string()),
                Some(base_commit.clone()),
                Some(base_ref.to_string()),
                Some(base_commit.clone()),
            )),
            ref_name: base_ref.to_string(),
            commit_sha: base_commit,
        }))
    }

    fn apply_work_delta(
        &self,
        handle: &ExecutionWorkspaceHandle,
        expected_wc_commit: &str,
        delta: &kata_types::tree_delta::TreeDelta,
        members: &dyn Fn(kata_types::primitives::ObjectId, u64) -> KataResult<Vec<u8>>,
        effect_tag: &str,
    ) -> KataResult<kata_effects_contract::AppliedCandidate> {
        self.durably("work_apply", |_| {
            JjBackend::apply_work_delta(
                self,
                handle,
                expected_wc_commit,
                delta,
                members,
                effect_tag,
            )
        })
    }

    fn classify_work_apply(
        &self,
        handle: &ExecutionWorkspaceHandle,
        recorded_head_commit: &str,
        effect_tag: &str,
        delta: &kata_types::tree_delta::TreeDelta,
        since_ms: i64,
    ) -> KataResult<kata_effects_contract::WorkApplyState> {
        JjBackend::classify_work_apply(
            self,
            handle,
            recorded_head_commit,
            effect_tag,
            delta,
            since_ms,
        )
    }

    fn repair_stale_checkout(&self, handle: &ExecutionWorkspaceHandle) -> KataResult<()> {
        self.durably("repair_stale_checkout", |_| {
            JjBackend::repair_stale_checkout(self, handle)
        })
    }

    fn commit_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
        effect_tag: &str,
    ) -> KataResult<kata_effects_contract::CommittedEffect> {
        self.durably("workspace_effect commit", |_| {
            JjBackend::commit_workspace_effect(self, key, expected_wc_commit, effect_tag)
        })
    }

    fn park_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
    ) -> KataResult<ParkedWorkspace> {
        self.durably("workspace_effect park", |barrier| {
            JjBackend::park_workspace_effect(
                self,
                key,
                expected_wc_commit,
                delivered_commit,
                effect_tag,
                barrier,
            )
        })
    }

    fn promote_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        pin: &CandidateTreePin,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
        landing_branch: Option<&str>,
    ) -> KataResult<PromotedWorkspace> {
        self.durably("workspace_effect promote", |barrier| {
            JjBackend::promote_workspace_effect(
                self,
                key,
                pin,
                expected_wc_commit,
                delivered_commit,
                effect_tag,
                landing_branch,
                barrier,
            )
        })
    }

    fn workspace_effect_delivered_commit(
        &self,
        op: kata_types::workflow::WorkspaceEffectOp,
        candidate_commit: &str,
        committed_commit: &str,
    ) -> KataResult<String> {
        JjBackend::workspace_effect_delivered_commit(self, op, candidate_commit, committed_commit)
    }

    fn require_clean_recorded_candidate(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
    ) -> KataResult<ExecutionWorkspaceStatus> {
        JjBackend::require_clean_recorded_candidate(self, key, expected_wc_commit)
    }

    fn classify_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        handle: Option<&ExecutionWorkspaceHandle>,
        op: kata_types::workflow::WorkspaceEffectOp,
        recorded_candidate: &str,
        delivered_commit: &str,
        landing_branch: Option<&str>,
    ) -> KataResult<kata_effects_contract::WorkspaceEffectClass> {
        JjBackend::classify_workspace_effect(
            self,
            key,
            handle,
            op,
            recorded_candidate,
            delivered_commit,
            landing_branch,
        )
    }

    /// The `{{ workspace.* }}` answer read off the SHARED
    /// repo view: the execution workspace's wc commit is named in the repo's
    /// recorded view (`workspace_path`/`load_at_head` on the ROOT workspace,
    /// never `Workspace::load` on the workspace dir, never a file snapshot).
    /// `None` when no workspace is registered — same undefined-namespace arm
    /// the disk reader took.
    fn recorded_workspace_status(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<kata_effects_contract::RecordedWorkspaceStatus>> {
        let Some(handle) = <Self as ExecutionWorkspaceProvider>::lookup_workspace(self, key)?
        else {
            return Ok(None);
        };
        let settings = self.user_settings()?;
        let root_workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(root_workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let agent = Self::execution_workspace_agent(key)?;
        let workspace_name = Self::workspace_name(&agent);
        let head = Self::head_metadata_from_repo(repo.as_ref(), &workspace_name, false)?;
        Ok(Some(kata_effects_contract::RecordedWorkspaceStatus {
            workspace_root: handle.path,
            head: head.target_commit_id,
            tree_id: head.tree_id,
        }))
    }

    fn recorded_commit_diff(
        &self,
        base_commit: &str,
        head_commit: &str,
    ) -> KataResult<Vec<kata_effects_contract::RecordedPathChange>> {
        JjBackend::recorded_commit_diff(self, base_commit, head_commit)
    }

    fn recorded_commit_text_diff(
        &self,
        base_commit: &str,
        head_commit: &str,
        max_bytes: usize,
    ) -> KataResult<kata_effects_contract::RecordedTextDiff> {
        JjBackend::recorded_commit_text_diff(self, base_commit, head_commit, max_bytes)
    }

    fn workspace_effect_candidate_commit(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<String>> {
        let Some(handle) = <Self as ExecutionWorkspaceProvider>::lookup_workspace(self, key)?
        else {
            return Ok(None);
        };
        Ok(Some(JjBackend::wc_position(self, &handle)?.wc_commit_id))
    }

    fn workspace_effect_candidate_tree(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<String>> {
        let Some(handle) = <Self as ExecutionWorkspaceProvider>::lookup_workspace(self, key)?
        else {
            return Ok(None);
        };
        Ok(Some(JjBackend::wc_position(self, &handle)?.tree_id))
    }

    fn commit_tree_id(&self, commit_sha: &str) -> KataResult<String> {
        JjBackend::commit_tree_id(self, commit_sha)
    }

    fn ensure_workspace_ref(
        &self,
        _key: &ExecutionWorkspaceKey,
        ref_name: &str,
        commit_sha: &str,
        effect_tag: &str,
    ) -> KataResult<()> {
        self.durably("workspace ref", |_| {
            JjBackend::set_local_bookmark_tagged(self, ref_name, commit_sha, Some(effect_tag))
        })
    }

    fn teardown_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        effect_tag: &str,
    ) -> KataResult<()> {
        let agent = Self::execution_workspace_agent(key)?;
        self.durably("workspace_effect teardown", |barrier| {
            JjBackend::remove_workspace_tagged(self, &agent, Some(effect_tag), barrier)
        })
    }

    fn write_workspace_effect_forge_ref(
        &self,
        key: &ExecutionWorkspaceKey,
        branch: &str,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
    ) -> KataResult<()> {
        self.durably("forge_export ref", |_| {
            JjBackend::write_exportable_forge_branch(
                self,
                key,
                branch,
                expected_wc_commit,
                delivered_commit,
                effect_tag,
            )
        })
    }

    fn push_workspace_effect_ref_expecting(
        &self,
        remote: &str,
        branch: &str,
        commit: &str,
        expected_remote: Option<&str>,
    ) -> KataResult<()> {
        JjBackend::push_forge_branch_expecting(self, remote, branch, commit, expected_remote)
    }

    fn forge_export_remote(&self, branch: &str) -> KataResult<String> {
        JjBackend::forge_export_remote(self, branch)
    }

    fn forge_export_repository(&self, remote: &str) -> KataResult<String> {
        JjBackend::forge_export_repository(self, remote)
    }

    fn forge_remote_head(
        &self,
        remote: &str,
        branch: &str,
        timeout: std::time::Duration,
    ) -> KataResult<Option<String>> {
        JjBackend::remote_branch_head(self, remote, branch, timeout)
    }
}
