//! jj-lib-backed implementation of [`VcsBackend`].
//!
//! `JjBackend` deliberately stores only filesystem paths. jj-lib workspaces,
//! repos, transactions, and working-copy locks are created inside each backend
//! call and never live across an async boundary owned by kata-vcs.
//!
//! The implementation is split by concern into sibling submodules:
//! this module owns the [`JjBackend`] value and its shared private helpers,
//! [`execution_provider`] carries the [`ExecutionWorkspaceProvider`] impl, and
//! [`vcs_backend`] carries the [`VcsBackend`] impl.
//!
//! [`ExecutionWorkspaceProvider`]: kata_effects_contract::ExecutionWorkspaceProvider
//! [`VcsBackend`]: crate::backend::VcsBackend

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jj_lib::backend::{CommitId, TreeId, TreeValue};
use jj_lib::config::{ConfigLayer, ConfigSource, StackedConfig};
use jj_lib::fileset::FilesetAliasesMap;
use jj_lib::gitignore::GitIgnoreFile;
use jj_lib::merge::Merge;
use jj_lib::merged_tree::MergedTree;
use jj_lib::object_id::ObjectId as _;
use jj_lib::op_store::RefTarget;
use jj_lib::ref_name::{GitRefNameBuf, RefNameBuf, WorkspaceNameBuf};
use jj_lib::repo::{Repo as _, StoreFactories};
use jj_lib::repo_path::RepoPathUiConverter;
use jj_lib::revset::{
    RevsetAliasesMap, RevsetDiagnostics, RevsetExtensions, RevsetParseContext,
    RevsetWorkspaceContext, UserRevsetExpression,
};
use jj_lib::settings::UserSettings;
use jj_lib::workspace::{Workspace, default_working_copy_factories};
use kata_types::target::{TARGET_TRUNK_RACED, TargetRefusal};
use kata_types::{AgentId, KataError, KataResult};
use ulid::Ulid;

use crate::revset::RevsetDiagnostic;
use crate::trunk::{PARKED_REF_PREFIX, TrunkObservation, TrunkResolution};
use crate::workspace::WorkspaceHeadMetadata;
use kata_effects_contract::{
    ExecutionWorkspaceBackend, ExecutionWorkspaceHandle, ExecutionWorkspaceKey,
    execution_workspace_identity,
};

mod apply;
mod base_tree;
mod census;
mod durability;
mod execution_provider;
mod forge_export;
mod git_view;
pub mod merge_queue;
pub mod op_log_gc;
pub mod recovery_references;
pub mod recovery_workspaces;
mod target;
mod text_diff;
mod vcs_backend;
mod workspace_effect;

pub use apply::{
    FORGE_EXPORT_CONFLICTED_COMMIT, KATA_EFFECT_TAG, WORK_APPLY_CANDIDATE_DIVERGED,
    WORK_APPLY_MEMBER_MISMATCH,
};

/// The admission census's `.gitattributes` checkout-conversion check, exposed
/// for the `/work` apply scope: a delta that WRITES a `.gitattributes` declaring
/// `filter`/`ident`/`working-tree-encoding`/`eol=crlf` would smuggle a
/// checkout conversion past the admission census — the delta's own content is
/// the attribute source it must be judged on, through the ONE parser.
pub fn checkout_conversion_findings(
    source_path: &str,
    bytes: &[u8],
) -> Vec<kata_effects_contract::UnsupportedRepositoryFeature> {
    let mut findings = Vec::new();
    census::emit_checkout_conversion_findings(
        &[(source_path.to_owned(), bytes.to_vec())],
        &mut findings,
    );
    findings
}
pub use durability::{REPOSITORY_NOT_DURABLE, REPOSITORY_TORN, TornRepair};
pub use op_log_gc::{OpLogGcPolicy, OpLogGcStats};
pub use workspace_effect::{
    FORGE_EXPORT_UNCOMMITTED_CANDIDATE, FORGE_REMOTE_UNRESOLVED, FORGE_REPOSITORY_UNRESOLVED,
    OCI_CANDIDATE_DISK_DIVERGED, OCI_CANDIDATE_DIVERGED, OCI_DELIVERED_TREE_DIVERGED,
    PARKED_REF_OCCUPIED,
};

/// The directory name kata joins onto the TARGET REPOSITORY ROOT to hold every
/// per-execution workspace (`<repo>/agents/<exec>`).
///
/// This is a name kata writes into a repository it does not own, so it has two
/// obligations that must not drift apart: [`JjBackend::agents_root`] CREATES the
/// tree, and `kata doctor`'s `target_repo_ignore` row proves the operator's repo
/// IGNORES it. Both read this constant.
///
/// The drift is not hypothetical. The first live `gold-loop` run promoted 46
/// files / 333 insertions of jj internals and candidate-workspace state into a
/// fixture repository's trunk, because the requirement "the target repo must
/// ignore these" was stated in kata's own `.gitignore` and in a `kata config
/// check` advisory string, and verified nowhere.
pub const AGENTS_DIR_NAME: &str = "agents";

/// jj's own metadata directory, created at the TARGET REPOSITORY ROOT by
/// [`VcsBackend::open`] when it colocates or adopts (`Workspace::init_colocated_git`
/// / `Workspace::init_external_git`).
///
/// Same two obligations as [`AGENTS_DIR_NAME`]: the code that probes for and
/// creates it and the doctor row that proves it is ignored read one constant.
///
/// [`VcsBackend::open`]: crate::backend::VcsBackend::open
pub const JJ_METADATA_DIR_NAME: &str = ".jj";

/// Record the wall-clock duration of an expensive jj VCS
/// operation as the `kata_vcs_operation_duration_seconds{operation}` histogram.
/// Wraps the whole call: the elapsed time
/// is recorded on BOTH the ok and err path (a slow *failing* op is exactly the
/// one an operator wants to see), so callers pass the expensive body as a
/// closure and use the returned value unchanged. `operation` is a small fixed
/// label set (`commit`, `snapshot`, `workspace_create`, `land`, `promote`,
/// `import`, `op_log_gc`, `census`, `resolve_target`, …) — bounded cardinality, no per-agent
/// dimension.
pub(super) fn record_vcs_op<T>(operation: &'static str, op: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    let result = op();
    metrics::histogram!(
        "kata_vcs_operation_duration_seconds",
        "operation" => operation,
    )
    .record(started.elapsed().as_secs_f64());
    result
}

/// Concrete jj-lib backend for kata-vcs.
///
/// The value is intentionally cheap and `Send + Sync`: it contains only the
/// canonical root workspace path. All jj-lib objects are local variables inside
/// individual calls.
#[derive(Clone, Debug)]
pub struct JjBackend {
    repo_path: PathBuf,
    /// Op-log GC horizon consumed by the boot sweep and the post-land
    /// cadence. Defaults to [`op_log_gc::OpLogGcPolicy::default`]; boot overrides
    /// it from `vcs.op_log_gc_*` via [`Self::with_op_log_gc_policy`].
    op_log_gc: op_log_gc::OpLogGcPolicy,
    /// `vcs.trunk`, when the operator named one - rank 1 of
    /// [`crate::trunk::resolve_trunk`]'s precedence, and the ONLY place kata
    /// carries a trunk NAME at all. There is no default: absent means "ask the
    /// repository", never "assume `main`".
    ///
    /// Carried on the VALUE rather than resolved once at `open()`, because the
    /// answer must be taken per operation. [`Self::refresh_trunk_from_git`]
    /// exists because a boot-time answer about trunk went stale once already,
    /// and a NAME goes stale the same way a commit does - a branch renamed, a
    /// `git remote set-head` run after the node booted.
    configured_trunk: Option<String>,
}

impl JjBackend {
    /// Override the op-log GC horizon. Called at boot with the operator's
    /// `[vcs]` retention knobs so the boot sweep and the post-land cadence bound
    /// the op-log per configuration. `JjBackend` is cheap + `Clone`, so the
    /// policy rides every clone the provider hands out.
    #[must_use]
    pub fn with_op_log_gc_policy(mut self, policy: op_log_gc::OpLogGcPolicy) -> Self {
        self.op_log_gc = policy;
        self
    }

    /// The op-log GC horizon in force for this backend.
    #[must_use]
    pub fn op_log_gc_policy(&self) -> op_log_gc::OpLogGcPolicy {
        self.op_log_gc
    }

    /// Carry the operator's `vcs.trunk` (rank 1 of the trunk precedence).
    ///
    /// `JjBackend` is cheap + `Clone`, so the binding rides every clone the
    /// provider hands out from its one construction site,
    /// `boot::build_workspace_provider_from_config`.
    #[must_use]
    pub fn with_configured_trunk(mut self, trunk: Option<String>) -> Self {
        self.configured_trunk = trunk.filter(|name| !name.trim().is_empty());
        self
    }

    /// The trunk `vcs.trunk` names, if any. Read by `kata doctor`'s
    /// `trunk_resolution` row so it reports the DAEMON's binding rather than
    /// re-deriving one of its own.
    #[must_use]
    pub fn configured_trunk(&self) -> Option<&str> {
        self.configured_trunk.as_deref()
    }

    /// jj settings for operations against THIS backend's repository, carrying
    /// the host's own commit identity.
    ///
    /// See [`Self::user_settings_at`] — this is the `&self` spelling, and it is
    /// what almost every call site wants.
    fn user_settings(&self) -> KataResult<UserSettings> {
        Self::user_settings_at(&self.repo_path)
    }

    /// jj settings for operations against the repository at `repo_root`.
    ///
    /// # Why not jj's defaults
    ///
    /// `UserSettings::from_config(StackedConfig::with_defaults())` is not enough.
    /// MEASURED: `with_defaults()` is exactly ONE layer — jj-lib's built-in
    /// `config/misc.toml` — which sets `user.name` and `user.email` to the EMPTY
    /// STRING. No file, no environment, no `~/.jjconfig.toml`, no `JJ_CONFIG`,
    /// no repo config: jj-lib does ZERO config path discovery, and every path
    /// rule lives in jj-CLI, which kata does not use. So every commit kata
    /// authored on those settings would carry jj's empty identity, which
    /// reaches the git side — and the operator's forge — as
    /// `JJ_EMPTY_STRING <JJ_EMPTY_STRING>`.
    ///
    /// # What is added, and at which precedence
    ///
    /// ONE layer at [`ConfigSource::CommandArg`], jj's HIGHEST precedence,
    /// carrying the identity [`crate::identity`] resolved by asking git about
    /// `repo_root`. `CommandArg` is the right rank because this is not a file
    /// kata found; it is a value kata RESOLVED and is stating, exactly as
    /// `jj --config user.email=…` would.
    ///
    /// # Why an unresolvable identity DEGRADES here rather than refusing
    ///
    /// This function is on the path of every jj operation kata performs,
    /// including pure reads (`workspace_status`, revset queries, op-log GC) that
    /// author nothing. Refusing here would make a repository with no host
    /// identity unreadable as well as unwritable, and — measured — would make
    /// ~100 `kata-vcs` tests host-dependent on the operator's global git config,
    /// which `just gate` must not be.
    ///
    /// The refusals are placed where they mean something instead, and there are
    /// two, because a configured identity alone would let an empty identity
    /// leave the host by the export route:
    ///
    /// * **ADMISSION** — `create_workspace` on both providers, before a stage is
    ///   dispatched or a token is spent.
    /// * **PUBLISH** — [`crate::identity::require_publishable_identity`] at every
    ///   point a commit leaves the execution workspace.
    ///
    /// The degraded state is not a new failure mode: it is jj's empty identity,
    /// which is precisely what the publish refusal recognises. A commit minted
    /// through a path this doc did not anticipate is caught there.
    ///
    /// # The cost, measured rather than assumed
    ///
    /// The identity is resolved PER OPERATION, never cached — the same rule
    /// [`crate::trunk`] follows, and for the same reason: an operator who fixes
    /// their git config must not have to restart the daemon. That spends one
    /// `git` spawn per jj operation. MEASURED on a ~300-branch checkout, under
    /// load from two concurrent builds: **~2.7 ms per probe** (272 ms / 100
    /// spawns). A jj operation loads a repo
    /// and snapshots a working copy; this is noise beside it.
    fn user_settings_at(repo_root: &Path) -> KataResult<UserSettings> {
        let mut config = StackedConfig::with_defaults();
        if let Ok(identity) = crate::identity::resolve_commit_identity(
            &crate::identity::observe_identity_at(repo_root),
        ) {
            let layer = ConfigLayer::parse(
                ConfigSource::CommandArg,
                &format!(
                    "[user]\nname = {}\nemail = {}\n",
                    toml_string(&identity.name),
                    toml_string(&identity.email),
                ),
            )
            .map_err(|err| {
                KataError::Config(format!("failed to build jj identity config layer: {err}"))
            })?;
            config.add_layer(layer);
        }
        UserSettings::from_config(config)
            .map_err(|err| KataError::Config(format!("failed to load jj settings: {err}")))
    }

    fn workspace_name(agent: &AgentId) -> WorkspaceNameBuf {
        WorkspaceNameBuf::from(format!("agent-{}", agent.0))
    }

    fn workspace_path(&self, agent: &AgentId) -> PathBuf {
        self.agents_root().join(agent.0.to_string())
    }

    /// The `<agents>` root that holds every execution workspace
    /// (`<agents>/<exec>`), so the `agents/` layout convention lives in ONE place.
    pub fn agents_root(&self) -> PathBuf {
        self.repo_path.join(AGENTS_DIR_NAME)
    }

    fn parked_bookmark_name(execution_id: Ulid, label: Option<&str>) -> String {
        let raw = label.filter(|value| !value.trim().is_empty()).map_or_else(
            || execution_id.to_string(),
            |value| value.trim().to_string(),
        );
        format!(
            "{PARKED_REF_PREFIX}{}",
            Self::safe_parked_label(&raw, execution_id)
        )
    }

    fn safe_parked_label(raw: &str, execution_id: Ulid) -> String {
        let mut label = raw
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                    c
                } else {
                    '-'
                }
            })
            .take(96)
            .collect::<String>();
        while label.starts_with('-') || label.starts_with('_') {
            label.remove(0);
        }
        while label.ends_with('-') || label.ends_with('_') {
            label.pop();
        }
        if label.is_empty() {
            execution_id.to_string()
        } else {
            label
        }
    }

    fn execution_workspace_agent(key: &ExecutionWorkspaceKey) -> KataResult<AgentId> {
        if key.invocation_id.is_some() || key.stage_name.is_some() {
            return Err(KataError::Validation(
                "jj execution workspace provider currently supports execution-scoped keys only"
                    .to_owned(),
            ));
        }
        Ok(AgentId(key.execution_id))
    }

    fn execution_workspace_handle(
        &self,
        key: &ExecutionWorkspaceKey,
        agent: AgentId,
    ) -> ExecutionWorkspaceHandle {
        ExecutionWorkspaceHandle {
            key: key.clone(),
            path: self.workspace_path(&agent),
            backend: ExecutionWorkspaceBackend::Jj,
        }
    }

    /// Build this execution's durable workspace identity.
    ///
    /// `base_ref` is DURABLE EVIDENCE, not a log line: it is what an operator
    /// and the reconcile probe read back to learn which ref this candidate was
    /// based on. It stamped the hard-coded `"main"` until the trunk binding
    /// landed, so on a `master` repository the recorded evidence named a
    /// bookmark that repository never had. It now carries what
    /// [`crate::trunk::resolve_trunk`] ACTUALLY resolved, or `None` when the
    /// repository has no trunk yet - never a constant.
    fn execution_workspace_identity_from_head(
        key: &ExecutionWorkspaceKey,
        workspace_ref: Option<String>,
        head: &WorkspaceHeadMetadata,
        base_ref: Option<String>,
        target_ref: Option<String>,
        target_commit_sha: Option<String>,
    ) -> kata_types::execution::ExecutionWorkspaceIdentity {
        execution_workspace_identity(
            key,
            ExecutionWorkspaceBackend::Jj,
            workspace_ref,
            // The candidate's SETTLED commit, not the raw `@`. `@` is jj's
            // working-copy commit and is content-free immediately after a
            // commit, so publishing it as this execution's candidate is what
            // made `forge_export` resolve an empty commit and made the
            // promote crash-window reconcile compare the wrong sha. See
            // [`Self::settled_candidate_commit`].
            Some(head.target_commit_id.clone()),
            base_ref,
            head.base_commit_id.clone(),
            target_ref,
            target_commit_sha,
        )
    }

    /// Every branch name this repository holds, plus the remote's own answer -
    /// the facts [`crate::trunk::resolve_trunk`] decides from.
    ///
    /// The local set is the UNION of jj's local bookmarks and the colocated
    /// `.git`'s `refs/heads/*`. Both halves are needed and neither is
    /// redundant: jj's view is authoritative for a non-colocated store and for
    /// anything kata itself created, while git's refs carry branches an
    /// operator made after the last import - and the import happens AFTER this
    /// resolve (`base_workspace_on_trunk_named` needs the name to scope its
    /// idempotency peek), so a jj-only observation would be blind to exactly
    /// the branch that just became the answer.
    ///
    /// The remote answer is `refs/remotes/<remote>/HEAD`, read as a SYMBOLIC
    /// ref. Every remote must agree: two remotes naming different defaults is
    /// not an answer, and kata declines rather than picking one.
    fn observe_trunk(&self, repo: &dyn jj_lib::repo::Repo) -> TrunkObservation {
        let mut local_branches: Vec<String> = repo
            .view()
            .local_bookmarks()
            .map(|(name, _)| name.as_str().to_owned())
            .collect();
        let mut remote_head: Option<String> = None;

        if let Ok(git_backend) = jj_lib::git::get_git_backend(repo.store()) {
            let git_repo = git_backend.git_repo();
            if let Ok(platform) = git_repo.references()
                && let Ok(branches) = platform.local_branches()
            {
                local_branches.extend(
                    branches
                        .filter_map(Result::ok)
                        .map(|reference| reference.name().shorten().to_string()),
                );
            }
            // `refs/remotes/<remote>/HEAD` -> `refs/remotes/<remote>/<branch>`.
            // Read WITHOUT following: `git remote set-head` can name a branch
            // that was never fetched, and following would then error rather
            // than report the name.
            if let Ok(platform) = git_repo.references()
                && let Ok(remotes) = platform.prefixed(b"refs/remotes/".as_slice())
            {
                let mut answers: Vec<String> = Vec::new();
                for reference in remotes.filter_map(Result::ok) {
                    let full = reference.name().as_bstr().to_string();
                    let Some(remote_path) = full.strip_prefix("refs/remotes/") else {
                        continue;
                    };
                    let Some(remote_name) = remote_path.strip_suffix("/HEAD") else {
                        continue;
                    };
                    let target = reference.target();
                    let Some(target) = target.try_name() else {
                        continue;
                    };
                    let target = target.as_bstr().to_string();
                    if let Some(branch) =
                        target.strip_prefix(&format!("refs/remotes/{remote_name}/"))
                    {
                        answers.push(branch.to_owned());
                    }
                }
                answers.sort_unstable();
                answers.dedup();
                if let [only] = answers.as_slice() {
                    remote_head = Some(only.clone());
                }
            }
        }

        local_branches.sort_unstable();
        local_branches.dedup();
        TrunkObservation {
            configured: self.configured_trunk.clone(),
            local_branches,
            remote_head,
        }
    }

    /// Resolve this repository's trunk from an already-loaded repo view.
    ///
    /// The ONE resolution both the FORK base ([`Self::base_workspace_on_trunk_named`])
    /// and the LANDING base ([`Self::run_landing_ladder`]) go through. They must
    /// be the same ref: a candidate forked from anything other than what the
    /// ladder lands against is a candidate whose base "advanced" the moment it
    /// was created, and the base-advance fence PARKS it needs-revalidation
    /// instead of landing it. Forking from `git_head()` instead of the
    /// resolved trunk would park every second execution this way.
    fn resolve_trunk_in(&self, repo: &dyn jj_lib::repo::Repo) -> KataResult<TrunkResolution> {
        crate::trunk::resolve_trunk(&self.observe_trunk(repo))
    }

    /// Resolve this repository's trunk, loading the root repo to do it.
    ///
    /// For callers that hold no repo handle. Prefer [`Self::resolve_trunk_in`]
    /// wherever a view is already open.
    pub fn resolve_trunk(&self) -> KataResult<TrunkResolution> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        self.resolve_trunk_in(repo.as_ref())
    }

    /// The resolved trunk NAME for durable evidence, or `None`.
    ///
    /// Deliberately non-failing, and the asymmetry is the point. The operations
    /// that MUST have a trunk - forking a workspace and landing a candidate -
    /// propagate the refusal loudly. The identity STAMP is not one of them:
    /// `commit` and `park` do not touch
    /// trunk, so refusing them because the repository grew a second branch
    /// would destroy work over a question they never asked. Recording `None`
    /// says "kata does not know this repository's trunk", which is true; the
    /// shipped code recorded `"main"`, which was not.
    fn trunk_name_for_evidence(&self) -> Option<String> {
        self.resolve_trunk()
            .ok()
            .and_then(|resolution| resolution.name().map(str::to_owned))
    }

    /// The AUTHOR RECEIPT for `commit_sha`, or a typed refusal — the PUBLISH
    /// half of the identity remedy.
    ///
    /// Asked at every point a commit leaves the execution workspace: `commit`
    /// (which publishes `exec-<id>` into the operator's `.git`), `park`,
    /// `promote`, and `forge_export`. It reads what the commit ACTUALLY CARRIES,
    /// so unlike the admission check it needs no host identity of its own and
    /// still fires on a commit minted before this landed, by a different tool,
    /// or by an AGENT inside the sandbox wrap.
    ///
    /// This is required in addition to a configured identity: a REFUSAL must
    /// fire on the `forge_export` path and not at commit time alone, or the
    /// empty identity still leaves the host by that route.
    ///
    /// Returns the `Name <email>` line so the caller can stamp it as
    /// [`kata_types::execution::ExecutionWorkspaceIdentity::author`]: the value
    /// the refusal read IS the receipt, produced by the act rather than
    /// re-derived afterwards.
    pub(super) fn publishable_author(
        &self,
        operation: &str,
        commit_sha: &str,
    ) -> KataResult<String> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let commit_id = CommitId::try_from_hex(commit_sha).ok_or_else(|| {
            KataError::Internal(format!(
                "{operation}: candidate commit id is not valid hex: {commit_sha}"
            ))
        })?;
        let commit = repo.store().get_commit(&commit_id).map_err(|err| {
            KataError::Internal(format!(
                "{operation}: candidate commit {commit_sha} is not in the store: {err}"
            ))
        })?;
        let author = commit.author();
        let committer = commit.committer();
        crate::identity::require_publishable_identity(
            operation,
            commit_sha,
            &author.name,
            &author.email,
            &committer.name,
            &committer.email,
        )
    }

    fn load_root_workspace(&self, settings: &UserSettings) -> KataResult<Workspace> {
        Workspace::load(
            settings,
            &self.repo_path,
            &StoreFactories::default(),
            &default_working_copy_factories(),
        )
        .map_err(|err| KataError::Internal(format!("failed to load jj root workspace: {err}")))
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }

    fn load_agent_workspace(
        &self,
        settings: &UserSettings,
        agent: &AgentId,
    ) -> KataResult<Workspace> {
        Workspace::load(
            settings,
            &self.workspace_path(agent),
            &StoreFactories::default(),
            &default_working_copy_factories(),
        )
        .map_err(|err| KataError::Internal(format!("failed to load agent workspace: {err}")))
    }

    fn workspace_commit(
        repo: &dyn jj_lib::repo::Repo,
        workspace_name: &WorkspaceNameBuf,
    ) -> KataResult<jj_lib::commit::Commit> {
        let wc_commit_id = repo
            .view()
            .get_wc_commit_id(workspace_name)
            .cloned()
            .ok_or_else(|| {
                KataError::Internal(format!(
                    "jj workspace has no commit: {}",
                    workspace_name.as_str()
                ))
            })?;
        Self::named_commit(repo, &wc_commit_id, "wc commit")
    }

    /// Stable hex encoding of a jj `MergedTree` root id (the tree_id).
    ///
    /// A resolved (non-conflicted) tree encodes as its single `TreeId` hex; a
    /// conflicted tree joins every side's hex with `+` so the value stays
    /// deterministic and side-preserving. The effect model keys on this.
    fn merged_tree_id_hex(tree_ids: &Merge<TreeId>) -> String {
        match tree_ids.as_resolved() {
            Some(resolved) => resolved.hex(),
            None => tree_ids
                .iter()
                .map(jj_lib::object_id::ObjectId::hex)
                .collect::<Vec<_>>()
                .join("+"),
        }
    }

    fn ref_target_commit_ids(target: &RefTarget) -> Vec<String> {
        target
            .added_ids()
            .map(jj_lib::object_id::ObjectId::hex)
            .collect()
    }

    /// Publish jj's local bookmarks into the COLOCATED `.git`, inside the
    /// caller's transaction.
    ///
    /// THE single git-export point for every kata effect that moves a
    /// git-visible ref. Without it a `promote` would move the jj `main` bookmark
    /// and leave `refs/heads/main` in the colocated `.git` at the pre-promote
    /// commit: every git tool, every CI system and every human would read an
    /// unchanged trunk while kata recorded a successful landing. A jj bookmark nobody but jj can
    /// see has not landed anything in any sense an operator can observe.
    ///
    /// Bookmark → `export_refs` (never a raw `git update-ref`) is what keeps the
    /// two views in lockstep: `export_refs` writes the ref AND records it in
    /// jj's `git_refs` view, so jj's next import sees the ref as ALREADY
    /// EXPORTED rather than as an external change to re-import.
    ///
    /// ## The invariant is GIT FIRST, jj records only on full success
    ///
    /// The export is NOT all-or-nothing with the caller's transaction, though a
    /// failed export can never leave a moved bookmark unpublished; the
    /// difference is the whole hazard. Read against jj-lib 0.39.0
    /// (`export_refs` → `export_some_refs` → `export_refs_to_git` →
    /// `update_git_ref` in its `git.rs`) and MEASURED here by
    /// `git_export_moves_the_git_ref_before_the_transaction_commits`:
    /// `update_git_ref` calls `gix`'s `edit_references` and the ref moves ON
    /// DISK inside this call. Only the companion `mut_repo.set_git_ref_target`
    /// — jj's memory of what it has exported — rides `tx.commit`. So the two
    /// halves are ASYMMETRIC, and the asymmetry has a direction:
    ///
    /// * **jj can never be ahead of git.** A bookmark move and its export share
    ///   one transaction, so if jj's view says the bookmark moved, the git ref
    ///   moved first. That is the property every effect here depends on: a
    ///   recorded landing is a landing git can see.
    /// * **git CAN be ahead of jj.** An error returned below, or a crash or a
    ///   `tx.commit` failure after `export_refs` returns, leaves `refs/heads/…`
    ///   moved while jj's bookmark and `git_refs` view have not. Nothing
    ///   detects that at the time.
    ///
    /// What the second state costs, also measured: a re-drive of the SAME effect
    /// to the SAME commit CONVERGES — `move_git_ref` treats "the ref is already
    /// at the target I wanted" as success and the following `tx.commit` records
    /// it — so an interrupted promote heals by being re-run. A LATER export of a
    /// DIFFERENT commit does not: its old-oid precondition is jj's stale
    /// remembered value, git holds something else, and the bookmark lands in
    /// `failed_bookmarks`. That is fail-closed and non-corrupting (trunk in git
    /// still holds kata's own last exported commit, and nothing is lost), but it
    /// blocks until jj re-imports — which `refresh_trunk_from_git` does on the
    /// next `create_workspace`.
    ///
    /// FAIL-CLOSED on `bookmark`: `export_refs` reports per-bookmark refusals
    /// (a ref an operator moved behind jj's back, a name that cannot be a git
    /// ref) in `failed_bookmarks` rather than erroring, and an effect whose own
    /// ref did not reach git must not report success. Other bookmarks' failures
    /// are not this effect's business and are left alone.
    ///
    /// OPERATOR NOTE: in a colocated repo the root working tree is checked out
    /// against these same refs, so a landed promote moves `refs/heads/main`
    /// under it exactly as `jj git export` does — the root checkout then reads
    /// as behind trunk until the operator updates it.
    fn export_bookmark_to_git(
        repo: &mut jj_lib::repo::MutableRepo,
        bookmark: &str,
        effect: &str,
    ) -> KataResult<()> {
        // Captured BEFORE the export: jj's memory of what it last published for
        // this ref. After a successful export it is overwritten, and after a
        // refusal it is the stale value whose mismatch caused the refusal — so
        // it is only readable here.
        let remembered = Self::remembered_git_ref(repo, bookmark);
        let stats = jj_lib::git::export_refs(repo).map_err(|err| {
            KataError::Internal(format!(
                "{effect}: failed to export jj bookmark `{bookmark}` to the colocated git repo: \
                 {err}"
            ))
        })?;
        if let Some((_, reason)) = stats
            .failed_bookmarks
            .iter()
            .find(|(symbol, _)| symbol.name.as_str() == bookmark)
        {
            // NAME THE THREE COORDINATES rather than assign blame. "A ref moved
            // behind jj's back" is one of TWO causes and reads as an accusation:
            // kata's own export writes git before `tx.commit`, so a crash in
            // that window leaves git ahead of jj and the next differing export
            // refuses for exactly this reason.
            let wanted = Self::local_bookmark_target(repo, bookmark);
            let on_disk = Self::git_ref_on_disk(repo, bookmark);
            return Err(KataError::Internal(format!(
                "{effect}: jj declined to export bookmark `{bookmark}` to git ({reason}), so the \
                 ref every git tool reads does not name this effect's commit. jj wants \
                 `{bookmark}` at {wanted}; jj last recorded exporting {remembered}; \
                 `refs/heads/{bookmark}` on disk holds {on_disk}. Two things produce that, and \
                 kata cannot tell them apart from here: (1) something outside jj moved the git \
                 ref, or (2) an earlier kata export of this ref wrote git and then died before \
                 its transaction committed — the export writes git FIRST and records the export \
                 only on a full `tx.commit`. Either way trunk still holds a real commit and \
                 nothing was lost; reconcile by re-importing the git refs into jj (kata does \
                 this on the next `create_workspace`) once the on-disk value is the one you want \
                 to keep. A colocated git backend is also required for any export to succeed."
            )));
        }
        Ok(())
    }

    /// jj's remembered value for `refs/heads/<bookmark>` — what it believes it
    /// last exported. Rendered for the diagnostic above; `<absent>` when jj has
    /// no record of ever exporting the ref, `<conflicted>` when the import left
    /// it with several candidates.
    fn remembered_git_ref(repo: &jj_lib::repo::MutableRepo, bookmark: &str) -> String {
        let name = GitRefNameBuf::from(format!("refs/heads/{bookmark}"));
        Self::render_ref_target(repo.view().get_git_ref(name.as_ref()))
    }

    /// The commit jj's LOCAL BOOKMARK names — the value the export is trying to
    /// publish.
    fn local_bookmark_target(repo: &jj_lib::repo::MutableRepo, bookmark: &str) -> String {
        let name = RefNameBuf::from(bookmark.to_owned());
        Self::render_ref_target(repo.view().get_local_bookmark(name.as_ref()))
    }

    /// What `refs/heads/<bookmark>` ACTUALLY holds in the colocated `.git` right
    /// now, read through the git backend rather than through jj's view of it —
    /// the coordinate that distinguishes the two causes above and the one jj's
    /// own error cannot report.
    fn git_ref_on_disk(repo: &jj_lib::repo::MutableRepo, bookmark: &str) -> String {
        let Ok(backend) = jj_lib::git::get_git_backend(repo.store()) else {
            return "<no colocated git backend>".to_string();
        };
        let git_repo = backend.git_repo();
        match git_repo.find_reference(format!("refs/heads/{bookmark}").as_str()) {
            Ok(reference) => reference
                .into_fully_peeled_id()
                .map_or_else(|_| "<unresolvable>".to_string(), |id| id.to_string()),
            Err(_) => "<absent>".to_string(),
        }
    }

    fn render_ref_target(target: &RefTarget) -> String {
        let ids = Self::ref_target_commit_ids(target);
        match ids.len() {
            0 => "<absent>".to_string(),
            1 => ids.into_iter().next().unwrap_or_default(),
            _ => format!("<conflicted: {}>", ids.join(", ")),
        }
    }

    /// The candidate commit a ref-moving effect must publish for a workspace
    /// whose working-copy commit is `wc_commit`.
    ///
    /// `@` is jj's WORKING-COPY commit, and it is not in general the commit that
    /// holds the candidate's work:
    ///
    /// * `create_workspace` checks out a fresh EMPTY `@` on top of the base, so
    ///   before anything is committed `@`'s tree IS the base tree;
    /// * [`VcsBackend::commit`] follows jj's own `jj commit` shape — it
    ///   finalizes `@` into a durable commit and checks out a NEW empty `@` on
    ///   top — so immediately after a commit `@` is again a content-free
    ///   pass-through whose tree is byte-identical to its parent's.
    ///
    /// Publishing `@` in either state lands a commit with an EMPTY diff against
    /// its parent: `commit` and `promote` envelopes would name a commit that
    /// contains nothing, and the candidate would then be torn down.
    ///
    /// So: step down to `@-` when `@` is a content-free pass-through, and stay
    /// on `@` otherwise. Only a single, non-root parent qualifies — a merge `@`
    /// has no unique predecessor, and the jj root commit has no git counterpart
    /// to export.
    fn settled_candidate_commit(
        repo: &dyn jj_lib::repo::Repo,
        wc_commit: &jj_lib::commit::Commit,
    ) -> KataResult<CommitId> {
        let parents = Self::block_on(wc_commit.parents()).map_err(|err| {
            KataError::Internal(format!("failed to load jj wc commit parents: {err}"))
        })?;
        let [parent] = parents.as_slice() else {
            return Ok(wc_commit.id().clone());
        };
        if parent.id() == repo.store().root_commit_id() {
            return Ok(wc_commit.id().clone());
        }
        if Self::merged_tree_id_hex(parent.tree_ids())
            == Self::merged_tree_id_hex(wc_commit.tree_ids())
        {
            return Ok(parent.id().clone());
        }
        Ok(wc_commit.id().clone())
    }

    fn set_local_bookmark(&self, name: &str, commit_id: &str) -> KataResult<()> {
        self.set_local_bookmark_tagged(name, commit_id, None)
    }

    /// `set_local_bookmark` with `kata.effect` = `effect_tag` on the publishing
    /// transaction when a tag is given — the `oci` `workspace_effect` verbs'
    /// variant; the untagged verbs delegate with `None`.
    fn set_local_bookmark_tagged(
        &self,
        name: &str,
        commit_id: &str,
        effect_tag: Option<&str>,
    ) -> KataResult<()> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let commit_id = CommitId::try_from_hex(commit_id).ok_or_else(|| {
            KataError::Internal(format!(
                "jj commit id for parked workspace is not valid hex: {commit_id}"
            ))
        })?;
        Self::named_commit(repo.as_ref(), &commit_id, "parked commit")?;

        let barrier = durability::RepositoryBarrier::for_git_store(repo.store())?;
        let mut tx = repo.start_transaction();
        let bookmark_name = RefNameBuf::from(name.to_owned());
        tx.repo_mut()
            .set_local_bookmark_target(&bookmark_name, RefTarget::normal(commit_id));
        // Publish to the colocated `.git` in the SAME transaction — a parked or
        // candidate ref only jj can resolve is not preserved in any sense an
        // operator can act on.
        Self::export_bookmark_to_git(tx.repo_mut(), name, "set bookmark")?;
        workspace_effect::tag_effect(&mut tx, effect_tag);
        durability::commit_transaction(
            &barrier,
            tx,
            format!("kata set bookmark {name}"),
            "failed to commit jj parked bookmark",
        )?;
        Ok(())
    }

    fn local_bookmark_commit(&self, name: &str) -> KataResult<Option<String>> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let bookmark_name = RefNameBuf::from(name.to_owned());
        let ids = repo
            .view()
            .get_local_bookmark(bookmark_name.as_ref())
            .added_ids()
            .map(jj_lib::object_id::ObjectId::hex)
            .collect::<Vec<_>>();
        if ids.len() == 1 {
            Ok(ids.into_iter().next())
        } else {
            Ok(None)
        }
    }

    /// The landing ladder's fast-forward of `base_bookmark` onto
    /// `target_commit_id`, a compare-and-swap on `read_base`: the commit its one
    /// production caller, the ladder, read `base_bookmark` at under the landing
    /// lock and judged an ancestor of the target. That lock serializes landings
    /// and no other writer, so a re-read here that finds the bookmark anywhere
    /// but `read_base` — absent, conflicted, or at any other commit, a rewind
    /// to an ancestor of the target and the target itself included — means a
    /// writer outside kata moved trunk in jj's view since, and is refused
    /// `target_trunk_raced` before anything moves. The ladder's ancestry
    /// judgment of `read_base` therefore still holds for the commit moved from.
    /// A move undone inside the window leaves `read_base` standing and is not
    /// seen; landing over it overwrites nothing.
    ///
    /// `kata.effect` = `effect_tag` rides the fast-forward transaction when the
    /// caller is an `oci` `workspace_effect` promote; the merge-queue's own
    /// call passes `None`.
    fn promote_local_bookmark_ff_only_tagged(
        &self,
        base_bookmark: &str,
        read_base: &CommitId,
        target_commit_id: &str,
        execution_id: Ulid,
        effect_tag: Option<&str>,
    ) -> KataResult<()> {
        let settings = self.user_settings()?;
        let workspace = self.load_root_workspace(&settings)?;
        let repo = Self::block_on(workspace.repo_loader().load_at_head())
            .map_err(|err| KataError::Internal(format!("failed to load jj repo head: {err}")))?;
        let bookmark_name = RefNameBuf::from(base_bookmark.to_owned());
        match repo
            .view()
            .get_local_bookmark(bookmark_name.as_ref())
            .as_normal()
        {
            Some(now) if now == read_base => {}
            Some(now) => {
                return Err(Self::trunk_raced(
                    execution_id,
                    base_bookmark,
                    read_base,
                    target_commit_id,
                    &format!("now names {}", now.hex()),
                ));
            }
            None => {
                return Err(Self::trunk_raced(
                    execution_id,
                    base_bookmark,
                    read_base,
                    target_commit_id,
                    "is now absent or conflicted",
                ));
            }
        }
        let target_commit_id = CommitId::try_from_hex(target_commit_id).ok_or_else(|| {
            KataError::Internal(format!(
                "jj promotion target commit id is not valid hex: {target_commit_id}"
            ))
        })?;
        repo.store().get_commit(&target_commit_id).map_err(|err| {
            KataError::Internal(format!("failed to load jj promotion target commit: {err}"))
        })?;

        let barrier = durability::RepositoryBarrier::for_git_store(repo.store())?;
        let mut tx = repo.start_transaction();
        tx.repo_mut()
            .set_local_bookmark_target(&bookmark_name, RefTarget::normal(target_commit_id));
        // A promote that moves the jj bookmark and leaves `refs/heads/<base>`
        // stale has landed nothing an operator, a git tool, or a CI system can
        // see. Export in the SAME transaction so the landing is atomic across
        // both views.
        Self::export_bookmark_to_git(tx.repo_mut(), base_bookmark, "promote")?;
        workspace_effect::tag_effect(&mut tx, effect_tag);
        durability::commit_transaction(
            &barrier,
            tx,
            format!("kata promote workspace {execution_id} to {base_bookmark}"),
            "failed to commit jj promotion",
        )?;
        Ok(())
    }

    /// The `target_trunk_raced` refusal of the landing's fast-forward;
    /// `trunk_now` says what its re-read of `base_bookmark` found instead of
    /// `read_base`.
    fn trunk_raced(
        execution_id: Ulid,
        base_bookmark: &str,
        read_base: &CommitId,
        target_commit: &str,
        trunk_now: &str,
    ) -> KataError {
        TargetRefusal::new(
            TARGET_TRUNK_RACED,
            format!(
                "execution {execution_id}'s landing read trunk `{base_bookmark}` at {}, an \
                 ancestor of candidate {target_commit}, and decided to fast-forward it; under \
                 the landing lock, which serializes only kata's landings, trunk \
                 `{base_bookmark}` {trunk_now}: a writer outside kata moved it in between. \
                 Nothing moved; trunk is judged again when the promote is next driven",
                read_base.hex()
            ),
        )
        .into()
    }

    pub(super) fn head_metadata_from_repo(
        repo: &dyn jj_lib::repo::Repo,
        workspace_name: &WorkspaceNameBuf,
        stale: bool,
    ) -> KataResult<WorkspaceHeadMetadata> {
        let wc_commit = Self::workspace_commit(repo, workspace_name)?;
        let commit_id = wc_commit.id().hex();
        let tree_id = Self::merged_tree_id_hex(wc_commit.tree_ids());
        let parents = Self::block_on(wc_commit.parents()).map_err(|err| {
            KataError::Internal(format!("failed to load jj wc commit parents: {err}"))
        })?;
        let parent_commit_ids: Vec<_> = parents.iter().map(|commit| commit.id().hex()).collect();
        let base_commit_id = parent_commit_ids.first().cloned();

        Ok(WorkspaceHeadMetadata {
            commit_id,
            change_id: wc_commit.change_id().hex(),
            tree_id,
            parent_commit_ids,
            base_commit_id,
            // NOT a duplicate of `commit_id`: `@` is jj's working-copy commit and
            // is a content-free pass-through both before the first commit and
            // straight after every commit. `target_commit_id` is the commit that
            // actually holds the candidate's content — see
            // [`Self::settled_candidate_commit`] — and it is what every
            // ref-moving effect publishes.
            target_commit_id: Self::settled_candidate_commit(repo, &wc_commit)?.hex(),
            stale,
        })
    }

    fn collect_tree_files(tree: &MergedTree) -> KataResult<BTreeSet<String>> {
        let mut paths = BTreeSet::new();
        for (path, value) in tree.entries() {
            let value = value.map_err(|err| {
                KataError::Internal(format!("failed to read jj tree entry: {err}"))
            })?;
            if value
                .as_resolved()
                .and_then(Option::as_ref)
                .is_some_and(|value| {
                    matches!(value, TreeValue::File { .. } | TreeValue::Symlink(_))
                })
            {
                paths.insert(path.into_internal_string());
            }
        }
        Ok(paths)
    }

    fn collect_disk_files(root: &Path) -> KataResult<BTreeSet<String>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeSet<String>) -> KataResult<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if entry.file_name() == ".jj" {
                    continue;
                }
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.is_dir() {
                    walk(base, &path, out)?;
                } else if metadata.is_file() || metadata.file_type().is_symlink() {
                    let rel = path.strip_prefix(base).map_err(|err| {
                        KataError::Internal(format!("failed to relativize path: {err}"))
                    })?;
                    out.insert(rel.to_string_lossy().replace('\\', "/"));
                }
            }
            Ok(())
        }

        let mut files = BTreeSet::new();
        walk(root, root, &mut files)?;
        Ok(files)
    }

    fn base_ignores(root: &Path) -> Arc<GitIgnoreFile> {
        let _ = root;
        GitIgnoreFile::empty()
    }

    fn collect_ignored_disk_files(
        root: &Path,
        tracked_files: &BTreeSet<String>,
    ) -> KataResult<BTreeSet<String>> {
        fn rel_path(base: &Path, path: &Path) -> KataResult<String> {
            Ok(path
                .strip_prefix(base)
                .map_err(|err| {
                    KataError::Internal(format!("failed to relativize ignored path: {err}"))
                })?
                .to_string_lossy()
                .replace('\\', "/"))
        }

        fn collect_all_untracked_files(
            base: &Path,
            dir: &Path,
            tracked_files: &BTreeSet<String>,
            out: &mut BTreeSet<String>,
        ) -> KataResult<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if entry.file_name() == ".jj" {
                    continue;
                }
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.is_dir() {
                    collect_all_untracked_files(base, &path, tracked_files, out)?;
                } else if metadata.is_file() || metadata.file_type().is_symlink() {
                    let rel = rel_path(base, &path)?;
                    if !tracked_files.contains(&rel) {
                        out.insert(rel);
                    }
                }
            }
            Ok(())
        }

        fn walk(
            base: &Path,
            dir: &Path,
            prefix: &str,
            ignores: Arc<GitIgnoreFile>,
            tracked_files: &BTreeSet<String>,
            out: &mut BTreeSet<String>,
        ) -> KataResult<()> {
            let current = ignores
                .chain_with_file(prefix, dir.join(".gitignore"))
                .map_err(|err| {
                    KataError::Internal(format!("failed to load jj gitignore metadata: {err}"))
                })?;

            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if entry.file_name() == ".jj" {
                    continue;
                }
                let metadata = fs::symlink_metadata(&path)?;
                let rel = rel_path(base, &path)?;
                if metadata.is_dir() {
                    let rel_dir = format!("{rel}/");
                    if current.matches(&rel_dir) {
                        collect_all_untracked_files(base, &path, tracked_files, out)?;
                    } else {
                        walk(base, &path, &rel_dir, current.clone(), tracked_files, out)?;
                    }
                } else if (metadata.is_file() || metadata.file_type().is_symlink())
                    && !tracked_files.contains(&rel)
                    && current.matches(&rel)
                {
                    out.insert(rel);
                }
            }
            Ok(())
        }

        let mut files = BTreeSet::new();
        walk(
            root,
            root,
            "",
            GitIgnoreFile::empty(),
            tracked_files,
            &mut files,
        )?;
        Ok(files)
    }

    /// Parse a user-supplied revset query into a `UserRevsetExpression` using
    /// jj-lib's own revset grammar.
    ///
    /// Delegating to [`jj_lib::revset::parse`] gives callers the full jj revset
    /// language — set operators (`|`, `&`, `~`), DAG operators (`::`, `..`,
    /// ancestors/descendants), function calls (`author`, `description`,
    /// `heads`, `conflicts`, `file`, …), and workspace-relative `file()` path
    /// predicates — rather than a hand-rolled subset. Parse failures are
    /// lowered to a [`RevsetDiagnostic`] so the query surface never returns a
    /// raw jj-lib error.
    fn revset_expression(
        query: &str,
        workspace_root: &Path,
        workspace_name: &WorkspaceNameBuf,
        user_email: &str,
    ) -> Result<Arc<UserRevsetExpression>, RevsetDiagnostic> {
        let query = query.trim();
        if query.is_empty() {
            return Err(RevsetDiagnostic::EmptyQuery);
        }

        // The path converter resolves `file()` predicate arguments relative to
        // the agent workspace root; parsing is workspace-scoped so `@` and
        // `<workspace>@` resolve to the correct working copy.
        let path_converter = RepoPathUiConverter::Fs {
            cwd: workspace_root.to_path_buf(),
            base: workspace_root.to_path_buf(),
        };
        let workspace_ctx = RevsetWorkspaceContext {
            path_converter: &path_converter,
            workspace_name,
        };

        let aliases_map = RevsetAliasesMap::new();
        let fileset_aliases_map = FilesetAliasesMap::new();
        let extensions = RevsetExtensions::default();
        let context = RevsetParseContext {
            aliases_map: &aliases_map,
            local_variables: HashMap::new(),
            user_email,
            date_pattern_context: chrono::Local::now().into(),
            // Mirror the jj CLI default so `remote_bookmarks()` ignores the
            // colocated git remote by default.
            default_ignored_remote: Some("git".as_ref()),
            fileset_aliases_map: &fileset_aliases_map,
            use_glob_by_default: false,
            extensions: &extensions,
            workspace: Some(workspace_ctx),
        };

        let mut diagnostics = RevsetDiagnostics::new();
        jj_lib::revset::parse(&mut diagnostics, query, &context).map_err(|err| {
            RevsetDiagnostic::Invalid {
                message: err.to_string(),
            }
        })
    }
}

/// A TOML basic-string literal for `value`.
///
/// A git identity may legally contain a `"` or a `\` — git's ident grammar
/// forbids only `<`, `>`, newline and the ASCII control range — and splicing one
/// raw into a TOML document either fails to parse or, worse, parses as a
/// DIFFERENT identity than the host stated. Escaping is therefore not
/// defensive: it is what makes the layer say what git said.
fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod toml_string_tests {
    use super::toml_string;

    #[test]
    fn a_quote_or_backslash_in_a_name_is_escaped_not_spliced() {
        assert_eq!(toml_string(r#"A "Person""#), r#""A \"Person\"""#);
        assert_eq!(toml_string(r"back\slash"), r#""back\\slash""#);
        assert_eq!(toml_string("plain"), r#""plain""#);
    }

    #[test]
    fn the_escaped_layer_round_trips_to_the_original_identity() {
        let name = r#"A "Weird\Person"#;
        let layer = jj_lib::config::ConfigLayer::parse(
            jj_lib::config::ConfigSource::CommandArg,
            &format!("[user]\nname = {}\n", toml_string(name)),
        )
        .expect("the escaped layer parses");
        let settings = jj_lib::settings::UserSettings::from_config({
            let mut config = jj_lib::config::StackedConfig::with_defaults();
            config.add_layer(layer);
            config
        })
        .expect("settings");
        assert_eq!(settings.user_name(), name);
    }
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod apply_tests;
#[cfg(test)]
#[path = "../jj_tests.rs"]
mod tests;
