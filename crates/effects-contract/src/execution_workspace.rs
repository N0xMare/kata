//! Execution workspace provider boundary.
//!
//! This is the orchestration-facing workspace lifecycle API. It lives apart from
//! its implementation: `kata-vcs`'s `JjBackend` is its one production
//! implementation, so every method is required — there is no default a provider
//! could inherit a refusal from.

use std::path::PathBuf;

use kata_types::error::{KataError, KataResult};
use kata_types::execution::{
    CandidateTreePin, EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION, ExecutionWorkspaceIdentity,
};
use kata_types::primitives::ObjectId;
use kata_types::target::{ExecutionTarget, TargetSpec};
use kata_types::tree_artifact::{CommittedBaseGitView, CommittedBaseTree, WorkTreeInputBounds};
use smol_str::SmolStr;
use ulid::Ulid;

/// Stable key for a kata execution workspace.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExecutionWorkspaceKey {
    /// Owning execution id. The current runtime uses execution-scoped
    /// workspaces; jj-backed providers can also use invocation/stage metadata
    /// to represent finer-grained agent workspaces under the same execution.
    pub execution_id: Ulid,
    pub invocation_id: Option<Ulid>,
    pub stage_name: Option<SmolStr>,
}

impl ExecutionWorkspaceKey {
    /// Execution-scoped workspace key used by today's runtime.
    #[must_use]
    pub fn execution(execution_id: Ulid) -> Self {
        Self {
            execution_id,
            invocation_id: None,
            stage_name: None,
        }
    }

    #[must_use]
    pub fn invocation_id_string(&self) -> Option<String> {
        self.invocation_id.map(|id| id.to_string())
    }

    #[must_use]
    pub fn stage_name_string(&self) -> Option<String> {
        self.stage_name.as_ref().map(ToString::to_string)
    }
}

/// Backend implementation kind. Operator-facing metadata only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionWorkspaceBackend {
    Jj,
}

impl ExecutionWorkspaceBackend {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jj => "jj",
        }
    }
}

/// A live execution workspace handle returned by a provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionWorkspaceHandle {
    pub key: ExecutionWorkspaceKey,
    pub path: PathBuf,
    pub backend: ExecutionWorkspaceBackend,
}

/// Provider-neutral status for an execution workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionWorkspaceStatus {
    pub handle: ExecutionWorkspaceHandle,
    pub exists: bool,
    pub dirty: Option<bool>,
    pub changed_paths: Vec<SmolStr>,
    pub status_error: Option<String>,
    pub identity: Option<ExecutionWorkspaceIdentity>,
}

impl ExecutionWorkspaceStatus {
    #[must_use]
    pub fn changed_path_count(&self) -> usize {
        self.changed_paths.len()
    }
}

/// An execution workspace's RECORDED `{{ workspace.* }}`
/// answer. Computed through the shared repo view (`load_at_head` + the
/// workspace's recorded wc commit): no working-copy snapshot, no read of the
/// workspace dir's files, so foreign on-disk edits cannot leak into a
/// capsule's prompt. On a clean checkout the values are byte-identical to the
/// disk reader's — and under `oci` the recorded apply is the checkout's only
/// writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedWorkspaceStatus {
    /// The workspace root — retained ONLY so `{{ workspace.query("<revset>") }}`
    /// keeps opening this workspace (its workspace-relative `exec-…@`/`@`
    /// resolution); the recorded fields below never consulted its files.
    pub workspace_root: std::path::PathBuf,
    /// `{{ workspace.head }}`/`head_sha`: the commit a publishable effect would
    /// land (`target_commit_id` — the recorded `@` steps down past jj's
    /// content-free working-copy commit to the last real commit).
    pub head: String,
    /// `{{ workspace.tree_id }}`: the recorded `@`'s `MergedTree` id.
    pub tree_id: String,
}

/// How one path differs between two recorded commits' trees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordedChangeKind {
    /// Absent in the base tree, present in the head tree.
    Added,
    /// Present in both, with a different value (content, mode, or kind).
    Modified,
    /// Present in the base tree, absent in the head tree.
    Deleted,
}

/// One path of [`ExecutionWorkspaceProvider::recorded_commit_diff`]: a file
/// (or symlink) the head commit changes relative to the base commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedPathChange {
    /// Repository-relative path, `/`-separated.
    pub path: SmolStr,
    /// How the path changed.
    pub kind: RecordedChangeKind,
}

/// [`ExecutionWorkspaceProvider::recorded_commit_text_diff`]'s answer: a
/// git-format text diff, cut at a whole line before it would pass its bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedTextDiff {
    /// The diff text, at most the caller's byte bound.
    pub text: String,
    /// The diff did not fit the bound: `text` is a prefix of it, ending at a
    /// whole line.
    pub truncated: bool,
}

/// Durable reference created by parking a workspace without integrating it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParkedWorkspace {
    pub ref_name: String,
    pub commit_sha: String,
    pub identity: Option<ExecutionWorkspaceIdentity>,
}

/// Durable reference created by integrating a workspace into the trusted base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromotedWorkspace {
    pub ref_name: String,
    pub commit_sha: String,
    pub identity: Option<ExecutionWorkspaceIdentity>,
}

/// What [`ExecutionWorkspaceProvider::apply_work_delta`] committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedCandidate {
    /// The rewritten `@` commit id (hex) — the candidate commit that now holds
    /// the delta's tree.
    pub commit_id: String,
    /// The candidate's `MergedTree` id (hex), kata's `tree_id` convention.
    pub tree_id: String,
}

/// [`ExecutionWorkspaceProvider::classify_work_apply`]'s answer: the recovery rule's three
/// outcomes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkApplyState {
    /// No apply landed: the workspace's `@` is still the recorded head commit.
    NotApplied,
    /// The apply published: the `kata.effect` tag walked from the op head, or
    /// the current `@` lists the recorded head among its predecessors AND
    /// carries the delta's node on every changed path.
    Applied {
        /// The commit the workspace now names (hex).
        commit_id: String,
        /// Its `MergedTree` id (hex).
        tree_id: String,
    },
    /// The workspace moved in a way neither the apply nor "nothing happened"
    /// explains — the execution fails with explicit uncertainty; nothing is
    /// re-driven.
    Diverged {
        /// What was observed that neither classification accepts.
        reason: String,
    },
}

/// The `commit` op's durable answer: the finalized candidate commit and the
/// fresh empty `@` the head row advances to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedEffect {
    /// The `exec-<id>` bookmark the commit writes — the envelope's `ref_name`
    /// and the only thing keeping the finalized commit reachable after the
    /// workspace is eventually reaped.
    pub ref_name: String,
    /// The commit that HOLDS the candidate's content — the `@` at perform time
    /// (the head row's recorded candidate), now finalized; what the head row's
    /// `committed_commit_id` becomes, and what `promote`/`forge_export` deliver.
    pub commit_sha: String,
    /// The new working-copy commit `jj commit` leaves on top of the finalized
    /// one — what the head row's `candidate_commit_id` becomes.
    pub new_wc_commit_id: String,
}

/// [`ExecutionWorkspaceProvider::classify_workspace_effect`]'s answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkspaceEffectClass {
    /// Nothing the op would have written exists — perform it.
    NotPerformed,
    /// `commit` landed: the wc commit's parent is the recorded candidate.
    Committed {
        /// The finalized commit — the recorded candidate itself.
        commit_sha: String,
        /// The new `@` — the head row's candidate after resolution.
        new_wc_commit_id: String,
    },
    /// `park` landed: the parked ref resolves to the recorded candidate.
    Parked {
        /// The execution's parked ref name.
        ref_name: String,
        /// The commit it names.
        commit_sha: String,
    },
    /// `promote` landed: the trunk bookmark's head IS or CONTAINS the delivered
    /// commit (jj ancestry — the same fact `land_committed_candidate` answers
    /// `AlreadyLanded` from).
    Promoted {
        /// The trunk ref the candidate landed on.
        ref_name: String,
        /// The landed head — the candidate itself after a fast-forward, or the
        /// trunk head a re-landing would produce.
        commit_sha: String,
    },
    /// `promote`'s landing ran and PARKED the delivered commit's rebase for
    /// revalidation instead of landing it: `parked/<exec>` names the landing's
    /// own rebase (`classify_promote_effect` states the evidence), and the
    /// workspace is gone or still at the recorded candidate. The landing's
    /// answer is a refusal, so the attempt resolves `failed` with it after the
    /// workspace teardown the verb still owed.
    LandingParked {
        /// The refusal the verb returns for that park, byte-identical.
        reason: String,
    },
    /// Repository state neither "ran" nor "did not run" explains.
    Diverged {
        /// What was observed that no leg accepts.
        reason: String,
    },
}

#[must_use]
pub fn execution_workspace_identity(
    key: &ExecutionWorkspaceKey,
    backend: ExecutionWorkspaceBackend,
    workspace_ref: Option<String>,
    workspace_commit_sha: Option<String>,
    base_ref: Option<String>,
    base_commit_sha: Option<String>,
    target_ref: Option<String>,
    target_commit_sha: Option<String>,
) -> ExecutionWorkspaceIdentity {
    ExecutionWorkspaceIdentity {
        schema_version: EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION,
        execution_id: key.execution_id.to_string(),
        invocation_id: key.invocation_id_string(),
        stage_name: key.stage_name_string(),
        backend: backend.as_str().to_string(),
        workspace_ref,
        workspace_commit_sha,
        base_ref,
        base_commit_sha,
        target_ref,
        target_commit_sha,
        // The author RECEIPT is stamped by the act that made or published the
        // commit — `ExecutionWorkspaceIdentity::with_author`. It is deliberately
        // absent here: this function composes what can be READ BACK from the
        // repository, and a receipt read back from the repository is not a
        // receipt.
        author: None,
    }
}

/// The main's durable lifecycle verdict on an execution, used by the
/// terminal-workspace reaper to decide reap-eligibility for a leaked
/// `exec-<id>` workspace. The boot layer owns the lifecycle store and composes
/// this; the jj provider's reaper consumes it. The variants are ordered by
/// increasing reap-eagerness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionLiveness {
    /// Explicitly non-terminal lifecycle — a live or about-to-resume run.
    /// NEVER reaped, at any age.
    Live,
    /// Explicit terminal lifecycle. `terminal_since_ms` is its durable terminal
    /// timestamp, or `None` when an older record cannot supply one. Reaped once
    /// the workspace is older than the terminal TTL *and* the transition is
    /// older than the grace period.
    Terminal { terminal_since_ms: Option<u64> },
    /// Not known to the lifecycle store. This is not terminal proof, so the
    /// longer unknown TTL applies before a leaked workspace is reclaimed.
    Unknown,
}

/// The age/grace thresholds the terminal-workspace reaper enforces.
/// Composed once at boot from `runtime.workspace_ttl_secs` /
/// `runtime.ledger_ttl_secs`; passed through the provider trait to the reaper.
#[derive(Clone, Copy, Debug)]
pub struct TerminalWorkspaceReapPolicy {
    /// Minimum workspace age (dir mtime) before a TERMINAL execution's
    /// workspace is reaped — the operator's promote/inspect window.
    pub terminal_ttl: std::time::Duration,
    /// Minimum workspace age before an execution UNKNOWN to the ledger is
    /// reaped. Must be `>= terminal_ttl`; the caller sets it to
    /// `max(workspace_ttl, ledger_ttl)` so a terminal-then-compacted execution
    /// is never reaped before the ledger would still have vouched for it.
    pub unknown_ttl: std::time::Duration,
    /// Grace after a terminal transition before its workspace becomes
    /// reap-eligible, so the hourly sweep never races the normal promote/park
    /// teardown of a run that only just reached terminal.
    pub terminal_grace: std::time::Duration,
}

impl TerminalWorkspaceReapPolicy {
    /// The shortest reap window across every liveness verdict. Below it nothing
    /// is reapable regardless of classification, so a reaper uses this as the
    /// CHEAPEST-FIRST gate and skips the (durable-store-hitting) classifier for
    /// entries too young to reap under any verdict.
    #[must_use]
    pub fn min_ttl(&self) -> std::time::Duration {
        self.terminal_ttl.min(self.unknown_ttl)
    }

    /// THE reap decision, shared by every provider's reaper.
    ///
    /// It lives on the policy rather than in each reaper because the git and jj
    /// reapers walk different on-disk layouts but must answer the *same*
    /// question — and a second hand-written copy of a three-arm predicate whose
    /// wrong answer destroys an operator's work is exactly the drift kata has
    /// already paid for elsewhere. The FILESYSTEM contributes only `age`; the
    /// durable lifecycle verdict in `liveness` is the authority.
    ///
    /// * [`ExecutionLiveness::Live`] — NEVER reaped, at any age. A workspace
    ///   whose execution is in flight (or about to be replayed into by
    ///   recovery) is exactly what a resume needs; reaping it breaks resume.
    /// * [`ExecutionLiveness::Terminal`] — reaped once the workspace is older
    ///   than `terminal_ttl` AND the terminal transition is older than
    ///   `terminal_grace`, so a sweep never races the normal promote/park
    ///   teardown of a run that only just finished. A record with no transition
    ///   stamp falls back to the TTL gate alone.
    /// * [`ExecutionLiveness::Unknown`] — not terminal PROOF, so the longer
    ///   `unknown_ttl` applies before a leaked workspace is reclaimed.
    #[must_use]
    pub fn permits_reap(
        &self,
        liveness: ExecutionLiveness,
        age: std::time::Duration,
        now_ms: u64,
    ) -> bool {
        match liveness {
            ExecutionLiveness::Live => false,
            ExecutionLiveness::Terminal { terminal_since_ms } => {
                let grace_ms = u64::try_from(self.terminal_grace.as_millis()).unwrap_or(u64::MAX);
                let grace_ok =
                    terminal_since_ms.is_none_or(|since| now_ms.saturating_sub(since) >= grace_ms);
                age >= self.terminal_ttl && grace_ok
            }
            ExecutionLiveness::Unknown => age >= self.unknown_ttl,
        }
    }
}

/// The stable refusal token of the `oci` admission
/// repository census, emitted when the workspace's base tree or its git store
/// carries a feature the profile does not serve.
pub const OCI_UNSUPPORTED_REPOSITORY_FEATURES: &str = "oci_unsupported_repository_features";

/// A path still conflicted in the committed base tree a
/// `/work` input is published from. A conflicted tree has no single committed
/// content: the provider refuses to pick a side.
pub const WORK_TREE_BASE_CONFLICTED: &str = "work_tree_base_conflicted";

/// A `gitlink` (mode-160000 submodule pin) at any depth in
/// the committed base tree. The admission census refuses the same trees via
/// [`UnsupportedRepositoryFeature::GitSubmodule`]; this token is the
/// producer's own refusal, so the refused set does not depend on which check
/// ran first.
pub const WORK_TREE_BASE_GITLINK: &str = "work_tree_base_gitlink";

/// A committed base-tree entry no [`TreeManifest`] node can
/// carry: a path `TreePath` rejects, a symlink target `SymlinkTarget` rejects,
/// a workspace `@` without a single base parent, or a backend value kind the
/// manifest schema has no arm for.
///
/// [`TreeManifest`]: kata_types::tree_artifact::TreeManifest
pub const WORK_TREE_BASE_UNREPRESENTABLE: &str = "work_tree_base_unrepresentable";

/// The execution workspace's committed base is not the head the execution's
/// frozen target names — a workspace a crash left standing on another commit is
/// not this execution's input, so the `/work` head is never published from it.
pub const WORK_TREE_BASE_NOT_THE_TARGET: &str = "work_tree_base_not_the_target";

/// The store no longer holds the commit an execution's target froze: its pin
/// was removed and the commit collected. The run is refused rather than forked
/// from anything else.
pub const TARGET_HEAD_ABSENT: &str = "target_head_absent";

/// The namespace an execution's target pins live under:
/// `refs/kata/targets/<execution-id>/head` (the frozen head) and
/// `…/compare` (the compare base). Outside `refs/heads`, `refs/remotes` and
/// `refs/tags`, so neither jj's git import nor the trunk resolver ever reads
/// it.
pub const TARGET_PIN_PREFIX: &str = "refs/kata/targets/";

/// What the boot target-pin sweep ([`ExecutionWorkspaceProvider::sweep_target_pins`])
/// is told about an execution that holds pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetPinClaim {
    /// No admitted, live execution owns the pins: they are deleted, intact or torn.
    Unowned,
    /// An admitted, live execution owns them. With its recorded target, a pin a
    /// power loss TORE is re-derived from it; with `None` (the record could not
    /// be read) every pin is kept exactly as it stands.
    Owned(Option<Box<ExecutionTarget>>),
}

/// What one boot target-pin sweep did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetPinSweep {
    /// How many executions' pins were deleted: no live admission owns them.
    pub deleted: usize,
    /// Owned pins a power loss tore (a loose ref that does not parse, or one
    /// naming an object the store cannot read), rewritten at the commit the
    /// execution's recorded target names, by full ref name.
    pub rederived: Vec<String>,
    /// Owned torn pins whose recorded commit the store does not hold intact
    /// either, by full ref name: deleted, and the execution's next read of that
    /// commit refuses `target_head_absent` (workspace creation) by name.
    pub head_absent: Vec<String>,
}

/// The ONE time bound on resolving a `pr:<N>` target: the forge's two reads,
/// the ref checks and the fetch together, not each. A step that starts past
/// it is refused without running.
pub const PULL_REQUEST_RESOLUTION_BOUND: std::time::Duration = crate::FORGE_COMMAND_TIMEOUT;

/// One member of the committed base tree is over
/// [`kata_types::tree_artifact::MAX_MEMBER_BYTES`], the same per-member bound
/// the worker's materializer enforces when it reads the tree back.
pub const WORK_TREE_BASE_MEMBER_TOO_LARGE: &str = "work_tree_base_member_too_large";

/// The committed base tree is over the `[node]`-configured
/// `/work` INPUT ceiling (`work_tree_max_bytes` total member bytes or
/// `work_tree_max_entries` manifest entries). This is the INPUT bound; capsule
/// result budgets are a separate class and keep their own tokens.
pub const WORK_TREE_BASE_BOUND_EXCEEDED: &str = "work_tree_base_bound_exceeded";

/// The jj backend behind an execution workspace has no git object store —
/// the git-view history producer packs git objects, so a jj store
/// that is not git-backed has nothing the artifact could carry.
pub const GIT_VIEW_REQUIRES_GIT_BACKEND: &str = "git_view_requires_git_backend";

/// The committed base commit resolves to nothing — or to a non-commit — in
/// the workspace's git object store. A trunkless repository's empty-root base
/// is the jj root commit, which has no git object.
pub const GIT_VIEW_BASE_COMMIT_ABSENT: &str = "git_view_base_commit_absent";

/// The workspace's committed base is not the head the execution's target
/// froze — the view would show the agent a repository admission never saw.
pub const GIT_VIEW_BASE_NOT_THE_TARGET: &str = "git_view_base_not_the_target";

/// The git history artifact WITH the target's REVIEW RANGE (head → merge base,
/// and the compare base → merge base) is over `[git_view]
/// history_bytes_ceiling`, and the range reached commits the
/// `history_depth`-bounded walk did not. The range is shipped whatever
/// `history_depth` says, so the artifact is refused rather than truncated.
pub const GIT_VIEW_REVIEW_RANGE_OVER_CEILING: &str = "git_view_review_range_over_ceiling";

/// No inherited commit identity: the same set `create_workspace` refuses at
/// admission under its own message — `resolve_commit_identity` could not
/// produce a `user.name`/`user.email` from the repository's own git settings.
pub const GIT_VIEW_IDENTITY_UNAVAILABLE: &str = "git_view_identity_unavailable";

/// The history artifact's member bytes totaled more than the node's
/// `[git_view] history_bytes_ceiling` — refused, never truncated silently.
pub const GIT_VIEW_HISTORY_OVER_CEILING: &str = "git_view_history_over_ceiling";

/// One pack member exceeds
/// [`kata_types::tree_artifact::MAX_MEMBER_BYTES`] — the tree-member bound no
/// pack split can repair, because a pack IS the member.
pub const GIT_VIEW_MEMBER_TOO_LARGE: &str = "git_view_member_too_large";

/// One repository feature the `oci` admission census found and refuses
/// The census collects EVERY finding so the refusal
/// names the repository's whole refused set in one durable message.
///
/// jj materializes committed tree bytes verbatim: it cannot reproduce the
/// checkout-side semantics git applies for these features — a submodule's
/// populated tree, a declaration that makes git write different bytes than
/// the committed blob (a `filter=` clean/smudge hook — LFS's pointer
/// indirection — `ident`'s `$Id$` expansion, `working-tree-encoding`'s
/// charset conversion, `eol=crlf`'s CRLF endings), or a clone whose object
/// store is incomplete on purpose. That gap is refused at admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsupportedRepositoryFeature {
    /// The base tree carries a committed `.gitmodules` at its root — the
    /// repository declares submodules.
    GitmodulesFile,
    /// The base tree carries a mode-160000 gitlink at `path` — a live
    /// submodule pin whose checked-out content jj does not materialize.
    GitSubmodule {
        /// Repository-relative path of the gitlink entry.
        path: String,
    },
    /// The repository's own git config sets `core.attributesFile`, pointing
    /// attribute declarations at a path OUTSIDE the committed tree and
    /// outside `info/attributes` — a file this census cannot read. A bare or
    /// empty value means nothing is pointed at and produces no finding.
    GitAttributesConfig {
        /// The config key in its canonical spelling, `core.attributesFile`.
        key: String,
    },
    /// `source` (a committed `.gitattributes` path, or the repository's
    /// `info/attributes`) declares `pattern` a clean/smudge filter —
    /// `value` is the filter's name (`lfs` being the well-known case), or
    /// `None` when the declaration is the bare `filter` token git reports as
    /// `set`. The declaration may be direct or through an `[attr]` macro the
    /// rule sets.
    GitFilter {
        /// The attribute file the declaration was read from.
        source: String,
        /// The gitattributes pattern the filter applies to.
        pattern: String,
        /// The declared filter name; `None` for the bare `filter` form.
        value: Option<String>,
    },
    /// `source` (a committed `.gitattributes` path, or the repository's
    /// `info/attributes`) declares `pattern` an attribute that makes git
    /// write bytes the committed blob does not carry on this platform —
    /// `ident` (`$Id$` expansion), `working-tree-encoding` (a charset
    /// conversion) or `eol=crlf` (CRLF endings). The declaration may be
    /// direct or through an `[attr]` macro the rule sets.
    GitCheckoutConversion {
        /// The attribute file the declaration was read from.
        source: String,
        /// The gitattributes pattern the declaration applies to.
        pattern: String,
        /// The refused declaration verbatim — `ident`, `ident=<v>`,
        /// `working-tree-encoding`, `working-tree-encoding=<v>` or
        /// `eol=crlf` (in the file's own case).
        attribute: String,
    },
    /// The repository's own git config sets `key` so that git converts
    /// committed text bytes at checkout on this platform — `core.autocrlf`
    /// at git-true (bare included) or `core.eol` at `crlf`
    /// (case-insensitive). `autocrlf=input`, `autocrlf=false` and
    /// `eol=lf`/`native` write the blob's own bytes and are admitted.
    GitCheckoutConversionConfig {
        /// The config key in its canonical spelling — `core.autocrlf` or
        /// `core.eol`.
        key: String,
    },
    /// The git store carries a `shallow` boundary — the clone's history is
    /// truncated at it by design.
    ShallowClone,
    /// The repository's own git config sets `include.path` to a path the
    /// census cannot safely answer for: `~/` or absolute (a GLOBAL file —
    /// git would honor its conversion keys while the census reads only the
    /// repository's own config), `..`-escaping above the repository root, or
    /// present but unreadable (a read failure is a refusal, never a silent
    /// skip — the same rule `config` itself follows).
    GitConfigInclude {
        /// The include value verbatim, plus why it is outside the census's
        /// read set.
        path: String,
    },
    /// The repository's own git config carries `key` — the store is a
    /// partial clone whose missing objects are missing BY DESIGN (the
    /// `promisor`/`partialclonefilter` remote markers, or the
    /// `extensions.partialclone` extension record).
    PartialClone {
        /// The config key that proves the partial clone, in its canonical
        /// dotted spelling (the remote subsection keeps its verbatim case).
        key: String,
    },
}

impl std::fmt::Display for UnsupportedRepositoryFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitmodulesFile => write!(
                f,
                "the base tree carries a committed `.gitmodules` (declared submodules)"
            ),
            Self::GitSubmodule { path } => write!(
                f,
                "the base tree carries a submodule pin (gitlink) at `{path}`"
            ),
            Self::GitAttributesConfig { key } => write!(
                f,
                "the repository's git config sets `{key}` — attribute declarations outside \
                 the committed tree"
            ),
            Self::GitFilter {
                source,
                pattern,
                value,
            } => {
                let declared = match value {
                    Some(value) => format!("filter={value}"),
                    None => "filter (set)".to_string(),
                };
                write!(
                    f,
                    "`{source}` applies `{declared}` to `{pattern}` — a clean/smudge filter, \
                     the mechanism Git LFS rides"
                )
            }
            Self::GitCheckoutConversion {
                source,
                pattern,
                attribute,
            } => write!(
                f,
                "`{source}` applies `{attribute}` to `{pattern}` — a declaration that makes \
                 git write different bytes than the committed blob on checkout"
            ),
            Self::GitCheckoutConversionConfig { key } => write!(
                f,
                "the repository's git config sets `{key}` — committed text bytes are \
                 converted at checkout"
            ),
            Self::ShallowClone => write!(
                f,
                "the repository is a SHALLOW clone (`$GIT_DIR/shallow` exists)"
            ),
            Self::GitConfigInclude { path } => write!(
                f,
                "the repository's git config `include.path`s `{path}` — outside the \
                 repository's own files, or unreadable; the census answers for neither"
            ),
            Self::PartialClone { key } => write!(
                f,
                "the repository's git config carries `{key}` — a partial clone"
            ),
        }
    }
}

/// The census refusal itself: every finding joined into one durable message
/// behind [`OCI_UNSUPPORTED_REPOSITORY_FEATURES`].
pub fn oci_unsupported_features_refusal(features: &[UnsupportedRepositoryFeature]) -> KataError {
    debug_assert!(
        !features.is_empty(),
        "a census refusal is only ever built from a non-empty finding set"
    );
    KataError::Validation(format!(
        "{OCI_UNSUPPORTED_REPOSITORY_FEATURES}: every stage runs in a rootless OCI container over \
         the workspace's committed tree, and the admission census of the execution workspace found \
         repository features that route does not serve: {}. jj materializes committed tree bytes verbatim, so a capsule cannot \
         reproduce the checkout-side semantics these features declare, and a clone missing objects \
         on purpose cannot prove what the workspace carries. Lift the feature out of the repository",
        features
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    ))
}

/// Orchestrator-facing execution workspace lifecycle.
///
/// ## Durable on return
///
/// A method that WRITES the repository answers only once what it wrote is on
/// stable storage — the target pins, a workspace's commits and checkout, an
/// applied delta, a stale checkout's repair, a workspace effect's commit and
/// ref, a park, a landing, a forge export's local branch, a teardown, and the
/// pins' release and boot sweep (a deletion can rewrite the repository-wide
/// `packed-refs`, which every packed ref lives in) — so the caller's durable
/// transition never outlives a repository write a power loss could take back.
/// The jj provider holds this with a `syncfs` barrier over the repository's
/// filesystems (`kata_vcs::jj` `durability`), and refuses
/// `repository_not_durable` when one fails. Excepted, stated: a terminal
/// workspace's removal ([`Self::remove_workspace`]) and reap — one a power loss
/// takes back leaves a workspace of a terminal run, which the next boot's reap
/// reclaims — and [`Self::push_workspace_effect_ref_expecting`], whose durable
/// half is the remote's.
pub trait ExecutionWorkspaceProvider: Send + Sync {
    fn backend(&self) -> ExecutionWorkspaceBackend;

    /// Whether [`Self::promote_workspace`] settles dirty disk state into a
    /// commit before integrating the workspace.
    ///
    /// This is a DECLARATION consumed by the operator apply-gate
    /// (`require_promotable_workspace_for_promotion`) and by the
    /// workspace-promotion projection an operator reads. It is NOT a refusal,
    /// and the in-graph route does not consult it: the promotion gate that route
    /// now runs (`WorkflowRunner::authorize_promote_dispatch`) asks about the
    /// declared criteria and the candidate binding, deliberately NOT about
    /// dirtiness — the in-graph promote settles the working copy on its way to
    /// the land, so "clean" is not a precondition it could sensibly have. A
    /// provider returning `false` therefore MUST make the dirty case a typed
    /// failure inside its own `promote_workspace`. The jj provider declared
    /// `false`, refused nothing, and silently landed an empty commit; it now
    /// settles and returns `true`, which makes the operator route's dirty arm
    /// vacuous for it.
    #[must_use]
    fn promotion_snapshots_dirty(&self) -> bool;

    /// Resolve `spec` for `execution_id` and PIN what it resolved: the frozen
    /// head (and the compare base, when there is one) under
    /// [`TARGET_PIN_PREFIX`], so a trunk that moves — even one force-moved and
    /// collected — cannot lose the commit before the workspace exists.
    ///
    /// Runs before acceptance and outside the executor's admission permit, and
    /// answers only once the pins are durable, so an admission that commits
    /// after it never outlives them; a pin with no admission behind it is
    /// collected by [`Self::sweep_target_pins`] at boot. Only the provider reads the
    /// repository, so only the provider resolves. A `pr:<N>` target reads the
    /// pull request through `forge` and fetches its head and base straight
    /// into the pins, all within [`PULL_REQUEST_RESOLUTION_BOUND`].
    ///
    /// # Errors
    ///
    /// The trunk resolver's refusals, a trunk bookmark absent or conflicted,
    /// `target_requires_git_backend` for a commit to pin in a store with no
    /// git object store behind it, the pull-request refusals
    /// (`target_forge_unavailable` — `forge` `None` included —,
    /// `target_pr_not_found`, `target_pr_ref_invalid`, `target_pr_url_invalid`,
    /// `target_pr_remote_unresolved`, `target_pr_fetch_failed`,
    /// `target_pr_head_raced`, `target_pr_no_merge_base`), and the pin writes'
    /// I/O failures.
    fn resolve_target(
        &self,
        execution_id: Ulid,
        spec: &TargetSpec,
        forge: Option<&dyn crate::Forge>,
    ) -> KataResult<ExecutionTarget>;

    /// Delete `execution_id`'s target pins, intact or torn. Idempotent: absent
    /// pins are not an error, and a store with no git object store behind it
    /// holds none. Run by the execution's terminal cleanup obligation.
    fn release_target_pins(&self, execution_id: Ulid) -> KataResult<()>;

    /// The boot sweep over every execution holding a pin, intact or torn, as
    /// `claim` answers for it ([`TargetPinClaim`]): an unowned execution's pins
    /// are deleted; an owned one's pins are kept, except that a pin a power
    /// loss tore is rewritten at the recorded target's commit when the store
    /// holds it intact, and deleted (`head_absent`) when it does not. Exactly a
    /// TORN pin is re-derived — a loose ref that does not parse, or one naming
    /// an object the store cannot read; an intact pin is never rewritten, and
    /// an owned execution with no pin left at all is not enumerated. Run at
    /// boot before any submission can exist, so it never races a live
    /// resolution.
    fn sweep_target_pins(
        &self,
        claim: &dyn Fn(Ulid) -> TargetPinClaim,
    ) -> KataResult<TargetPinSweep>;

    /// Create the execution workspace FORKED FROM `target.head` — the commit
    /// admission froze, or the empty root for an unborn trunk — never from a
    /// ref resolved now. Recovery passes the stored target, so a re-creation
    /// forks the same commit.
    fn create_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        target: &ExecutionTarget,
    ) -> KataResult<ExecutionWorkspaceHandle>;

    /// The admission repository census, invoked by the
    /// executor immediately after [`Self::create_workspace`] for every
    /// `worktree_isolated` program (a non-isolated program has no workspace to
    /// census). `Ok` admits; `Err` refuses the submission before a
    /// stage dispatches or a token is spent, naming the repository's WHOLE
    /// refused feature set in one message.
    ///
    /// The refused set is exactly: committed `.gitmodules` at the base tree's
    /// root or any gitlink in it (submodules); a committed `.gitattributes`
    /// anywhere in the base tree, the repository's `info/attributes`,
    /// `core.attributesFile`, or a `[filter "<name>"]` section in the
    /// repository's own config — the declaration surfaces Git LFS and every
    /// other clean/smudge filter rides, itemized by each `filter=`
    /// declaration they carry; a `shallow` marker in the git store (shallow
    /// clones); and the repository config's `extensions.partialclone` /
    /// `remote.*.promisor` / `remote.*.partialclonefilter` keys (partial
    /// clones). Nothing else.
    fn refuse_unsupported_repository_features(
        &self,
        handle: &ExecutionWorkspaceHandle,
    ) -> KataResult<()>;

    /// Convert the execution workspace's COMMITTED BASE
    /// tree (the parent of the working-copy commit, not the mutable checkout)
    /// into a [`CommittedBaseTree`]: a [`kata_types::tree_artifact::TreeManifest`]
    /// plus every member's bytes streamed to `put_member`.
    ///
    /// The executor calls this at admission, immediately after
    /// [`Self::refuse_unsupported_repository_features`], for `worktree_isolated`
    /// executions only, and publishes the result as the execution's recorded
    /// `/work` head. The walk reads COMMITTED state exclusively — an
    /// uncommitted operator edit in the checkout never reaches the callback.
    ///
    /// `put_member` is invoked once per file member with the member's full
    /// bytes (each already bounded by
    /// [`kata_types::tree_artifact::MAX_MEMBER_BYTES`]); the caller streams
    /// them into CAS. The conversion refuses by name:
    /// [`WORK_TREE_BASE_CONFLICTED`], [`WORK_TREE_BASE_GITLINK`],
    /// [`WORK_TREE_BASE_UNREPRESENTABLE`], [`WORK_TREE_BASE_MEMBER_TOO_LARGE`],
    /// and [`WORK_TREE_BASE_BOUND_EXCEEDED`] against `bounds` — the refused
    /// set is documented per token on the constants.
    fn committed_base_tree(
        &self,
        handle: &ExecutionWorkspaceHandle,
        bounds: WorkTreeInputBounds,
        put_member: &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
    ) -> KataResult<CommittedBaseTree>;

    /// The committed base's git HISTORY the execution's
    /// `/git-history` artifact is published from: the objects reachable from
    /// the base commit within `history_depth`, packed, plus the target's
    /// REVIEW RANGE whatever the depth (head → merge base, and the compare
    /// base → merge base), the base-tree index, and a `shallow` member when the
    /// walk was truncated. The view's branch ref is the target's (trunk's name
    /// at the head, a PR's base branch at its compare base). `history_depth` /
    /// `history_bytes_ceiling` are the node's `[git_view]` knobs the executor
    /// already validated.
    fn committed_base_git_history(
        &self,
        handle: &ExecutionWorkspaceHandle,
        target: &ExecutionTarget,
        history_depth: Option<u32>,
        history_bytes_ceiling: u64,
        put_member: &mut dyn FnMut(&[u8]) -> KataResult<ObjectId>,
    ) -> KataResult<CommittedBaseGitView>;

    /// The execution's LIVE workspace, or `None`. Live means the repository
    /// still registers it, not only that its directory stands: the leftover of
    /// a teardown a crash interrupted is `None`, though its directory may
    /// stand until the recovery that answers the `park`/`promote` removes it
    /// ([`Self::teardown_workspace_effect`]). Answering reads the repository's
    /// view whenever the directory's `.jj` stands (one load of the repository
    /// at its head), so a repository that cannot be loaded is an error here,
    /// never `None` and never a workspace.
    fn lookup_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<ExecutionWorkspaceHandle>>;

    fn workspace_status(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<ExecutionWorkspaceStatus>>;

    fn remove_workspace(&self, key: &ExecutionWorkspaceKey) -> KataResult<()>;

    /// Reclaim the on-disk workspaces of definitively-not-live
    /// executions. This is the boot backstop against unbounded worktree/dir +
    /// ref accumulation on a long-running node.
    ///
    /// `classify` is the lifecycle verdict the provider cannot supply itself
    /// (it holds no lifecycle-store handle). It yields one of three states per execution
    /// (see [`ExecutionLiveness`]):
    /// * `Live` — a non-terminal (in-flight / about-to-resume) run: NEVER
    ///   reaped, at any age.
    /// * `Terminal` — explicit terminal lifecycle: reaped once its workspace is
    ///   older than `policy.terminal_ttl` AND its terminal transition is older
    ///   than `policy.terminal_grace` (so the sweep cannot race the normal
    ///   promote/park teardown window).
    /// * `Unknown` — no lifecycle record: reaped only once its workspace is
    ///   older than the longer `policy.unknown_ttl`.
    ///
    /// ## What a reaper reclaims, and what it must NOT
    ///
    /// It reclaims the leaked **on-disk workspace** and whatever per-workspace
    /// registration the backend holds for it. It reclaims **no ref**. The three
    /// kata-owned ref namespaces each outlive their workspace ON PURPOSE and
    /// each would be a data-loss defect to sweep:
    ///
    /// * `kata_vcs::trunk::PARKED_REF_PREFIX` — a park is *deliberately
    ///   preserved* work; it is the mechanism by which a failed revalidation
    ///   does not lose the agent's changes. `park_workspace` already removes the
    ///   workspace, so a parked candidate leaves nothing on disk to reap; its
    ///   ref is the operator's to retire, never a sweep's.
    /// * `kata_vcs::trunk::EXECUTION_REF_PREFIX` — `exec-<id>` exists precisely
    ///   to keep a `commit`-effect's published commit durably reachable AFTER
    ///   the non-terminal workspace is gone. The ref and the workspace have
    ///   different lifetimes by design; deleting the ref while reclaiming the
    ///   workspace would make the commit unreachable and collectable.
    /// * `kata_vcs::trunk::FORGE_BRANCH_PREFIX` — `kata/<id>` has been PUSHED to
    ///   a remote. Deleting the local half desynchronises a published artifact.
    ///
    /// The jj provider reaps `<repo>/agents/<exec-id>`; it is the only reclaim of
    /// that directory, so `boot::reap_terminal_workspaces_once` (at startup and
    /// hourly) depends on it.
    fn reap_terminal_workspaces(
        &self,
        policy: TerminalWorkspaceReapPolicy,
        classify: &dyn Fn(Ulid) -> ExecutionLiveness,
    ) -> KataResult<usize>;

    /// TERMINAL: integrate the execution's candidate onto the trusted base ref
    /// and then REMOVE the workspace.
    ///
    /// ## Required contract
    ///
    /// **Terminal on every success path.** A caller records
    /// [`kata_types::workflow::WorkspaceEffectOp::Promote`] as terminal, and the
    /// workflow validator refuses `depends_on` edges into the stage on that
    /// classification alone. An `Ok(_)` that leaves the workspace standing makes
    /// a load-time refusal assert a teardown that did not happen. Every arm that
    /// returns `Ok` — including a no-op integration — tears the workspace down.
    ///
    /// **Idempotent while the workspace exists.** Re-driving after the base ref
    /// already advanced to this execution's candidate (a crash between the
    /// landing and the teardown) MUST converge: integrate nothing, remove the
    /// workspace, return the same `ref_name`/`commit_sha`. The jj provider
    /// satisfies this structurally — its landing ladder answers
    /// `LandingKind::AlreadyLanded` when the base already contains the
    /// candidate — so the
    /// `workspace_effect` stage calls this unconditionally rather than probing
    /// [`Self::lookup_promoted_workspace`] and skipping. Once the workspace has
    /// been removed a re-drive fails typed (`NotFound`); that window is the
    /// executor apply-gate's, not this method's.
    ///
    /// **A candidate that contributes nothing still succeeds, and still tears
    /// down.** An execution whose agent produced no work resolves to the base
    /// commit; integrating it is a genuine no-op. That is not an error — the
    /// caller distinguishes it in its recorded envelope (`"ref_moved": false`),
    /// because the honest statement is about the repository, not about who put
    /// the base where it is.
    ///
    /// ## `pin` — what validation judged is what lands
    ///
    /// `pin` carries the tree identity a recorded validation criterion bound to
    /// this candidate. An implementation MUST call
    /// [`CandidateTreePin::require_tree`] with the tree of the SETTLED candidate
    /// — after the snapshot that produces the commit it is about to publish,
    /// and BEFORE both the landing and the teardown, so a refusal leaves trunk
    /// untouched and the agent's work on disk. That is the last point at which
    /// the comparison is meaningful: earlier, disk state can still move; later,
    /// the tree has already landed.
    ///
    /// [`CandidateTreePin::Unpinned`] admits everything — see its doc: "a
    /// promote must have validation criteria" is a different question from "the
    /// tree that lands is the tree that was judged", and it is asked by the
    /// promotion gate above this call on both routes, each of which refuses
    /// `Unpinned` itself. This fence stays permissive about it so that its
    /// refused set remains exactly the identity one.
    ///
    /// ## `landing_branch` — the trunk the execution froze
    ///
    /// The execution's frozen target's landable branch, when it has one. The
    /// trunk the landing ladder resolves under its lock must carry that name, or
    /// the promote refuses `target_trunk_renamed` before anything moves — the
    /// same check the `oci` `promote` effect runs. `None` asks for no check.
    /// A trunk a writer outside kata moves in the provider's view between the
    /// ladder's read and its fast-forward refuses `target_trunk_raced`, with
    /// nothing moved, on both routes.
    fn promote_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        pin: &CandidateTreePin,
        landing_branch: Option<&str>,
    ) -> KataResult<PromotedWorkspace>;

    /// Park the live execution workspace: settle its candidate (the one
    /// snapshot point), write `parked/<label>` (`parked/<execution-id>` with
    /// no label) at the settled commit, then tear the workspace down. A ref
    /// already naming another commit refuses `parked_ref_occupied` before
    /// the ref is written or the workspace removed: a park never overwrites a
    /// commit it did not write. A ref already at the settled commit is
    /// adopted, and the park completes.
    ///
    /// # Errors
    ///
    /// `Internal` when `key` has no live workspace, `parked_ref_occupied`,
    /// the publishable-author refusal, and the jj publish's own refusals.
    fn park_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        label: Option<&str>,
    ) -> KataResult<ParkedWorkspace>;

    /// The canonical durable ref/bookmark name [`Self::park_workspace`] would
    /// create for `(key, label)`.
    ///
    /// Exposed so a caller can compute the parked ref WITHOUT mutating, then
    /// [`Self::lookup_parked_workspace`] it to reconcile an already-applied
    /// park. The crash-safe `workspace_effect` backend uses this to return the
    /// recorded envelope on re-dispatch instead of re-parking a torn-down
    /// (already-parked) workspace and failing `NotFound`. Implementations MUST
    /// keep this in lockstep with the ref `park_workspace` actually creates.
    fn parked_ref_name(&self, key: &ExecutionWorkspaceKey, label: Option<&str>) -> String;

    /// Observe a previously-created parked ref/bookmark without requiring the
    /// live execution workspace to still exist.
    fn lookup_parked_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        ref_name: &str,
    ) -> KataResult<Option<ParkedWorkspace>>;

    /// Observe whether a promotion has DURABLY LANDED: the trusted base
    /// ref/bookmark `base_ref` has advanced to `candidate_commit_sha` (the
    /// workspace HEAD that [`Self::promote_workspace`] fast-forwards the base
    /// onto). Returns the resulting [`PromotedWorkspace`] when the base ref is
    /// observably at the candidate commit, else `None`.
    ///
    /// Mirrors [`Self::lookup_parked_workspace`]: a PURE observation with NO
    /// side effects. It exists so a caller holding an execution whose workspace
    /// is already GONE can tell "already landed" from "never ran" without
    /// re-driving — [`Self::promote_workspace`] fails typed once the workspace
    /// has been removed. That is the executor apply-gate's resume path.
    ///
    /// **This is a WEAK signal and callers must not read more into it than it
    /// says.** It reports only that `base_ref` currently resolves to
    /// `candidate_commit_sha`. That is NOT proof this execution landed anything:
    /// an execution that produced no work resolves to the base commit it forked
    /// from, and the base ref trivially "already holds" it — the predicate is
    /// TRUE and nothing was ever promoted. "The candidate sha is unique to this
    /// execution's work" is false for exactly that input; a `workspace_effect`
    /// promote stage that believed it would skip the mutation and record a
    /// landing that never happened while leaking the worktree. A caller that
    /// needs "this execution landed something" must also establish that the
    /// candidate is not simply the base.
    fn lookup_promoted_workspace(
        &self,
        key: &ExecutionWorkspaceKey,
        base_ref: &str,
        candidate_commit_sha: &str,
    ) -> KataResult<Option<PromotedWorkspace>>;

    /// Apply a recorded [`kata_types::tree_delta::TreeDelta`]
    /// to the execution workspace's candidate commit, in one jj transaction
    /// tagged `kata.effect`, then check the result out so the on-disk working
    /// copy is never left stale. `expected_wc_commit` is the head row's
    /// recorded commit id — a candidate that has moved since is refused
    /// `work_apply_candidate_diverged`, never silently re-based.
    fn apply_work_delta(
        &self,
        handle: &ExecutionWorkspaceHandle,
        expected_wc_commit: &str,
        delta: &kata_types::tree_delta::TreeDelta,
        members: &dyn Fn(kata_types::primitives::ObjectId, u64) -> KataResult<Vec<u8>>,
        effect_tag: &str,
    ) -> KataResult<AppliedCandidate>;

    /// Whether the `effect_tag` apply already landed on
    /// `handle`'s workspace — the recovery question after a crash around the
    /// apply's publish. See [`WorkApplyState`]. `since_ms` bounds
    /// the op-log walk at ops older than the effect's issue time.
    fn classify_work_apply(
        &self,
        handle: &ExecutionWorkspaceHandle,
        recorded_head_commit: &str,
        effect_tag: &str,
        delta: &kata_types::tree_delta::TreeDelta,
        since_ms: i64,
    ) -> KataResult<WorkApplyState>;

    /// Converge a workspace left stale by a crash between
    /// the apply's jj publish and its checkout — jj's update-stale, a no-op on
    /// a fresh working copy.
    fn repair_stale_checkout(&self, handle: &ExecutionWorkspaceHandle) -> KataResult<()>;

    /// The `oci` `commit` workspace-effect —
    /// finalize the recorded candidate (the `jj commit` shape: `@` rewritten
    /// with the op's description, a fresh empty `@` on top) and write the
    /// `exec-<id>` bookmark. `expected_wc_commit` is the head row's recorded
    /// candidate the verb fences on; `effect_tag` is the attempt id carried on
    /// every jj transaction (`kata.effect`).
    fn commit_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
        effect_tag: &str,
    ) -> KataResult<CommittedEffect>;

    /// The `oci` `park` workspace-effect — the
    /// `parked/<exec>` ref on `delivered_commit` + teardown, tagged.
    /// `expected_wc_commit` is the fence: `@` must still be the recorded
    /// candidate. The authored `label` is metadata on the spec, NEVER the ref
    /// name: the ref is execution-scoped (`parked/<exec-id>`) so recovery names
    /// it unambiguously and two executions cannot collide on one label.
    fn park_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
    ) -> KataResult<ParkedWorkspace>;

    /// The `oci` `promote` workspace-effect —
    /// pin fence + merge-queue land of `delivered_commit` + teardown, tagged.
    /// `expected_wc_commit` stays the fence: `@` must still be the recorded
    /// candidate. `landing_branch` is the execution's frozen target's landable
    /// branch: the trunk the ladder resolves under its lock must be that name,
    /// or the promote refuses `target_trunk_renamed` with trunk untouched.
    fn promote_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        pin: &kata_types::execution::CandidateTreePin,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
        landing_branch: Option<&str>,
    ) -> KataResult<PromotedWorkspace>;

    /// The commit an `op` claimed against `candidate_commit` delivers — the
    /// claim's whole rule, so the runner and every cell ask this one door. A
    /// `commit` acts on the candidate itself. A `park`, `promote` or
    /// `forge_export` delivers `committed_commit` (the head row's
    /// `committed_commit_id`) when the candidate is its EMPTY child — sole
    /// parent `committed_commit`, same tree — which is exactly the `@` a
    /// `commit` effect leaves; otherwise the candidate itself (no commit ran —
    /// `committed_commit` is `''` — or the candidate changed after the
    /// commit). Both ids are immutable commits in the store, so the answer is
    /// a function of the op and the two ids.
    ///
    /// # Errors
    ///
    /// `Internal` when an id is not valid hex or names no commit in the store.
    fn workspace_effect_delivered_commit(
        &self,
        op: kata_types::workflow::WorkspaceEffectOp,
        candidate_commit: &str,
        committed_commit: &str,
    ) -> KataResult<String>;

    /// The shared precondition — `key`'s workspace
    /// status proves `@` is the recorded candidate AND the working copy is
    /// clean; refuses `oci_candidate_diverged` / `oci_candidate_disk_diverged`
    /// otherwise. Returns the status so the caller does not re-read it.
    fn require_clean_recorded_candidate(
        &self,
        key: &ExecutionWorkspaceKey,
        expected_wc_commit: &str,
    ) -> KataResult<ExecutionWorkspaceStatus>;

    /// The recovery question for a pending
    /// `workspace_effect` attempt — did its mutation land? `handle` is the
    /// execution workspace when still live (`None` after a terminal op's
    /// teardown). `forge_export` is classified by the caller from the
    /// remote's head ([`Self::forge_remote_head`]), not here.
    ///
    /// `landing_branch` is the execution's frozen landable branch, the same
    /// value [`Self::promote_workspace_effect`] is passed: a `promote` is
    /// judged landed or not on THAT branch, never on the trunk the repository
    /// resolves at recovery, so the perform and its reconcile judge one branch.
    fn classify_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        handle: Option<&ExecutionWorkspaceHandle>,
        op: kata_types::workflow::WorkspaceEffectOp,
        recorded_candidate: &str,
        delivered_commit: &str,
        landing_branch: Option<&str>,
    ) -> KataResult<WorkspaceEffectClass>;

    /// Ensure the execution-scoped ref names
    /// `commit_sha` — the `commit` verb's second publish, re-run by the sweep
    /// leg when a crash split the finalize from the bookmark. Idempotent.
    fn ensure_workspace_ref(
        &self,
        key: &ExecutionWorkspaceKey,
        ref_name: &str,
        commit_sha: &str,
        effect_tag: &str,
    ) -> KataResult<()>;

    /// Tear the execution workspace down with
    /// `kata.effect` on the working-copy-removal transaction — a recovery
    /// leg's completion of a `park`/`promote` whose ref landed but whose
    /// teardown did not, or did only in part. Idempotent step by step: the
    /// working-copy commit's removal runs only while the view names it, the
    /// workspace store's `forget` of an absent name changes nothing, and the
    /// directory is removed only while it stands — so a teardown a crash
    /// interrupted anywhere finishes, and one that completed changes nothing.
    fn teardown_workspace_effect(
        &self,
        key: &ExecutionWorkspaceKey,
        effect_tag: &str,
    ) -> KataResult<()>;

    /// Write `branch` → `delivered_commit` in the colocated root,
    /// `kata.effect`-tagged — a `forge_export`'s idempotent local half, written
    /// by a drive that issues the push, before the read that leases it (a drive
    /// that resumes at an observer or at the pull request writes nothing
    /// here). It refuses first a live workspace whose disk is dirty or whose
    /// `@` is not `expected_wc_commit`, a conflicted `delivered_commit`, and
    /// one whose identity kata will not publish — each a typed `Validation`,
    /// with nothing written.
    fn write_workspace_effect_forge_ref(
        &self,
        key: &ExecutionWorkspaceKey,
        branch: &str,
        expected_wc_commit: &str,
        delivered_commit: &str,
        effect_tag: &str,
    ) -> KataResult<()>;

    /// Push `commit` — the one the push's intent recorded, resolved by object
    /// id and never read off a local ref, `branch` or one spelled as `commit`,
    /// nor through a local replace ref or graft — to `branch` on `remote`,
    /// with the objects it reaches and nothing else (no tag, no submodule), under the lease `expected_remote` names:
    /// the head the read before the push's intent found (`None`: the branch
    /// must not exist on the remote). Any other head refuses the push.
    fn push_workspace_effect_ref_expecting(
        &self,
        remote: &str,
        branch: &str,
        commit: &str,
        expected_remote: Option<&str>,
    ) -> KataResult<()>;

    /// The `oci` terminal-closeout park: pin the parked ref to
    /// the RECORDED candidate the head row names. `expected_wc_commit` is the
    /// head's `candidate_commit_id`; the precondition
    /// [`Self::require_clean_recorded_candidate`] refuses
    /// `oci_candidate_diverged`/`oci_candidate_disk_diverged`, so a workspace
    /// whose `@` moved or whose disk holds foreign edits parks NOTHING rather
    /// than publishing unrecorded content; the workspace is left standing.
    /// The ref names the SETTLED candidate: a content-free `@` steps down to
    /// its parent (`settle_candidate`). A ref already naming another commit is
    /// not this park's write (a landing's revalidation park, an outside write):
    /// the park refuses `parked_ref_occupied` and changes nothing. A ref
    /// already AT the settled candidate is adopted and the park completes —
    /// the check is commit equality, so it covers this park's own earlier
    /// write whose teardown never ran and any other write of that same commit
    /// (a conflict park leaves the delivered commit itself at the ref).
    ///
    /// No `kata.effect` tag: closeout is not an effect attempt.
    ///
    /// # Errors
    ///
    /// `Internal` when `key` has no live workspace to park, the precondition's
    /// refused set, `parked_ref_occupied`, and the ref-write/checkout
    /// refusals of the jj publish.
    fn park_workspace_recorded(
        &self,
        key: &ExecutionWorkspaceKey,
        label: Option<&str>,
        expected_wc_commit: &str,
    ) -> KataResult<ParkedWorkspace>;

    /// The `oci` route's `{{ workspace.* }}` namespace:
    /// the execution workspace's RECORDED head, read through the shared repo
    /// view rather than the working copy. `None` when `key` has no workspace
    /// (torn down or never created), and the namespace then stays undefined.
    ///
    /// # Errors
    ///
    /// The store's own read refusal.
    fn recorded_workspace_status(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<RecordedWorkspaceStatus>>;

    /// The paths `head_commit`'s tree changes relative to `base_commit`'s, in
    /// path order — the `{{ workspace.changed_files }}` / `{{ workspace.diff }}`
    /// answer, with `base_commit` the execution's recorded base (its head row)
    /// and `head_commit` the [`RecordedWorkspaceStatus::head`]. Both are
    /// commits in the repository store, so the answer is a function of the two
    /// ids: no working copy, no workspace file, no ref is read.
    ///
    /// # Errors
    ///
    /// `Internal` when either id is not valid hex or names no commit in the
    /// store, and the store's own read refusal — among them a directory that
    /// differs between the two trees (the root does whenever anything changed)
    /// holding an entry name that is not UTF-8, which jj-lib will not read.
    fn recorded_commit_diff(
        &self,
        base_commit: &str,
        head_commit: &str,
    ) -> KataResult<Vec<RecordedPathChange>>;

    /// The git-format text diff from `base_commit`'s tree to `head_commit`'s,
    /// at most `max_bytes` long — the `{{ target.diff }}` answer, `base_commit`
    /// the target's frozen merge base and `head_commit` its frozen head. Like
    /// [`Self::recorded_commit_diff`], a function of the two ids. The text ends
    /// at a whole line, and once the next line would pass `max_bytes` no later
    /// file is read and the answer is marked truncated.
    ///
    /// # Errors
    ///
    /// `Internal` when either id is not valid hex or names no commit in the
    /// store, and the store's own read refusal — among them a directory that
    /// differs between the two trees (the root does whenever anything changed)
    /// holding an entry name that is not UTF-8, which jj-lib will not read.
    fn recorded_commit_text_diff(
        &self,
        base_commit: &str,
        head_commit: &str,
        max_bytes: usize,
    ) -> KataResult<RecordedTextDiff>;

    /// The workspace's `@` commit id — the
    /// recorded candidate the verbs fence on — `None` when the workspace is
    /// gone.
    fn workspace_effect_candidate_commit(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<String>>;

    /// The tree of a commit in the repository — the
    /// LANDED candidate's tree, which `forge_export`'s claim must bind when
    /// the execution workspace is already gone (`promote` tore it down). A
    /// commit the store does not hold is a rig inconsistency, refused typed
    /// rather than reported absent.
    fn commit_tree_id(&self, commit_sha: &str) -> KataResult<String>;

    /// The workspace's `@` jj tree id — the
    /// approval gate's `candidate_tree_id` binding and the promote pin's
    /// measured value — read without mutating, or `None` when the execution
    /// workspace is gone.
    fn workspace_effect_candidate_tree(
        &self,
        key: &ExecutionWorkspaceKey,
    ) -> KataResult<Option<String>>;

    /// The git remote a `forge_export` into `branch` — the execution's frozen
    /// landable branch — pushes to: git's push remote for it
    /// (`branch.<branch>.pushRemote`, else `remote.pushDefault`, else
    /// `branch.<branch>.remote`) when it names a configured remote, else the
    /// repository's only remote. Asked once, before
    /// the export is claimed; the claim records the answer.
    ///
    /// # Errors
    ///
    /// `forge_remote_unresolved` (`Validation`) when the repository names no
    /// single remote: kata never guesses one.
    fn forge_export_remote(&self, branch: &str) -> KataResult<String>;

    /// The forge repository the git remote `remote` names, as
    /// `HOST/OWNER/REPO` (case-folded): read off the remote's configured push
    /// URL (`remote.<remote>.pushurl`, else `remote.<remote>.url`) BEFORE any
    /// `url.*.insteadOf` rewrite, the same reading the `pr:<N>` target's
    /// remote match takes. Every [`crate::Forge`] call of a `forge_export`
    /// is bound to it, so the pull request opens and is observed where the
    /// branch was pushed, never in the forge client's default repository.
    ///
    /// # Errors
    ///
    /// `forge_export_repository_unresolved` (`Validation`) when `remote` is no
    /// configured remote, has no URL, or its URL names no host (a local path,
    /// a `file://` URL) or a path that is not exactly `OWNER/REPO`. A
    /// shorthand only a rewrite expands is read as written (`gh:o/r` as host
    /// `gh`), and an SSH host alias as its literal host: the export's
    /// [`crate::Forge::confirm_repository`] refuses a host the forge does not
    /// address, before the push.
    fn forge_export_repository(&self, remote: &str) -> KataResult<String>;

    /// The head `remote` advertises for `refs/heads/<branch>`, read within
    /// `timeout`: `Some(sha)`, or `None` when the remote advertises no such
    /// branch. A remote that cannot answer is an error, never `None`. A
    /// `forge_export` reads it before its push intent (the answer is the
    /// push's lease) and again as the push's observer.
    fn forge_remote_head(
        &self,
        remote: &str,
        branch: &str,
        timeout: std::time::Duration,
    ) -> KataResult<Option<String>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_key_is_execution_scoped_by_default() {
        let execution_id = Ulid::new();
        let key = ExecutionWorkspaceKey::execution(execution_id);

        assert_eq!(key.execution_id, execution_id);
        assert!(key.invocation_id.is_none());
        assert!(key.stage_name.is_none());
    }

    #[test]
    fn the_census_refusal_names_every_finding_in_order() {
        let features = vec![
            UnsupportedRepositoryFeature::GitmodulesFile,
            UnsupportedRepositoryFeature::GitSubmodule {
                path: "vendor/dep".to_string(),
            },
            UnsupportedRepositoryFeature::GitAttributesConfig {
                key: "core.attributesFile".to_string(),
            },
            UnsupportedRepositoryFeature::GitCheckoutConversionConfig {
                key: "core.autocrlf".to_string(),
            },
            UnsupportedRepositoryFeature::GitFilter {
                source: "sub/.gitattributes".to_string(),
                pattern: "*.big".to_string(),
                value: Some("lfs".to_string()),
            },
            UnsupportedRepositoryFeature::GitFilter {
                source: "$GIT_DIR/info/attributes".to_string(),
                pattern: "*".to_string(),
                value: None,
            },
            UnsupportedRepositoryFeature::GitCheckoutConversion {
                source: ".gitattributes".to_string(),
                pattern: "*.i".to_string(),
                attribute: "ident".to_string(),
            },
            UnsupportedRepositoryFeature::ShallowClone,
            UnsupportedRepositoryFeature::PartialClone {
                key: "remote.origin.promisor".to_string(),
            },
        ];
        let error = oci_unsupported_features_refusal(&features);
        let message = error.to_string();

        assert!(matches!(error, KataError::Validation(_)));
        // `KataError::Validation` Displays as `validation error: <inner>` — the
        // stable code leads the INNER message.
        assert!(message.contains(&format!("{OCI_UNSUPPORTED_REPOSITORY_FEATURES}:")));
        // Every variant's Display lands in the message, in the order given.
        let fragments = [
            ".gitmodules",
            "vendor/dep",
            "core.attributesFile",
            "core.autocrlf",
            "sub/.gitattributes",
            "filter=lfs",
            "$GIT_DIR/info/attributes",
            "filter (set)",
            "ident",
            "shallow",
            "remote.origin.promisor",
        ];
        let mut cursor = 0;
        for fragment in fragments {
            let at = message[cursor..]
                .find(fragment)
                .unwrap_or_else(|| panic!("missing `{fragment}` in: {message}"));
            cursor += at + fragment.len();
        }
    }
}
