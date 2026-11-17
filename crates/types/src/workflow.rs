//! Workflow definition and execution types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use ulid::Ulid;

use crate::agent::BackendType;
use crate::cache::CachePolicy;
use crate::execution::CandidateTreePin;
use crate::execution_class::StageClassDeclaration;
use crate::primitives::ContentHash;
use crate::review_loop::ReviewLoop;
use crate::sandbox::{SandboxProfile, SandboxRef};

/// The AUTHORING default wall-clock budget a stage gets when it declares no
/// `timeout_ms=`: one hour.
///
/// # Measured, not chosen by feel
///
/// The largest literal `timeout_ms=` any shipped pack under `workflows/**`
/// declares is exactly `3_600_000` — `workflows/std/test-crate.star`,
/// `workflows/std/kata-gate-fix-loop.star`'s gate stage, and
/// `workflows/kata-factory/kata/factory.star`'s gate stage.
/// Those three are the longest-running shipped stages: each runs a
/// cold-workspace `just gate` / `just test-crate`, and
/// `kata-gate-fix-loop.star` records in its own comment that a fresh-workspace
/// cold run "finishes well inside the 1h stage `timeout_ms`". So the longest
/// shipped stage's own measured envelope IS this constant, measured by the
/// authors who declared it rather than re-guessed here.
///
/// Generosity is the point: this default exists so that "no timeout" is
/// unrepresentable in the checked IR, not to police anyone's runtime. A stage
/// that wants a tighter bound declares one, and a declared value always wins.
/// No node-level cap exists, so this is also the ONLY wall clock an operator
/// can observe: there is nothing in `kata.toml` that raises or lowers it.
pub const DEFAULT_STAGE_TIMEOUT_MS: u64 = 3_600_000;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct WorkflowId(pub Ulid);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct StageId(pub SmolStr);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct ExecutionId(pub Ulid);

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum EdgeCondition {
    Always,
    OnPass,
    OnRefine,
    OnBlock,
    Custom(SmolStr),
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum AgentSelector {
    Backend(BackendType),
    Labelled(SmolStr),
    Any,
    /// Agent fallback panel: an ordered `try-A-then-B` list of agent
    /// labels. The FIRST member is the PRIMARY (it drives initial dispatch);
    /// when the primary's attempt FAILS (a backend/spawn error or timeout —
    /// NOT a content/validation-verdict rejection, which stays the
    /// validate/review loop's job) the effect-retry layer advances to the next
    /// member. A panel of `N` members is the stage's whole failure-retry
    /// budget — `N - 1` immediate advances, no backoff, no hidden
    /// multiplication of spend — and the agent chosen for attempt `i` is
    /// `panel[i]`, a pure function of the durable failure-retry attempt
    /// counter, so resume replays the same decision.
    ///
    /// Frontends never construct a `Panel` with fewer than two members: a
    /// single-element `agent = ["x"]` collapses to [`Self::Labelled`], keeping
    /// single-agent stages byte-identical.
    Panel(Vec<SmolStr>),
}

impl AgentSelector {
    /// The ordered fallback panel labels (primary first). Empty for every
    /// non-panel selector — the discriminator callers use to detect a panel.
    #[must_use]
    pub fn panel_labels(&self) -> &[SmolStr] {
        match self {
            Self::Panel(members) => members,
            Self::Backend(_) | Self::Labelled(_) | Self::Any => &[],
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StageInput {
    pub name: SmolStr,
    pub from: StageId,
    pub field: SmolStr,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StageOutput {
    pub name: SmolStr,
    pub ty: SmolStr,
}

/// Stage topology declaration.
///
/// This describes the intended intra-stage agent shape. Inspect lowers it to
/// an invocation-plan preview; the runner can use the same metadata to spawn
/// executable child assignments under a parent stage.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StageTopology {
    /// Stable topology label, e.g. `single_agent`,
    /// `root_with_parallel_workers`, `review_quorum`.
    pub kind: SmolStr,
    /// Optional root/orchestrator role for this stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<AgentRolePolicy>,
    /// Optional implementation/research worker roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workers: Vec<AgentRolePolicy>,
    /// Optional reviewer roles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reviewers: Vec<AgentRolePolicy>,
    /// Maximum child invocations the runtime may run concurrently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
    /// Maximum dynamic fanout width for package/research expansion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout_limit: Option<u32>,
    /// When true, child invocations are selected from the root assignment's
    /// completed output instead of dispatched immediately from the static role
    /// list. The output must include bounded child invocation requests.
    #[serde(default)]
    pub dynamic_fanout: bool,
    /// How runtime child invocations are allowed to mutate the repository.
    ///
    /// `Advisory` (the default): prompts may describe scopes,
    /// but the runner does not require a machine-checkable ownership contract.
    /// `OwnedPaths` requires dynamic worker requests to declare non-overlapping
    /// repo-relative `owned_paths` before the runner dispatches them.
    #[serde(default, skip_serializing_if = "is_default_mutation_policy")]
    pub mutation_policy: MutationPolicy,
    /// Optional review quorum declaration for review-shaped stages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_quorum: Option<ReviewQuorumPolicy>,
}

/// Repository mutation policy for stage-level child invocations.
#[derive(
    Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize, strum::VariantArray,
)]
#[serde(rename_all = "snake_case")]
pub enum MutationPolicy {
    /// No machine-enforced path ownership contract.
    #[default]
    Advisory,
    /// Dynamic worker children must declare disjoint repo-relative paths.
    OwnedPaths,
}

impl MutationPolicy {
    /// Every policy, in declaration order (the derived `strum::VariantArray`):
    /// the DSL catalog's `topology_mutation_policy` domain and the set
    /// `topology(mutation_policy=)` parses through [`Self::from_label`].
    #[must_use]
    pub fn variants() -> &'static [Self] {
        <Self as strum::VariantArray>::VARIANTS
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::OwnedPaths => "owned_paths",
        }
    }

    /// The policy whose [`Self::label`] is `label`, or `None`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::variants()
            .iter()
            .copied()
            .find(|policy| policy.label() == label)
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_mutation_policy(policy: &MutationPolicy) -> bool {
    *policy == MutationPolicy::default()
}

/// One declared agent role inside a stage topology.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AgentRolePolicy {
    /// Role label inside the stage, e.g. `root`, `package_writer`,
    /// `primary_reviewer`.
    pub role: SmolStr,
    /// Workflow agent label to use for this role when the runtime can spawn
    /// child invocations. Static invocation previews may omit this and inherit
    /// the stage-level agent, but dynamic fanout child roles must declare it so
    /// runtime child requests cannot choose an unchecked agent label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<SmolStr>,
    /// Whether this role is required for the topology to be valid.
    #[serde(default = "default_required_role")]
    pub required: bool,
}

fn default_required_role() -> bool {
    true
}

/// Non-executing declaration of how many reviewers must pass.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ReviewQuorumPolicy {
    /// Minimum approving reviewer count required by the runtime.
    pub required: u32,
    /// Whether any serious finding should block even if quorum count passes.
    #[serde(default = "default_block_on_any_finding")]
    pub block_on_any_finding: bool,
    /// Whether optional/advisory reviewer approvals may satisfy `required`.
    ///
    /// Defaults to false so `required = false` reviewer roles are genuinely
    /// advisory: their output is recorded, but only required reviewers decide
    /// the gate unless the workflow opts into counting optional reviewers.
    #[serde(default)]
    pub count_optional_reviewers: bool,
    /// Whether optional/advisory reviewer blocker verdicts should fail the
    /// quorum when `block_on_any_finding` is true.
    #[serde(default)]
    pub block_on_optional_findings: bool,
}

fn default_block_on_any_finding() -> bool {
    true
}

/// The operator-facing label of the in-process workspace-effect backend.
///
/// A `stage(agent="workspace_effect", op=…)` routes to this backend, which
/// performs a recorded, replay-safe candidate-workspace mutation (park or
/// promote) through the execution's [`ExecutionWorkspaceProvider`] instead of
/// calling an LLM. The effect's JSON envelope is recorded as the stage's
/// Completed output, so resume/replay never re-runs the mutation.
///
/// [`ExecutionWorkspaceProvider`]: ../../kata_effects_contract/trait.ExecutionWorkspaceProvider.html
pub const WORKSPACE_EFFECT_AGENT_LABEL: &str = "workspace_effect";

/// The deterministic candidate-workspace mutation a `workspace_effect` stage
/// performs.
///
/// Factory-as-loop foundation: workspace effects live at a stage/effect
/// boundary so a `branch(decision)` can route to a `park`, `promote`, or
/// `commit` stage. [`Self::Park`], [`Self::Promote`] and [`Self::ForgeExport`]
/// are TERMINAL effects — the first two tear down the live worktree, the third
/// is a SINK that runs once it is gone — so no stage may `depends_on` them.
/// [`Self::Commit`] is NON-terminal: it names the VCS commit as a recorded
/// Effect — it finalizes the recorded candidate commit in place and leaves
/// the worktree LIVE so later stages keep working in it.
///
/// [`Self::terminal_reason`] is the ONE place that classification lives; every
/// caller (notably the load-time `depends_on` check in
/// `kata_program::parser::validate`) derives it from there rather than
/// re-listing the ops.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Serialize,
    Deserialize,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::VariantArray,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum WorkspaceEffectOp {
    /// Park the candidate workspace as a named ref/bookmark without
    /// integrating it (preserves the work for later inspection/promotion).
    Park,
    /// Promote the candidate workspace into the target branch.
    Promote,
    /// Finalize the recorded candidate commit — the commit earlier stages'
    /// recorded applies built — as a recorded Effect at the named VCS
    /// boundary. Runs the VCS commit IN-PROCESS on the host, OUTSIDE any agent
    /// sandbox (the determinism boundary: VCS mutation is an Effect at a named
    /// boundary, never shelled inside the agent sandbox). It refuses a
    /// worktree whose disk or `@` no longer matches the recorded candidate.
    /// Non-terminal: the worktree stays live afterward. A re-driven attempt is
    /// classified against the repository and lands no second commit.
    Commit,
    /// Export the commit the execution's claim DELIVERS — the one its latest
    /// `commit` finalized, or the one its `promote` landed — to the forge as a
    /// `kata/<exec>` branch (colocated root → git push → open PR into the
    /// frozen landable branch). TERMINAL SINK: it runs after a `commit` or a
    /// `promote` among its ancestors; a forge/push failure fails THIS stage
    /// with a typed error but NEVER mutates trunk, un-lands a candidate, or
    /// produces a validation report — the forge is a SINK, never a completion
    /// source. The extra [`WorkspaceEffect::forge`] fields (`title`/`body`)
    /// parameterize the PR; they are absent on every other op.
    ForgeExport,
}

impl WorkspaceEffectOp {
    /// Stable snake_case label matching the serde representation
    /// (`park` / `promote` / `commit`). Used in the effect-stage's synthetic
    /// prompt directive and the recorded envelope. Delegates to the derived
    /// `strum::IntoStaticStr` so the mapping is defined once.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    /// Every op, in declaration order (the derived `strum::VariantArray`): the
    /// DSL catalog's `stage_op` domain, the set [`Self::from_label`] accepts.
    #[must_use]
    pub fn variants() -> &'static [Self] {
        <Self as strum::VariantArray>::VARIANTS
    }

    /// Parse an op label (the inverse of [`Self::as_str`]). Returns `None` for
    /// any unrecognized label. Delegates to the derived `strum::EnumString`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        <Self as std::str::FromStr>::from_str(label).ok()
    }

    /// Why THIS op is terminal, or `None` when it is not.
    ///
    /// THE ONE PLACE terminality is decided. Terminal means: after this effect
    /// runs, no stage can be dispatched into the execution's candidate
    /// worktree — either because the effect tore that worktree down, or
    /// because the op is a SINK that runs once it is already gone. A caller
    /// that needs the boolean asks [`Self::is_terminal`]; a caller that must
    /// TELL AN AUTHOR why asks this. The reason and the classification are one
    /// value on purpose — a second list of "which ops are terminal" is exactly
    /// the drift that let the load-time `depends_on` check refuse `commit`
    /// while publishing park/promote's reason, which was never `commit`'s.
    ///
    /// The returned fragment is a sentence body (no leading capital, no
    /// trailing period) so a message can splice it inline.
    #[must_use]
    pub const fn terminal_reason(self) -> Option<&'static str> {
        match self {
            Self::Park => Some(
                "`park` commits the candidate, force-creates its parked ref, and then TEARS THE \
                 WORKTREE DOWN",
            ),
            Self::Promote => Some(
                "`promote` fast-forwards the trusted base ref onto the candidate (onto the \
                 commit a `commit` effect finalized when the candidate is the empty commit it \
                 left above it) and then TEARS THE WORKTREE DOWN",
            ),
            Self::ForgeExport => Some(
                "`forge_export` is a terminal SINK — it pushes the commit its claim delivers \
                 and opens a PR, never a workspace a later stage could use",
            ),
            // NOT terminal: `commit` finalizes the recorded candidate IN PLACE
            // and leaves the worktree LIVE. See
            // `ExecutionWorkspaceProvider::commit_workspace_effect`, which —
            // unlike the park and promote effects — never calls
            // `remove_workspace`.
            Self::Commit => None,
        }
    }

    /// Whether this op is TERMINAL — see [`Self::terminal_reason`], the sole
    /// classifier this delegates to.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        self.terminal_reason().is_some()
    }
}

/// Authored declaration of a workspace-effect stage.
///
/// Present on a [`StageDefinition`] iff the stage is a `workspace_effect`
/// stage. `#[serde(skip_serializing_if = "Option::is_none")]` on the field
/// keeps every non-effect pack byte-identical.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct WorkspaceEffect {
    /// Which deterministic mutation to perform.
    pub op: WorkspaceEffectOp,
    /// Optional human-facing label, descriptive metadata only (park only;
    /// ignored by promote). It is recorded in the directive but is NOT part of
    /// the parked git ref: an effect-stage park is **execution-scoped**
    /// (`parked/<exec-id>`) so a crash-window re-dispatch reconciles
    /// unambiguously and same-label loop iterations never collide. (The
    /// operator apply-gate's `park --label` path keeps its own
    /// `parked/<label>` scheme.) `None` is the common case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// `forge_export` only: the PR parameters (remote / base / title / body).
    /// `None` for every other op, so a non-forge effect stays byte-identical on
    /// the wire (`skip_serializing_if`). See [`ForgeExportSpec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forge: Option<ForgeExportSpec>,
    /// `promote` only, and **never authored**: the tree identity a recorded
    /// validation criterion bound to this execution's candidate.
    ///
    /// The Starlark surface cannot set it — `dsl::decode` constructs this struct
    /// with [`CandidateTreePin::Unpinned`] and there is no keyword that reaches
    /// it — and the runner OVERWRITES whatever the directive carried when it
    /// dispatches the stage, resolving the value from the durable validation
    /// evidence instead. So the pin is trusted by construction, exactly like the
    /// candidate binding it is read from: a pack cannot name the tree it wants
    /// to be measured against, and neither can an agent.
    ///
    /// [`CandidateTreePin::Unpinned`] serializes to nothing, so every non-promote
    /// stage and every unpinned promote keeps a byte-identical directive.
    #[serde(default, skip_serializing_if = "CandidateTreePin::is_unpinned")]
    pub candidate_tree: CandidateTreePin,
}

/// `forge_export` PR parameters, carried on [`WorkspaceEffect::forge`].
///
/// A pack names no machine fact here: the pull request's base is the
/// execution's FROZEN landable branch (`ExecutionTarget::branch`) and the push
/// remote is inherited from the repository when the export is claimed, so
/// neither is an authoring field. The backend derives a title/body when the author omits
/// them. Title/body are LITERAL strings (no minijinja) so they survive the
/// directive-prompt round-trip verbatim, exactly like the effect directive
/// itself. Unknown fields are refused, so a recorded spec that names a remote
/// or a base is never read as one that does not.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgeExportSpec {
    /// PR title. When omitted the backend derives one from the execution id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// PR body. When omitted the backend derives a neutral one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// The top-level key under which a [`WorkspaceEffect`] directive is carried in
/// the synthetic effect-stage prompt. The frontend renders
/// `{"workspace_effect": {"op": …, "label": …}}` as the stage's
/// `prompt_template`; the in-process `workspace_effect` backend parses it back
/// out. Kept here so frontend and backend share one source of truth.
pub const WORKSPACE_EFFECT_DIRECTIVE_KEY: &str = "workspace_effect";

impl WorkspaceEffect {
    /// Render the literal directive prompt the frontend lowers onto a
    /// `workspace_effect` stage's `prompt_template`. This is NOT a minijinja
    /// template — it is a literal JSON object with no `{{ … }}` placeholders,
    /// so it survives prompt rendering verbatim and reaches the backend
    /// unchanged.
    #[must_use]
    pub fn directive_prompt(&self) -> String {
        // Hand-built rather than serde-serialized so the byte shape is
        // pinned by this function (stable across serde version bumps) and
        // trivially round-trips through [`Self::from_directive_prompt`].
        let mut directive = serde_json::Map::new();
        directive.insert(
            "op".to_string(),
            serde_json::Value::String(self.op.as_str().to_string()),
        );
        if let Some(label) = self.label.as_deref() {
            directive.insert(
                "label".to_string(),
                serde_json::Value::String(label.to_string()),
            );
        }
        if let Some(forge) = self.forge.as_ref() {
            // Nest the forge fields under "forge" so they never collide with
            // op/label and a non-forge effect stays byte-identical (this block
            // is skipped entirely when `forge` is None).
            let mut forge_map = serde_json::Map::new();
            let mut put = |key: &str, value: &Option<String>| {
                if let Some(value) = value.as_deref() {
                    forge_map.insert(
                        key.to_string(),
                        serde_json::Value::String(value.to_string()),
                    );
                }
            };
            put("title", &forge.title);
            put("body", &forge.body);
            directive.insert("forge".to_string(), serde_json::Value::Object(forge_map));
        }
        // Two flat keys rather than a tagged object: the state IS the key, so a
        // reader (and an operator reading the recorded prompt) sees `the tree
        // validation approved` or `the criterion that stamped no tree` without
        // decoding a discriminator. `Unpinned` writes neither.
        match &self.candidate_tree {
            CandidateTreePin::Unpinned => {}
            CandidateTreePin::Pinned(tree_id) => {
                directive.insert(
                    "candidate_tree".to_string(),
                    serde_json::Value::String(tree_id.clone()),
                );
            }
            CandidateTreePin::Unstamped(criterion_id) => {
                directive.insert(
                    "candidate_tree_unstamped".to_string(),
                    serde_json::Value::String(criterion_id.clone()),
                );
            }
        }
        let mut root = serde_json::Map::new();
        root.insert(
            WORKSPACE_EFFECT_DIRECTIVE_KEY.to_string(),
            serde_json::Value::Object(directive),
        );
        serde_json::Value::Object(root).to_string()
    }

    /// Parse a [`Self::directive_prompt`] back into a [`WorkspaceEffect`].
    /// Returns `None` if the prompt is not a workspace-effect directive (so the
    /// backend can surface a clear error) — `Some(Err)` semantics are folded
    /// into `None` here; the caller validates op presence. A `forge` member
    /// carrying any key but `title` and `body` is no directive this build
    /// writes, and is `None` too.
    #[must_use]
    pub fn from_directive_prompt(prompt: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(prompt.trim()).ok()?;
        let directive = value.get(WORKSPACE_EFFECT_DIRECTIVE_KEY)?.as_object()?;
        let op = WorkspaceEffectOp::from_label(directive.get("op")?.as_str()?)?;
        let label = directive
            .get("label")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let forge = match directive.get("forge") {
            None => None,
            Some(value) => {
                let f = value.as_object()?;
                if f.keys().any(|key| key != "title" && key != "body") {
                    return None;
                }
                let field =
                    |key: &str| f.get(key).and_then(|v| v.as_str()).map(ToString::to_string);
                Some(ForgeExportSpec {
                    title: field("title"),
                    body: field("body"),
                })
            }
        };
        let string_at = |key: &str| {
            directive
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
        };
        // A directive carrying BOTH keys is malformed — the runner writes at
        // most one. Read the refusing one, so a corrupted directive fails closed
        // at the fence rather than landing on the other half.
        let candidate_tree = string_at("candidate_tree_unstamped").map_or_else(
            || {
                string_at("candidate_tree")
                    .map_or(CandidateTreePin::Unpinned, CandidateTreePin::Pinned)
            },
            CandidateTreePin::Unstamped,
        );
        Some(Self {
            op,
            label,
            forge,
            candidate_tree,
        })
    }
}

/// Parsed authoring marker that turns a stage into a SUBWORKFLOW spawn
/// point.
///
/// The native `subworkflow(pack=..)` graph constructor records this on
/// [`StageDefinition::subworkflow`]; the compiler lowers it into the checked-IR
/// marker (`ExecutionProgramStage::subworkflow`, a
/// `kata_program::execution_program::SubworkflowSpec`), resolving and compiling
/// [`pack`](Self::pack) through its library roots at CHECK and embedding the bound
/// child program; the runner spawns a child execution of THAT program instead of
/// dispatching the stage to a worker.
///
/// Serde-default: a stage that omits it carries nothing on the wire
/// (`skip_serializing_if` on the field).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SubworkflowRef {
    /// The child workflow pack identity the spawned execution runs.
    pub pack: SmolStr,
    /// Authored constant invocation params (`{name: value}`) supplied to
    /// the child pack at spawn, resolved + default-filled against the child
    /// program's declared param contract at admission. Empty for a child with no
    /// params, and skipped from serialization when empty. (There is no
    /// parent-output → child-param dataflow; this carries authored constants
    /// only.)
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub params: serde_json::Map<String, serde_json::Value>,
}

/// Parsed authoring marker that turns a stage into a DURABLE SLEEP.
///
/// The frontend-facing twin of `kata_types::wait::DurableSleep`. The
/// native `sleep(for_ms=..|until_ms=..)` builtin records this on
/// [`StageDefinition::durable_sleep`]; the compiler lowers it into the checked-IR
/// marker (`kata_program::execution_program::ExecutionProgramStage::durable_sleep`,
/// a `kata_types::wait::DurableSleep`), and the runner resolves the stage
/// MAIN-SIDE: it claims a main attempt parked on a durable timer
/// (`awaiting_timer`) at the sleep's deadline instead of dispatching to a worker,
/// and the dispatcher's due-wait sweep (`Dispatcher::sweep_due_waits`) completes
/// it after the deadline, so it survives a restart. `kata_types` cannot depend on
/// `kata_workflow`, so this is the structural mirror of that runtime enum
/// (identical `snake_case` wire shape).
///
/// Serde-default: a stage that omits it carries nothing on the wire
/// (`skip_serializing_if` on the [`StageDefinition::durable_sleep`] field).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableSleepSpec {
    /// Relative sleep: wake `ms` after the park instant (resolved against the
    /// wall clock at park time).
    For { ms: u64 },
    /// Absolute sleep: wake at a fixed Unix-ms deadline.
    Until { epoch_ms: u64 },
}

/// The parsed authoring marker that turns a stage into a TYPED MEMORY SNAPSHOT
/// — the `memory_snapshot(kind=.., status=..)` builtin's declared filter.
///
/// A memory-snapshot stage runs no process on any profile: the runner resolves
/// it MAIN-SIDE — kata reads the node's own native memory store under the
/// authored filter and accepts the stage with the `MemorySnapshot` as its
/// output — which is what makes `sandbox = "host"` and a loopback
/// `kata memory snapshot` call unnecessary. Each field is
/// the authored `kind=`/`status=` kwarg verbatim (`None` = unfiltered); the
/// spelling domain ([`crate::memory::MemoryObjectKind`],
/// [`crate::memory::MemoryObjectStatus`]) is enforced at the builtin, so a
/// decoded spec is already in-domain.
///
/// Additive + serde-default: a stage that omits it stays byte-identical on the
/// wire (`skip_serializing_if` on the [`StageDefinition::memory_snapshot`]
/// field), so pre-slice-5 packs are unaffected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct MemorySnapshotSpec {
    /// `kind=` — one [`crate::memory::MemoryObjectKind`] to snapshot, or
    /// `None` for every kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<crate::memory::MemoryObjectKind>,
    /// `status=` — one [`crate::memory::MemoryObjectStatus`] to snapshot, or
    /// `None` for every status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<crate::memory::MemoryObjectStatus>,
}

/// Which frontend construct synthesized a stage the author never wrote.
///
/// One variant today. A future construct that mints a stage adds its own variant
/// rather than reusing this one, so a reader can always say WHICH orchestration
/// artifact it is looking at.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynthesizedStage {
    /// The fan-in barrier `parallel()` mints (`__parallel_join_<n>`): it exists only so a
    /// downstream stage can wait for every branch. Its body is the shell no-op `:`. The typed
    /// lowering keys `RuntimeOperation::Join` on this marker, and under the `oci` profile the body
    /// never runs: the submit path's divert resolves the join MAIN-SIDE — one `executor = 'main'`
    /// attempt accepted with `{"joined": [<input occurrence ids>]}` once every input is accepted —
    /// with no capsule and no dispatch.
    ParallelJoin,
}

/// How a shell (or `run=`) stage's process EXIT STATUS maps to the
/// stage's terminal outcome.
///
/// # The DEFAULT terminalizes, and `content` is the opt-out
///
/// The default is [`Self::ZeroSuccess`]: a nonzero exit is a distinct stage
/// FAILURE (a `ShellNonzeroExit` terminal), while a zero exit completes normally.
/// [`Self::Content`] is the DECLARED opt-out — a nonzero exit is CONTENT: the
/// stage COMPLETES, its output records the code at its root `exit_code` (the
/// `capsule_result` record `kata_core::operational::capsule_result_output`
/// writes), and the structured-output validator (if the stage
/// declares one) decides success. It is what a gate/loop pack wants when the
/// exit code is INFORMATION the graph branches on rather than a verdict.
///
/// **Why the default terminalizes.** A nonzero exit is the command's own
/// verdict on itself; under a `content` default a failing body would COMPLETE
/// with empty content — a failure that completes green. (A write to an
/// unauthored stage's `workspace = "ro"` `/work` is not such a failure under
/// `oci`: the mount is writable, and a delta the write leaves is refused at
/// adoption as `work_delta_out_of_scope` whatever the exit status.) See
/// [`Self::is_zero_success`] for the wire encoding and
/// [`crate::execution::HASHED_CONTRACT`] for where it is committed.
///
/// This is orthogonal to the two OTHER shell-stage failure classes, which keep
/// their own distinct terminals: a schema-VALIDATION failure still consumes the
/// isolated `validate_retries` budget, and an ENGINE failure (spawn / timeout /
/// output-cap) stays its own reason — a timeout is never reclassified as a
/// command exit and never implies a safe retry.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellExitPolicy {
    /// A nonzero exit is content: the stage completes and its output records the
    /// code at its root `exit_code`. The DECLARED opt-out from the default — a pack asks
    /// for it when the exit code is information the graph reads.
    Content,
    /// A nonzero exit fails the stage with a distinct `ShellNonzeroExit`
    /// terminal; a zero exit completes normally. **The default.**
    #[default]
    ZeroSuccess,
}

impl ShellExitPolicy {
    /// The closed set of exit-policy variants, in a stable order — the single
    /// source of truth for the DSL catalog's `exit_policy` domain and the
    /// load-time decoder's accepted spellings.
    #[must_use]
    pub const fn variants() -> &'static [Self] {
        &[Self::Content, Self::ZeroSuccess]
    }

    /// The canonical `snake_case` wire spelling — the SAME token serde emits.
    #[must_use]
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::ZeroSuccess => "zero_success",
        }
    }

    /// `true` for the DEFAULT (`ZeroSuccess`) policy. The `skip_serializing_if`
    /// predicate for every `exit_policy` field: the default never serializes, so
    /// a stage that omits `exit_policy=` stays byte-identical on the wire and in
    /// every hash material (`normalized_hash`, `contract_hash`, `program_hash`).
    ///
    /// The OMITTED spelling means "the default": `zero_success` omits and
    /// `content` serializes, so a stage that authors no `exit_policy=` and one
    /// that authors `zero_success` hash identically.
    #[must_use]
    pub const fn is_zero_success(&self) -> bool {
        matches!(self, Self::ZeroSuccess)
    }

    /// THE ONE JUDGEMENT of a shell stage's exit status against this checked policy.
    ///
    /// Every route that runs a shell stage asks this and nothing else — today the `oci`
    /// capsule acceptance at the main (`kata_workflow::dispatcher`'s exit leg, when a
    /// `CompletedCapsule` reports its exit status). One predicate and one error, so a stage
    /// cannot complete on one route and fail on another for the same exit — as it would if
    /// a route recorded the exit code and never asked.
    ///
    /// `exit_code` is the code the process reported, [`SIGNALLED_EXIT_CODE`] when it
    /// reported none.
    ///
    /// # Errors
    ///
    /// The `ShellNonzeroExit` terminal ([`SHELL_NONZERO_EXIT_ERROR_PREFIX`]) —
    /// exactly when `self` is [`Self::ZeroSuccess`] (the default) and `exit_code` is
    /// not 0. A [`Self::Content`] stage is never refused here, whatever
    /// it exited.
    pub fn judge_exit(self, exit_code: i32, stderr: &str) -> crate::error::KataResult<()> {
        if self == Self::ZeroSuccess && exit_code != 0 {
            return Err(shell_nonzero_exit_error(exit_code, stderr));
        }
        Ok(())
    }

    /// THE ONE JUDGEMENT of a shell stage completion an EXECUTION PROVIDER reported —
    /// its capture ([`judge_provider_capture`]) FIRST, then its exit status
    /// ([`Self::judge_exit`]), in that order. The
    /// `oci` profile's capsule acceptance at the main asks this, and a capsule content
    /// cache source is re-judged with it before it is reused.
    ///
    /// `captured_by` names who bounded the capture (see [`judge_provider_capture`]);
    /// `exit_code` is the provider's report, `None` read as [`SIGNALLED_EXIT_CODE`].
    ///
    /// # Errors
    ///
    /// Exactly [`judge_provider_capture`]'s and then [`Self::judge_exit`]'s.
    pub fn judge_provider_completion(
        self,
        captured_by: &str,
        exit_code: Option<i32>,
        stderr: &str,
        capture_exceeded: bool,
    ) -> crate::error::KataResult<()> {
        judge_provider_capture(captured_by, capture_exceeded)?;
        self.judge_exit(exit_code.unwrap_or(SIGNALLED_EXIT_CODE), stderr)
    }
}

/// The phrase naming the capsule route's capture in a
/// [`SHELL_CAPTURE_TRUNCATED_MARKER`] reason: the main reads the completion off a worker
/// and does not know which provider the worker drove.
pub const CAPSULE_CAPTURE_PROVIDER: &str = "the capsule's execution provider";

/// The distinguishable part of the reason a shell stage fails with when its provider
/// stopped its capture at the combined bound ([`judge_provider_capture`]).
///
/// The provider's spool bound is COMBINED and a breach KILLS the stage rather
/// than truncating its record; the constant is named `TRUNCATED` because
/// *"the provider stopped the stage at its capture bound"* is what the word
/// names in a durable row.
pub const SHELL_CAPTURE_TRUNCATED_MARKER: &str =
    "KILLED this stage for exceeding its combined capture bound";

/// THE ONE JUDGEMENT of a shell stage capture an execution PROVIDER bounded: a
/// capture the provider reported `capture_exceeded` fails the stage, whatever
/// its exit policy and whatever it exited — a shell stage's `content` IS its
/// stdout.
///
/// The bound is the COMBINED ceiling the supervisor named in
/// `kata_provider_protocol::CaptureSpec::limit_bytes` — the capsule's own
/// `output_bytes`.
///
/// `captured_by` is the noun phrase naming the provider, e.g. ``the external provider
/// `youki` `` or [`CAPSULE_CAPTURE_PROVIDER`].
///
/// # Errors
///
/// `KataError::Internal` — the same variant as `ShellNonzeroExit`, a definite failure
/// and not an ambiguous one — carrying [`SHELL_CAPTURE_TRUNCATED_MARKER`], exactly
/// when `capture_exceeded`.
pub fn judge_provider_capture(
    captured_by: &str,
    capture_exceeded: bool,
) -> crate::error::KataResult<()> {
    if !capture_exceeded {
        return Ok(());
    }
    Err(crate::error::KataError::Internal(format!(
        "shell: {captured_by} {SHELL_CAPTURE_TRUNCATED_MARKER}. A shell stage's `content` IS \
         its stdout, so publishing a silently shortened payload as the stage's answer would \
         hand every downstream template and every `produces` contract a value that is not \
         what the command emitted."
    )))
}

/// The distinguishable reason PREFIX for a shell stage that exited nonzero
/// under a terminalizing exit policy: the ShellNonzeroExit terminal class. That
/// policy is the DEFAULT (`ShellExitPolicy::ZeroSuccess`), so this prefix is
/// what an author who declared nothing at all sees.
///
/// Deliberately distinct from the ENGINE-failure reasons this backend produces —
/// `"shell: spawn failed"`, `"shell: timed out after"`, and the output-cap
/// `"exceeded … ceiling"` — so an operator (and the exit-matrix regression) can
/// tell a COMMAND-level failure from a spawn/timeout/output-cap engine failure.
/// The prefix is the classification; nothing re-runs it. A timeout keeps its own
/// reason and is never read as a command exit.
pub const SHELL_NONZERO_EXIT_ERROR_PREFIX: &str = "shell: command exited nonzero";

/// Maximum stderr-tail bytes carried as evidence on a `ShellNonzeroExit` reason,
/// so a runaway stderr can never bloat the durable ledger failure string.
const MAX_STDERR_TAIL_BYTES: usize = 512;

/// The exit code a shell stage REPORTS for a process with no exit status of its own — a
/// signal death, a runtime that killed it and reported no status, or a runtime client
/// that failed without finishing its own delete, so the status it exited with was its
/// own. It
/// is a different fact from exiting 0 and is carried as a nonzero code, so every exit
/// policy judges it.
pub const SIGNALLED_EXIT_CODE: i32 = -1;

/// Build the [`SHELL_NONZERO_EXIT_ERROR_PREFIX`] stage-failure error, carrying
/// the process `exit_code`, a bounded stderr TAIL, the POLICY that terminalized
/// it, and the RECOURSE.
///
/// All four are required. `zero_success` is the DEFAULT, so the failure reaches
/// authors who declared nothing — and the message has to carry the one spelling
/// that turns it back off. Without it a reader may see only *"content is not
/// valid JSON: EOF while parsing a value at line 1 column 0"*, a message about
/// JSON for a cause that was a filesystem policy, and a reader given only
/// `exit_code=2` is still one hop from the answer.
fn shell_nonzero_exit_error(exit_code: i32, stderr: &str) -> crate::error::KataError {
    crate::error::KataError::Internal(format!(
        "{SHELL_NONZERO_EXIT_ERROR_PREFIX}: exit_code={exit_code}; \
         policy exit_policy=\"{}\" (the default) terminalizes a \
         nonzero exit; if this exit code is INFORMATION the graph reads rather than a \
         failure, declare exit_policy=\"{}\" on the stage; stderr tail: {}",
        ShellExitPolicy::ZeroSuccess.as_tag(),
        ShellExitPolicy::Content.as_tag(),
        stderr_tail(stderr)
    ))
}

/// The last [`MAX_STDERR_TAIL_BYTES`] of `stderr` (trailing whitespace trimmed,
/// truncated on a char boundary), prefixed with `…` when truncated.
fn stderr_tail(stderr: &str) -> String {
    let trimmed = stderr.trim_end();
    if trimmed.len() <= MAX_STDERR_TAIL_BYTES {
        return trimmed.to_owned();
    }
    let mut start = trimmed.len() - MAX_STDERR_TAIL_BYTES;
    while start < trimmed.len() && !trimmed.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &trimmed[start..])
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StageDefinition {
    pub id: StageId,
    pub agent: AgentSelector,
    pub prompt_template: String,
    /// Optional per-dispatch model hint forwarded to agent backends through the
    /// checked execution program and worker assignment contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hint: Option<SmolStr>,
    /// Per-dispatch wall-clock budget in milliseconds. ALWAYS present: a stage
    /// that declares no `timeout_ms=` is given [`DEFAULT_STAGE_TIMEOUT_MS`] at
    /// AUTHORING, in the `stage()` builtin, so "this stage has no wall-time
    /// bound" has no spelling anywhere downstream of the frontend. `0` is
    /// rejected by frontends. The field is unconditionally serialized, so it is
    /// visible in the checked IR and folded into every hash over it.
    pub timeout_ms: u64,
    /// `output_bytes=` — the COMBINED stdout+stderr capture bound the stage's
    /// capsule promises its provider. `None` (omitted or `0`) means the
    /// `CAPSULE_OUTPUT_BYTES` default and stays unserialized, so an omitted
    /// bound adds nothing to the checked IR or its hash. `[node]
    /// output_bytes_ceiling` checks the authored value at admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<u64>,
    /// `work_delta_bytes=` — the `/work` delta byte bound. CARRIED on the
    /// capsule (contract v7) and enforced when the worker publishes the delta
    /// and when the main adopts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_delta_bytes: Option<u64>,
    /// `work_delta_entries=` — the `/work` delta ENTRY bound, same disposition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_delta_entries: Option<u32>,
    /// Tool names this stage may use. Empty means the stage does not constrain
    /// the backend beyond its sandbox and agent routing policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tools: Vec<SmolStr>,
    /// Scheduler capability labels required for this stage. No `agent:<label>`
    /// is derived from [`Self::agent`]: capsule placement demands none, and under
    /// `oci` a non-empty list is refused at CHECK
    /// (`required_capabilities_unsupported_under_oci`).
    ///
    /// Values use the normalized main-side scheduler strings, e.g. `shell`,
    /// `network`, `disk:50`, `gpu:16`, or an operator-defined custom label.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<SmolStr>,
    pub inputs: Vec<StageInput>,
    pub outputs: Vec<StageOutput>,
    pub cache_policy: CachePolicy,
    /// Gate this stage on operator approval before dispatch. When
    /// true, the runner parks the assignment in the ledger as
    /// `AwaitingApproval { reason }` instead of dispatching to a
    /// worker. The operator resumes via
    /// `POST /api/v1/executions/{id}/approve`.
    #[serde(default)]
    pub approval: bool,
    /// Custom reason string shown to the operator alongside the
    /// pending approval. Defaults to a generic message if None.
    #[serde(default)]
    pub approval_reason: Option<String>,
    /// This stage's AUTHORED sandbox reference. `None` means the author declared
    /// none; checked lowering then materializes
    /// [`SandboxProfile::confined_default`] for a process executor.
    #[serde(default)]
    pub sandbox: Option<SandboxRef>,
    /// Retry budget for schema-validation
    /// auto-retry. When `outputs` is non-empty AND the agent's
    /// response fails parse / structural validation, the runner
    /// re-prompts with the parse error baked into the prompt, up to
    /// `validate_retries` times. Default 2.
    /// `0` disables auto-retry (fail-fast on first validation
    /// error). Retries do NOT consume an agent fallback panel's
    /// failure-retry budget — they are budget-isolated.
    #[serde(default = "default_validate_retries")]
    pub validate_retries: u32,
    /// Optional workflow-author-baked feedback prompt used on
    /// validation-retry attempts. When set, rendered through
    /// minijinja with `{{ error }}` bound to the validation error
    /// string and appended to the original prompt on each retry.
    /// When `None`, the runner falls back to a hardcoded default
    /// (see `crates/program/src/template.rs::DEFAULT_VALIDATE_FEEDBACK_TEMPLATE`).
    /// Static configuration — NOT runtime steering.
    #[serde(default)]
    pub validate_feedback_template: Option<String>,
    /// Cost-budget enforcement (per-stage scope). When the running
    /// cost for this stage crosses the policy's limit, the runner
    /// takes the policy-specified action: `Halt` fails the stage and
    /// cascades skip-dependents; `Warn` emits a metric + event and
    /// continues. Default `Unlimited`.
    #[serde(default)]
    pub cost_budget: crate::budget::BudgetPolicy,
    /// Per-stage knob that shapes how (or whether) the worker
    /// surfaces capsule progress frames over the transport.
    /// Default [`ProgressVisibility::Off`]. `Summary` emits byte counts + short
    /// head-of-delta preview; `Full` emits raw delta verbatim.
    #[serde(default)]
    pub progress_visibility: ProgressVisibility,
    /// Non-executing topology declaration for future root/subagent,
    /// fanout, and quorum runtime support.
    #[serde(default)]
    pub topology: Option<StageTopology>,
    /// The constrained JSON-Schema this stage's output is
    /// declared to satisfy, lowered from a native `stage(produces=contract(..))`
    /// declaration. `None` (the default for dict/TOML stages and any Starlark
    /// stage that omits `produces=`) leaves the stage's
    /// [`crate::workflow`]-derived `ExecutionStagePolicies.output_schema` unset.
    /// When `Some`, the schema is threaded
    /// into the checked program's `output_schema` and thereby folds into the
    /// stage `contract_hash`. The schema is exactly the value
    /// `kata_types::agent_run::validate_agent_run_output_schema` accepts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// The constrained JSON-Schema this stage declares it *consumes* from
    /// upstream, lowered from a native `stage(consumes=contract(..))`
    /// declaration. The load-time type-check (`kata_program::dsl::builder`'s
    /// `validate`) compares it against the upstream producer's `output_schema`.
    /// `None` for any stage omitting `consumes=`. It is deliberately excluded
    /// from `ExecutionStagePolicies` (and therefore from `contract_hash`)
    /// because it is not a runtime-significant contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    /// Factory-as-loop foundation: when `Some`, this stage is a
    /// deterministic workspace-effect stage (`agent="workspace_effect"`).
    /// It carries no prompt/produces; instead the frontend synthesizes a
    /// literal directive prompt from this declaration, and the in-process
    /// `workspace_effect` backend performs the recorded, replay-safe park /
    /// promote mutation. `None` (every non-effect stage) is omitted from
    /// serialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_effect: Option<WorkspaceEffect>,
    /// When `Some`, this stage is a SUBWORKFLOW — the compiler lowers it
    /// onto the checked-IR marker `ExecutionProgramStage::subworkflow`
    /// (`kata_program::execution_program::SubworkflowSpec`), binding the referenced
    /// pack's checked program at CHECK, and the runner spawns a CHILD execution of
    /// that bound program instead of dispatching this stage to a worker. Authored by the native graph DSL's
    /// `subworkflow(pack=..)`. `None`
    /// (every non-subworkflow stage) is omitted from serialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subworkflow: Option<SubworkflowRef>,
    /// When `Some`, this stage is a DURABLE SLEEP — the compiler lowers it
    /// onto the checked-IR marker `ExecutionProgramStage::durable_sleep`
    /// (`kata_types::wait::DurableSleep`), and the runner claims a main
    /// attempt parked on a durable timer (`awaiting_timer`) instead of dispatching
    /// to a worker; `Dispatcher::sweep_due_waits` completes it after the deadline,
    /// so the graph resumes exactly where it left off —
    /// crash/restart-safe. Authored by `sleep(for_ms=..|until_ms=..)` in the
    /// native graph DSL. `None` (every non-sleep stage) is omitted from
    /// serialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_sleep: Option<DurableSleepSpec>,
    /// When `Some`, this stage is a TYPED MEMORY SNAPSHOT — the
    /// compiler carries it onto the checked-IR marker
    /// `ExecutionProgramStage::memory_snapshot` and the typed-operation lowering
    /// produces `RuntimeOperation::MemorySnapshot`, which the runner resolves
    /// MAIN-SIDE on every profile (a snapshot of the node's own memory store
    /// under the authored filter — no worker, no shell, no loopback API call).
    /// Authored by `memory_snapshot(kind=.., status=..)` in the native graph
    /// DSL. `None` (every non-snapshot stage) is omitted from serialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_snapshot: Option<MemorySnapshotSpec>,
    /// FRONTEND PROVENANCE for a stage the author never wrote.
    ///
    /// `Some` marks a stage the frontend SYNTHESIZED while lowering a
    /// higher-level construct, naming which construct minted it. It exists
    /// because the checked IR otherwise ERASES that fact: a `parallel()` barrier
    /// is emitted as `agent = "shell"` with the body `":"` and default policies —
    /// byte-identical in every other IR field to an authored shell no-op — so no
    /// downstream reader can tell an orchestration artifact from an action the
    /// author asked for. Absent this marker such a reader is reduced to sniffing
    /// the minted id prefix, which is not a contract.
    ///
    /// `None` for every authored stage, omitted from serialization.
    /// DELIBERATELY OUTSIDE the runtime-significant contract material and NOT
    /// folded into `stage_contract_hash`, exactly like [`Self::durable_sleep`] and
    /// [`Self::subworkflow`]: it is provenance about where the stage came from,
    /// not a term of what it must do. A pack that DOES synthesize moves its
    /// whole-program hash, because that hash is taken over the serialized stages —
    /// the same way a `sleep()` marker moves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synthesized: Option<SynthesizedStage>,
    /// AUTHORING PROVENANCE — the `pack.star:LINE:COL` call site of the builtin
    /// that declared this stage (`stage()`, `sleep()`, `subworkflow()`), resolved
    /// from the Starlark evaluator's call-stack top. For the one stage no author
    /// wrote — `parallel()`'s fan-in barrier — it is the `parallel()` CALL's own
    /// span, because that call is truthfully where the barrier came from; the
    /// stage is still distinguishable as unauthored by
    /// [`Self::synthesized`], which is the field that answers "did a human write
    /// this".
    ///
    /// `file` is a BASENAME
    /// ([`kata_types::source::SourceSpan`](crate::source::SourceSpan)), so this
    /// never puts a host path into a workflow definition or into the checked IR
    /// lowered from it.
    ///
    /// `None` when the call has no resolvable Starlark frame (a pack built through
    /// the Rust API rather than evaluated) or the frame's filename has no final
    /// path component; omitted from serialization. `kata_workflow`'s
    /// `dsl_span_from_eval` states that refused set.
    ///
    /// It is the span of the `stage()` CALL, wherever that call textually is. A
    /// pack that composes its graph out of helper functions in a `load()`ed module
    /// therefore records the HELPER's file and line — `factory.star:855`, not the
    /// pack — because that is where the call the author made actually resolves. A
    /// span alone consequently does not identify the pack.
    ///
    /// # Which identities it enters, and which it must not
    ///
    /// Like [`Self::synthesized`] it is provenance about where the stage came
    /// from, not a term of what it must do. So:
    ///
    /// * NOT in the per-stage `contract_hash` of the checked IR — re-indenting a
    ///   pack must not rotate a stage's identity or discard its cached results;
    /// * NOT in `normalized_definition_hash` — that is the canonical SEMANTIC
    ///   identity of the definition, and a pack basename and a line number are
    ///   not part of what the workflow is. Projected out explicitly; see
    ///   `StagesWithoutSpans` beside [`WorkflowDefinition::normalized_hash`];
    /// * IS in `program_hash`, which is taken over the serialized checked stages,
    ///   and so in the `workflow_class_identity` that folds it. That adds nothing
    ///   the hash did not already commit to: `program_hash` is a SOURCE-AND-IR
    ///   identity — its material carries the hash of the pack's exact source bytes
    ///   and of every `load()`ed module (`ExecutionProgramSource::source_hash`,
    ///   `import_hashes`) — so ANY byte edit of a pack, a comment or a trailing
    ///   newline included, rotates `program_hash` and `workflow_class` whether or
    ///   not a span moves. The semantic identity is `normalized_definition_hash`.
    ///
    /// A PERSISTED program self-verifies whether or not its stages carry a span:
    /// the whole-program hash is re-derived over the DECODED struct, a stage with
    /// none decodes `authored_span: None`, `skip_serializing_if` omits it, and the
    /// bytes rehash to the header they were stored with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authored_span: Option<crate::source::SourceSpan>,
    /// The DECLARED read-closure of this stage (hermetic-by-closure) —
    /// repo-relative globs naming exactly the worktree paths a
    /// deterministic-hermetic action reads. Two independent purposes, both keyed
    /// on this being NON-EMPTY:
    ///
    /// * **Key precision:** for a content-cacheable stage the
    ///   reuse key narrows onto the CLOSURE's resolved content rather than the
    ///   whole worktree, so a change OUTSIDE the closure no longer spuriously
    ///   misses (hit-rate) while a change INSIDE it still invalidates.
    /// * **Read-failure enforcement:** the same closure
    ///   is the `/work` view a confinable stage's capsule materializes, so a
    ///   read outside it finds nothing.
    ///
    /// DELIBERATELY OUTSIDE the runtime-significant contract material and NOT
    /// folded into `contract_hash`: it is a closure DECLARATION, mirroring how
    /// `input_schema` sits outside the hashed contract. Empty (every stage that
    /// omits `reads=`) is the whole-worktree behavior, omitted on the wire
    /// (`skip_serializing_if`). Automatic closure DISCOVERY does not
    /// exist (landlock 0.4 has no audit substrate); the closure is DECLARED.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reads: Vec<SmolStr>,
    /// The DECLARED output-file set of this stage (the output closure) — repo-relative globs naming
    /// exactly the worktree paths this stage is permitted to produce or modify. The OUTPUT analog
    /// of [`Self::reads`] (the input closure). Two consumers:
    ///
    /// * **Output-closure record:** at stage completion the runtime RECORDS
    ///   the OBSERVED output set (the worktree change set) as durable evidence and
    ///   the checkable [`crate`]-agnostic predicate flags any observed path not
    ///   covered by a declared glob (observed ⊄ declared). RECORD-not-enforce: a
    ///   non-conforming stage is surfaced (warn + metric) but NOT hard-failed.
    ///   Empty (every stage that omits `produces_files=`) is a vacuous closure —
    ///   the check is skipped.
    /// * **Enforcement:** under `oci` the capsule route's adoption judge
    ///   (`Dispatcher::judge_work_delta_scope`) refuses a `/work` delta writing
    ///   outside the declared globs — see
    ///   [`crate::sandbox::ExecBackend::enforces_declared_write_closure`].
    ///
    /// DELIBERATELY OUTSIDE the runtime-significant contract material and NOT
    /// folded into the stage `contract_hash`: it is a closure DECLARATION,
    /// mirroring how `reads` and `input_schema` sit outside the hashed contract.
    /// Empty is `skip_serializing_if`-omitted. Backend-agnostic (git + jj
    /// worktrees).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub produces_files: Vec<SmolStr>,
    /// What the AUTHOR declared about this stage's execution class —
    /// `execution_requirements=` in Starlark.
    ///
    /// DELIBERATELY OUTSIDE THE RUNTIME-SIGNIFICANT CONTRACT, on the same terms
    /// as `reads` and `produces_files`: it is not folded into
    /// `stage_contract_hash`, it never reaches `ExecutionProgramStage`, and no
    /// runtime verdict reads it. It exists for exactly one door — the compile
    /// check that refuses a declaration disagreeing with the derivation — and it
    /// is spent there.
    ///
    /// That placement IS the design: the derived class stays the single runtime
    /// authority, so a declaration can never widen what a stage is allowed to do.
    /// It can only refuse a build. Carrying it further would create a second
    /// authority over the same fact, which is the duplicate-authority defect this
    /// corpus keeps finding.
    ///
    /// Empty is `skip_serializing_if`-omitted, so a stage that declares nothing
    /// carries nothing for it in `WorkflowDefinition::normalized_hash`.
    #[serde(default, skip_serializing_if = "StageClassDeclaration::is_empty")]
    pub declared_class: StageClassDeclaration,
    /// How this stage's shell/`run=` process EXIT STATUS maps to the stage
    /// terminal. Default [`ShellExitPolicy::ZeroSuccess`]: a nonzero exit FAILS
    /// the stage by name. `#[serde(default,
    /// skip_serializing_if)]` keeps a stage that omits `exit_policy=`
    /// byte-identical on the wire and in `normalized_hash` — the default never
    /// serializes; a non-default policy folds into the stage's checked identity.
    #[serde(default, skip_serializing_if = "ShellExitPolicy::is_zero_success")]
    pub exit_policy: ShellExitPolicy,
}

/// Default retry budget for schema-validation auto-retry.
fn default_validate_retries() -> u32 {
    2
}

/// How (or whether) a stage surfaces mid-execution
/// capsule progress over the SSE wire. See
/// [`StageDefinition::progress_visibility`] for the per-stage
/// surface.
///
/// The privacy ratchet is `Off > Summary > Full` — workflows start
/// with the maximally-conservative default ([`Self::Off`]) and
/// workflow authors must explicitly relax it when they want
/// observability. The default exists because progress
/// frames carry raw model output that some workflows must not
/// leak across the SSE wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressVisibility {
    /// Suppress every progress frame. Default.
    #[default]
    Off,
    /// Emit byte counts plus a short head-of-delta preview. The
    /// preview is truncated at the worker before the frame leaves
    /// the process — operators opting into `summary` are explicitly
    /// trading verbosity for some surface visibility.
    Summary,
    /// Emit the full delta verbatim. Use only when the stage's
    /// streamed reasoning is safe to put on the wire.
    Full,
}

impl ProgressVisibility {
    /// The closed set of visibility variants, in the privacy-ratchet order
    /// (`Off` > `Summary` > `Full`). The single source of truth for the DSL
    /// catalog's `progress_visibility` domain and the load-time decoder's
    /// accepted spellings.
    #[must_use]
    pub const fn variants() -> &'static [Self] {
        &[Self::Off, Self::Summary, Self::Full]
    }

    /// The canonical `snake_case` wire spelling — the SAME token serde emits.
    #[must_use]
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Summary => "summary",
            Self::Full => "full",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StageEdge {
    pub from: StageId,
    pub to: StageId,
    pub condition: Option<EdgeCondition>,
}

/// A `branch` control-flow route — runtime verdict-tag routing
/// on a variant-producing condition stage.
///
/// The condition stage (`condition_stage`) MUST declare `produces=contract(..)`
/// whose field named `verdict_field` is a `variant(..)`. At runtime, after the
/// condition stage completes, the runner reads the externally-tagged variant
/// discriminant from the stage's validated `parsed` output
/// (`parsed[verdict_field]`, a `{"<tag>": payload}` object whose single key is
/// the tag) and routes to the matching arm: the taken arm's `targets` proceed
/// (their `depends_on` on the condition stage is now satisfied), and every other
/// arm's targets are marked `Skipped`.
///
/// The arms' tag set MUST exactly equal the variant's tag set — checked at load
/// time by the builder's exhaustiveness type-check (every variant tag has an arm
/// and no arm names a non-existent tag). This is the typed-branch guarantee: a
/// verdict-producing stage routes only to declared arms.
///
/// Stored in a canonical order (by `condition_stage`, then each arm's `tag`) so
/// author order never changes [`WorkflowDefinition::normalized_hash`].
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BranchRoute {
    /// The variant-producing condition stage whose completion triggers routing.
    pub condition_stage: StageId,
    /// The field name on the condition stage's `produces` contract that carries
    /// the `variant(..)` whose tag selects the arm.
    pub verdict_field: SmolStr,
    /// The routing arms, one per variant tag. Stored in canonical (tag-sorted)
    /// order so author order never changes the definition hash.
    pub arms: Vec<BranchArm>,
}

/// One arm of a [`BranchRoute`]: a verdict tag mapped to the stage targets that
/// run when that tag is the condition stage's discriminant.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct BranchArm {
    /// The variant tag this arm matches.
    pub tag: SmolStr,
    /// Stage targets gated by this tag. Each target depends on the
    /// `condition_stage`; non-taken arms' targets are marked `Skipped` at
    /// runtime.
    pub targets: Vec<StageId>,
}

/// Canonicalize a list of [`BranchRoute`]s into stable hash order so author
/// order never changes [`WorkflowDefinition::normalized_hash`].
///
/// Sorts routes by `condition_stage`, and within each route sorts the arms by
/// `tag`. Arm `targets` keep their author order (the runtime skips the whole
/// arm's subtree, so target order within an arm has no semantic effect, but
/// preserving it keeps the lowering a faithful echo of the source).
#[must_use]
pub fn canonical_order_branch_routes(mut routes: Vec<BranchRoute>) -> Vec<BranchRoute> {
    for route in &mut routes {
        route.arms.sort_by(|a, b| a.tag.cmp(&b.tag));
    }
    routes.sort_by(|a, b| a.condition_stage.cmp(&b.condition_stage));
    routes
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowSourceFormat {
    #[default]
    Starlark,
    Api,
}

/// Source, import, and compiler identity for a checked workflow definition.
///
/// This provenance is attached after frontend parsing and validation. It is
/// intentionally excluded from [`WorkflowDefinition::normalized_hash`] so the
/// normalized identity remains a function of the checked definition itself, not
/// of the source bytes that produced it.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WorkflowDefinitionProvenance {
    /// Frontend source and import evidence.
    pub frontend: WorkflowFrontendProvenance,
    /// Compiler/evaluator identity that produced the checked definition.
    pub compiler: WorkflowCompilerIdentity,
    /// Stable checked-definition identity with random ids, frontend format,
    /// and provenance stripped.
    pub normalized_definition_hash: ContentHash,
}

/// Frontend source and resolved import graph hashes.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WorkflowFrontendProvenance {
    /// Source frontend used to produce the checked definition.
    pub format: WorkflowSourceFormat,
    /// Hash of the exact source bytes presented to the frontend.
    #[serde(default)]
    pub source_hash: Option<ContentHash>,
    /// Hashes of Starlark files resolved through `load()`, keyed by the
    /// authored load path.
    #[serde(default)]
    pub import_hashes: BTreeMap<String, ContentHash>,
}

/// Compiler/evaluator identity for provenance and replay diagnostics.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WorkflowCompilerIdentity {
    /// Checked-definition compiler identity.
    pub compiler: SmolStr,
    /// Frontend evaluator/parser identity.
    pub evaluator: SmolStr,
}

impl Default for WorkflowCompilerIdentity {
    fn default() -> Self {
        Self {
            compiler: SmolStr::new("unknown"),
            evaluator: SmolStr::new("unknown"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub id: WorkflowId,
    pub name: SmolStr,
    pub stages: BTreeMap<StageId, StageDefinition>,
    pub edges: Vec<StageEdge>,
    pub source_format: WorkflowSourceFormat,
    /// Checked-definition provenance populated by parser/evaluator frontends.
    #[serde(default)]
    pub provenance: WorkflowDefinitionProvenance,
    /// Workflow-scoped worker/reviewer iteration loops. Each entry ties
    /// two already-defined stages together with an iteration budget and
    /// on-max policy. See [`crate::review_loop`]. Empty
    /// for workflows that don't declare loops — the runner falls back
    /// to the normal DAG-driven execution.
    #[serde(default)]
    pub review_loops: Vec<ReviewLoop>,
    /// Workflow-local sandbox profiles declared by
    /// `workflow(sandbox_profiles = {"name": sandbox_profile(...)})`. Stages reference these by
    /// name through their [`StageDefinition::sandbox`] field. Empty
    /// for workflows that don't declare any profiles.
    #[serde(default)]
    pub sandbox_profiles: BTreeMap<String, SandboxProfile>,
    /// Cost-budget enforcement (per-execution / workflow-wide scope).
    /// Applies to every stage that doesn't override via
    /// [`StageDefinition::cost_budget`]. Default `Unlimited`.
    #[serde(default)]
    pub cost_budget: crate::budget::BudgetPolicy,
    /// Opt-in per-execution workspace isolation. When `true`, the main
    /// creates the execution's jj workspace (`<jj_repo>/agents/<exec-id>`) at
    /// submit and publishes its committed base as the execution's recorded
    /// `/work` head; capsule deltas land on that candidate, never the
    /// operator's checkout, and reach trunk only through a `promote`. Default
    /// `false`: the execution's `/work` is the canonical empty tree.
    #[serde(default)]
    pub worktree_isolated: bool,
    /// Workflow-scope composable walk-away
    /// [`crate::bound::Bound`]s, lowered from a native `workflow(bounds=[..])`
    /// declaration. Each entry is a kind-tagged guard (a wall-clock `Time` or a
    /// `Cost` ceiling); the list carries at most one bound per kind and is
    /// stored in canonical order (`Time` before `Cost`) so author order never
    /// changes [`Self::normalized_hash`]. Empty for every workflow that omits
    /// `bounds=` — an empty list is skipped from the normalized hash
    /// entirely.
    ///
    /// The runner enforces these as hard durable workflow walk-aways: cost is
    /// checked against accumulated workflow usage and time against total elapsed
    /// wall time from the original execution start. See [`crate::bound`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounds: Vec<crate::bound::Bound>,
    /// `branch` control-flow routes lowered from a native
    /// `branch(on=.., verdict_field=.., arms={..})` declaration. Each route
    /// runtime-routes a variant-producing condition stage's verdict tag to the
    /// taken arm's targets, marking the non-taken arms' targets `Skipped`. The
    /// list is stored in canonical order (by `condition_stage`, then each arm's
    /// `tag`) so author order never changes [`Self::normalized_hash`]. Empty for
    /// every workflow that omits `branch(..)` — an empty list is skipped from the
    /// normalized hash entirely. See
    /// [`BranchRoute`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub branch_routes: Vec<BranchRoute>,
    /// The `parallel` primitive's optional workflow-level concurrency
    /// throttle, lowered from a native `workflow(max_concurrency=N)`
    /// declaration. Caps how many stages the runner dispatches/keeps in flight
    /// CONCURRENTLY across the whole execution. This is a pure SCHEDULING
    /// throttle, not a [`crate::bound::Bound`]: excess ready stages stay Ready
    /// and are submitted as in-flight stages complete; it never fails or
    /// escalates a run, and correctness is unchanged.
    ///
    /// `None` (the default, and the value for every workflow that omits
    /// `max_concurrency=`): the runner submits every ready stage each tick.
    /// Skipped from the normalized hash when `None`. When `Some(n)`,
    /// the DSL enforces `n >= 1`.
    ///
    /// This is distinct from [`StageTopology::max_concurrency`], which caps
    /// dynamic-fanout CHILD invocations within a single stage. Both apply
    /// independently — the workflow-level cap counts ALL in-flight stages,
    /// including loop iterations and fanout children.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
}

/// The stage map as [`WorkflowDefinition::normalized_hash`] hashes it: every
/// [`StageDefinition`] serialized normally EXCEPT [`StageDefinition::authored_span`],
/// which is projected out.
///
/// # Why the exclusion is load-bearing
///
/// `normalized_definition_hash` is the CANONICAL SEMANTIC identity of a checked
/// definition — the answer to "is this the same workflow", which is why the
/// function already excludes the parser-assigned `id`, the frontend
/// `source_format`, and `provenance`. An `authored_span` names the pack BASENAME
/// and the LINE a `stage()` call sits on, so folding it in would make two facts
/// part of definition identity that are not part of the definition:
///
/// * RENAMING a pack file would produce a different definition identity for the
///   same workflow;
/// * RE-INDENTING a pack, or inserting a blank line above a stage, would too.
///
/// Those are the same arguments that keep the span out of the per-stage
/// `contract_hash` in the checked IR. The whole-program hash is a different
/// identity: it commits to the pack's exact source bytes
/// (`ExecutionProgramSource::source_hash` in its material) as well as to the
/// checked stages, span included, so ANY byte edit — a re-indent, a comment —
/// rotates `program_hash` while leaving definition and stage identity alone.
///
/// A stage with no span serializes byte-identically to a plain `&BTreeMap`
/// reference, so every pre-span definition hashes exactly as it did.
struct StagesWithoutSpans<'a>(&'a BTreeMap<StageId, StageDefinition>);

impl Serialize for StagesWithoutSpans<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (stage_id, stage) in self.0 {
            if stage.authored_span.is_none() {
                map.serialize_entry(stage_id, stage)?;
            } else {
                let mut projected = stage.clone();
                projected.authored_span = None;
                map.serialize_entry(stage_id, &projected)?;
            }
        }
        map.end()
    }
}

impl WorkflowDefinition {
    /// Compute the stable normalized-definition hash for this checked
    /// definition.
    ///
    /// The hash excludes `id` because parser-assigned ULIDs are not semantic,
    /// excludes `source_format` because frontend evidence lives in provenance,
    /// and excludes `provenance` because provenance records how the checked
    /// definition was produced.
    ///
    /// By that same rule it excludes each stage's
    /// [`StageDefinition::authored_span`] — see [`StagesWithoutSpans`] for why
    /// that exclusion is load-bearing rather than tidy.
    pub fn normalized_hash(&self) -> Result<ContentHash, serde_json::Error> {
        #[derive(Serialize)]
        struct Normalized<'a> {
            name: &'a SmolStr,
            // Every stage, with `authored_span` projected out — WHERE the author
            // wrote a stage is not part of WHAT the definition is.
            stages: StagesWithoutSpans<'a>,
            edges: &'a [StageEdge],
            review_loops: &'a [ReviewLoop],
            sandbox_profiles: &'a BTreeMap<String, SandboxProfile>,
            cost_budget: crate::budget::BudgetPolicy,
            worktree_isolated: bool,
            // Workflow-scope bounds fold into the normalized identity in
            // canonical order. Skipped when empty (every workflow that omits
            // `bounds=`).
            #[serde(skip_serializing_if = "<[crate::bound::Bound]>::is_empty")]
            bounds: &'a [crate::bound::Bound],
            // Branch routes fold into the normalized identity in canonical
            // order. Skipped when empty (every workflow that omits
            // `branch(..)`).
            #[serde(skip_serializing_if = "<[BranchRoute]>::is_empty")]
            branch_routes: &'a [BranchRoute],
            // The workflow-level concurrency throttle folds into the normalized
            // identity. Skipped when `None` (every workflow that omits
            // `max_concurrency=`).
            #[serde(skip_serializing_if = "Option::is_none")]
            max_concurrency: Option<u32>,
        }

        let normalized = Normalized {
            name: &self.name,
            stages: StagesWithoutSpans(&self.stages),
            edges: &self.edges,
            review_loops: &self.review_loops,
            sandbox_profiles: &self.sandbox_profiles,
            cost_budget: self.cost_budget,
            worktree_isolated: self.worktree_isolated,
            bounds: &self.bounds,
            branch_routes: &self.branch_routes,
            max_concurrency: self.max_concurrency,
        };
        let bytes = serde_json::to_vec(&normalized)?;
        Ok(hash_with_domain(
            b"kata.workflow.normalized_definition.v1",
            &bytes,
        ))
    }

    /// Attach parser/evaluator provenance to a checked definition.
    pub fn attach_provenance(
        &mut self,
        frontend: WorkflowFrontendProvenance,
        compiler: WorkflowCompilerIdentity,
    ) -> Result<(), serde_json::Error> {
        self.provenance = WorkflowDefinitionProvenance {
            frontend,
            compiler,
            normalized_definition_hash: self.normalized_hash()?,
        };
        Ok(())
    }
}

/// Hash exact frontend source bytes under the workflow provenance domain.
#[must_use]
pub fn workflow_source_hash(source: &[u8]) -> ContentHash {
    hash_with_domain(b"kata.workflow.frontend_source.v1", source)
}

/// Hash exact Starlark import bytes under the workflow provenance domain.
#[must_use]
pub fn workflow_import_hash(source: &[u8]) -> ContentHash {
    hash_with_domain(b"kata.workflow.starlark_import.v1", source)
}

fn hash_with_domain(domain: &[u8], body: &[u8]) -> ContentHash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update(&(body.len() as u64).to_le_bytes());
    hasher.update(body);
    let digest = hasher.finalize();
    crate::primitives::FixedBytes::new(*digest.as_bytes())
}
