//! Thread-local workflow graph builder for the native `workflow()` DSL.
//!
//! The `stage()` / `workflow()` builtins let workflow authors describe a
//! workflow as a *typed graph* directly. This module
//! owns the registration-and-drain machinery those builtins share, plus the
//! lowering that turns the drained graph into a [`WorkflowDefinition`].
//!
//! # Why a thread-local is sound here
//!
//! `.star` evaluation runs on a dedicated single OS thread (see
//! `crate::starlark_eval::evaluate_starlark_checked_with`, which spawns one
//! worker thread per evaluation). Each evaluation therefore has the builder all
//! to itself: there is no concurrent `stage()`/`workflow()` interleaving across
//! evaluations, so a `thread_local!` cell carrying the in-progress graph is both
//! safe and deterministic. The builder is reset at the start of evaluation
//! (`reset_workflow_builder`) and read back after evaluation
//! (`take_drained_workflow`), so even a thread reused for a later evaluation
//! starts from a clean slate.
//!
//! # Registration vs. drain
//!
//! * `stage(...)` *registers* a [`StageNode`] into the thread-local builder in
//!   call order. Its stable id is the explicit `id=` argument, or
//!   `stage_<index>` derived from the 0-based registration order when omitted.
//!   It returns a lightweight [`StageRef`] frozen value carrying that id.
//! * `workflow(name, root=..)` is the single *drain* point. It records the
//!   workflow metadata (name, description, ordered root stage ids) into the
//!   builder, marks it drained, and returns a [`Workflow`] frozen value. The
//!   evaluator then calls [`take_drained_workflow`] to pull the assembled graph
//!   out and lower it.
//!
//! # Determinism
//!
//! Stage iteration order in the lowered [`WorkflowDefinition`] is fixed by the
//! `BTreeMap<StageId, _>` key order. Edge order
//! is fixed by iterating registered stages in registration order and emitting
//! one edge per `depends_on` entry in author order. No clock, RNG, or hash-map
//! iteration influences the lowered structure, so the same source always lowers
//! to the same normalized definition.

use std::cell::RefCell;
use std::collections::BTreeMap;

use kata_types::review_loop::{OnMaxAction, ReviewLoop};
use kata_types::workflow::{
    AgentSelector, StageDefinition, StageEdge, StageId, StageInput, WorkflowDefinition, WorkflowId,
    WorkflowSourceFormat,
};
use kata_types::{KataError, KataResult};
use smol_str::SmolStr;
use ulid::Ulid;

use crate::policy::WorkflowExtensions;

/// One registered stage node, captured by `stage()` before drain.
#[derive(Clone, Debug)]
pub(crate) struct StageNode {
    /// Stable stage id (explicit `id=` or `stage_<index>`).
    pub(crate) id: String,
    /// Prompt template rendered to the worker.
    pub(crate) prompt: String,
    /// Agent selector spelling (mapped to [`AgentSelector`] at lowering).
    pub(crate) agent: String,
    /// Upstream stage ids this stage depends on, in author order.
    pub(crate) depends_on: Vec<String>,
    /// The constrained JSON-Schema generated from a
    /// `produces=contract(..)` declaration, lowered to
    /// [`StageDefinition::output_schema`]. `None` when the stage omits
    /// `produces=`. The schema is exactly what
    /// `kata_types::agent_run::validate_agent_run_output_schema` accepts.
    pub(crate) produces_schema: Option<serde_json::Value>,
    /// The constrained JSON-Schema generated from a
    /// `consumes=contract(..)` declaration, compared against the upstream
    /// producer by the load-time type-checker. `None` when the stage omits
    /// `consumes=`. Plumbed onto [`StageDefinition::input_schema`].
    pub(crate) consumes_schema: Option<serde_json::Value>,
    /// The declared contract NAME from `produces=contract(..)`
    /// (the `name` passed to `contract(name, ..)`), threaded purely so the
    /// type-checker can name the producer's contract in its error message.
    /// `None` iff [`produces_schema`](Self::produces_schema) is `None`.
    pub(crate) produces_name: Option<String>,
    /// The declared contract NAME from `consumes=contract(..)`,
    /// threaded for the type-checker's error message. `None` iff
    /// [`consumes_schema`](Self::consumes_schema) is `None`.
    pub(crate) consumes_name: Option<String>,
    /// The flat scalar/simple-value field surface, lowered
    /// 1:1 onto the matching [`StageDefinition`] fields. Each carries the SAME
    /// default the lowering applies when its kwarg is unset. The
    /// decode/validation routes through the shared `parser::normalize_stage_*`
    /// helpers.
    pub(crate) flat: StageFlatFields,
    /// Which higher-level construct SYNTHESIZED this stage, when the author did
    /// not write it. `None` for every authored `stage()`; `Some` only at the one
    /// mint site that creates a stage on the author's behalf (today
    /// `register::parallel`'s fan-in barrier). Lowered 1:1 onto
    /// [`kata_types::workflow::StageDefinition::synthesized`], which is where the
    /// rationale lives.
    ///
    /// Deliberately on the NODE rather than in [`StageFlatFields`]: the flat
    /// surface is the authored kwarg surface, and `StageFlatFields::join_default`
    /// is inherited via `..` by the subworkflow and sleep defaults — a marker
    /// placed there would silently claim those stages are parallel barriers too.
    pub(crate) synthesized: Option<kata_types::workflow::SynthesizedStage>,
    /// The `pack.star:LINE:COL` call site of the builtin that declared this stage,
    /// resolved by `graph_globals::dsl_span_from_eval` at the call and lowered 1:1
    /// onto [`kata_types::workflow::StageDefinition::authored_span`], which holds
    /// the rationale. For the synthesized `parallel()` barrier this is the
    /// `parallel()` call's own span — the call that minted it.
    ///
    /// `None` when no Starlark frame resolves. Deliberately on the NODE rather
    /// than in [`StageFlatFields`], for the same reason as
    /// [`Self::synthesized`]: the flat surface is the authored KWARG surface, and
    /// a span is not a kwarg.
    pub(crate) authored_span: Option<kata_types::source::SourceSpan>,
}

/// The FLAT (scalar / simple-value) stage field surface the
/// native `stage()` builtin accepts, captured before lowering.
///
/// Every field defaults to the value the normalized JSON shape uses when a
/// field is omitted. The structured constructors (topology / sandbox / memory /
/// validation / channels / human-requests) are deliberately NOT here.
#[derive(Clone, Debug)]
pub(crate) struct StageFlatFields {
    /// `execution_requirements=` — the AUTHORED execution-class claim
    /// Default-empty means the author said
    /// nothing, which is never compared and can never refuse.
    pub(crate) declared_class: kata_types::execution_class::StageClassDeclaration,
    /// `model_hint=` (empty string → `None`). Validated/trimmed by
    /// [`crate::parser::normalize_stage_model_hint`] at lowering.
    pub(crate) model_hint: Option<String>,
    /// `timeout_ms=` (`0` → `None`, i.e. the AUTHOR declared nothing). Resolved
    /// by [`crate::parser::resolve_stage_timeout_ms`] at lowering, which is
    /// where `None` becomes `DEFAULT_STAGE_TIMEOUT_MS` — this field is the
    /// authored spelling, so it stays `Option`.
    pub(crate) timeout_ms: Option<u64>,
    /// `output_bytes=` / `work_delta_bytes=` / `work_delta_entries=` (`0` →
    /// `None`, the same omitted sentinel `timeout_ms` uses). They stay `Option`
    /// at every layer — an unauthored stage serializes none of them and the
    /// checked IR of a pack that authors none of them carries no such field.
    pub(crate) output_bytes: Option<u64>,
    pub(crate) work_delta_bytes: Option<u64>,
    pub(crate) work_delta_entries: Option<u32>,
    /// `allowed_tools=` (empty list → empty `Vec`). Validated by
    /// [`crate::parser::normalize_stage_allowed_tools`] at lowering.
    pub(crate) allowed_tools: Vec<String>,
    /// `required_capabilities=` (empty list → empty `Vec`). Trimmed/sorted/
    /// deduped by [`crate::parser::normalize_stage_required_capabilities`].
    pub(crate) required_capabilities: Vec<String>,
    /// `outputs=` flat `{name: "type-label"}` (empty dict → empty `Vec`),
    /// lowered to [`kata_types::workflow::StageOutput`] in declaration order.
    pub(crate) outputs: Vec<(String, String)>,
    /// `cache_policy=` (already decoded from the shared serde spelling to
    /// the typed enum; unset → [`kata_types::cache::CachePolicy::default`]).
    pub(crate) cache_policy: kata_types::cache::CachePolicy,
    /// `validate_retries=` (unset → 2, matching `default_validate_retries`).
    pub(crate) validate_retries: u32,
    /// `validate_feedback_template=` (empty string → `None`).
    pub(crate) validate_feedback_template: Option<String>,
    /// `approval=` (unset → false).
    pub(crate) approval: bool,
    /// `approval_reason=` (empty string → `None`).
    pub(crate) approval_reason: Option<String>,
    /// `cost_budget=` raw JSON of the `{mode, limit_usd}` dict (unset →
    /// `None`), routed through [`crate::parser::normalize_budget_value`] at
    /// lowering through the shared normalized JSON helper.
    pub(crate) cost_budget: Option<serde_json::Value>,
    /// `progress_visibility=` (already decoded from the shared serde string
    /// spelling; unset → [`kata_types::ProgressVisibility::default`]).
    pub(crate) progress_visibility: kata_types::ProgressVisibility,
    /// `topology=topology(..)` raw JSON of the topology
    /// shape (unset → `None`), routed through
    /// [`crate::starlark_eval::topology_from_json`] at lowering, producing the
    /// canonical [`kata_types::workflow::StageTopology`].
    pub(crate) topology: Option<serde_json::Value>,
    /// `sandbox=` raw JSON — a bare string (names a
    /// workflow profile) or an inline `sandbox_profile(..)` object (unset →
    /// `None`), routed through [`crate::starlark_eval::sandbox_ref_from_json`]
    /// at lowering through the canonical normalized JSON decoder, producing a
    /// [`kata_types::sandbox::SandboxRef`].
    pub(crate) sandbox: Option<serde_json::Value>,
    /// Factory-as-loop foundation: the workspace-effect declaration lowered
    /// from `stage(agent="workspace_effect", op=…, label=…)`. `None` for every
    /// non-effect stage, so the lowered [`StageDefinition::workspace_effect`]
    /// stays `None` → omitted from serialization → byte-identical packs.
    pub(crate) workspace_effect: Option<kata_types::workflow::WorkspaceEffect>,
    /// The subworkflow pack reference lowered from `subworkflow(pack=..)`.
    /// `None` for every ordinary `stage()`, so the lowered
    /// [`StageDefinition::subworkflow`] stays `None` → omitted from serialization
    /// → byte-identical packs. When `Some`, the compiler carries it onto the
    /// checked-IR marker `ExecutionProgramStage::subworkflow` and the runner
    /// spawns a child workflow execution instead of dispatching to a worker.
    pub(crate) subworkflow: Option<kata_types::workflow::SubworkflowRef>,
    /// The durable-sleep marker lowered from `sleep(for_ms=..|until_ms=..)`.
    /// `None` for every ordinary `stage()`, so the lowered
    /// [`StageDefinition::durable_sleep`] stays `None` → omitted from serialization
    /// → byte-identical packs. When `Some`, the compiler carries it onto the
    /// checked-IR marker `ExecutionProgramStage::durable_sleep` and the runner
    /// parks the stage on a durable main-side timer instead of dispatching it.
    pub(crate) durable_sleep: Option<kata_types::workflow::DurableSleepSpec>,
    /// The memory-snapshot marker lowered from
    /// `memory_snapshot(kind=.., status=..)`. `None` for every ordinary
    /// `stage()`, so the lowered [`StageDefinition::memory_snapshot`] stays
    /// `None` → omitted from serialization → byte-identical packs. When `Some`,
    /// the compiler carries it onto the checked-IR marker
    /// `ExecutionProgramStage::memory_snapshot` and the runner resolves the
    /// stage MAIN-SIDE against the node's memory store instead of dispatching
    /// to a worker.
    pub(crate) memory_snapshot: Option<kata_types::workflow::MemorySnapshotSpec>,
    /// The stage's DECLARED read-closure globs
    /// lowered from `stage(reads=[..])`. Empty for every stage that omits
    /// `reads=`, so the lowered [`StageDefinition::reads`] stays empty → omitted
    /// from serialization → byte-identical packs.
    pub(crate) reads: Vec<String>,
    /// The stage's DECLARED output-file closure
    /// globs lowered from `stage(produces_files=[..])`. Empty for every stage
    /// that omits `produces_files=`, so the lowered
    /// [`StageDefinition::produces_files`] stays empty → omitted from
    /// serialization → byte-identical packs. The OUTPUT analog of [`Self::reads`].
    pub(crate) produces_files: Vec<String>,
    /// The ordered agent fallback panel (primary first) lowered from
    /// `stage(agent=[..])`. Empty for a single-agent stage (the scalar
    /// `agent="x"` spelling), so lowering keeps `Any`/`Labelled`. A panel with
    /// two or more members lowers to
    /// [`kata_types::workflow::AgentSelector::Panel`]; its first element mirrors
    /// the [`StageNode::agent`] primary.
    pub(crate) agent_panel: Vec<String>,
    /// The shell EXIT POLICY decoded from `stage(exit_policy=..)`.
    /// [`kata_types::workflow::ShellExitPolicy::ZeroSuccess`] (the default) for
    /// every stage that omits it, so the lowered
    /// [`StageDefinition::exit_policy`] stays at the default → omitted from
    /// serialization → byte-identical packs. This field is set from
    /// `ShellExitPolicy::default()` and follows it rather than naming a variant.
    pub(crate) exit_policy: kata_types::workflow::ShellExitPolicy,
}

impl StageFlatFields {
    /// The flat-field surface of a synthetic `parallel()` JOIN/barrier stage.
    ///
    /// A join carries no author-supplied surface: it is a deterministic shell
    /// no-op whose only job is to fan in (`depends_on` all branch exits) so a
    /// downstream node can wait for every branch. Every field is the value the
    /// lowering applies when its kwarg is unset, so the synthetic stage lowers
    /// byte-identically to a minimal authored shell stage and never perturbs the
    /// determinism boundary: `cache_policy` is the default `Omitted` (the
    /// `#[default]`, so the join matches an unauthored stage; clause 4 tests an
    /// AUTHORED `ContentCache`), no contract/topology/sandbox.
    fn join_default() -> Self {
        Self {
            declared_class: kata_types::execution_class::StageClassDeclaration::default(),
            model_hint: None,
            timeout_ms: None,
            output_bytes: None,
            work_delta_bytes: None,
            work_delta_entries: None,
            allowed_tools: Vec::new(),
            required_capabilities: Vec::new(),
            outputs: Vec::new(),
            cache_policy: kata_types::cache::CachePolicy::default(),
            // Mirrors `kata_types::workflow::default_validate_retries()` (private)
            // and the `stage()` builtin's `VALIDATE_RETRIES_DEFAULT`. A join is a
            // deterministic no-op with no `produces=`, so retries never fire.
            validate_retries: 2,
            validate_feedback_template: None,
            approval: false,
            approval_reason: None,
            cost_budget: None,
            progress_visibility: kata_types::ProgressVisibility::default(),
            topology: None,
            sandbox: None,
            workspace_effect: None,
            subworkflow: None,
            // A synthetic join/subworkflow stage is not a durable sleep.
            durable_sleep: None,
            memory_snapshot: None,
            // A synthetic join/subworkflow stage declares no read-closure.
            reads: Vec::new(),
            produces_files: Vec::new(),
            // A synthetic join/subworkflow stage declares no agent panel.
            agent_panel: Vec::new(),
            // A synthetic join/subworkflow/sleep stage is a deterministic
            // no-op; the default `ZeroSuccess` exit policy is omitted from
            // serialization, so it keeps the stage byte-identical.
            exit_policy: kata_types::workflow::ShellExitPolicy::default(),
        }
    }

    /// The flat-field surface of a `subworkflow(pack=..)` stage.
    ///
    /// Identical to [`Self::join_default`] in every field EXCEPT `subworkflow`,
    /// which carries the child-pack reference. The compiler lowers that onto the
    /// checked-IR `ExecutionProgramStage::subworkflow` marker; leaving every other
    /// field at its unset-default keeps the stage byte-identical to a minimal
    /// stage in all other respects (no produces/consumes, no topology/sandbox, the
    /// default `Omitted` cache policy so it never trips the determinism-boundary
    /// content-addressed-cache check).
    fn subworkflow_default(subworkflow: kata_types::workflow::SubworkflowRef) -> Self {
        Self {
            subworkflow: Some(subworkflow),
            ..Self::join_default()
        }
    }

    /// The flat-field surface of a `sleep(for_ms=..|until_ms=..)` stage.
    ///
    /// Identical to [`Self::join_default`] in every field EXCEPT `durable_sleep`,
    /// which carries the resolved wake target. The `agent="shell"`/`prompt=":"`
    /// body is inert: the marker lowers the stage to `RuntimeOperation::Wait`, the
    /// main parks it as an `awaiting_timer` main attempt and accepts it when the
    /// deadline is due, and the body never runs — which is why its class is R2's
    /// `WaitForInput` row (`StagePayload::MainResolved`), not the shell op's.
    /// Every other field stays at its unset-default (no
    /// produces/consumes, no topology/sandbox, the default `Omitted` cache policy
    /// so it never trips the determinism-boundary content-addressed-cache check).
    fn sleep_default(durable_sleep: kata_types::workflow::DurableSleepSpec) -> Self {
        Self {
            durable_sleep: Some(durable_sleep),
            ..Self::join_default()
        }
    }

    /// The flat-field surface of a `memory_snapshot(kind=.., status=..)` stage.
    ///
    /// Identical to [`Self::join_default`] in every field EXCEPT
    /// `memory_snapshot`, which carries the authored filter, `outputs`, which
    /// declares the snapshot envelope's fields (so the accepted
    /// `{"content": <snapshot JSON>}` validates and injects `parsed` for
    /// downstream `{{ stages.<id>.parsed.objects }}` reads — the same shape
    /// `kata memory snapshot` prints), `cache_policy`, which
    /// stays `Disabled` because a snapshot answers live memory state and never
    /// a content key, and `progress_visibility`, which is `summary`. The `agent="shell"` /
    /// `run=":"` surface is inert placeholder text: on every profile the marker
    /// diverts the stage to its main-side resolution before any body could
    /// dispatch.
    fn memory_snapshot_default(memory_snapshot: kata_types::workflow::MemorySnapshotSpec) -> Self {
        Self {
            memory_snapshot: Some(memory_snapshot),
            outputs: vec![
                ("schema_version".to_owned(), "u32".to_owned()),
                ("generated_at_ms".to_owned(), "u64".to_owned()),
                ("revision_head".to_owned(), "u64".to_owned()),
                ("object_count".to_owned(), "u32".to_owned()),
                ("objects".to_owned(), "array".to_owned()),
            ],
            cache_policy: kata_types::cache::CachePolicy::Disabled,
            progress_visibility: kata_types::ProgressVisibility::Summary,
            ..Self::join_default()
        }
    }
}

/// Assembled workflow metadata recorded at `workflow()` drain time.
#[derive(Clone, Debug)]
pub(crate) struct WorkflowMeta {
    pub(crate) name: String,
    /// Surfaced through [`PackMetadata`] at drain time (see
    /// `lower::take_drained_workflow`): pack discovery
    /// (`WorkflowLibrary` / `kata workflows list`) reads it back.
    pub(crate) description: Option<String>,
    /// Root stage ids in author-declared order. Used only to confirm the
    /// referenced stages exist; the DAG itself is expressed via each stage's
    /// `depends_on`.
    #[allow(dead_code)]
    pub(crate) root: Vec<String>,
    /// Optional pack version string from `workflow(version=..)`.
    /// A free-form authored label — kata does not interpret or enforce semver
    /// ordering. `None` for packs that omit `version=`.
    pub(crate) version: Option<String>,
    /// Free-form discovery tags from `workflow(tags=[..])`,
    /// author order preserved. Empty when omitted.
    pub(crate) tags: Vec<String>,
    /// The typed parameter schema from
    /// `workflow(params={name: field(..) | "type"})` — an ordered set of
    /// [`kata_types::params::WorkflowParamSpec`]s (canonical name order). Not a
    /// discovery-only surface: lowering threads these onto
    /// [`WorkflowExtensions::params`] so they ride the checked program and become
    /// enforced, digest-bound invocation inputs, and derives the discovery
    /// `(name, type-label)` projection onto `PackMetadata`. Empty when omitted.
    pub(crate) params: Vec<kata_types::params::WorkflowParamSpec>,
    /// Workflow-wide `cost_budget=` raw JSON of the
    /// `{mode, limit_usd}` dict (unset → `None`), routed through
    /// [`crate::parser::normalize_budget_value`] at lowering.
    pub(crate) cost_budget: Option<serde_json::Value>,
    /// `worktree_isolated=` (unset → false), lowered onto
    /// [`WorkflowDefinition::worktree_isolated`].
    pub(crate) worktree_isolated: bool,
    /// `sandbox_profiles={name: sandbox_profile(..)}` raw
    /// JSON keyed by profile name (unset → empty map). Each value is decoded
    /// through [`crate::starlark_eval::sandbox_profile_from_json`] at lowering
    /// into [`WorkflowDefinition::sandbox_profiles`]. A `BTreeMap` preserves
    /// deterministic key order for the normalized hash.
    pub(crate) sandbox_profiles: BTreeMap<String, serde_json::Value>,
    /// The workflow-level orchestration-extension section
    /// JSON captured from `workflow()`'s extension kwargs (memory selectors /
    /// writebacks, validation criteria, external input channels, human requests,
    /// workflow pattern). Lowered through the shared
    /// [`crate::parser::normalize_extensions_from_json`] into a
    /// [`WorkflowExtensions`]. Default (every field `None`) lowers to
    /// [`WorkflowExtensions::empty`].
    pub(crate) extensions: WorkflowExtensionsJson,
    /// Workflow-scope composable walk-away
    /// [`kata_types::bound::Bound`]s from `workflow(bounds=[..])`, already
    /// value-validated (`ms > 0`, `usd > 0`) by the `time_bound`/`cost_bound`
    /// constructors. The per-kind-uniqueness invariant and canonical ordering
    /// are enforced at drain via [`kata_types::bound::validate_bounds`], and the
    /// result lowers 1:1 onto [`WorkflowDefinition::bounds`]. Empty when
    /// `bounds=` is unset, leaving the normalized hash unchanged.
    ///
    /// The runner enforces these as durable workflow walk-aways: cost against
    /// accumulated workflow usage and time against the original execution start.
    pub(crate) bounds: Vec<kata_types::bound::Bound>,
    /// `branch` control-flow routes from `branch(..)` calls,
    /// already DSL-validated (known condition stage, known arm targets, known
    /// verdict field) and arm-target dependency-wired at registration. The
    /// load-time exhaustiveness type-check ([`check_branch_routes`]) runs at
    /// drain; the result lowers 1:1 (in canonical order) onto
    /// [`WorkflowDefinition::branch_routes`]. Empty when the author declares no
    /// `branch(..)`, leaving the normalized hash unchanged.
    pub(crate) branch_routes: Vec<BranchNode>,
    /// Workflow-level concurrency throttle from
    /// `workflow(max_concurrency=N)`. `None` when unset (unthrottled);
    /// `Some(n)` with `n >= 1` (the `0` rejection is enforced at the
    /// `workflow()` builtin before drain). Lowers 1:1 onto
    /// [`WorkflowDefinition::max_concurrency`].
    pub(crate) max_concurrency: Option<u32>,
}

/// The workflow-level orchestration-extension surface the
/// native `workflow()` builtin now accepts, captured as normalized section JSON
/// before lowering.
///
/// Each field uses the `Raw*` JSON shape that
/// [`crate::parser::normalize_extensions_from_json`] deserializes, or `None`
/// when the corresponding `workflow()` kwarg is unset. Lowering routes each
/// `Some` value through that one normalizer to produce canonical
/// [`WorkflowExtensions`]. A `workflow()` that declares no extensions leaves
/// every field `None`, yielding [`WorkflowExtensions::empty`].
#[derive(Clone, Debug, Default)]
pub(crate) struct WorkflowExtensionsJson {
    pub(crate) human_request_queue: Option<serde_json::Value>,
    pub(crate) external_input_channels: Option<serde_json::Value>,
    pub(crate) memory_selectors: Option<serde_json::Value>,
    pub(crate) memory_writebacks: Option<serde_json::Value>,
    pub(crate) validation_criteria: Option<serde_json::Value>,
    pub(crate) workflow_pattern: Option<serde_json::Value>,
}

impl WorkflowExtensionsJson {
    /// Lower the captured section JSON through
    /// [`crate::parser::normalize_extensions_from_json`], producing canonical
    /// [`WorkflowExtensions`]. When
    /// every field is `None` this is exactly [`WorkflowExtensions::empty`].
    fn lower(&self) -> KataResult<WorkflowExtensions> {
        crate::parser::normalize_extensions_from_json(
            self.human_request_queue.as_ref(),
            self.external_input_channels.as_ref(),
            self.memory_selectors.as_ref(),
            self.memory_writebacks.as_ref(),
            self.validation_criteria.as_ref(),
            self.workflow_pattern.as_ref(),
        )
    }
}

/// One review loop recorded by `loop()` before drain.
///
/// `loop(body=<stage>, gate=<stage>, ..)` lowers onto kata's
/// [`ReviewLoop`] runtime (gate-as-stage): `body` is the worker (exit) stage,
/// `gate` is the reviewer stage; a multi-stage body is recorded in
/// `body_stages`.
#[derive(Clone, Debug)]
pub(crate) struct LoopNode {
    /// Worker stage id (the `body=` stage).
    pub(crate) worker_id: String,
    /// Reviewer stage id (the `gate=` stage). Must list `worker_id` in its
    /// `depends_on` — enforced by [`drain_workflow`] for a DSL-shaped error and
    /// re-checked by the shared `validate_review_loops`.
    pub(crate) reviewer_id: String,
    /// Iteration ceiling lowered to [`ReviewLoop::max_iterations`]. `>= 1`.
    pub(crate) max_iterations: u32,
    /// Exhaustion action lowered to [`ReviewLoop::on_max`].
    pub(crate) on_max: OnMaxAction,
    /// Loop-scope composable
    /// walk-away [`kata_types::bound::Bound`]s from `loop(bounds=[..])`, already
    /// value-validated (`ms > 0`, `usd > 0`) by the `time_bound`/`cost_bound`
    /// constructors and made per-kind-unique + canonically ordered by
    /// [`kata_types::bound::validate_bounds`] at `register_loop`. Lowers 1:1 onto
    /// [`ReviewLoop::bounds`]. Empty when `bounds=` is unset, leaving the
    /// normalized hash unchanged.
    ///
    /// The review-loop runner folds cumulative usage and elapsed time across
    /// iterations, checks these bounds before further dispatch, and resolves a
    /// trip through the configured `on_max` walk-away path. Resume reconstructs
    /// the cumulative state rather than resetting either ceiling.
    pub(crate) bounds: Vec<kata_types::bound::Bound>,
    /// An OPTIONAL custom gate verdict
    /// vocabulary from `loop(gate_verdict={..})`, already validated (non-empty
    /// field + disjoint non-empty tag-sets) by
    /// [`kata_types::review_loop::LoopVerdictConfig::new`] at `register_loop`.
    /// Lowers 1:1 onto [`ReviewLoop::gate_verdict`]. `None` when `gate_verdict=`
    /// is unset ⇒ the default vocabulary.
    pub(crate) gate_verdict: Option<kata_types::review_loop::LoopVerdictConfig>,
    /// The ordered body sub-DAG member ids (entry …
    /// exit). EMPTY for a single-stage body — the body is just `worker_id`,
    /// lowering to an empty [`ReviewLoop::body_stages`] (byte-identical). When
    /// non-empty the LAST element equals `worker_id` (the body's exit stage),
    /// enforced at `register_loop`. Lowers 1:1 onto [`ReviewLoop::body_stages`].
    pub(crate) body_stages: Vec<String>,
    /// Continue-as-new: the loop-scope context-budget rollover window from
    /// `loop(rollover_after_iterations=N)`, already validated (`>= 1`) at
    /// `register_loop`. Lowers 1:1 onto
    /// [`kata_types::review_loop::ReviewLoop::rollover_after_iterations`]. `None`
    /// when unset ⇒ the runtime default is applied (rollover is ON BY DEFAULT).
    pub(crate) rollover_after_iterations: Option<u32>,
}

/// One branch route recorded by `branch()` before drain.
///
/// `branch(on=<condition>, verdict_field=<str>, arms={<tag>: <targets>})` routes
/// the condition stage's variant verdict tag to the taken arm's targets at
/// runtime, marking the non-taken arms' targets `Skipped`. The condition stage
/// must `produces=contract(..)` a `variant(..)` field named `verdict_field`; the
/// arms' tag set must exactly equal that variant's tag set — both checked at
/// drain by [`check_branch_routes`].
#[derive(Clone, Debug)]
pub(crate) struct BranchNode {
    /// The variant-producing condition stage id (`on=`).
    pub(crate) condition_id: String,
    /// The `produces` contract field carrying the `variant(..)` (`verdict_field=`).
    pub(crate) verdict_field: String,
    /// Author-ordered arms: `(tag, [target stage ids])`. Each target was wired to
    /// `depends_on` the condition stage at `branch()` registration.
    pub(crate) arms: Vec<(String, Vec<String>)>,
}

/// In-progress workflow graph for a single `.star` evaluation.
#[derive(Default)]
pub(crate) struct WorkflowBuilder {
    /// Registered stages in call order.
    stages: Vec<StageNode>,
    /// Review loops recorded by `loop()` in call order.
    loops: Vec<LoopNode>,
    /// Ordered member lists of `sequence(..)`
    /// handles, keyed by the sequence's TAIL stage id (the value `sequence(..)`
    /// returns). Lets `loop(body=sequence(a, b, c))` recover the full ordered
    /// body `[a, b, c]` from the tail handle alone. A later `sequence(..)` over
    /// a prior tail composes naturally — the most recent registration for a tail
    /// wins, capturing the widest body the author chained through that handle.
    sequence_members: std::collections::HashMap<String, Vec<String>>,
    /// Branch routes recorded by `branch()` in call order.
    branches: Vec<BranchNode>,
    /// Count of synthetic JOIN/barrier stages registered by
    /// `parallel()`, used to mint each join a stable, collision-free id
    /// (`__parallel_join_<n>`) in registration order. A pure counter keyed on
    /// call order keeps the id deterministic (no clock/RNG), so two evaluations
    /// of the same module mint identical join ids and hash identically.
    parallel_joins: usize,
    /// Recorded at `workflow()` drain. `Some` once drained.
    meta: Option<WorkflowMeta>,
}

thread_local! {
    /// Per-evaluation workflow graph. `None` until the first `stage()` call (or
    /// an explicit reset) initializes it.
    static WORKFLOW_BUILDER: RefCell<Option<WorkflowBuilder>> = const { RefCell::new(None) };

    /// Per-evaluation durable-schedule registry. Each
    /// module-scope `schedule(...)` call appends its validated
    /// [`crate::schedule::ScheduleSpec`] here in call order; the evaluator drains
    /// it after `eval_module` via [`take_registered_schedules`] and attaches the
    /// specs to the [`crate::parser::CheckedWorkflowDefinition`] so boot can
    /// install them through `kata_workflow::schedule::ScheduleFace` into
    /// `operational.db`'s schedule tables. Reset
    /// alongside the graph builder so a reused worker thread never leaks
    /// schedules across evaluations, and isolated across `load()` (a loaded
    /// helper module's schedules do NOT leak into the importer's pack — same
    /// rule as `stage()`/`workflow()`).
    static SCHEDULE_REGISTRY: RefCell<Vec<crate::schedule::ScheduleSpec>> =
        const { RefCell::new(Vec::new()) };
}

/// Clear any builder state left over from a previous evaluation on this thread.
///
/// Called by the evaluator before each `eval_module` so a reused worker thread
/// never sees a stale graph.
pub(crate) fn reset_workflow_builder() {
    WORKFLOW_BUILDER.with(|cell| *cell.borrow_mut() = None);
    SCHEDULE_REGISTRY.with(|cell| cell.borrow_mut().clear());
}

/// Append a validated durable schedule declared by a module-scope `schedule(...)`
/// call into the per-evaluation registry. Called by the
/// `schedule()` builtin so the drained specs reach [`take_registered_schedules`].
pub(crate) fn register_schedule(spec: crate::schedule::ScheduleSpec) {
    SCHEDULE_REGISTRY.with(|cell| cell.borrow_mut().push(spec));
}

/// Drain the durable schedules registered during this evaluation, in call order.
/// Called by the evaluator after `eval_module` (mirrors [`take_drained_workflow`]
/// for the graph). Leaves the registry empty.
pub(crate) fn take_registered_schedules() -> Vec<crate::schedule::ScheduleSpec> {
    SCHEDULE_REGISTRY.with(|cell| std::mem::take(&mut *cell.borrow_mut()))
}

/// True when the thread-local registry holds any schedule registered during this
/// evaluation — i.e. some module called `schedule()` at module scope.
///
/// The `load()` gate reads this (alongside [`workflow_builder_touched`]) so a
/// `load()`ed helper module that (wrongly) declares a durable `schedule(...)` at
/// module scope fails LOUDLY, exactly like `stage()`/`workflow()` in that
/// position, rather than having its schedule silently discarded on guard drop.
pub(crate) fn schedule_registered() -> bool {
    SCHEDULE_REGISTRY.with(|cell| !cell.borrow().is_empty())
}

/// Snapshot the thread-local builder and clear it for the duration of a nested
/// `load()` evaluation, restoring it when the returned guard drops.
///
/// `load()`ed modules evaluate on the same thread and share the same
/// `stage()`/`workflow()` builtins, so without isolation a loaded module that
/// called those builtins at module scope would register into the *top-level
/// file's* graph and silently corrupt it. The loader wraps each imported-module
/// eval in this guard and rejects any load target that leaves the builder
/// [`workflow_builder_touched`]. The durable-schedule registry is isolated the
/// same way, so a loaded helper module's `schedule(...)` declarations never leak
/// into the importer's pack.
pub(crate) fn isolate_for_load() -> LoadIsolationGuard {
    let saved = WORKFLOW_BUILDER.with(|cell| cell.borrow_mut().take());
    // The load-time diagnostics sink is per-evaluation thread-local state
    // too. Snapshot + clear it so any authoring diagnostic a loaded module
    // records is attributed to that module's (rejected) load rather than leaking
    // into the importer's collected report.
    let saved_diagnostics = super::diagnostics::snapshot_and_clear();
    let saved_schedules = SCHEDULE_REGISTRY.with(|cell| std::mem::take(&mut *cell.borrow_mut()));
    LoadIsolationGuard {
        saved,
        saved_diagnostics,
        saved_schedules,
    }
}

/// RAII guard from [`isolate_for_load`]; restores the snapshotted builder when
/// it drops (including on the error-unwind path), so the importer's graph is
/// never affected by what a loaded module did.
pub(crate) struct LoadIsolationGuard {
    saved: Option<WorkflowBuilder>,
    saved_diagnostics: Vec<super::diagnostics::SpannedDiagnostic>,
    saved_schedules: Vec<crate::schedule::ScheduleSpec>,
}

impl Drop for LoadIsolationGuard {
    fn drop(&mut self) {
        let saved = self.saved.take();
        WORKFLOW_BUILDER.with(|cell| *cell.borrow_mut() = saved);
        super::diagnostics::restore(std::mem::take(&mut self.saved_diagnostics));
        let saved_schedules = std::mem::take(&mut self.saved_schedules);
        SCHEDULE_REGISTRY.with(|cell| *cell.borrow_mut() = saved_schedules);
    }
}

/// True when the thread-local builder holds any registered stage or a drained
/// workflow — i.e. some module called `stage()`/`workflow()`.
pub(crate) fn workflow_builder_touched() -> bool {
    WORKFLOW_BUILDER.with(|cell| {
        cell.borrow().as_ref().is_some_and(|builder| {
            !builder.stages.is_empty()
                || !builder.loops.is_empty()
                || !builder.branches.is_empty()
                || builder.meta.is_some()
        })
    })
}

mod lower;
mod register;
mod validate;

pub(crate) use lower::*;
pub(crate) use register::*;
pub(crate) use validate::*;

#[cfg(test)]
mod schedule_registry_tests {
    use super::{
        isolate_for_load, register_schedule, reset_workflow_builder, take_registered_schedules,
    };
    use crate::schedule::{ScheduleSpec, ScheduleTrigger};

    fn spec(id: &str) -> ScheduleSpec {
        ScheduleSpec {
            id: id.to_owned(),
            submit_pack: "p".to_owned(),
            trigger: ScheduleTrigger::Interval { every_ms: 1_000 },
            on_missed: crate::schedule::MissedPolicy::FireOnceOnBoot,
            params: serde_json::Map::new(),
        }
    }

    /// `register_schedule` accumulates in call order; `take_registered_schedules`
    /// drains it and leaves the registry empty.
    #[test]
    fn register_then_take_drains_in_order() {
        reset_workflow_builder();
        register_schedule(spec("a"));
        register_schedule(spec("b"));
        let drained = take_registered_schedules();
        assert_eq!(
            drained.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        // A second take after a drain sees nothing (no double-drain leak).
        assert!(take_registered_schedules().is_empty());
    }

    /// `reset_workflow_builder` clears a stale registry so a reused worker thread
    /// never leaks a previous evaluation's schedules into the next.
    #[test]
    fn reset_clears_stale_registry() {
        register_schedule(spec("leftover"));
        reset_workflow_builder();
        assert!(take_registered_schedules().is_empty());
    }

    /// A nested `load()` is isolated: schedules a loaded module declares are
    /// discarded on guard drop and never leak into the importer's pack, and the
    /// importer's own registry is restored intact.
    #[test]
    fn load_isolation_discards_loaded_schedules_and_restores_importer() {
        reset_workflow_builder();
        register_schedule(spec("importer"));
        {
            let _guard = isolate_for_load();
            // Inside the load, the importer's registry is hidden (empty).
            assert!(take_registered_schedules().is_empty());
            register_schedule(spec("from_loaded_module"));
            // Guard drops here, discarding the loaded module's schedules.
        }
        let drained = take_registered_schedules();
        assert_eq!(
            drained.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["importer"],
            "the importer's schedule survives; the loaded module's does not leak"
        );
    }
}
