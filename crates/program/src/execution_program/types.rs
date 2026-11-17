//! Core checked-execution-program data structures.
//!
//! The serializable/hashable types that make up an [`ExecutionProgram`] plus the
//! compile-option carrier. Compilation, lowering, hashing, output-reference
//! checking, preflight, and verification live in sibling submodules.

use std::collections::BTreeMap;

use kata_types::bound::Bound;
use kata_types::budget::BudgetPolicy;
use kata_types::cache::{ActionManifest, CachePolicy};
use kata_types::execution::WorkflowClassIdentity;
use kata_types::execution_class::{
    CheckedExecutionClass, Computation, Containment, Determinism, ExternalIssuance, Network,
    PreCommitRecovery,
};
use kata_types::memory::MemoryScope;
use kata_types::params::WorkflowParamSpec;
use kata_types::primitives::ContentHash;
use kata_types::review_loop::ReviewLoop;
use kata_types::sandbox::{SandboxProfile, SandboxRef};
use kata_types::source::SourceSpan;
use kata_types::workflow::{
    BranchRoute, MutationPolicy, ProgressVisibility, ShellExitPolicy, StageId,
    WorkflowCompilerIdentity, WorkflowSourceFormat,
};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::invocation_plan::{InvocationRolePreview, ReviewQuorumPreview};

/// Schema version for the checked execution-program projection: the shape of
/// the program bytes, and hash material of every program. The program store
/// reads it as `CURRENT_EXECUTION_PROGRAM_SCHEMA_VERSION`, whose doc states what
/// a bump owes (it moves the operational stamp too).
pub const EXECUTION_PROGRAM_SCHEMA_VERSION: u32 = 11;

/// Checked stage name used by the API-owned one-shot agent-run compiler.
pub const AGENT_RUN_STAGE_NAME: &str = "agent_run";

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

/// `true` when the program's effective memory scope is the default `Global`
/// tier. Used as the `skip_serializing_if` for [`ExecutionProgram::memory_scope`]
/// so every pack that does not declare a scope tier (all of them today) keeps a
/// byte-identical serialized program and program hash.
fn is_global_memory_scope(scope: &MemoryScope) -> bool {
    matches!(scope, MemoryScope::Global)
}

/// A checked orchestration program derived from a normalized workflow.
///
/// # Its stored form carries each bound child ONCE
///
/// `Serialize` and `Deserialize` are written by hand in `bound_children` over the
/// derived field-by-field form (`#[serde(remote = "Self")]`): a program with subworkflow
/// stages is stored with every DISTINCT bound child program, at any depth, once in a
/// top-level `bound_children` table keyed by its program hash, and each
/// [`BoundChildProgram`] is stored as that hash alone. So a stored program grows with the
/// number of distinct children, never with the number of invocations of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(remote = "Self")]
pub struct ExecutionProgram {
    pub schema_version: u32,
    pub workflow_name: SmolStr,
    pub source: ExecutionProgramSource,
    pub program_hash: ContentHash,
    pub workflow_class: WorkflowClassIdentity,
    pub summary: ExecutionProgramSummary,
    #[serde(default)]
    pub workflow_budget: BudgetPolicy,
    /// Workflow-scope composable walk-away
    /// [`Bound`]s lowered from `workflow(bounds=[..])`, in canonical order
    /// (`Time` before `Cost`). Empty for every workflow that omits `bounds=`,
    /// and skipped from JSON + the program hash when empty. Both kinds are
    /// runtime walk-away halts: the runner captures them at construction and
    /// halts the run when accumulated spend ([`Bound::Cost`]) or total elapsed
    /// wall time ([`Bound::Time`]) exceeds the limit. Enforcement is purely
    /// runtime and reads this field — it does NOT alter the checked IR or the
    /// program hash.
    /// See [`kata_types::bound`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounds: Vec<Bound>,
    /// `branch` control-flow routes lowered from a native
    /// `branch(on=.., verdict_field=.., arms={..})` declaration, in canonical
    /// order (by `condition_stage`, then arm `tag`). Empty for every workflow
    /// that omits `branch(..)`, and skipped from JSON + the program hash when
    /// empty. The runner reads this field at
    /// stage-completion to route the condition stage's verdict tag to the taken
    /// arm's targets and skip the rest. Enforcement is purely runtime and reads
    /// this field — it does NOT alter the checked IR or the program hash beyond
    /// the route list itself. See [`kata_types::workflow::BranchRoute`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub branch_routes: Vec<BranchRoute>,
    /// Workflow-level concurrency throttle (the `parallel` primitive)
    /// lowered from `workflow(max_concurrency=N)`. Caps how many stages the
    /// runner keeps in flight CONCURRENTLY across the whole execution. `None`
    /// (every workflow that omits `max_concurrency=`): the runner submits every
    /// ready stage each tick. Skipped from JSON + the program hash when `None`.
    /// Enforcement is purely runtime and reads this field — it
    /// is a pure SCHEDULING throttle (excess ready stages stay Ready and are
    /// submitted as in-flight stages complete) and never fails or escalates a
    /// run, so correctness is unchanged. See
    /// [`kata_types::workflow::WorkflowDefinition::max_concurrency`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
    pub stages: BTreeMap<StageId, ExecutionProgramStage>,
    pub edges: Vec<ExecutionProgramEdge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_loops: Vec<ReviewLoop>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sandbox_profiles: BTreeMap<String, SandboxProfile>,
    #[serde(default)]
    pub human_request_queue: ExecutionHumanRequestQueue,
    #[serde(
        default,
        skip_serializing_if = "ExecutionExternalInputChannels::is_empty"
    )]
    pub external_input_channels: ExecutionExternalInputChannels,
    /// The declared typed invocation-param specs from
    /// `workflow(params={..})`. The executor resolves caller-supplied values
    /// against these at every submit face, and the redaction boundary reads the
    /// secret markers here. Empty for every pack that omits `params=`, and
    /// skipped from JSON + the program hash when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<WorkflowParamSpec>,
    #[serde(default, skip_serializing_if = "ExecutionMemorySelectors::is_empty")]
    pub memory_selectors: ExecutionMemorySelectors,
    #[serde(default, skip_serializing_if = "ExecutionMemoryWritebacks::is_empty")]
    pub memory_writebacks: ExecutionMemoryWritebacks,
    /// The memory-scope tier this execution's runtime
    /// memory reads and writebacks are entitled to. The runner threads it into
    /// the read visibility window (`WorkflowRunner::memory_scope`) and every
    /// runtime writeback lands through the gated `apply_proposal_entitled` at
    /// this scope. Defaults to [`MemoryScope::Global`] — the flat,
    /// operator-visible tier — for every pack that declares no scope tier.
    /// Skipped from JSON and excluded from the program hash when `Global`.
    #[serde(default, skip_serializing_if = "is_global_memory_scope")]
    pub memory_scope: MemoryScope,
    #[serde(default, skip_serializing_if = "ExecutionValidationCriteria::is_empty")]
    pub validation_criteria: ExecutionValidationCriteria,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_pattern: Option<ExecutionWorkflowPattern>,
    pub verifier: VerifierReport,
}

/// Source metadata for Starlark-authored workflows or the programmatic `Api`
/// source format after checked normalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProgramSource {
    pub format: WorkflowSourceFormat,
    /// Stable source-format label for operator/UI surfaces. Kept alongside the
    /// typed enum so generated JSON remains easy to scan without coupling
    /// clients to Rust enum spellings.
    pub frontend: SmolStr,
    /// Canonical checked-definition identity from
    /// `WorkflowDefinition.provenance.normalized_definition_hash`.
    pub normalized_definition_hash: ContentHash,
    /// Hash of the exact source bytes presented to the compiler.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_hash: Option<ContentHash>,
    /// Hashes of resolved Starlark imports keyed by authored load path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub import_hashes: BTreeMap<SmolStr, ContentHash>,
    /// Compiler/evaluator identity that produced the checked definition.
    pub compiler: WorkflowCompilerIdentity,
}

/// Compact whole-program counts for preflight and dashboards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProgramSummary {
    pub stage_count: usize,
    pub edge_count: usize,
    pub review_loop_count: usize,
    pub sandbox_profile_count: usize,
    pub planned_invocation_count: usize,
    pub worktree_isolated: bool,
    #[serde(default)]
    pub human_request_count: usize,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub external_input_channel_count: usize,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub memory_selector_count: usize,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub memory_writeback_count: usize,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub validation_criterion_count: usize,
}

/// One checked stage operation in the program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProgramStage {
    pub stage_id: StageId,
    pub op: ExecutionStageOp,
    /// Stable hash of the normalized stage contract excluding prompt text.
    ///
    /// The prompt has its own identity (`op.prompt_hash`) because prompt edits
    /// should be distinguishable from policy/output/topology edits during
    /// review, replay, and A/B comparison.
    pub contract_hash: ContentHash,
    pub depends_on: Vec<StageId>,
    pub outputs: Vec<ExecutionOutputContract>,
    pub policies: ExecutionStagePolicies,
    pub invocation_envelope: ExecutionInvocationEnvelope,
    /// The stage's hashed seven-axis [`CheckedExecutionClass`] — the
    /// checked execution SEMANTICS (computation / determinism / containment /
    /// workspace / network / issuance / recovery) DERIVED from the authored
    /// executor + resolved sandbox at lowering
    /// ([`derive_execution_class`](super::derive_execution_class)) and folded into
    /// [`Self::contract_hash`] (invariant: the checked contract commits to the
    /// resolved execution semantics, not just the authoring knobs — a semantic-axis
    /// change rotates stage identity). It is the SOURCE OF TRUTH the verdict readers
    /// ([`Self::is_content_cacheable`]) read.
    ///
    /// REQUIRED (no serde default).
    /// The metadata-first schema gate (`execution_program_from_json`) refuses a
    /// non-current program BEFORE serde, so its absence never surfaces as a raw
    /// serde missing-field error — a schema-3+ program always carries it.
    pub execution_class: CheckedExecutionClass,
    /// This stage's declared INPUT contract, lowered from
    /// `consumes=contract(..)` (`StageDefinition::input_schema`). Threaded here
    /// purely so the load-time cross-stage reference check
    /// ([`check_output_references`](super::check_output_references)) can
    /// TYPE-check a `{{ stages.X.parsed.f }}` reference against the consumer's
    /// expected input type for `f`.
    ///
    /// DELIBERATELY OUTSIDE [`ExecutionStagePolicies`] (and therefore NOT folded
    /// into `contract_hash`): the consumes contract is a load-time type
    /// declaration, not a runtime-significant validator
    /// (`kata_types::workflow::StageDefinition::input_schema`). `None` for every
    /// stage that omits `consumes=`, and `skip_serializing_if` keeps such stages
    /// byte-identical on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    /// The DECLARED read-closure (hermetic-by-closure) — repo-relative
    /// globs (`StageDefinition::reads`) naming exactly the worktree paths a
    /// deterministic-hermetic action reads. Under `oci` a confinable stage's
    /// capsule materializes only the `/work` members a non-empty closure covers
    /// ([`kata_types::execution_contract`]'s confined `/work` view), so a read
    /// outside it finds nothing. Empty (every stage that omits
    /// `reads=`) is no declared-closure enforcement. DELIBERATELY OUTSIDE
    /// `contract_hash` (a closure declaration, not runtime contract material —
    /// like `input_schema`), and `skip_serializing_if` keeps such programs
    /// byte-identical on the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reads: Vec<SmolStr>,
    /// The DECLARED
    /// output-file set — repo-relative globs naming exactly the worktree paths
    /// this stage may produce/modify (`StageDefinition::produces_files`). The
    /// OUTPUT analog of [`Self::reads`]. When NON-EMPTY, at stage completion the
    /// runtime RECORDS the OBSERVED output set (the worktree change set — reusing
    /// the existing change-detection probe) as durable
    /// [`ExecutionOutputClosureEvidence`](kata_types::execution::ExecutionOutputClosureEvidence),
    /// and [`check_output_closure`](super::output_closure::check_output_closure)
    /// flags any observed path not covered by a declared glob (observed ⊄
    /// declared).
    ///
    /// SCOPE: recording only. The observed tree is not content-addressed into
    /// the CAS here, and a stage is never hard-failed on an undeclared output: a
    /// non-conforming stage is surfaced (warn +
    /// `kata_stage_undeclared_output_total`) but never failed. (The capsule
    /// route's adoption judge separately refuses a `/work` delta outside the
    /// closure on an enforcing backend.)
    ///
    /// Empty (every stage that omits `produces_files=`) is a vacuous closure — the
    /// check is skipped. DELIBERATELY OUTSIDE
    /// `contract_hash` (a closure declaration, not runtime contract material —
    /// like `reads` and `input_schema`), and `skip_serializing_if` keeps such
    /// programs byte-identical on the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub produces_files: Vec<SmolStr>,
    /// When set, this stage is a SUBWORKFLOW: instead of dispatching to
    /// a worker it spawns a CHILD workflow execution (its own `ExecutionId` and
    /// workspace), parks in
    /// [`AwaitingChildCompletion`](kata_types::ledger::AssignmentStatus::AwaitingChildCompletion)
    /// until the child reaches a terminal state, then completes with the child's
    /// output envelope injected as this stage's output.
    ///
    /// Serde-default: a stage with `subworkflow: None` (every non-subworkflow
    /// stage) dispatches normally, and
    /// `skip_serializing_if` keeps such programs/blobs byte-identical on the
    /// wire. Deliberately OUTSIDE [`ExecutionStagePolicies`] and therefore NOT
    /// folded into `contract_hash`: it is a dispatch-routing marker, mirroring
    /// how `input_schema` sits outside the hashed contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subworkflow: Option<SubworkflowSpec>,
    /// When set, this stage is a DURABLE SLEEP: instead of dispatching anything
    /// the runner claims a main attempt parked on a durable timer at the wake
    /// deadline, and
    /// `kata_workflow::dispatcher::Dispatcher::sweep_due_waits`
    /// completes it once the deadline is due — so the graph resumes exactly where
    /// it left off, crash/restart-safe (the deadline is a durable column).
    ///
    /// Serde-default: a stage with `durable_sleep: None` (every non-sleep stage)
    /// dispatches normally,
    /// and `skip_serializing_if` keeps such programs/blobs byte-identical on the
    /// wire. Deliberately OUTSIDE [`ExecutionStagePolicies`] and therefore NOT
    /// folded into `contract_hash`: it is a dispatch-routing marker, mirroring
    /// how `subworkflow` sits outside the hashed contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_sleep: Option<kata_types::wait::DurableSleep>,
    /// When set, this stage is a TYPED MEMORY SNAPSHOT: the
    /// typed-operation lowering produces `RuntimeOperation::MemorySnapshot`,
    /// which the runner resolves MAIN-SIDE on EVERY profile — kata reads the
    /// node's own memory store under the authored filter and accepts the stage
    /// with the snapshot as its output (`runner::dispatch::main_resolved`).
    /// It runs no worker, no shell and no capsule, on either profile.
    ///
    /// Serde-default: a stage with `memory_snapshot: None` dispatches
    /// normally, and `skip_serializing_if` keeps such programs
    /// byte-identical on the wire. Deliberately OUTSIDE
    /// [`ExecutionStagePolicies`] and therefore NOT folded into
    /// `contract_hash`: it is a dispatch-routing marker, mirroring how
    /// `durable_sleep` and `subworkflow` sit outside the hashed contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_snapshot: Option<kata_types::workflow::MemorySnapshotSpec>,
    /// FRONTEND PROVENANCE — which higher-level construct SYNTHESIZED this stage,
    /// when the author did not write it. Carried verbatim from
    /// [`kata_types::workflow::StageDefinition::synthesized`], which holds the
    /// rationale: without it the checked IR erases the difference between a
    /// `parallel()` fan-in barrier (a shell no-op with body `":"`) and an authored
    /// shell command, leaving a reader to sniff the minted id prefix.
    ///
    /// `None` for every authored stage, and `skip_serializing_if` keeps such
    /// stages byte-identical on the wire — so a pack that synthesizes nothing keeps
    /// its `program_hash` unchanged. Like [`Self::durable_sleep`] and
    /// [`Self::subworkflow`] it sits OUTSIDE [`ExecutionStagePolicies`] and is NOT
    /// folded into [`Self::contract_hash`]: provenance about where a stage came
    /// from is not a term of the contract it must satisfy. It DOES enter the
    /// whole-program hash, which is taken over the serialized stages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synthesized: Option<kata_types::workflow::SynthesizedStage>,
    /// AUTHORING PROVENANCE — the `pack.star:LINE:COL` call site that declared
    /// this stage, carried verbatim from
    /// [`kata_types::workflow::StageDefinition::authored_span`], which holds the
    /// rationale. It is what lets a diagnostic, an operator view, or a typed
    /// operation contract point an author at the line they wrote instead of at a
    /// minted stage id.
    ///
    /// The span's `file` is a BASENAME, so this carries no host path into the
    /// checked IR (the locked authoring rule: a content-hashed program may not
    /// name a machine's facts).
    ///
    /// Like [`Self::synthesized`], [`Self::durable_sleep`], [`Self::subworkflow`]
    /// and [`Self::workspace_effect_op`] it sits OUTSIDE
    /// [`ExecutionStagePolicies`] and is NOT folded into [`Self::contract_hash`]:
    /// WHERE a stage was written is not a term of the contract it must satisfy, so
    /// re-indenting a pack must not rotate a stage's identity or invalidate its
    /// cached results. It is likewise projected OUT of the frontend's
    /// `normalized_definition_hash` (`StagesWithoutSpans`, beside
    /// [`kata_types::workflow::WorkflowDefinition::normalized_hash`]), which is the
    /// canonical semantic identity of the definition.
    ///
    /// It IS inside `program_hash`, which is taken over the serialized stages, and
    /// so inside the `workflow_class_identity` that folds that hash. Neither is a
    /// semantic identity: `program_hash` is a source-and-IR identity whose material
    /// also carries the pack's exact source-bytes hash and its `load()`ed modules'
    /// hashes (`ExecutionProgramSource::source_hash`, `import_hashes`), so ANY byte
    /// edit of the pack or of a loaded module rotates both, a comment or a trailing
    /// newline included, while every `contract_hash` and the definition hash stay
    /// byte-identical. The semantic identity is `normalized_definition_hash`.
    ///
    /// A stage whose span is `None` serializes exactly as if the field did not exist
    /// (`skip_serializing_if`), so `rederive_program_hash`, which hashes the DECODED
    /// struct, reproduces the header such a stage was stored with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authored_span: Option<SourceSpan>,
    /// TYPED VCS EFFECT — which deterministic workspace mutation this stage
    /// performs, when its resolved executor is the in-process
    /// `workspace_effect` backend. Carried verbatim from
    /// [`kata_types::workflow::WorkspaceEffect::op`]
    /// (`StageDefinition::workspace_effect`).
    ///
    /// It exists because the checked IR otherwise carries the mutation ONLY
    /// inside the frontend-synthesized directive prompt
    /// ([`WorkspaceEffect::directive_prompt`](kata_types::workflow::WorkspaceEffect::directive_prompt)),
    /// so every reader that needs to know a park from a promote must PARSE that
    /// prompt — string-sniffing a JSON blob for a semantic fact, which is not a
    /// contract. (`execution_class::classify_executor` still does exactly that
    /// for its own admission routing; this field is what lets a new reader not
    /// have to.)
    ///
    /// `None` for every stage that is not a workspace-effect stage, and
    /// `skip_serializing_if` keeps such stages byte-identical on the wire — so a
    /// pack with no effect stage keeps its `program_hash`. A pack that DOES carry
    /// an effect stage ROTATES its `program_hash`: the whole-program hash is taken
    /// over the serialized stages
    /// (`execution_program::hashing::hash_program_material`), so a newly
    /// serialized field on any stage moves it — exactly as `synthesized` moved the
    /// hash of every pack that mints a `parallel()` barrier. That is a checked-IR
    /// identity change for those packs, not a byte-identical addition. Like
    /// [`Self::synthesized`], [`Self::durable_sleep`] and [`Self::subworkflow`] it
    /// sits OUTSIDE [`ExecutionStagePolicies`] and is NOT folded into
    /// [`Self::contract_hash`]: it is provenance carried off the authored
    /// declaration, not a new term of the contract.
    ///
    /// NOTE, and it is not this field's doing: [`Self::contract_hash`] does not by
    /// itself distinguish a `park` from a `promote`. It excludes prompt text (the
    /// directive lives in `op.prompt_hash`) and both ops derive the SAME
    /// seven-axis class ([`CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION`](kata_types::execution_class::CheckedExecutionClass::ADMISSION_RECORDED_LOCAL_MUTATION)),
    /// so two otherwise-identical effect stages differ only in their prompt hash.
    /// That is why the typed operation contract carries the op itself
    /// (`ActionExecutor::Effect { effect_kind, op }`) rather than leaning on the
    /// stage contract to have committed to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_effect_op: Option<kata_types::workflow::WorkspaceEffectOp>,
}

/// Checked-IR marker that turns a stage into a subworkflow spawn point.
///
/// A subworkflow stage does not run on a worker. Its runtime job is to launch a
/// child workflow execution of the BOUND child program, wait for it, and return
/// the child's result as this stage's output.
///
/// # The child is bound at the parent's CHECK
///
/// A pack compiles to a content-hashed IR frozen at admission and may not name a
/// machine's facts. A pack NAME is such a fact: which bytes it
/// resolves to depends on the library roots of whatever machine reads it, and when.
/// So the compiler resolves [`pack`](Self::pack) once, through the library roots it
/// was handed, compiles it, and embeds the result in [`bound`](Self::bound). The
/// runtime spawns exactly those bytes; nothing re-resolves the name. `pack` is kept as
/// PROVENANCE only — it says where the bound program came from.
///
/// The parent's `program_hash` folds [`BoundChildProgram::program_hash`], and every
/// decode of a [`BoundChildProgram`] re-derives the bound program's hash and refuses a
/// body that does not produce it, so an edited child cannot ride inside an unedited
/// parent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubworkflowSpec {
    /// The child pack NAME the compiler resolved — provenance only.
    pub pack: SmolStr,
    /// Authored constant invocation params (`{name: value}`) supplied to
    /// the child at spawn, resolved against the child program's declared param
    /// contract at admission. Empty for a child with no params, and skipped from
    /// JSON + the program hash when empty.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub params: serde_json::Map<String, serde_json::Value>,
    /// The checked child program, bound at the parent's CHECK.
    pub bound: BoundChildProgram,
}

/// A checked child program bound into its parent, and the hash that binds it.
///
/// # Invariant
///
/// `program_hash` is the whole-program hash RE-DERIVED from `program`'s body
/// ([`rederive_program_hash`](super::rederive_program_hash)) and equals the hash the
/// body carries. [`Self::bind`] establishes it for a freshly compiled program, and the
/// decode (`bound_children`) re-establishes it for every decoded one — refusing
/// `bound_child_program_mismatch` otherwise — so no value of this type describes bytes
/// other than the ones it holds. The fields are private for that reason.
///
/// # Identity is content, so a child is held — and stored — once
///
/// The body is SHARED (`Arc`): every invocation of one distinct child, at any depth of
/// one compile, holds the same allocation, and the stored program carries it once, in
/// its `bound_children` table, with this value stored as its hash alone. Only
/// `program_hash` enters the PARENT's hash material: the child's own hash already folds
/// its body, and hashing the body a second time inside the parent would also fold the
/// child's sandbox placement brand, which no program hash may carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundChildProgram {
    program_hash: ContentHash,
    program: std::sync::Arc<ExecutionProgram>,
}

impl BoundChildProgram {
    /// Bind a checked child program, refusing one whose body does not re-derive the
    /// hash it carries.
    pub fn bind(program: ExecutionProgram) -> kata_types::KataResult<Self> {
        Self::bind_shared(std::sync::Arc::new(program))
    }

    /// [`Self::bind`] over a body that is already shared.
    pub(super) fn bind_shared(
        program: std::sync::Arc<ExecutionProgram>,
    ) -> kata_types::KataResult<Self> {
        let derived = super::rederive_program_hash(&program);
        if derived != program.program_hash {
            return Err(bound_child_mismatch(
                &program,
                program.program_hash,
                derived,
            ));
        }
        Ok(Self {
            program_hash: derived,
            program,
        })
    }

    /// The bound child's whole-program hash.
    #[must_use]
    pub const fn program_hash(&self) -> ContentHash {
        self.program_hash
    }

    /// The bound child program.
    #[must_use]
    pub fn program(&self) -> &ExecutionProgram {
        &self.program
    }

    /// The shared body, for the stored table's walk.
    pub(super) fn shared(&self) -> &std::sync::Arc<ExecutionProgram> {
        &self.program
    }
}

pub(super) fn bound_child_mismatch(
    program: &ExecutionProgram,
    claimed: ContentHash,
    derived: ContentHash,
) -> kata_types::KataError {
    kata_types::KataError::Validation(format!(
        "bound_child_program_mismatch: the embedded child program \"{}\" is bound as {claimed}, \
         but its body re-derives {derived} (and carries {}). Refusing a subworkflow whose \
         embedded child describes different bytes than the parent's check bound",
        program.workflow_name, program.program_hash
    ))
}

/// **CONFINEMENT, spelled for what it means**: does NOTHING in this class's
/// DECLARED semantics require an undeclared, ambient host input?
///
/// The predicate [`ExecutionProgramStage::should_confine_to_declared_inputs`]
/// reads, and the reason it exists as a named function rather than an inline
/// conjunction: the thing it decides is a CONTAINMENT question, and a CACHING
/// predicate (`is_content_cache_eligible`) must not stand in for one.
/// Confinement is gated on whether the **provider can enforce** it — never on
/// determinism; wiring it to the disposition layer is the category error this
/// name exists to make hard to write.
///
/// # INVARIANT
///
/// This is [`CheckedExecutionClass::is_content_cache_eligible`]'s conjunction
/// MINUS the `workspace` clause, and minus nothing else. The workspace axis
/// describes what the action may WRITE and what may be REUSED afterwards; it
/// says nothing about what the action must REACH to run, which is the only
/// question here. `containment == Contained` is retained, so callers must NOT
/// conjoin it separately — it is subsumed.
///
/// # FAILURE MODE it closes
///
/// With the workspace clause in, a stage would lose its confinement the moment
/// its output set stopped being provably bounded — the `DeclaredOutputs` →
/// `MutableCandidate` demotion. Neither containment nor the durable activity
/// claim may erase the other, and that collapse runs the unsound way round: an
/// action nobody bounded is the one that most needs bounding.
///
/// # ENFORCEMENT POINT
///
/// [`ExecutionProgramStage::should_confine_to_declared_inputs`], which the
/// runner stamps onto
/// [`kata_types::sandbox::SandboxDirective::confine_to_declared_inputs`]; the
/// capsule route confines such a stage's `/work` to its declared inputs
/// ([`kata_types::execution_contract`]'s confined `/work` view).
///
/// # PROOF
///
/// `a_hermetic_writable_shell_stage_keeps_confinement_and_loses_cacheability`
/// and `every_derived_model_class_fails_confinement_on_determinism_and_on_issuance`
/// (`crate::execution_program::execution_class`'s tests), plus the matrix-side
/// width measurement
/// `confinement_predicate_is_strictly_wider_than_cacheability_by_one_valid_tuple`
/// (`crates/types/src/execution_class/tests.rs`).
#[must_use]
pub(crate) fn class_needs_no_ambient_host_input(class: CheckedExecutionClass) -> bool {
    class.computation == Computation::ProcessAction
        && class.determinism == Determinism::Deterministic
        && class.containment == Containment::Contained
        && class.network == Network::Offline
        && class.external_issuance == ExternalIssuance::None
        && class.pre_commit_recovery == PreCommitRecovery::RecomputeAllowed
}

impl ExecutionProgramStage {
    /// Re-stamp this stage's [`contract_hash`](Self::contract_hash) over the stage
    /// AS IT NOW STANDS.
    ///
    /// Excluded from release builds for the same reason
    /// `compile_execution_program_from_parts_for_tests` is: production has exactly
    /// ONE stamper — the lowering pass — and a second public one would let a caller
    /// mint a self-consistent checked stage no compiler produced.
    ///
    /// # Why it exists
    ///
    /// A fixture for *"a checked program written by a DIFFERENT binary"* is
    /// otherwise unbuildable from outside this crate. `contract_hash` folds
    /// [`execution_class`](Self::execution_class), and `preflight_stage_dispatch`
    /// re-derives it, so a fixture that edits the class and leaves the hash alone is
    /// refused for contract-hash DRIFT — and a test built on it could never tell
    /// "the seam under test caught this" apart from "a later gate would have caught
    /// it anyway". Re-stamping makes the fixture exactly as self-consistent as the
    /// foreign binary's own output, which is the only version of it that proves
    /// anything.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn restamp_contract_hash_for_tests(&mut self) {
        self.contract_hash = super::stage_contract_hash(
            &self.stage_id,
            &self.op,
            &self.depends_on,
            &self.outputs,
            &self.policies,
            &self.invocation_envelope,
            self.execution_class,
        );
    }

    /// How many times a failed attempt of this stage may FALL BACK: one
    /// immediate advance per agent fallback panel member after the primary
    /// (`panel.len() - 1`), and `0` for every single-agent stage. It is already
    /// hash material (`agent_panel` folds into
    /// [`contract_hash`](Self::contract_hash)). A transient model provider
    /// failure's re-runs on the same agent are outside it, a fixed number on
    /// every plain stage (`WorkflowRunner::capsule_failure_retry`).
    #[must_use]
    pub fn failure_retry_budget(&self) -> u32 {
        u32::try_from(self.op.agent_panel.len().saturating_sub(1)).unwrap_or(u32::MAX)
    }

    /// True if this stage is a DURABLE SLEEP: on first dispatch the
    /// runner PARKS it instead of dispatching to a worker. `false` for every
    /// stage that omits the `durable_sleep` marker (the default).
    #[must_use]
    pub fn is_durable_sleep(&self) -> bool {
        self.durable_sleep.is_some()
    }

    /// The declared child role a `<stage>#child-<tail>` runtime name names, or
    /// `None` when no role authorizes `tail`.
    ///
    /// A static topology names the role itself (`tail == role`). A DYNAMIC
    /// fanout's tail is `<role>-<discriminator>` and must match EXACTLY one
    /// role, so an ambiguous tail resolves to nothing rather than to an
    /// arbitrary role.
    #[must_use]
    pub fn child_role_for_runtime_tail(&self, tail: &str) -> Option<&InvocationRolePreview> {
        let children = &self.invocation_envelope.children;
        if !self.invocation_envelope.dynamic_fanout {
            return children.iter().find(|child| tail == child.role.as_str());
        }
        let mut matching = children.iter().filter(|child| {
            tail.strip_prefix(child.role.as_str())
                .is_some_and(|suffix| suffix.starts_with('-') && suffix.len() > 1)
        });
        let role = matching.next()?;
        matching.next().is_none().then_some(role)
    }

    /// True if this stage DECLARES a non-empty output-file closure
    /// (`produces_files=`). When `false` (every stage that omits it) the
    /// output-closure check is vacuous and skipped: an undeclared closure imposes
    /// no constraint.
    #[must_use]
    pub fn declares_output_closure(&self) -> bool {
        !self.produces_files.is_empty()
    }

    /// Check an OBSERVED output set (the worktree change set
    /// captured at completion) against this stage's DECLARED output-file closure.
    ///
    /// Returns the checkable [`OutputClosureReport`]: every observed path covered
    /// by no declared glob is a violation
    /// ([`OutputClosureReport::is_conforming`]). Callers should gate enforcement on
    /// [`Self::declares_output_closure`] — an undeclared closure yields an
    /// all-undeclared report and must NOT be treated as a violation.
    #[must_use]
    pub fn check_observed_output_closure<O: AsRef<str>>(
        &self,
        observed: &[O],
    ) -> super::OutputClosureReport {
        super::check_output_closure(&self.produces_files, observed)
    }

    /// True if this stage routes to a deterministic command executor (not an
    /// LLM agent), so its output is replay-stable.
    ///
    /// `agent = "shell"` lowers to `AgentSelector::Labelled("shell")`, i.e.
    /// `op.agent == "shell"` / `op.agent_label == Some("shell")`. Both the
    /// label and the bare agent name are checked against the deterministic
    /// label set so a backend-selector lowering (`op.agent_label`) and a raw
    /// labelled selector (`op.agent`) are both recognized. This is sound only
    /// because `KataConfig::validate` reserves the deterministic names for
    /// deterministic backends — see
    /// [`kata_types::agent::is_deterministic_agent_label`].
    ///
    /// NOTE: this includes `workspace_effect`, which is deterministic but is
    /// NOT a valid validation-proof stage (it emits no validation report). The
    /// promotion trust gate must use [`Self::is_validation_proof_eligible`].
    #[must_use]
    pub fn is_deterministic_executor(&self) -> bool {
        self.op
            .agent_label
            .as_deref()
            .is_some_and(kata_types::agent::is_deterministic_agent_label)
            || kata_types::agent::is_deterministic_agent_label(self.op.agent.as_str())
    }

    /// True iff this stage routes to the in-process, main-owned
    /// `WorkspaceEffect` backend (a recorded jj park/promote via the
    /// execution's workspace provider) rather than a process-spawning executor
    /// (shell or a model/agent CLI backend). Mirrors
    /// [`Self::is_deterministic_executor`]'s label check so a backend-selector
    /// lowering (`op.agent_label`) and a raw labelled selector (`op.agent`) are
    /// both recognized. This is the ONLY
    /// executor whose stage carries `policies.sandbox == None`: every shell and
    /// model stage is lowered with an explicit sandbox by `materialize_sandbox`,
    /// and `ExecutionProgram::validate_carried_stage_execution_classes` refuses a
    /// durable process stage that lacks one at every decode door.
    #[must_use]
    pub fn is_workspace_effect_executor(&self) -> bool {
        self.op.agent_label.as_deref() == Some(kata_types::workflow::WORKSPACE_EFFECT_AGENT_LABEL)
            || self.op.agent.as_str() == kata_types::workflow::WORKSPACE_EFFECT_AGENT_LABEL
    }

    /// True if a validation-proof stage routed to this stage's backend may be
    /// TRUSTED to self-certify a required criterion verdict.
    ///
    /// Strictly narrower than [`Self::is_deterministic_executor`]: excludes
    /// `workspace_effect` (deterministic, but emits a park/promote envelope,
    /// never a validation report). The `kata-api` validation-proof-stage gate
    /// keys on THIS predicate so an effect stage can never gate promotion. See
    /// [`kata_types::agent::is_validation_proof_eligible_agent_label`].
    #[must_use]
    pub fn is_validation_proof_eligible(&self) -> bool {
        self.op
            .agent_label
            .as_deref()
            .is_some_and(kata_types::agent::is_validation_proof_eligible_agent_label)
            || kata_types::agent::is_validation_proof_eligible_agent_label(self.op.agent.as_str())
    }

    /// True if this stage may carry the content-addressed cache
    /// (determinism boundary). A thin READER of the hashed
    /// [`Self::execution_class`] — content-cache eligibility is
    /// [`CheckedExecutionClass::is_content_cache_eligible`] (deterministic +
    /// contained + offline + a captured/vacuous workspace closure), the seven-axis
    /// form of "deterministic executor AND hermetic sandbox". The class is
    /// derived from the authored executor + sandbox at lowering, so no
    /// `profiles` argument is needed.
    #[must_use]
    pub fn is_content_cacheable(&self) -> bool {
        self.execution_class.is_content_cache_eligible()
    }

    /// CONFINEMENT — should this stage's action be held to its declared inputs?
    /// Stamped onto [`kata_types::sandbox::SandboxDirective::confine_to_declared_inputs`].
    ///
    /// # `should_` is load-bearing: this is NOT the axis
    ///
    /// The directive FIELD it feeds is the pure containment axis. This METHOD is
    /// a POLICY VERDICT over the class, so the two must not share a name — a
    /// reader who saw `confine_to_declared_inputs()` here would reasonably
    /// conclude the derivation is "`Contained` ⇒ confine" and be wrong. The field
    /// it lands on is the resulting FACT.
    ///
    /// This sits next to [`Self::is_content_cacheable`] on purpose: the two
    /// belong to different layers. *Confinement* ("the action sees only its
    /// declared inputs") is gated on whether the provider can enforce it — never
    /// on determinism; *Disposition* ("what may be done with the result") is
    /// gated on determinism × external issuance. Wiring the first to the second
    /// is the category error this method exists to make impossible to write by
    /// accident.
    ///
    /// # The predicate
    ///
    /// Exactly [`class_needs_no_ambient_host_input`]: `is_content_cache_eligible`'s
    /// conjunction MINUS the workspace conjunct. It asks `containment ==
    /// Contained` itself — the exec BRAND `derive_process_class` reads (`oci`
    /// certifies containment, `host` cannot) — so no separate containment
    /// conjunct is written beside it.
    ///
    /// It is strictly WIDER than cacheability over the closed-world-valid set by
    /// exactly one tuple —
    /// `confinement_predicate_is_strictly_wider_than_cacheability_by_one_valid_tuple`
    /// (`crates/types/src/execution_class/tests.rs`) measures it:
    ///
    /// ```text
    /// ProcessAction + Deterministic + Contained + MutableCandidate
    ///   + Offline + issuance None + RecomputeAllowed
    /// ```
    ///
    /// — a hermetic, offline, non-issuing shell action holding an UNBOUNDED
    /// writable tree, which `workspace_from_fs` mints for every writable
    /// deterministic stage that does not declare an enforced output closure.
    /// Such a stage loses content-cache eligibility and KEEPS confinement;
    /// `a_hermetic_writable_shell_stage_keeps_confinement_and_loses_cacheability`
    /// (`crate::execution_program::execution_class`'s tests) pins that pair.
    ///
    /// # What agent stages are refused BY
    ///
    /// Three conjuncts, each independently sufficient. `derive_process_class`
    /// sets `Nondeterministic` for every model executor unconditionally, and
    /// `DurableActivity` on `is_model || network != Offline` — the `is_model`
    /// disjunct fires even offline — and R13 then forces recovery off
    /// `RecomputeAllowed`. A future edit relaxing exactly ONE of them still would
    /// not start confining agent stages; it takes all three.
    /// `every_derived_model_class_fails_confinement_on_determinism_and_on_issuance`
    /// pins that over every model executor × every sandbox posture. Confining an
    /// agent stage would cut its CLI off from the `$PATH` entry and `$HOME` it
    /// resolves through, so agent-stage confinement is a design decision, not a
    /// refactor.
    ///
    /// # The gap between what this REFUSES and what its name CLAIMS
    ///
    /// The name claims "needs no ambient host input"; what it decides is six axes
    /// of DECLARED semantics. A class it admits can still need something ambient
    /// the axes do not model. The predicate is NECESSARY for declared-input
    /// confinement and is not SUFFICIENT for the action to survive one.
    #[must_use]
    pub fn should_confine_to_declared_inputs(&self) -> bool {
        class_needs_no_ambient_host_input(self.execution_class)
    }

    // There is no separate reuse-key read-closure fence: a capsule mounts only
    // declared inputs by construction, so the narrowing such a fence would
    // police is what the container itself is. A second spelling read off the
    // checked stage could disagree with the resolved `SandboxDirective` (which
    // carries the `fs` policy and the workspace bind the stage cannot see).

    /// Build this stage's [`ActionManifest`] (fine-grained action
    /// identity) from a `command` identity (the prompt/contract hash). The
    /// DECLARED output set is captured from [`Self::produces_files`].
    ///
    /// Scope: the declared output globs are recorded; they are not resolved to
    /// post-execution digests, and the output set is not materialized on its own
    /// (see [`ActionManifest`]).
    #[must_use]
    pub fn action_manifest(&self, command: kata_types::primitives::ContentHash) -> ActionManifest {
        ActionManifest::new(command, self.produces_files.clone())
    }
}

/// Stage operation kind. Starlark's `prompt=` / `run=` authoring choices are
/// already normalized into one prompt template, so the checked IR uses a
/// conservative generic stage op.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStageOp {
    pub kind: ExecutionStageOpKind,
    pub agent: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_label: Option<SmolStr>,
    /// The ordered agent fallback panel (primary first) lowered from
    /// [`kata_types::workflow::AgentSelector::Panel`]. Empty for every
    /// single-agent stage, so the field is skip-serialized. When non-empty its
    /// first element equals
    /// [`Self::agent`] / [`Self::agent_label`]; the dispatcher's failure-retry
    /// re-dispatch advances through the remaining members, one per attempt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_panel: Vec<SmolStr>,
    #[serde(default, skip_serializing_if = "ExecutionPromptRendering::is_template")]
    pub prompt_rendering: ExecutionPromptRendering,
    pub prompt_present: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prompt_template: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_hash: Option<ContentHash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStageOpKind {
    Stage,
}

/// How the checked prompt text should be materialized before worker dispatch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPromptRendering {
    /// Render with Kata's strict Minijinja runtime context.
    #[default]
    Template,
    /// Forward the prompt bytes exactly as checked into the program.
    Literal,
}

impl ExecutionPromptRendering {
    #[must_use]
    pub const fn is_template(value: &Self) -> bool {
        matches!(value, Self::Template)
    }
}

/// Declared machine-checkable output field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionOutputContract {
    pub name: SmolStr,
    pub ty: SmolStr,
}

/// Policies that the runtime must enforce for one stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStagePolicies {
    pub cache_policy: CachePolicy,
    pub approval_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hint: Option<SmolStr>,
    /// Per-dispatch wall-clock budget in milliseconds. ALWAYS present — see
    /// [`kata_types::workflow::DEFAULT_STAGE_TIMEOUT_MS`], which the `stage()`
    /// builtin substitutes for an undeclared `timeout_ms=`. Unconditionally
    /// serialized, so it is part of `StageContractHashMaterial` for every stage
    /// rather than only for the ones that declared a bound.
    pub timeout_ms: u64,
    /// `output_bytes=` — the AUTHORED combined capture bound, `None` when the
    /// stage omitted the kwarg (`skip_serializing_if` keeps the key out of such a
    /// stage's bytes). The capsule folds
    /// `unwrap_or(CAPSULE_OUTPUT_BYTES)`; the `[node] output_bytes_ceiling`
    /// refusal bounds the authored value at admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<u64>,
    /// `work_delta_bytes=` — authored `/work` delta byte bound, same
    /// disposition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_delta_bytes: Option<u64>,
    /// `work_delta_entries=` — authored `/work` delta entry bound, same
    /// disposition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_delta_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tools: Vec<SmolStr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<SmolStr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxRef>,
    /// Always `None` in a program this binary lowers: no source writes it
    /// (`POST /agents/run` refuses a working tree), and nothing at run time reads
    /// it. It stays in the type only because it is part of the durable program's
    /// shape and its hash; removing it is a program-schema change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_tree: Option<String>,
    pub validate_retries: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validate_feedback_template: Option<String>,
    pub cost_budget: BudgetPolicy,
    pub progress_visibility: ProgressVisibility,
    /// The checked shell EXIT POLICY, lowered from
    /// `StageDefinition::exit_policy`. `ZeroSuccess` (the default) is
    /// byte-stable (`skip_serializing_if` keeps it out of the
    /// hashed policies, so a stage that omits `exit_policy=` leaves
    /// `contract_hash`/`program_hash` unchanged); a declared `Content` policy —
    /// the opt-out — folds into the checked stage identity. Either way the
    /// main enforces it: `Dispatcher::judge_capsule_completion` reads it off the
    /// execution's durable checked program, never off the capsule.
    #[serde(default, skip_serializing_if = "ShellExitPolicy::is_zero_success")]
    pub exit_policy: ShellExitPolicy,
}

/// The bounded child-invocation envelope for a stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionInvocationEnvelope {
    pub topology_kind: SmolStr,
    pub root: InvocationRolePreview,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<InvocationRolePreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fanout_limit: Option<u32>,
    pub dynamic_fanout: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_policy: Option<MutationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_quorum: Option<ReviewQuorumPreview>,
}

/// Checked dependency edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProgramEdge {
    pub from: StageId,
    pub to: StageId,
}

/// Checked human requests carried by the execution program, preserving whether
/// each request is advisory or blocks its scoped stage durably.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionHumanRequestQueue {
    pub max_items: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<ExecutionHumanRequest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionHumanRequest {
    pub index: u32,
    pub id: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<StageId>,
    pub priority: SmolStr,
    pub question: String,
    pub default_assumption: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Blocking requests park their target `stage` until
    /// answered (durable, via `AwaitingApproval`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub blocking: bool,
    /// Optional self-heal deadline (milliseconds) for a
    /// `blocking` park. Carried into the durable checked program so the
    /// input-await timeout sweep can recompute the deadline after a restart from
    /// `awaiting_approval_at_ms + timeout_ms`. `None` blocks until answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Checked side-channel input declarations carried by the execution program.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionExternalInputChannels {
    pub max_channels: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<ExecutionExternalInputChannel>,
}

impl ExecutionExternalInputChannels {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.max_channels == 0 && self.channels.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionExternalInputChannel {
    pub index: u32,
    pub id: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<StageId>,
    pub expose_as: SmolStr,
    pub kind: SmolStr,
    pub schema: SmolStr,
    pub max_items: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
}

/// Checked native-memory selector declarations carried by the execution program.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionMemorySelectors {
    pub max_selectors: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<ExecutionMemorySelector>,
}

impl ExecutionMemorySelectors {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.max_selectors == 0 && self.selectors.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionMemorySelector {
    pub index: u32,
    pub id: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<StageId>,
    pub expose_as: SmolStr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<SmolStr>,
    pub statuses: Vec<SmolStr>,
    pub max_objects: u32,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// Checked native-memory writeback declarations carried by an execution
/// program.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionMemoryWritebacks {
    pub max_writebacks: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writebacks: Vec<ExecutionMemoryWriteback>,
}

impl ExecutionMemoryWritebacks {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.max_writebacks == 0 && self.writebacks.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionMemoryWriteback {
    pub index: u32,
    pub id: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<StageId>,
    pub field: SmolStr,
    pub kinds: Vec<SmolStr>,
    pub statuses: Vec<SmolStr>,
    pub max_objects: u32,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Declared scope tier (`global`/`project`/`workflow`) a producer stage may
    /// write into, or `None` for own scope. Skipped when `None`,
    /// so it does not perturb the `program_hash` of programs that omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_tier: Option<SmolStr>,
}

/// Checked validation boundary carried by an execution program.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionValidationCriteria {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub criteria: Vec<ExecutionValidationCriterion>,
}

impl ExecutionValidationCriteria {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.criteria.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionValidationCriterion {
    pub index: u32,
    pub id: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<StageId>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWorkflowPattern {
    pub name: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_tier: Option<SmolStr>,
    pub escape_hatch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escape_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<SmolStr>,
}

/// Verifier output attached to a checked execution program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierReport {
    pub status: VerifierStatus,
    pub diagnostics: Vec<VerifierDiagnostic>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierStatus {
    Pass,
    Warn,
    Error,
}

impl VerifierStatus {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierDiagnostic {
    pub severity: VerifierSeverity,
    pub code: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<StageId>,
    pub message: String,
    /// The source-span origin of this diagnostic, when known.
    /// Serde-default (omitted when `None`). Populated where a call-site span is
    /// available; template diagnostics carry no source map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierSeverity {
    Info,
    Warning,
    Error,
}

impl VerifierSeverity {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl ExecutionProgram {
    /// Return checked static stages whose declared dependencies are already
    /// terminal according to the caller's runtime state view.
    ///
    /// This helper intentionally knows nothing about runtime synthetic names
    /// such as review-loop iterations, validation retries, or dynamic-fanout
    /// children. It only walks the static stage graph retained in the checked
    /// program.
    pub fn static_ready_stage_ids(
        &self,
        mut dependency_terminal: impl FnMut(&StageId) -> bool,
    ) -> Vec<StageId> {
        self.stages
            .values()
            .filter(|stage| stage.depends_on.iter().all(&mut dependency_terminal))
            .map(|stage| stage.stage_id.clone())
            .collect()
    }

    /// The stages `stage` transitively `depends_on` — exactly the set the
    /// orchestrator holds terminal before `stage` may dispatch
    /// (`Orchestrator::from_execution_program` drives readiness off these edges
    /// and no others). `stage` is not in its own closure; a stage the program
    /// does not hold has an empty one.
    ///
    /// THE one answer to "which upstream outputs may this stage read": CHECK
    /// refuses a `stages.<producer>` reference outside it
    /// (`output_reference_outside_dependency_closure`) and
    /// [`Self::outputs_in_dependency_closure`] narrows the render context to it,
    /// so the two cannot disagree.
    #[must_use]
    pub(crate) fn dependency_closure(
        &self,
        stage: &StageId,
    ) -> std::collections::BTreeSet<StageId> {
        let mut closure = std::collections::BTreeSet::new();
        let mut frontier: Vec<&StageId> = self
            .stages
            .get(stage)
            .map(|s| s.depends_on.iter().collect())
            .unwrap_or_default();
        while let Some(ancestor) = frontier.pop() {
            if !closure.insert(ancestor.clone()) {
                continue;
            }
            if let Some(ancestor_stage) = self.stages.get(ancestor) {
                frontier.extend(ancestor_stage.depends_on.iter());
            }
        }
        closure.remove(stage);
        closure
    }

    /// `outputs` (completed envelopes keyed by checked stage id) narrowed to
    /// `stage`'s [`Self::dependency_closure`] — the `stages.*` namespace a
    /// template of `stage` renders against. A completion outside the closure —
    /// a sibling branch that happened to finish first — is never visible, so a
    /// render cannot depend on scheduling order.
    #[must_use]
    pub fn outputs_in_dependency_closure(
        &self,
        stage: &StageId,
        outputs: &BTreeMap<SmolStr, serde_json::Value>,
    ) -> BTreeMap<SmolStr, serde_json::Value> {
        let closure = self.dependency_closure(stage);
        outputs
            .iter()
            .filter(|(name, _)| closure.contains(&StageId((*name).clone())))
            .map(|(name, envelope)| (name.clone(), envelope.clone()))
            .collect()
    }

    /// THE binding between a validation criterion and the stage that proves it,
    /// read out of the frozen IR rather than reconstructed from a stage NAME.
    ///
    /// REFUSES: every runtime stage whose checked base id is not named by a
    /// `validation_criterion(stage = …)` this program declares. CLAIMS: nothing
    /// about whether that stage's output actually CONTAINS a report —
    /// `ExecutionValidationEvidence::from_stage_output` answers `None` when it
    /// does not — and nothing about whether the stage may be TRUSTED, which is
    /// [`ExecutionProgramStage::is_validation_proof_eligible`]'s job at the
    /// promotion gate. Trust and recording are deliberately separate: this
    /// decides what becomes evidence, that decides what evidence authorizes.
    ///
    /// The declaration is the binding, never a stage-name convention: under a
    /// name convention a criterion declared on a stage the convention did not
    /// recognize (`check`, `gate_run`) would be permanently unprovable — the pack
    /// emits its criteria, passes its checks, and can then never be promoted, with
    /// nothing said at authoring time. Here the two cannot disagree.
    ///
    /// `runtime_stage_name` may carry synthetic invocation suffixes
    /// (`#iter-N`, `#validate-M`, `#child-…`, and their composites); the checked
    /// base is the part before the first `#`. A criterion whose `stage` is `None` binds
    /// nothing — `validate_validation_criteria` refuses that shape at load, and
    /// a durable program admitted before that guard stays fail-closed here.
    #[must_use]
    pub fn stage_records_validation_evidence(&self, runtime_stage_name: &str) -> bool {
        let base = runtime_stage_name
            .split('#')
            .next()
            .unwrap_or(runtime_stage_name);
        self.validation_criteria.criteria.iter().any(|criterion| {
            criterion
                .stage
                .as_ref()
                .is_some_and(|s| s.0.as_str() == base)
        })
    }

    /// Resolve a RUNTIME stage name — which may carry synthetic invocation
    /// suffixes — to the checked stage id it was derived from, or `None` when no
    /// checked stage authorizes that name.
    ///
    /// REFUSES: a bare name that is not a checked stage; a `#validate-0` /
    /// `#iter-0` (attempt/iteration 0 IS the base dispatch, so the suffixed
    /// spelling is not a name the runtime mints); and a `#child-<tail>` whose
    /// tail no declared child role authorizes. CLAIMS nothing about whether the
    /// resolved stage has run, may be trusted, or is reachable.
    ///
    /// This is STRICTER than [`Self::stage_records_validation_evidence`]'s
    /// `split('#')` peel, deliberately: that one answers "is this a stage the
    /// program declared a criterion on", where an unauthorized suffix cannot
    /// forge a criterion binding; this one answers "which checked stage's policy
    /// governs this dispatch", where it could.
    ///
    /// Lives here, on the program, because BOTH promotion routes need it: the
    /// operator/factory gate in `kata-api` and the in-graph gate in
    /// `kata-workflow`'s runner, and a second copy in either would drift from
    /// its twin.
    #[must_use]
    pub fn checked_stage_id_for_runtime_stage(&self, runtime_stage_name: &str) -> Option<StageId> {
        let direct = StageId(SmolStr::new(runtime_stage_name));
        if self.stages.contains_key(&direct) {
            return Some(direct);
        }
        for marker in ["#validate-", "#iter-"] {
            if let Some((base, number)) = parse_numbered_runtime_suffix(runtime_stage_name, marker)
                && number > 0
            {
                let stage_id = StageId(SmolStr::new(base));
                if self.stages.contains_key(&stage_id) {
                    return Some(stage_id);
                }
            }
        }
        if let Some(base) = runtime_stage_name.strip_suffix("#escalate-gate") {
            let stage_id = StageId(SmolStr::new(base));
            if self.stages.contains_key(&stage_id) {
                return Some(stage_id);
            }
        }
        self.stages.iter().find_map(|(stage_id, checked_stage)| {
            let tail = runtime_stage_name.strip_prefix(&format!("{}#child-", stage_id.0))?;
            checked_child_runtime_tail_is_authorized(checked_stage, tail).then(|| stage_id.clone())
        })
    }
}

#[derive(Debug)]
pub struct ExecutionProgramCompileOptions<'a> {
    pub output_schemas: &'a BTreeMap<StageId, serde_json::Value>,
    pub prompt_rendering: &'a BTreeMap<StageId, ExecutionPromptRendering>,
}

impl ExecutionProgramCompileOptions<'_> {
    pub fn empty() -> Self {
        Self {
            output_schemas: &EMPTY_OUTPUT_SCHEMAS,
            prompt_rendering: &EMPTY_PROMPT_RENDERING,
        }
    }
}

static EMPTY_OUTPUT_SCHEMAS: BTreeMap<StageId, serde_json::Value> = BTreeMap::new();
static EMPTY_PROMPT_RENDERING: BTreeMap<StageId, ExecutionPromptRendering> = BTreeMap::new();

/// Split `<base><marker><number>` into its base and number, or `None` when the
/// marker is absent or the tail is not a number.
fn parse_numbered_runtime_suffix<'a>(name: &'a str, marker: &str) -> Option<(&'a str, u32)> {
    let (base, tail) = name.rsplit_once(marker)?;
    tail.parse().ok().map(|number| (base, number))
}

/// Whether a `<stage>#child-<tail>` runtime name is authorized by one of the
/// stage's declared child roles — [`ExecutionProgramStage::child_role_for_runtime_tail`]
/// names one.
fn checked_child_runtime_tail_is_authorized(
    checked_stage: &ExecutionProgramStage,
    tail: &str,
) -> bool {
    checked_stage.child_role_for_runtime_tail(tail).is_some()
}
