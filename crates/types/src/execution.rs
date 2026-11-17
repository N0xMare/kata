//! Execution lifecycle types — wire shape of `GET /api/v1/executions`
//! and `GET /api/v1/executions/{id}`.
//!
//! Pure data: no I/O, no locks, no dispatcher dependency. The
//! `kata-api` crate owns the constructor that builds an
//! `ExecutionRecord` from the chain's attempt states
//! (`kata_workflow::attempt_delivery::ChainAssignmentState`); that
//! constructor stays in api because it depends on ledger/dispatcher
//! types that would pull a heavy dependency tree into `kata-types`.
//!
//! The types live here, not in `kata-api`, so the SDK re-exports them rather
//! than keeping a per-field mirror; the api crate re-exports them via
//! `pub use`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::effect::ObservationProvenance;
use crate::ledger::AgentInvocationGraph;
use crate::memory::MemoryObject;
use crate::primitives::ContentHash;
use crate::workspace_awareness::ExecutionWorkspacePromotion;

pub const WORKFLOW_CLASS_IDENTITY_SCHEMA_VERSION: u32 = 1;
pub const HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION: u32 = 1;
/// The `status` string a RESOLVED [`ExecutionHumanRequestEvidence`] carries.
///
/// Public and owned by `kata-types` because four crates test against it. It was
/// a private `const` in `kata-api` plus three hardcoded `"answered"` literals in
/// `kata-client` and `kata-workflow`; changing the string would have moved the
/// server and left every client-side reader believing the request was still
/// open.
pub const HUMAN_REQUEST_ANSWER_STATUS: &str = "answered";
pub const HUMAN_REQUEST_ANSWER_SUMMARY_MAX_CHARS: usize = 240;
pub const EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const EXTERNAL_INPUT_TEXT_MAX_CHARS: usize = 2_000;
pub const MEMORY_SELECTOR_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const CHECK_ARTIFACT_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const MEMORY_WRITEBACK_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const CONTROLLER_DECISION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const CONTROLLER_APPLICATION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const CHECKED_RUNTIME_AUTHORITY_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const CHECKED_DISPATCH_GUARD_EVIDENCE_SCHEMA_VERSION: u32 = 1;
/// Schema version for the per-stage output-closure OBSERVATION
/// evidence ([`ExecutionOutputClosureEvidence`]) the runtime records at stage
/// completion for a stage that declared a `produces_files=` closure.
pub const OUTPUT_CLOSURE_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const CHECKED_DISPATCH_GUARD_ID: &str = "dispatch_policy_coverage";
pub const CHECKED_DISPATCH_POLICY_FIELDS: &[&str] = &[
    "cache_policy",
    "approval_required",
    "model_hint",
    "timeout_ms",
    "allowed_tools",
    "required_capabilities",
    "sandbox",
    "validate_retries",
    "cost_budget",
    "progress_visibility",
    // The hashed seven-axis execution class is part of the checked stage
    // contract, and the dispatch guard commits to it alongside the authored
    // policy knobs (containment/placement/cache eligibility derive from it).
    "execution_class",
    // The checked shell exit policy. A non-default policy folds into the hashed
    // stage contract, so the dispatch guard commits to it alongside the other
    // policy knobs. `content` is the spelling that serializes and hashes,
    // `zero_success` the one that omits.
    "exit_policy",
];

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if requires &T.
fn is_false(value: &bool) -> bool {
    !*value
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip_serializing_if requires &T.
fn is_true(value: &bool) -> bool {
    *value
}

/// Returns `true` when `token` is a natural-language sentinel an LLM
/// controller/agent emits to mean "no blocker" — e.g. `"none"`, `"N/A"`,
/// `"-"`, or the empty string. Comparison is case-insensitive and tolerant
/// of surrounding whitespace and a single trailing period.
///
/// This is the determinism-boundary (Contract membrane) coercion: agent
/// free-text that *means* the empty list must be normalized to the canonical
/// empty form before any pass/fail gate inspects it. Without this, a
/// `validation_blockers: ["none"]` from the controller is treated as a real
/// blocker and forces `validation_passed = false`.
#[must_use]
pub fn is_sentinel_blocker(token: &str) -> bool {
    let normalized = token
        .trim()
        .trim_end_matches('.')
        .trim()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "" | "none" | "n/a" | "na" | "-" | "no blockers" | "no blocker" | "nil" | "empty"
    )
}

/// Drops sentinel "no blocker" tokens (see [`is_sentinel_blocker`]) from a
/// parsed blockers list, yielding the canonical form where a non-empty list
/// always contains at least one *real* blocker. A list that contained only
/// sentinels normalizes to empty; a list with a genuine blocker keeps it.
#[must_use]
pub fn filter_sentinel_blockers(blockers: Vec<String>) -> Vec<String> {
    blockers
        .into_iter()
        .filter(|blocker| !is_sentinel_blocker(blocker))
        .collect()
}

/// Public projection of a submitted execution's lifecycle. Advances linearly:
/// `Pending` → `Running` → (`Completed` | `Failed` | `Cancelled`).
///
/// Cancel is a public terminal: a cancelled execution projects `Cancelled` so
/// consumers do not read an operator stop as a `Failed` — and do not treat it
/// as retry-worthy. The per-attempt detail of how the stop
/// was honoured stays on `ExecutionRecord.evidence.worker_stops[]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    /// Submitted, not yet picked up by the background task.
    Pending,
    /// `WorkflowRunner::run()` is executing.
    Running,
    /// All stages reached a terminal state successfully.
    Completed,
    /// One or more stages failed, or the runner returned an error.
    Failed,
    /// The operator cancelled the run before it completed; the lifecycle
    /// row is `cancelled` and the per-attempt stop story is on
    /// `evidence.worker_stops`.
    Cancelled,
}

impl ExecutionStatus {
    /// True when the status is `Completed`, `Failed` or `Cancelled` — no
    /// further transitions can happen.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ExecutionStatus::Completed | ExecutionStatus::Failed | ExecutionStatus::Cancelled
        )
    }

    /// Wire string for this status (`pending` / `running` / `completed`
    /// / `failed` / `cancelled`) — the `snake_case` serde tag, projected
    /// without round-tripping through serde for one field.
    #[must_use]
    pub fn as_tag(&self) -> &'static str {
        match self {
            ExecutionStatus::Pending => "pending",
            ExecutionStatus::Running => "running",
            ExecutionStatus::Completed => "completed",
            ExecutionStatus::Failed => "failed",
            ExecutionStatus::Cancelled => "cancelled",
        }
    }
}

/// One row of `GET /api/v1/executions/{id}` (or one entry of
/// `GET /api/v1/executions`).
///
/// Serialized straight to JSON as the HTTP response body. Field names
/// and types are wire-stable — see the round-trip tests below and the
/// integration coverage in the api/client crates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    /// Ulid as a string.
    pub id: String,
    /// Workflow name from the resolved `WorkflowDefinition`.
    pub workflow_name: String,
    /// Checked execution-program identity used for this run.
    ///
    /// Present for checked-IR executions, and for restarted executions whose
    /// durable `ExecutionProgram` or reserved execution-evidence row can be
    /// replayed. Omitted for a row where neither source is available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_program: Option<ExecutionProgramIdentity>,
    /// Lifecycle status. See [`ExecutionStatus`].
    pub status: ExecutionStatus,
    /// Milliseconds since UNIX epoch. Populated on submit.
    pub submitted_at_ms: u64,
    /// Milliseconds since UNIX epoch. Populated when the background
    /// task transitions to Running. `None` while Pending.
    pub started_at_ms: Option<u64>,
    /// Milliseconds since UNIX epoch. Populated on terminal
    /// transition. `None` while Pending or Running.
    pub finished_at_ms: Option<u64>,
    /// Worker the runner was pinned to. `"pending"` until the first
    /// assignment is dispatched; `"unknown"` for cache hits.
    pub worker_id: String,
    /// Stage outputs on success; `None` on failure or while running.
    pub outputs: Option<BTreeMap<String, serde_json::Value>>,
    /// Error message on failure; `None` on success or while running.
    pub error: Option<String>,
    /// Cumulative cost in micro-USD across all assignments that have
    /// reached `Completed`. In-flight assignments don't contribute (their
    /// cost isn't known until the worker reports `Completed`).
    /// Derived at aggregation time from per-assignment output JSON's
    /// `token_usage.cost_micro_usd` (set by the executor).
    /// `#[serde(default)]` keeps an entry without it decodable.
    /// Unit is **micro-USD**; dashboards divide by 1_000_000 to recover USD.
    ///
    /// # This number does not stand alone — read [`Self::metering`] with it
    ///
    /// The sum is over stages whose cost kata could actually
    /// determine, and the three ways it got there are not equivalent:
    ///
    /// * an **authoritative** stage contributes what the provider billed,
    /// * an **estimated** stage contributes kata's own arithmetic over token
    ///   counts (for an unpriced model, a deliberately-high frontier floor that
    ///   can be an order of magnitude above the real charge), and
    /// * an **unmetered** stage contributes NOTHING AT ALL.
    ///
    /// So when `metering.unmetered_stages > 0` this is a **lower bound**, not a
    /// total. kata does not invent a number for an unmetered stage (a silent
    /// `0` would make the field look complete while under-reporting); it makes
    /// the omission visible.
    #[serde(default)]
    pub running_cost_micro_usd: u64,
    /// The part of [`Self::running_cost_micro_usd`] this execution's `Invoke`
    /// stages carry for their CHILD executions — spend each child accepted on its
    /// own chain, which the child's own record counts too. The parent's total
    /// includes it because the child's spend is what the parent spent; a sum
    /// across records must not, so it reads [`Self::own_cost_micro_usd`].
    #[serde(default, skip_serializing_if = "is_zero")]
    pub child_cost_micro_usd: u64,
    /// How well [`Self::running_cost_micro_usd`] is known.
    ///
    /// A hard cost policy (`cost_bound(..)`, `cost_budget("halt", ..)`) is a
    /// promise about spend, and a promise evaluated against an unknowable number
    /// is not one kata can keep. This field is the operator-readable half of
    /// that: it says how many completed stages were billed, priced, or not
    /// measurable at all, and names the unmeasurable ones with the
    /// `(backend, model)` pair to add to `kata.toml`.
    ///
    /// `#[serde(default)]` keeps an entry without it decodable, and
    /// `skip_serializing_if` keeps the field off the response body of an
    /// execution with no completions.
    #[serde(
        default,
        skip_serializing_if = "crate::metering::MeteringSummary::is_empty"
    )]
    pub metering: crate::metering::MeteringSummary,
    /// Operator-actionable facts about this execution that no other field
    /// carries. Empty in the common case; every populated row is a thing a human
    /// needs to know and cannot infer from `status` alone.
    ///
    /// # Producers
    ///
    /// Three, each a fixed line prefix: `walk_away_halt:` (below),
    /// `unmetered_cost:` (a stage whose cost is unknown, so
    /// [`Self::running_cost_micro_usd`] is a lower bound) and
    /// `checked_program_unreadable:` (this binary cannot read the execution's
    /// durable checked program, so every projection it binds — validation
    /// evidence, routing, input waits, the invocation graph — is absent).
    ///
    /// # WALK-AWAY halts
    ///
    /// `walkaway_halt_warnings` in `kata-api`'s record aggregator emits one
    /// `walk_away_halt:`-prefixed line per synthetic `<stage>#bound-halt-<kind>` /
    /// `<stage>#budget-halt` Failed row — the durable evidence that a
    /// [`crate::bound::Bound`] or a `cost_budget("halt", ..)` limit stopped an
    /// unattended run.
    ///
    /// Two things make that a warning rather than something `status` covers:
    ///
    /// 1. **It is the only place the DROPPED WORK is recorded.** Stages
    ///    downstream of a halt are never dispatched, so they hold no assignment
    ///    row and are simply ABSENT from `outputs` and `agent_invocation_graph` —
    ///    there is no `Skipped` status on the record to find, because there is no
    ///    row to put one on.
    /// 2. **It is derived independently of `status`.** The executor's lifecycle
    ///    read reassigns `status` from the operational plane, and a `Completed`
    ///    lifecycle could erase a `Failed` the ledger already proved — a
    ///    bound-halted run reporting `"status":"completed"`, `"error":null` and
    ///    exit code 0. `warnings` is projected from the durable rows and no
    ///    lifecycle arm rewrites it, so it survives a clobber of `status`.
    ///
    /// There is NO orchestration-gap warning (declared stages the ledger never
    /// dispatched); do not read the absence of such a line as its absence in
    /// fact.
    ///
    /// `#[serde(default)]` keeps an entry without it decodable.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Optional replay/query projection of observed agent invocations for
    /// this execution. Absent for executions that have not recorded any
    /// invocation metadata yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_invocation_graph: Option<AgentInvocationGraph>,
    /// Operator-facing durable evidence attached to this execution.
    ///
    /// This is intentionally separate from `outputs`: evidence belongs to the
    /// run record even when the execution failed, while stage outputs are only
    /// surfaced for successful executions. The api crate derives this from
    /// typed ledger metadata rows, not synthetic worker assignments.
    #[serde(default, skip_serializing_if = "ExecutionEvidence::is_empty")]
    pub evidence: ExecutionEvidence,
    /// Every `branch()` route DECIDED under the `oci` execution profile: the accepted
    /// outcome of each route's `Select` occurrence, one entry per route that decided.
    ///
    /// Read off the operational plane's accepted program-operation outcomes, never off
    /// stage outputs — a route decision is not a stage and has no entry in
    /// [`Self::outputs`]. Empty for an execution with no route decided yet; omitted
    /// from the wire when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing: Vec<RoutingDecision>,
    /// The target an isolated execution's admission resolved and froze — its
    /// spec, the `/work` fork base, the landable branch and the review
    /// baseline — read off the stored invocation. `None` for an execution that
    /// forks no isolated workspace; omitted from the wire then.
    /// [`crate::target::ExecutionTarget::summary`] is its one-line rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<crate::target::ExecutionTarget>,
    /// The network every capsule this execution DECLARED was given — one entry
    /// per declared capsule, by stage then attempt, read off the capsule's own bytes
    /// on the operational plane (the allowlist the worker's proxy enforces).
    /// Empty until a capsule is declared; omitted from the wire then.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capsule_networks: Vec<StageCapsuleNetwork>,
}

/// One declared capsule's network, as [`ExecutionRecord::capsule_networks`]
/// shows it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageCapsuleNetwork {
    /// The stage the capsule ran.
    pub stage: String,
    /// The declared capsule's id.
    pub capsule_id: String,
    /// What the capsule's network is.
    pub network: crate::execution_contract::CapsuleNetworkPosture,
}

/// One `branch()` route's accepted decision, as [`ExecutionRecord::routing`] shows it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoutingDecision {
    /// The route's condition stage.
    pub condition: String,
    /// The arm the verdict selected.
    pub taken: String,
    /// Every target the decision skipped.
    pub not_taken: Vec<String>,
}

/// Stable identity for the checked execution program associated with a run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionProgramIdentity {
    pub schema_version: u32,
    pub program_hash: ContentHash,
    pub workflow_class: WorkflowClassIdentity,
}

/// Runtime authority derived from the checked execution program for a run.
///
/// This is the small, replayable subset of checked-program state that operator
/// projections need to match server-side factory policy. It is evidence, not
/// operator input: controllers may tighten these limits, but they cannot expand
/// them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionCheckedRuntimeAuthorityEvidence {
    pub schema_version: u32,
    pub program_hash: ContentHash,
    pub workflow_class: WorkflowClassIdentity,
    pub runtime_authority_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_cost_limit_micro_usd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_deadline_at_ms: Option<u64>,
}

/// Workflow-class identity for readiness evidence and replay surfaces.
///
/// It folds the program's source record and `program_hash`, so it is exactly as
/// stable as they are: a source-and-IR identity that ANY byte edit of the pack or
/// of a module it loads rotates, a comment included. Two runs share a class only
/// when they ran byte-identical sources through the same checked IR; the semantic
/// identity of a definition is `normalized_definition_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowClassIdentity {
    pub schema_version: u32,
    pub id: ContentHash,
}

impl ExecutionRecord {
    /// Convenience: true when the underlying status is terminal.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }

    /// The spend this execution ACCEPTED on its own chain: its running cost less
    /// what it carries for its `Invoke` children. Summing this across records counts
    /// each accepted cost exactly once, at the execution that accepted it; summing
    /// [`Self::running_cost_micro_usd`] counts every child's spend once per ancestor.
    #[must_use]
    pub fn own_cost_micro_usd(&self) -> u64 {
        self.running_cost_micro_usd
            .saturating_sub(self.child_cost_micro_usd)
    }
}

// `skip_serializing_if` takes a reference.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u64) -> bool {
    *value == 0
}

pub const EXECUTION_WORKSPACE_IDENTITY_SCHEMA_VERSION: u32 = 1;

/// Provider-neutral identity for a workspace/candidate side effect.
///
/// This is durable evidence for "which execution workspace/candidate did the
/// provider observe?" It intentionally uses strings so Git and jj providers can
/// share one operator/API surface while each backend keeps its native internals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionWorkspaceIdentity {
    pub schema_version: u32,
    pub execution_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_name: Option<String>,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_commit_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_commit_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_commit_sha: Option<String>,
    /// WHO kata committed as — `Name <email>`, the same rendering
    /// `git log --format='%an <%ae>'` produces.
    ///
    /// A RECEIPT: produced by the act that made or published the commit,
    /// recorded once, never re-derived. Without it kata could not answer *who
    /// committed this* from its own records — the one field an operator auditing
    /// a landed commit asks for first.
    ///
    /// `None` for an identity stamp taken where no commit was made or published
    /// (a live-workspace status read on a workspace with no candidate yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

impl ExecutionWorkspaceIdentity {
    /// Stamp the resolved [`Self::author`] receipt.
    ///
    /// A builder rather than a ninth positional parameter on
    /// `execution_workspace_identity`: eight `Option<String>` arguments in a row
    /// is already one too many, and the author is the only one of them produced
    /// by the ACT rather than read back from the repository.
    #[must_use]
    pub fn with_author(mut self, author: Option<String>) -> Self {
        self.author = author;
        self
    }
}

/// Response from `POST /api/v1/executions/{id}/park`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParkedExecution {
    pub status: String,
    pub parked_ref: String,
    pub commit_sha: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ExecutionWorkspaceIdentity>,
}

/// A terminal closeout's park refused by name: the closeout parked nothing, and
/// the workspace stands as the refusal left it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloseoutParkRefusal {
    /// The refusal's name, as the workspace provider spells it:
    /// `parked_ref_occupied` (the ref names a commit the park did not write),
    /// `oci_candidate_diverged` (the workspace's `@` moved off the recorded
    /// candidate), `oci_candidate_disk_diverged` (its disk carries edits no
    /// recorded apply wrote) or `repository_torn` (the repository's store lost
    /// the commit the park would read, after a power loss).
    pub refusal: String,
    /// The ref the park would have written (`parked/<execution-id>`).
    pub parked_ref: String,
    /// The provider's refusal text, naming the commits it judged.
    pub message: String,
}

/// Durable operator evidence projected onto an [`ExecutionRecord`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ExecutionEvidence {
    /// Checked execution-program identity for this run.
    ///
    /// `ExecutionRecord.execution_program` keeps the convenient top-level
    /// projection, but this evidence field is the durable source that can be
    /// replayed from the ledger when process-local caches and workflow
    /// definition rows are unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_program: Option<ExecutionProgramIdentity>,
    /// Checked-program runtime authority for factory controller projections.
    ///
    /// This keeps `kata factory status`, SDK explain surfaces, and replay
    /// packets aligned with `/factory/apply` even when policy depends on the
    /// durable checked `ExecutionProgram`, such as a workflow-level halt
    /// budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_runtime_authority: Option<ExecutionCheckedRuntimeAuthorityEvidence>,
    /// Candidate branch created by `kata run park` or by automatic parking
    /// of a failed isolated execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked_candidate: Option<ParkedExecution>,
    /// True when this evidence was written by the failure-path automatic
    /// parker rather than an explicit operator `park` request.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_parked: bool,
    /// The terminal closeout's park of this execution's candidate was refused
    /// by name, so the closeout parked nothing and the run closed out with its
    /// workspace standing for inspection. Written before the terminal lifecycle
    /// is published, by the closeout that asked; a closeout repaired after a
    /// crash that followed the record reads it as its answer rather than asking
    /// again, and the `parked/<exec>` it names is never adopted as the run's
    /// park. `None` for every run whose closeout parked, owed no park, or is not
    /// isolated. An operator's later park may still record a
    /// [`Self::parked_candidate`] beside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closeout_park_refusal: Option<CloseoutParkRefusal>,
    /// Structured validation evidence projected from completed validation
    /// stages. These reports are derived from durable assignment outputs and
    /// therefore remain available even when the execution as a whole fails
    /// after validation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_reports: Vec<ExecutionValidationEvidence>,
    /// Structured closeout evidence projected from completed closeout stages.
    /// Closeout is the per-wave operator record: outcome, proof, blockers, and
    /// recommended next action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub closeout_reports: Vec<ExecutionCloseoutEvidence>,
    /// Human-request queue entries active for this execution.
    ///
    /// These rows are the runtime source of truth for advisory and blocking
    /// requests. They record blocking mode, the effective default or exact-id
    /// operator answer, and the stage/global context consumed after normal
    /// dispatch or durable answer/timeout resume.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub human_requests: Vec<ExecutionHumanRequestEvidence>,
    /// External side-channel inputs appended during this execution.
    ///
    /// These rows capture nondeterministic input from outside the runner so
    /// stages can consume it through checked prompt/context channels without
    /// giving that input authority over scheduling, approvals, or sandboxing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_inputs: Vec<ExecutionExternalInputEvidence>,
    /// Per-param PROVENANCE recorded beside the admission digest — which
    /// face supplied each typed invocation param (`{name, source_face, secret}`,
    /// NEVER the value). Deliberately evidence, not invocation bytes: provenance
    /// is not hashed, so identical inputs from two faces converge to one
    /// admission digest while each admission's evidence names its own face.
    /// Empty for a param-less invocation, and skipped from serialization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub param_provenance: Vec<ExecutionParamProvenanceEvidence>,
    /// Native-memory context packets materialized from checked
    /// `ExecutionProgram.memory_selectors`.
    ///
    /// These rows are the replayable record of which memory objects a stage saw
    /// at prompt-render time. The object list is bounded by the selector's
    /// `max_objects`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_selectors: Vec<ExecutionMemorySelectorEvidence>,
    /// Check artifacts emitted by validation or factory stages.
    ///
    /// These are the compact, durable handles that let operators and future
    /// controllers distinguish concrete validation outputs from ordinary agent
    /// prose. They may also be written into native memory as `artifact`
    /// objects by the workflow memory-writeback path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub check_artifacts: Vec<ExecutionCheckArtifactEvidence>,
    /// Workflow-declared native-memory writeback attempts observed at runtime.
    ///
    /// This records the control-plane fact that a stage emitted an authorized
    /// memory object proposal and whether Kata applied, skipped, or rejected
    /// it. The authoritative object lives in the native memory store.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_writebacks: Vec<ExecutionMemoryWritebackEvidence>,
    /// Controller decisions emitted by a factory/controller stage.
    ///
    /// This is the first durable control-plane packet for autonomous factory
    /// waves: it records the selected next action, the evidence used, and
    /// alternatives considered. Later multi-wave controllers should build on
    /// this packet rather than inferring decisions from prose.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub controller_decisions: Vec<ExecutionControllerDecisionEvidence>,
    /// Durable applications of controller decisions.
    ///
    /// Decisions explain what a factory controller chose; applications record
    /// what Kata actually did with that choice: parked a candidate, promoted a
    /// workspace, or scheduled a bounded next wave. This is the replayable
    /// guard against applying the same autonomous decision twice.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub controller_applications: Vec<ExecutionControllerApplicationEvidence>,
    /// Per-stage runtime checks proving that the checked execution program was
    /// consulted before a stage was turned into a dispatch assignment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checked_dispatch_guards: Vec<ExecutionCheckedDispatchGuardEvidence>,
    /// Per-stage OUTPUT-CLOSURE OBSERVATIONS recorded at stage completion. For
    /// each stage that declared a `produces_files=` closure the runtime captures
    /// the OBSERVED worktree output set and the declared-vs-observed check
    /// result. It is RECORDED, not enforced here: it does NOT hard-fail on a
    /// violation. Empty for every run whose stages omit `produces_files=`, and
    /// skipped from serialization then.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_closures: Vec<ExecutionOutputClosureEvidence>,
    /// Every worker STOP this execution asked for, and whether the
    /// worker has answered.
    ///
    /// Read live from `operational.db`'s `attempt_stop_requests`, not projected
    /// from ledger metadata. `cancel` returns how many attempts it ASKED to stop,
    /// which is not the question an operator actually has — *has it stopped?* is
    /// answered only by the worker's own attempt-terminal frame, and this field
    /// is where that answer is visible.
    ///
    /// Empty for every execution nobody cancelled, and skipped from
    /// serialization then.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub worker_stops: Vec<ExecutionWorkerStopEvidence>,
    /// Every refusal an egress capsule's proxy recorded while its stage ran —
    /// each CONNECT the guest made that did not become a tunnel, with the
    /// authority it asked for and the refusal class.
    ///
    /// Written INSIDE the transaction that accepts the capsule's completion
    /// (`OperationalDb::adopt_and_accept_capsule_completion`'s `before_accept`),
    /// so a row exists exactly for an accepted attempt and a superseded or
    /// failed attempt records none — the refusal list is a fact ABOUT an
    /// accepted container run, never a claim a settlement declined to adopt.
    ///
    /// Empty for every execution that ran no `Egress` capsule (an `Offline`
    /// capsule has no proxy to refuse anything), and `skip_serializing_if`
    /// keeps the key off those records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress_refusals: Vec<crate::egress_refusal::EgressRefusalReport>,
    /// Every AGENT turn an accepted capsule attempt recorded — one row per
    /// accepted `CapsuleProcess::Agent` attempt, naming the Private CAS blob
    /// that holds the session's own grant-and-refusal record.
    ///
    /// Written INSIDE the transaction that accepts the capsule's completion
    /// (`OperationalDb::adopt_and_accept_capsule_completion`'s `before_accept`)
    /// on the same terms as `egress_refusals`: a row exists exactly for an
    /// accepted attempt, so a superseded or declined completion records none.
    /// Without it the session evidence was durable and invisible — named in a
    /// transition payload but on no operator surface, which is the blind spot
    /// the field exists to close.
    ///
    /// Empty for every execution that ran no `Agent` capsule, and
    /// `skip_serializing_if` keeps those records byte-identical to before this
    /// field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_turns: Vec<ExecutionAgentTurnEvidence>,
}

impl ExecutionEvidence {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.execution_program.is_none()
            && self.checked_runtime_authority.is_none()
            && self.parked_candidate.is_none()
            && !self.auto_parked
            && self.closeout_park_refusal.is_none()
            && self.validation_reports.is_empty()
            && self.closeout_reports.is_empty()
            && self.human_requests.is_empty()
            && self.external_inputs.is_empty()
            && self.param_provenance.is_empty()
            && self.memory_selectors.is_empty()
            && self.check_artifacts.is_empty()
            && self.memory_writebacks.is_empty()
            && self.controller_decisions.is_empty()
            && self.controller_applications.is_empty()
            && self.checked_dispatch_guards.is_empty()
            && self.output_closures.is_empty()
            && self.worker_stops.is_empty()
            && self.egress_refusals.is_empty()
            && self.agent_turns.is_empty()
    }
}

/// ONE accepted agent turn's session evidence, projected so an operator can
/// find the blob the adoption named — the answer to "which session's grant and
/// refusal record is this, and where are its bytes": the stage and attempt the
/// turn ran under, the adapter that ran it, the model the vendor reported, and
/// the Private CAS artifact triple.
///
/// The triple is spelled out as strings rather than carried as an
/// `ArtifactRef` for the same reason `capsule_result_output`'s durable payload
/// spells it: an `ArtifactRef`'s serde form carries the execution-contract
/// schema version and refuses a foreign one, and a durable row must decode
/// across the version bumps a deployed node sees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionAgentTurnEvidence {
    /// The canonical stage id (`attempts.stage_id`) whose capsule produced the
    /// turn, read off this node's own attempts row inside the accepting
    /// transaction — never off the frame.
    pub stage_id: String,
    /// The attempt that ran the turn (`attempts.attempt_id`, Ulid as a string).
    pub attempt_id: String,
    /// The adapter that ran the turn, by its `AdapterKind` label.
    pub adapter: String,
    /// The model the VENDOR reported on the wire — `None` when it stated none.
    /// Evidence, not the requested value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_reported: Option<String>,
    /// The session-evidence artifact's id — the content hash naming the
    /// Private CAS artifact the adoption verified (`SessionEvidence`, bounded
    /// at `SESSION_EVIDENCE_BYTES`).
    pub session_evidence_artifact_id: String,
    /// The session-evidence blob's CAS object id — the object to fetch to read
    /// the record.
    pub session_evidence_object_id: String,
    /// The session-evidence blob's verified size in bytes.
    pub session_evidence_size_bytes: u64,
}

pub const WORKER_STOP_EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// ONE worker stop an operator asked for, projected so they can see
/// whether it landed.
///
/// # The three timestamps are three OBSERVERS, and only one of them is safety
///
/// This mirrors the durable row exactly rather than collapsing it, because the
/// collapse is where the meaning is lost. `requested` says the main decided;
/// `delivered` says a transport accepted the frame and says NOTHING about the
/// worker; `acknowledged` says the worker's own attempt-terminal frame arrived,
/// and that one alone proves nothing is still running the attempt.
///
/// The dangerous state is delivered-and-unacknowledged: the frame is gone, so the
/// caller that sent it got a success, and the worker may be doing anything at
/// all. A projection that reported "delivered" as progress would present exactly
/// that state as reassurance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionWorkerStopEvidence {
    pub schema_version: u32,
    /// The attempt asked to stop (Ulid as a string).
    pub attempt_id: String,
    /// The GENERATION asked to stop: the epoch the attempt's dispatch fenced its
    /// command at. A stop is keyed by `(attempt_id, lease_epoch)`, so discharging
    /// it (`kata run discharge-stop`) needs the epoch as well as the attempt.
    pub lease_epoch: i64,
    /// The worker the stop was addressed to.
    pub worker_id: String,
    /// The operator's stated reason, echoed back so a timeline reads.
    pub reason: String,
    /// Milliseconds since UNIX epoch: when the MAIN decided to stop this
    /// generation. Written before the frame reached any transport.
    pub requested_at_ms: u64,
    /// Milliseconds since UNIX epoch: when a TRANSPORT accepted the frame.
    /// `None` means the stop never left the main, which is a transport fault
    /// rather than a wedged worker — the distinction an operator needs first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at_ms: Option<u64>,
    /// Milliseconds since UNIX epoch: when this stop was DISCHARGED — normally
    /// by the fenced worker's own attempt-terminal frame arriving, and otherwise
    /// by the operator assertion in [`Self::discharge`]. `None` while the stop is
    /// outstanding.
    ///
    /// This field alone does NOT say a worker answered; read it with
    /// [`Self::discharge`], which is what tells the two apart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_at_ms: Option<u64>,
    /// Present ONLY when this stop was discharged by an ATTRIBUTED
    /// OPERATOR ASSERTION rather than by a worker terminal.
    ///
    /// Carried rather than collapsed into the timestamp, because collapsing them
    /// is where the meaning is lost. Both discharges clear the parking refusal,
    /// but one is a worker reporting that it stopped and the other is a human
    /// asserting that it must have. A surface that showed only
    /// `acknowledged_at_ms` would present the second as the first — an operator's
    /// own judgement handed back to them as though the engine had confirmed it,
    /// which is the defect class `rests_on_a_proof` exists to prevent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discharge: Option<StopDischarge>,
    /// True while nothing has answered this stop — i.e. `acknowledged_at_ms` is
    /// absent.
    ///
    /// Carried rather than left to be re-derived: a consumer that
    /// re-derives it can invent its own reading, and the obvious wrong reading
    /// here — treating a delivered stop as settled — is the one that authorizes
    /// reclaiming a workspace a worker is still writing to.
    ///
    /// While this is true, `park` on this execution is REFUSED and names this row.
    pub awaiting_worker_acknowledgement: bool,
}

/// The schema version of the [`StopDischarge`] record persisted in
/// `attempt_stop_requests.discharge_json`.
pub const STOP_DISCHARGE_SCHEMA_VERSION: u32 = 1;

/// The DURABLE record of one operator-asserted stop
/// discharge: who asserted it, what they assert, and when.
///
/// # Why this exists at all
///
/// An `attempt_stop_requests` row is a LATCH: it outlives its attempt and is read
/// fail-closed. A latch with
/// exactly one discharge path — the fenced worker's own terminal — is a
/// PERMANENT refusal whenever that worker can never report, a "recourse nobody
/// can invoke". This is the exit.
///
/// # It reuses the provenance vocabulary rather than minting a second one
///
/// [`ObservationProvenance`] is the tree's one spelling of "how was this
/// determined, and is it a proof?", and `rests_on_a_proof` is its one spelling
/// of the question a later reader asks. A stop discharge is a human asserting
/// something kata cannot verify, so it is recorded in those words. A parallel
/// `StopProvenance` enum would be a second vocabulary for one question, and two
/// vocabularies for one question is how they come to disagree.
///
/// # Why a probe is UNREPRESENTABLE here, not merely refused
///
/// [`Self::from_provenance`] is the only constructor and it returns `None` for
/// [`ObservationProvenance::Probed`]. What must NOT happen is auto-discharge on
/// a worker-death declaration — *heartbeat loss is
/// not proof of process exit*, which is the premise of the fact-(2) conjunction
/// `require_terminal_lifecycle_for_parking` had to add. kata has no probe that
/// can prove a worker process is gone, so admitting a `Probed` discharge would
/// mean the first thing built against it would be that auto-discharge, wearing
/// a label that says it is a proof. The filter belongs on the only constructor,
/// so an inadmissible record cannot be built and then stored by a caller who did
/// not check.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StopDischarge {
    /// Schema version of this record ([`STOP_DISCHARGE_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// How the discharge was determined. Always
    /// [`ObservationProvenance::OperatorAsserted`] today — see the type doc for
    /// why the field carries the full enum rather than a bare operator name.
    pub provenance: ObservationProvenance,
    /// What the operator asserts they established, in their own words. Required
    /// and non-empty: a discharge whose record says only "an operator did this"
    /// tells the next reader nothing about what was checked.
    pub assertion: String,
    /// Milliseconds since UNIX epoch the discharge was recorded.
    pub discharged_at_ms: u64,
}

impl StopDischarge {
    /// Build the durable record, or `None` when the provenance cannot authorize a
    /// discharge (a probe — see the type doc) or the assertion text is blank.
    #[must_use]
    pub fn from_provenance(
        provenance: ObservationProvenance,
        assertion: impl Into<String>,
        discharged_at_ms: u64,
    ) -> Option<Self> {
        if provenance.is_a_proof() {
            return None;
        }
        let assertion = assertion.into();
        if assertion.trim().is_empty() {
            return None;
        }
        Some(Self {
            schema_version: STOP_DISCHARGE_SCHEMA_VERSION,
            provenance,
            assertion,
            discharged_at_ms,
        })
    }

    /// Whether this discharge rests on a machine PROOF rather than a human
    /// assertion. Delegates to [`ObservationProvenance::is_a_proof`] so there is
    /// one spelling of the question.
    ///
    /// Always `false` today, and it is carried anyway rather than assumed: a
    /// reader that re-derived it from the variant would be a second place the
    /// answer lives, and the field is what makes the record self-describing when
    /// a future provenance IS admissible.
    #[must_use]
    pub const fn rests_on_a_proof(&self) -> bool {
        self.provenance.is_a_proof()
    }

    /// Who asserted it, for the operator-facing record.
    #[must_use]
    pub fn operator(&self) -> Option<&str> {
        match &self.provenance {
            ObservationProvenance::OperatorAsserted { operator } => Some(operator.as_str()),
            ObservationProvenance::Probed { .. } => None,
        }
    }
}

/// One stage's OUTPUT-CLOSURE OBSERVATION, recorded at stage
/// completion.
///
/// This is the durable half of the declared-vs-observed output closure: the
/// stage DECLARED a `produces_files=` closure, and at completion the runtime
/// captured the OBSERVED worktree change set ([`Self::observed_outputs`]) and
/// checked it against the declared globs. [`Self::undeclared`] is the set of
/// observed paths NO declared glob covers (the closure VIOLATIONS); an empty
/// `undeclared` means the stage conformed. RECORD-not-enforce: this surfaces a
/// violation (warn + metric) but does NOT fail the stage; hard-fail enforcement
/// is the capsule route's adoption judge, not this record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionOutputClosureEvidence {
    pub schema_version: u32,
    /// The runtime stage name (base or derived) whose completion produced this
    /// observation.
    pub stage_name: String,
    /// The OBSERVED output set: repo-relative worktree paths the stage produced
    /// or modified, captured at completion (sorted, deduped). May be empty when a
    /// declaring stage produced nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_outputs: Vec<SmolStr>,
    /// The closure VIOLATIONS: observed paths covered by NO declared glob. Empty
    /// iff the stage conformed to its declared `produces_files=` closure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub undeclared: Vec<SmolStr>,
}

impl ExecutionOutputClosureEvidence {
    /// True iff every observed output path is covered by the declared closure —
    /// i.e. the observed set has no closure violations.
    #[must_use]
    pub fn is_conforming(&self) -> bool {
        self.undeclared.is_empty()
    }
}

/// Runtime result for the checked execution-program dispatch guard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCheckedDispatchGuardStatus {
    Passed,
    Failed,
}

/// Runtime assignment shape covered by a checked execution-program guard.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCheckedDispatchKind {
    StaticStage,
    ValidationRetry,
    DynamicFanoutChild,
    ExecutableChild,
    ReviewLoopIteration,
    ReviewLoopEscalationGate,
}

/// One stage-level dispatch guard result projected onto an execution record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionCheckedDispatchGuardEvidence {
    pub schema_version: u32,
    pub stage_name: String,
    pub guard: String,
    pub status: ExecutionCheckedDispatchGuardStatus,
    pub program_hash: ContentHash,
    pub workflow_class: WorkflowClassIdentity,
    pub dispatch_policy_coverage: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_kind: Option<ExecutionCheckedDispatchKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_stage_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostic_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One nonblocking advisory request projected onto an execution record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionHumanRequestEvidence {
    pub schema_version: u32,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    pub priority: String,
    pub question: String,
    pub default_assumption: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub blocking: bool,
    pub status: String,
    pub projection: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_by_steering_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_at_ms: Option<u64>,
    /// `true` when this blocking request was resolved not by an
    /// operator answer but by the input-await timeout sweep applying
    /// `default_assumption` as the effective answer after the self-heal deadline
    /// (`awaiting_approval_at_ms + timeout_ms`) elapsed. Auditable distinction
    /// from an operator answer (`answered_by_steering_id` set) and from an
    /// untouched advisory default (`status == "default_assumption_active"`).
    /// Omitted when `false`, so a row without the key deserializes to `false`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_defaulted: bool,
}

impl ExecutionHumanRequestEvidence {
    /// The ONE definition of "this request has been resolved and no longer
    /// holds its stage".
    ///
    /// # Why it lives here and not in each reader
    ///
    /// Several crates ask this question, and a reader that tests only one of
    /// the three marks (`status`, `answered_at_ms`, `auto_defaulted`) agrees
    /// with the others only while every writer happens to set all three
    /// together — an accident of the writers, not a contract.
    ///
    /// The union is the correct predicate, because every one of the three marks
    /// is written only by a path that has already resolved the request:
    /// `auto_defaulted` alone is a timeout self-heal that ALREADY re-dispatched
    /// the parked stage, so a reader that ignores it prints a "go answer this"
    /// command against a request the runtime resumed past.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.status == HUMAN_REQUEST_ANSWER_STATUS
            || self.answered_at_ms.is_some()
            || self.auto_defaulted
    }
}

/// Body of `POST /api/v1/executions/{id}/human-request-answer`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionHumanRequestAnswerRequest {
    pub request_id: String,
    pub answer_summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_by_steering_id: Option<u64>,
}

/// Response from `POST /api/v1/executions/{id}/human-request-answer`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionHumanRequestAnswerResponse {
    pub status: String,
    pub human_request: ExecutionHumanRequestEvidence,
}

/// One durable external side-channel input row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionExternalInputEvidence {
    pub schema_version: u32,
    pub id: String,
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_stage: Option<String>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    pub projection: String,
    pub appended_at_ms: u64,
}

/// One per-param PROVENANCE row recorded in admission evidence — which
/// face supplied a typed invocation param.
///
/// Carries the param NAME, the [`crate::params::ParamProvenance`] face, and the
/// program's secret marker — NEVER the value (the value's identity is bound by
/// the admission digest; its bytes live only in the authoritative invocation
/// blob). Not hashed: two faces supplying identical params produce one admission
/// digest while each records its own face here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionParamProvenanceEvidence {
    /// The declared param name.
    pub name: SmolStr,
    /// The face this admission's value entered through.
    pub source_face: crate::params::ParamProvenance,
    /// The program's secret marker for this param (redaction hint for readers).
    #[serde(default, skip_serializing_if = "is_false")]
    pub secret: bool,
}

/// Body of `POST /api/v1/executions/{id}/external-inputs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionExternalInputAppendRequest {
    pub channel: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

/// Response from `POST /api/v1/executions/{id}/external-inputs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionExternalInputAppendResponse {
    pub status: String,
    pub external_input: ExecutionExternalInputEvidence,
}

/// One native-memory context packet materialized for a checked selector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::struct_excessive_bools)] // Wire evidence uses explicit JSON booleans.
pub struct ExecutionMemorySelectorEvidence {
    pub schema_version: u32,
    pub selector_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    pub expose_as: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
    pub statuses: Vec<String>,
    pub max_objects: u32,
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    pub revision_head: u64,
    pub object_count: usize,
    pub truncated: bool,
    pub store_available: bool,
    pub missing_required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<MemoryObject>,
    pub projection: String,
    pub materialized_at_ms: u64,
}

/// One deterministic or bounded check artifact produced by a workflow stage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionCheckArtifactEvidence {
    pub schema_version: u32,
    pub artifact_id: String,
    pub stage_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl ExecutionCheckArtifactEvidence {
    /// Parse `check_artifacts` from a stage output envelope.
    ///
    /// Accepts the same raw, `parsed`, or JSON-string `content` forms used by
    /// validation report parsing.
    #[must_use]
    pub fn from_stage_output(
        stage_name: impl Into<String>,
        output: &serde_json::Value,
    ) -> Vec<Self> {
        let stage_name = stage_name.into();
        let parsed_content = output
            .get("content")
            .and_then(serde_json::Value::as_str)
            .and_then(|content| serde_json::from_str::<serde_json::Value>(content).ok());
        let parsed = output
            .get("parsed")
            .or(parsed_content.as_ref())
            .unwrap_or(output);
        parsed
            .get("check_artifacts")
            .or_else(|| parsed.get("artifacts"))
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|artifact| check_artifact_from_value(&stage_name, artifact))
            .collect()
    }
}

fn check_artifact_from_value(
    stage_name: &str,
    value: &serde_json::Value,
) -> Option<ExecutionCheckArtifactEvidence> {
    let artifact_id = string_field(value, "artifact_id").or_else(|| string_field(value, "id"))?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .unwrap_or(CHECK_ARTIFACT_EVIDENCE_SCHEMA_VERSION);
    Some(ExecutionCheckArtifactEvidence {
        schema_version,
        artifact_id,
        stage_name: string_field(value, "stage_name")
            .or_else(|| string_field(value, "stage"))
            .unwrap_or_else(|| stage_name.to_string()),
        status: string_field(value, "status"),
        commands: string_array_field(value, "commands"),
        paths: string_array_field(value, "paths"),
        evidence: string_array_field(value, "evidence"),
        missing: string_array_field(value, "missing"),
        summary: string_field(value, "summary"),
        source: string_field(value, "source"),
    })
}

/// Runtime evidence for one authorized native-memory writeback attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionMemoryWritebackEvidence {
    pub schema_version: u32,
    pub writeback_id: String,
    pub stage_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// One autonomous controller decision projected onto an execution record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerDecisionEvidence {
    pub schema_version: u32,
    pub stage_name: String,
    pub decision_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wave_id: Option<String>,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub human_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ExecutionControllerDecisionScopeEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<ExecutionControllerCompletionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_policy: Option<ExecutionControllerMemoryPolicyEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_policy: Option<ExecutionControllerRuntimePolicyEvidence>,
}

/// Typed scheduler scope selected by a factory controller decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerDecisionScopeEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub focus_areas: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Typed product-completion state selected by a factory controller decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerCompletionEvidence {
    pub status: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub validation_passed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Typed native-memory policy selected for the next factory wave.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerMemoryPolicyEvidence {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writebacks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_queries: Vec<String>,
    /// Native-memory objects the controller declares to write back as it
    /// schedules the next wave. Each is applied idempotently into native memory
    /// at advance time; the body wraps an optional controller-authored summary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proposals: Vec<ExecutionControllerMemoryProposalEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// A native-memory object a factory controller decision declares to write back
/// while scheduling an autonomous advance.
///
/// Intentionally string-shaped (no free-form JSON body) so the controller
/// decision evidence stays `Eq` and replay-comparable. Kata wraps `summary`
/// into a structured memory-object body when it applies the proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerMemoryProposalEvidence {
    pub object_id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Runtime limits selected by a factory controller decision.
///
/// These limits are interpreted as controller-selected tightening, not as an
/// authority to expand an operator or server budget. Derived next-wave policy
/// compares them against observed execution cost/time before scheduling another
/// autonomous wave.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerRuntimePolicyEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_limit_micro_usd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_wave_stage_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_max_waves: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Checked next-wave memory policy that Kata applied while scheduling an
/// autonomous factory advance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerMemoryPolicyApplicationEvidence {
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writebacks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_queries: Vec<String>,
    /// Compact, deterministic record of controller-declared memory proposals
    /// accepted for this advance. Kept body-free so the application evidence
    /// stays a pure function of the decision (preserving the
    /// `claim.memory_policy == plan.memory_policy` resume invariant).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proposals: Vec<MemoryProposalEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Compact record that a controller-declared memory proposal was accepted for
/// application during a factory advance. `action` is always `declared`; the
/// durable proof of application is the resulting native-memory object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryProposalEvidence {
    pub object_id: String,
    pub kind: String,
    pub action: String,
}

/// Minimal caller-supplied context for applying a controller decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerApplicationContext {
    pub decision_id: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request to apply one recorded controller decision through the main.
///
/// The server infers the default action from the recorded decision and returns
/// `already_applied` when durable controller-application evidence already
/// exists for the decision. This makes operator retries safe after client or
/// network interruption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ExecutionControllerApplyRequest {
    pub decision_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, alias = "ref_name", skip_serializing_if = "Option::is_none")]
    pub park_ref_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_ref: Option<String>,
    #[serde(
        default,
        rename = "workflow_starlark",
        skip_serializing_if = "Option::is_none"
    )]
    pub workflow_starlark: Option<String>,
    #[serde(
        default,
        rename = "workflow_filename",
        skip_serializing_if = "Option::is_none"
    )]
    pub workflow_filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_input_channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_input_id: Option<String>,
    /// Request server-side resume of a claimed but unfinished side effect.
    ///
    /// Retry support covers claims whose recorded side-effect metadata exactly
    /// matches the retry request. Default-ref `park` claims retry only the
    /// deterministic park ref. Pure `advance` claims submit only the recorded
    /// next-wave program and external-input routing. `promote_then_advance`
    /// claims resume only after promotion evidence exists and the execution
    /// worktree is absent, so retry submits the claimed next wave without
    /// rerunning promotion. Custom park labels and claims without enough
    /// durable metadata fail closed and must be finalized from observed
    /// evidence.
    #[serde(default, skip_serializing_if = "is_false")]
    pub resume_claimed_side_effect: bool,
}

/// Request to finalize an incomplete controller-application claim after an
/// operator/admin has verified that the side effect already happened.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ExecutionControllerApplyFinalizeRequest {
    pub decision_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub confirm_side_effect: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_execution_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked_candidate: Option<ParkedExecution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<ExecutionWorkspacePromotion>,
}

/// Result of a server-owned controller decision application attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerApplyResponse {
    pub status: String,
    pub execution_id: String,
    pub decision_id: String,
    pub decision: String,
    pub action: String,
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked_candidate: Option<ParkedExecution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<ExecutionWorkspacePromotion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_execution_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_external_input_channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_external_input_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_application: Option<ExecutionControllerApplicationEvidence>,
}

/// Runtime evidence for one applied controller decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerApplicationEvidence {
    pub schema_version: u32,
    pub application_id: String,
    pub decision_id: String,
    pub decision: String,
    pub action: String,
    pub applied: bool,
    pub applied_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_execution_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked_candidate: Option<ParkedExecution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<ExecutionWorkspacePromotion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_policy: Option<ExecutionControllerMemoryPolicyApplicationEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side_effect: Option<ExecutionControllerApplicationSideEffectEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<ExecutionControllerApplicationRecoveryEvidence>,
}

/// Durable side-effect arguments recorded before the side effect runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerApplicationSideEffectEvidence {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_execution_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_program_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_input_channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_input_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_cost_limit_micro_usd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_consumed_micro_usd: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_wave_stage_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_authority_source: Option<String>,
}

/// Operator/admin evidence for finalizing a durable application claim whose
/// side effect was observed out-of-band after an interruption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionControllerApplicationRecoveryEvidence {
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

#[cfg(test)]
mod human_request_tests {
    use super::*;

    #[test]
    fn human_request_unanswered_evidence_decodes_without_answer_fields() {
        let raw = serde_json::json!({
            "schema_version": HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION,
            "id": "HR-unanswered",
            "stage": "plan",
            "priority": "medium",
            "question": "Proceed with the default plan?",
            "default_assumption": "Yes.",
            "context": "No answer has been recorded.",
            "blocking": false,
            "status": "default_assumption_active",
            "projection": "HR-unanswered [plan]: Proceed with the default plan? Default: Yes."
        });
        let decoded: ExecutionHumanRequestEvidence = serde_json::from_value(raw).unwrap();
        assert_eq!(decoded.id, "HR-unanswered");
        assert!(decoded.answer_summary.is_none());
        assert!(decoded.answered_by_steering_id.is_none());
        assert!(decoded.answered_at_ms.is_none());
        // A row without `auto_defaulted` → serde default false.
        assert!(!decoded.auto_defaulted);
    }

    #[test]
    fn human_request_answer_evidence_roundtrips_optional_fields() {
        let evidence = ExecutionHumanRequestEvidence {
            schema_version: HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION,
            id: "HR-answered".to_string(),
            stage: None,
            priority: "high".to_string(),
            question: "Which answer path?".to_string(),
            default_assumption: "Use default.".to_string(),
            context: None,
            blocking: false,
            status: "answered".to_string(),
            projection: "HR-answered: Which answer path? Answer: Use REST.".to_string(),
            answer_summary: Some("Use REST.".to_string()),
            answered_by_steering_id: Some(7),
            answered_at_ms: Some(1_778_540_000_000),
            auto_defaulted: false,
        };
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["answer_summary"], "Use REST.");
        assert_eq!(json["answered_by_steering_id"], 7);
        assert_eq!(json["answered_at_ms"], 1_778_540_000_000u64);
        let decoded: ExecutionHumanRequestEvidence = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, evidence);
    }

    /// The truth table `ExecutionHumanRequestEvidence::is_resolved` owns, pinned
    /// so a reader cannot quietly re-derive a narrower one.
    ///
    /// The two rows that matter are the ones a narrower predicate gets wrong:
    /// `answered_at_ms` set under a non-`answered` status, and `auto_defaulted`
    /// alone (the timeout resolution that sets it has already re-dispatched the
    /// stage).
    #[test]
    fn is_resolved_is_the_union_of_the_three_resolution_marks() {
        let open = ExecutionHumanRequestEvidence {
            schema_version: HUMAN_REQUEST_EVIDENCE_SCHEMA_VERSION,
            id: "HR-matrix".to_string(),
            stage: Some("plan".to_string()),
            priority: "high".to_string(),
            question: "Resolved?".to_string(),
            default_assumption: "No.".to_string(),
            context: None,
            blocking: true,
            status: "blocked".to_string(),
            projection: "HR-matrix [plan]: Resolved?".to_string(),
            answer_summary: None,
            answered_by_steering_id: None,
            answered_at_ms: None,
            auto_defaulted: false,
        };
        assert!(!open.is_resolved(), "no mark set: still open");

        let by_status = ExecutionHumanRequestEvidence {
            status: HUMAN_REQUEST_ANSWER_STATUS.to_string(),
            ..open.clone()
        };
        assert!(by_status.is_resolved(), "status alone resolves");

        let by_timestamp = ExecutionHumanRequestEvidence {
            answered_at_ms: Some(1_778_540_000_000),
            ..open.clone()
        };
        assert!(
            by_timestamp.is_resolved(),
            "an answer timestamp under a non-`answered` status still resolves"
        );

        let by_auto_default = ExecutionHumanRequestEvidence {
            auto_defaulted: true,
            ..open.clone()
        };
        assert!(
            by_auto_default.is_resolved(),
            "the timeout self-heal has already re-dispatched the stage"
        );
    }

    #[test]
    fn external_input_evidence_roundtrips_optional_payload() {
        let evidence = ExecutionExternalInputEvidence {
            schema_version: EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION,
            id: "ei-1".to_string(),
            channel: "operator_steering".to_string(),
            source: Some("sidecar".to_string()),
            target_stage: Some("plan".to_string()),
            text: "Prefer the narrow implementation path.".to_string(),
            payload: Some(serde_json::json!({"priority": "high"})),
            projection: "operator_steering: Prefer the narrow implementation path.".to_string(),
            appended_at_ms: 1_778_540_000_000,
        };

        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(
            json["schema_version"],
            EXTERNAL_INPUT_EVIDENCE_SCHEMA_VERSION
        );
        assert_eq!(json["payload"]["priority"], "high");
        let decoded: ExecutionExternalInputEvidence = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, evidence);
    }
}

/// One validation-stage report projected onto an [`ExecutionRecord`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionValidationEvidence {
    pub stage_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub criteria: Vec<ExecutionValidationCriterionEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pgrep_clean: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub check_artifacts: Vec<ExecutionCheckArtifactEvidence>,
}

pub const VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
pub const VALIDATION_CRITERION_WAIVER_EVIDENCE_SCHEMA_VERSION: u32 = 1;
/// The version whose bindings carry [`ExecutionValidationCandidateEvidence::tree_id`].
/// Nothing BRANCHES on this value — the promote fence keys on whether `tree_id`
/// is present, never on the version.
pub const VALIDATION_CRITERION_CANDIDATE_EVIDENCE_SCHEMA_VERSION: u32 = 2;

/// Machine-readable status for one validation criterion observed at runtime.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionValidationCriterionStatus {
    Passed,
    Failed,
    Unknown,
    InsufficientEvidence,
    WaivedByPolicy,
}

impl ExecutionValidationCriterionStatus {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "passed" => Some(Self::Passed),
            "failed" => Some(Self::Failed),
            "unknown" => Some(Self::Unknown),
            "insufficient_evidence" => Some(Self::InsufficientEvidence),
            "waived_by_policy" => Some(Self::WaivedByPolicy),
            _ => None,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::InsufficientEvidence => "insufficient_evidence",
            Self::WaivedByPolicy => "waived_by_policy",
        }
    }
}

/// Runtime evidence for a declared validation criterion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionValidationCriterionEvidence {
    pub schema_version: u32,
    pub criterion_id: String,
    pub status: ExecutionValidationCriterionStatus,
    #[serde(
        default = "default_validation_criterion_evidence_required",
        skip_serializing_if = "is_true"
    )]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiver: Option<ExecutionValidationCriterionWaiverEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<ExecutionValidationCandidateEvidence>,
}

/// Explicit policy-waiver provenance for a validation criterion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionValidationCriterionWaiverEvidence {
    pub schema_version: u32,
    pub source: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// Workspace/candidate identity observed when a validation criterion was
/// evaluated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionValidationCandidateEvidence {
    pub schema_version: u32,
    pub execution_id: String,
    pub fingerprint: ContentHash,
    pub content_hash: ContentHash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_paths: Vec<String>,
    /// The CONTENT ADDRESS of the whole candidate tree at the instant the
    /// criterion was evaluated — a jj `MergedTree` root id, which on a
    /// colocated repository IS the git tree sha (measured: a jj candidate's
    /// `head.tree_id` equals `git rev-parse <commit>^{tree}` for
    /// the same content, on both providers).
    ///
    /// This, and NOT [`Self::fingerprint`], is what the promote fence compares.
    /// A fingerprint that folds `head_commit` on one backend and not another is
    /// rotated by a `commit` between validate and promote on one backend only.
    /// The tree id is one value space, does not move when a commit
    /// republishes identical content, does not move for a GITIGNORED write
    /// (which is why the flagship pack's `validate` may write
    /// `kata-out/check.log` into the tree it judges), and DOES move for a
    /// `chmod`, which the fingerprint misses.
    ///
    /// `None` on a workspace that is neither a jj nor a git working tree (a
    /// non-isolated run has no candidate to pin). At the promote fence `None`
    /// REFUSES — see [`CandidateTreePin`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_id: Option<String>,
}

/// The tree identity a promote is permitted to land: the last link of the
/// candidate → validation evidence → approval → landing chain.
///
/// # What this is for
///
/// Nothing in the graph forbids a stage between the validation stamp and the
/// in-graph `workspace_effect op="promote"`, and two shipped packs already put
/// one there. Without a fence, a stage that edits the worktree after validation
/// lands unvalidated content and nothing notices. This value is what the
/// runner-stamped proof hands to the provider so the provider can refuse.
///
/// # The refused set, exactly
///
/// [`Self::require_tree`] is the ONLY consumer, and it refuses exactly four
/// inputs — no more, and deliberately no fewer:
///
/// 1. [`Self::Unstamped`] — a criterion bound this candidate but recorded no
///    tree identity (a mint that could not read the worktree). The tree that
///    was judged is unknown, so it cannot be shown equal to the tree about to
///    land.
/// 2. [`Self::Pinned`] whose EXPECTED value is `+`-joined.
/// 3. [`Self::Pinned`] whose OBSERVED value is `+`-joined. A jj conflicted tree
///    encodes as its sides joined by `+` (`JjBackend::merged_tree_id_hex`), and
///    a conflicted candidate exports `.jjconflict-base-0` / `-side-0` /
///    `-side-1` sidecars plus a `JJ-CONFLICT-README`, with the top-level file
///    holding one arbitrary side. Two `+`-joined values that happen to be equal
///    must therefore NOT be read as "the same tree landed" — the compare is
///    skipped entirely, never performed and then overridden.
/// 4. [`Self::Pinned`] whose expected and observed single tree ids differ.
///
/// It admits exactly two: an equal pair of resolved tree ids, and
/// [`Self::Unpinned`].
///
/// # Why `Unpinned` is admitted, and where it IS refused
///
/// `Unpinned` means no recorded validation criterion bound a candidate to this
/// execution at all. This value is the mechanical IDENTITY fence and nothing
/// more: it guarantees that *if* something was judged, the thing that lands is
/// the thing that was judged. Refusing `Unpinned` here would mean "a promote
/// requires validation criteria", which is the promote GATE — a different
/// question, asked in a different place.
///
/// That gate exists on BOTH routes, and each refuses `Unpinned` itself, upstream
/// of this fence:
///
/// * IN-GRAPH — `kata_workflow::promotion_gate::authorize_promote_directive`
///   refuses a promote whose required criteria bound no candidate, and STAMPS the
///   pin, every time a dispatchable directive for that stage is written.
/// * OPERATOR / FACTORY — `require_promotable_workspace_for_promotion` recomputes
///   the live candidate binding and denies a criterion that carries none
///   (`candidate_missing`).
///
/// # Why no directive drops the pin after it is stamped
///
/// The in-graph pin is stamped where a dispatchable promote directive is
/// written, and a capsule stage's prompt is frozen at admission, so a parked
/// assignment's directive is never rewritten afterwards and has no rewrite for
/// the pin to be lost through. A promote that reaches this fence `Unpinned`
/// therefore reached `promote_workspace` through neither gate — the
/// direct-provider-call case, which has no policy above it by construction. The
/// property belongs to the call sites of `authorize_promote_directive`, not to
/// any one crate's dispatch funnel.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateTreePin {
    /// No recorded validation criterion bound a candidate to this execution.
    #[default]
    Unpinned,
    /// The tree id validation observed, which the settled candidate must equal.
    Pinned(String),
    /// A criterion (named here) bound this candidate but carried no tree id.
    Unstamped(String),
}

impl CandidateTreePin {
    /// Whether this pin names nothing — the serde skip predicate that keeps the
    /// key off a directive carrying no pin.
    #[must_use]
    pub const fn is_unpinned(&self) -> bool {
        matches!(self, Self::Unpinned)
    }

    /// A jj `MergedTree` root id joins the sides of a CONFLICTED tree with this
    /// character; a resolved tree never contains it.
    pub const CONFLICT_JOIN: char = '+';

    /// Resolve the pin from an execution's recorded validation reports.
    ///
    /// LAST STAMPED WINS. A loop pack re-validates on every iteration and
    /// appends a fresh report each time, so the judgement that authorizes the
    /// promote is the most recent one; an earlier iteration's tree is history,
    /// not a second opinion. Within a single report every criterion carries the
    /// SAME binding by construction —
    /// `WorkflowRunner::attach_validation_candidate_binding` writes one binding
    /// to every criterion and errors when an agent-supplied one disagrees — so
    /// there is no intra-report divergence to reconcile.
    /// A criterion whose status is not PASSED binds no pin, and the reason is the
    /// whole point of the fence.
    ///
    /// If the pin took the last
    /// binding REGARDLESS of status, the two halves would answer from different
    /// reports: the verdict from a stale PASS, the pin from a fresh FAIL. The
    /// fence would then compare the failed tree against itself, agree, and land
    /// the tree whose most recent judgement was RED — a promote authorized by
    /// evidence that no longer holds about the thing being promoted.
    ///
    /// Reports `[Passed(A), Failed(B)]` must not authorize `Pinned(B)`. The fence
    /// is a second aggregation over the same slice, and two aggregations that
    /// disagree are worse than one.
    fn criterion_binds_a_pin(criterion: &ExecutionValidationCriterionEvidence) -> bool {
        matches!(criterion.status, ExecutionValidationCriterionStatus::Passed)
    }

    /// Select the last passed, bound criterion from an already-selected evidence
    /// stream. This only derives identity: the caller must establish declaration,
    /// producer and required-criterion policy before using it to authorize a tree.
    #[must_use]
    pub fn from_validation_criteria<'a>(
        criteria: impl IntoIterator<Item = &'a ExecutionValidationCriterionEvidence>,
    ) -> Self {
        let mut pin = Self::Unpinned;
        for criterion in criteria {
            if !Self::criterion_binds_a_pin(criterion) {
                continue;
            }
            let Some(candidate) = criterion.candidate.as_ref() else {
                continue;
            };
            pin = match candidate.tree_id.as_deref() {
                Some(tree_id) => Self::Pinned(tree_id.to_string()),
                None => Self::Unstamped(criterion.criterion_id.clone()),
            };
        }
        pin
    }

    /// The pinned tree id, if this pin names one.
    #[must_use]
    pub fn pinned_tree_id(&self) -> Option<&str> {
        match self {
            Self::Pinned(tree_id) => Some(tree_id.as_str()),
            Self::Unpinned | Self::Unstamped(_) => None,
        }
    }

    /// THE FENCE. Refuse unless `observed` — the tree of the SETTLED candidate,
    /// read after the snapshot that produced the commit about to land — is the
    /// tree validation approved.
    ///
    /// Call this BEFORE the landing and BEFORE the workspace teardown: every
    /// refusal here must leave trunk untouched and the candidate's work
    /// RECOVERABLE, so an author can fix the pack and re-land rather than lose
    /// the run.
    ///
    /// **"Recoverable", not "on disk".** This refusal destroys nothing: it
    /// returns before the landing ladder and before `remove_workspace`. But it
    /// FAILS the stage, and a Failed worktree-isolated execution then closes
    /// out through the API executor's Terminalizing arm, which calls
    /// `park_workspace` — publishing `parked/<execution-id>` at the settled
    /// candidate commit and removing the worktree afterwards. So by the time an
    /// operator looks, the checkout is gone and the work is a REF. Both
    /// providers order the publish before the removal for exactly this reason.
    ///
    /// See the type doc for the exact refused set.
    pub fn require_tree(
        &self,
        operation: &str,
        execution_id: &str,
        observed: &str,
    ) -> crate::KataResult<()> {
        let refuse = |code: &str, detail: String| {
            Err(crate::KataError::Validation(format!(
                "{operation} for execution {execution_id} REFUSED ({code}): {detail}"
            )))
        };
        let expected = match self {
            Self::Unpinned => return Ok(()),
            Self::Unstamped(criterion_id) => {
                return refuse(
                    "candidate_tree_unstamped",
                    format!(
                        "validation criterion `{criterion_id}` bound this candidate but recorded \
                         no tree identity, so the tree validation approved cannot be shown equal \
                         to the tree about to land; re-run validation against the current \
                         candidate"
                    ),
                );
            }
            Self::Pinned(expected) => expected.as_str(),
        };
        for (side, value) in [("approved", expected), ("candidate", observed)] {
            if value.contains(Self::CONFLICT_JOIN) {
                return refuse(
                    "candidate_tree_conflicted",
                    format!(
                        "the {side} tree id `{value}` is a CONFLICTED jj merge (sides joined by \
                         `{join}`); a conflicted candidate materializes `.jjconflict-*` sidecars \
                         and one arbitrary side of every conflicted file, so it is never compared \
                         and never landed",
                        join = Self::CONFLICT_JOIN
                    ),
                );
            }
        }
        if expected != observed {
            return refuse(
                "candidate_tree_mismatch",
                format!(
                    "validation approved tree {expected} but the settled candidate holds tree \
                     {observed}; tracked content changed after the validation stamp, so the tree \
                     about to land is not the tree that was judged"
                ),
            );
        }
        Ok(())
    }
}

fn default_validation_criterion_evidence_required() -> bool {
    true
}

impl ExecutionValidationEvidence {
    /// Parse a validation-stage output envelope into durable validation
    /// evidence. Accepts the raw parsed object, an envelope with a `parsed`
    /// field, or an envelope whose `content` field is a JSON object string.
    #[must_use]
    pub fn from_stage_output(
        stage_name: impl Into<String>,
        output: &serde_json::Value,
    ) -> Option<Self> {
        let stage_name = stage_name.into();
        let parsed_content = output
            .get("content")
            .and_then(serde_json::Value::as_str)
            .and_then(|content| serde_json::from_str::<serde_json::Value>(content).ok());
        let parsed = output
            .get("parsed")
            .or(parsed_content.as_ref())
            .unwrap_or(output);
        let status = string_field(parsed, "status");
        let criteria = validation_criterion_evidence_from_stage_output(stage_name.as_str(), parsed);
        let commands = string_array_field(parsed, "commands");
        let evidence = string_array_field(parsed, "evidence");
        let test_count = u64_field(parsed, "test_count");
        let git_sha = string_field(parsed, "git_sha");
        let pgrep_clean = bool_field(parsed, "pgrep_clean");
        let check_artifacts =
            ExecutionCheckArtifactEvidence::from_stage_output(stage_name.clone(), output);
        if status.is_none()
            && criteria.is_empty()
            && commands.is_empty()
            && evidence.is_empty()
            && test_count.is_none()
            && git_sha.is_none()
            && pgrep_clean.is_none()
            && check_artifacts.is_empty()
        {
            return None;
        }
        Some(Self {
            stage_name,
            status,
            criteria,
            commands,
            evidence,
            test_count,
            git_sha,
            pgrep_clean,
            check_artifacts,
        })
    }
}

fn validation_criterion_evidence_from_stage_output(
    stage_name: &str,
    parsed: &serde_json::Value,
) -> Vec<ExecutionValidationCriterionEvidence> {
    let Some(values) = parsed
        .get("criteria")
        .or_else(|| parsed.get("validation_criteria"))
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };

    values
        .iter()
        .filter_map(|value| validation_criterion_evidence(stage_name, value))
        .collect()
}

fn validation_criterion_evidence(
    stage_name: &str,
    value: &serde_json::Value,
) -> Option<ExecutionValidationCriterionEvidence> {
    let criterion_id = string_field(value, "criterion_id").or_else(|| string_field(value, "id"))?;
    let status = string_field(value, "status")
        .as_deref()
        .and_then(ExecutionValidationCriterionStatus::parse)
        .unwrap_or(ExecutionValidationCriterionStatus::Unknown);
    let stage_name = string_field(value, "stage_name")
        .or_else(|| string_field(value, "stage"))
        .or_else(|| Some(stage_name.to_string()));
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .unwrap_or(VALIDATION_CRITERION_EVIDENCE_SCHEMA_VERSION);
    Some(ExecutionValidationCriterionEvidence {
        schema_version,
        criterion_id,
        status,
        required: bool_field(value, "required").unwrap_or(true),
        stage_name,
        evidence: string_array_field(value, "evidence"),
        missing: string_array_field(value, "missing"),
        source: string_field(value, "source"),
        waiver: validation_criterion_waiver_evidence(value),
        candidate: validation_criterion_candidate_evidence(value),
    })
}

fn validation_criterion_waiver_evidence(
    value: &serde_json::Value,
) -> Option<ExecutionValidationCriterionWaiverEvidence> {
    let waiver = value.get("waiver").or_else(|| value.get("policy_waiver"))?;
    let source = non_empty_string_field(waiver, "source")?;
    let reason = non_empty_string_field(waiver, "reason")?;
    let schema_version = waiver
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .unwrap_or(VALIDATION_CRITERION_WAIVER_EVIDENCE_SCHEMA_VERSION);
    Some(ExecutionValidationCriterionWaiverEvidence {
        schema_version,
        source,
        reason,
        authority_id: non_empty_string_field(waiver, "authority_id")
            .or_else(|| non_empty_string_field(waiver, "policy_id"))
            .or_else(|| non_empty_string_field(waiver, "decision_id")),
        approved_by: non_empty_string_field(waiver, "approved_by"),
        approved_at_ms: u64_field(waiver, "approved_at_ms"),
        evidence: string_array_field(waiver, "evidence"),
    })
}

fn validation_criterion_candidate_evidence(
    value: &serde_json::Value,
) -> Option<ExecutionValidationCandidateEvidence> {
    let candidate = value
        .get("candidate")
        .or_else(|| value.get("candidate_binding"))
        .or_else(|| value.get("workspace_candidate"))?;
    let execution_id = non_empty_string_field(candidate, "execution_id")?;
    let fingerprint = content_hash_field(candidate, "fingerprint")
        .or_else(|| content_hash_field(candidate, "candidate_fingerprint"))?;
    let content_hash = content_hash_field(candidate, "content_hash")
        .or_else(|| content_hash_field(candidate, "workspace_content_hash"))
        .unwrap_or(fingerprint);
    let schema_version = candidate
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .unwrap_or(VALIDATION_CRITERION_CANDIDATE_EVIDENCE_SCHEMA_VERSION);
    Some(ExecutionValidationCandidateEvidence {
        schema_version,
        execution_id,
        fingerprint,
        content_hash,
        workspace_backend: non_empty_string_field(candidate, "workspace_backend")
            .or_else(|| non_empty_string_field(candidate, "backend")),
        head_commit: non_empty_string_field(candidate, "head_commit")
            .or_else(|| non_empty_string_field(candidate, "commit_sha"))
            .or_else(|| non_empty_string_field(candidate, "git_sha")),
        dirty: bool_field(candidate, "dirty"),
        changed_paths: string_array_field(candidate, "changed_paths"),
        tree_id: non_empty_string_field(candidate, "tree_id"),
    })
}

fn content_hash_field(value: &serde_json::Value, field: &str) -> Option<ContentHash> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<ContentHash>().ok())
}

fn non_empty_string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    let value = string_field(value, field)?;
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn string_array_field(value: &serde_json::Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect()
}

fn u64_field(value: &serde_json::Value, field: &str) -> Option<u64> {
    value.get(field).and_then(serde_json::Value::as_u64)
}

fn bool_field(value: &serde_json::Value, field: &str) -> Option<bool> {
    value.get(field).and_then(serde_json::Value::as_bool)
}

/// One closeout-stage report projected onto an [`ExecutionRecord`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionCloseoutEvidence {
    pub stage_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_action: Option<String>,
}

#[cfg(test)]
mod sentinel_blocker_tests {
    use super::*;

    #[test]
    fn sentinel_blocker_recognizes_common_no_blocker_tokens() {
        for token in [
            "",
            "none",
            "None",
            "  NONE  ",
            "n/a",
            "N/A.",
            "na",
            "-",
            "no blockers",
            "no blocker",
            "nil",
            "empty",
            "None.",
        ] {
            assert!(is_sentinel_blocker(token), "{token:?} should be a sentinel");
        }
        for token in [
            "missing test coverage",
            "validation failed",
            "needs review",
            "nonexistent",
        ] {
            assert!(
                !is_sentinel_blocker(token),
                "{token:?} must not be treated as a sentinel"
            );
        }
    }
}
