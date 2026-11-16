//! Agent identity, backend, and configuration types.

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use ulid::Ulid;

/// Stable identifier for an agent instance within a main.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct AgentId(pub Ulid);

/// Full backend taxonomy — the canonical enum `WorkerResource::AgentBackend`
/// points at.
///
/// `Shell` is the non-LLM backend that runs the prompt as a
/// shell command. It runs in the same capsule route and through the same
/// structured-outputs validator as the LLM backends, but spawns `sh -c
/// <prompt>` instead of an agent CLI — sub-2s, no API cost, deterministic
/// sandbox probes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendType {
    /// A capsule agent: kata's embedded nanocode harness, the backend of every
    /// `[agents.<label>]` block outside the reserved deterministic labels — the
    /// [`crate::config::AgentBackendConfig::Harness`] variant that carries the
    /// capsule fields (`adapter`, `credential`, `env`, `model`,
    /// `reasoning_effort`). The `adapter` names the provider; the backend is one.
    Harness,
    /// Non-LLM shell stage executor. Runs the prompt as a
    /// shell command (`sh -c <prompt>`), respecting the same sandbox
    /// `command_prefix` every CLI backend honors. Output is a JSON
    /// blob `{stdout, stderr, exit_code, duration_ms}` that the
    /// workflow's structured-outputs validator parses identically to
    /// LLM responses. Always available — registered automatically in
    /// every kata install, no `[agents.shell]` config needed.
    Shell,
    /// Factory-as-loop foundation: the in-process workspace-effect backend.
    /// A `stage(agent="workspace_effect", op="park"|"promote")` routes here;
    /// the backend performs a recorded, replay-safe candidate-workspace
    /// mutation via the execution's `ExecutionWorkspaceProvider` and returns a
    /// JSON envelope `{operation, ref_name, commit_sha}`. Deterministic and
    /// non-LLM (like `Shell`), but mutates the real candidate workspace, so it
    /// always runs in-process on the main with no sandbox: the runner claims a
    /// durable main attempt and the dispatcher performs it through the
    /// execution's workspace provider. No worker runs it, so the capacity
    /// preflight never counts it (and demands no label for any stage), and
    /// kata's supervised node never advertises
    /// `agent:workspace_effect`; no `[agents.*]` block exists.
    WorkspaceEffect,
}

impl BackendType {
    /// Stable snake_case label for this backend, matching the
    /// `rename_all = "snake_case"` serde representation. Recorded as the
    /// `agent_label` on durable ledger rows and used as the capability
    /// suffix (`agent:<label>`) advertised by workers.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Harness => "harness",
            Self::Shell => "shell",
            Self::WorkspaceEffect => crate::workflow::WORKSPACE_EFFECT_AGENT_LABEL,
        }
    }

    /// Inverse of [`Self::label`]: resolve a routing label back to its
    /// [`BackendType`]. Returns `None` for a label that names no backend
    /// (e.g. a config-defined agent alias like `"planner"`, or the
    /// `"any"` sentinel from [`crate::workflow::AgentSelector::Any`]).
    ///
    /// Used by the workflow runner's cache-key builder to recover the
    /// stage's resolved backend discriminator from its agent label, so
    /// two otherwise-identical stages routed to different backends
    /// (e.g. `shell` vs `workspace_effect`) never alias on one cache
    /// key. Keep in lockstep with [`Self::label`] — every variant `label`
    /// emits must round-trip back here.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        let backend = match label {
            "harness" => Self::Harness,
            "shell" => Self::Shell,
            // `WorkspaceEffect.label()` is this const, so match it by value
            // rather than duplicating the string literal.
            _ if label == crate::workflow::WORKSPACE_EFFECT_AGENT_LABEL => Self::WorkspaceEffect,
            _ => return None,
        };
        Some(backend)
    }

    /// True if this backend is a deterministic, non-LLM command executor.
    ///
    /// [`BackendType::Shell`] (runs `sh -c <command>`, reports a mechanical
    /// `exit_code`) and [`BackendType::WorkspaceEffect`] (performs a recorded
    /// park/promote mutation, no LLM) both qualify: neither calls a model, so
    /// their outputs are replay-stable. This drives routing/replay determinism.
    ///
    /// NOTE: determinism ≠ validation-proof eligibility. A `workspace_effect`
    /// stage is deterministic but emits NO validation report — it cannot
    /// self-certify a criterion verdict. The promotion trust gate must use
    /// [`Self::is_validation_proof_eligible`] (which excludes
    /// `WorkspaceEffect`), NOT this predicate. Any future non-LLM executor
    /// must be classified into BOTH predicates deliberately.
    #[must_use]
    pub const fn is_deterministic(self) -> bool {
        matches!(self, Self::Shell | Self::WorkspaceEffect)
    }

    /// True if a validation-proof stage routed to this backend may be TRUSTED
    /// to self-certify a required criterion's `passed` verdict.
    ///
    /// Strictly narrower than [`Self::is_deterministic`]: only
    /// [`BackendType::Shell`] qualifies. A `workspace_effect` stage is
    /// deterministic but emits only a `{operation, ref_name, commit_sha}`
    /// envelope — never a validation report — so it can carry no verdict and
    /// must never gate promotion. Keeping this predicate separate from raw
    /// determinism prevents a change from leaning on "only shell is
    /// deterministic", which is false. Keep in lockstep with
    /// [`is_validation_proof_eligible_agent_label`].
    #[must_use]
    pub const fn is_validation_proof_eligible(self) -> bool {
        matches!(self, Self::Shell)
    }
}

/// The RATE KEY a metered agent turn is priced under: the vendor whose list
/// prices a built-in price-table row, or an operator `[[pricing.models]]` row,
/// states. [`AdapterKind::billing_backend`] maps a kind to one.
///
/// Deliberately NOT a [`BackendType`]: a backend type is a ROUTING label (a
/// definition's `AgentSelector::Backend`, a worker's `agent_backend=<label>`
/// capability), and a vendor's price list is no runtime a stage routes to. The
/// `anthropic` label in particular is a retired backend label every routing door
/// refuses; here it names only a rate key. A billing key is billable by
/// construction — a shell or effect stage, which bills nothing, never has one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingBackend {
    /// Anthropic's list prices — a `nanocode_anthropic` turn's key.
    Anthropic,
}

impl BillingBackend {
    /// The key's snake_case label, identical to the serde representation — the
    /// `[[pricing.models]] backend` spelling and the `Unavailable` cost's
    /// `backend` on a priced kind's unpriceable turn.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
        }
    }
}

/// The ADAPTER dispatch key: which admitted agent contract an attempt-scoped
/// agent session runs.
///
/// # This is a PARALLEL key, not a `BackendType` variant
///
/// [`BackendType`] answers *which registered backend does a stage route to* — it
/// is the routing label on an assignment, the capability suffix a worker
/// advertises, the discriminator a cache key folds, and the axis
/// [`BackendType::is_deterministic`] partitions. `AdapterKind` answers a
/// different question: *which harness drives the attempt's capsule, against
/// which model provider?* Folding them into one enum would either give every
/// existing `BackendType` consumer an arm it has no answer for, or give a
/// provider an accidental routing identity.
///
/// It is therefore deliberately NOT added to `BackendType`, and nothing here
/// derives a `BackendType` or vice versa. ADR-0001 "Agent execution" names the
/// admitted set — the embedded nanocode harness, and nothing else — which is
/// why this enum is closed and has no `Other(String)` arm.
///
/// The embedded harness is TWO kinds, one per model provider, because the
/// provider changes every per-kind fact kata keys on: the host tool set, the
/// model-facing tool set, the credential and the price table. The provider is
/// part of the kind, so a capsule names it without a field of its own.
///
/// Every kind runs as a capsule whose init is `kata-toolhost`: the harness's
/// agent loop runs in the worker, and every tool call reaches the capsule as a
/// toolhost frame. The launch is therefore fixed by the kind — a turn carries
/// no launch vector, the bundle renders
/// `/.kata/kata-toolhost` as `process.args` and binds the provider entry's
/// `toolhost/` read-only at `/.kata`, and kata renders the capsule's `HOME`.
/// The harness's model traffic leaves from the process hosting the worker, so
/// the capsule opens no vendor endpoint. A declared adapter label that names no
/// kind is what the `oci` CHECK and the capsule assembly refuse as
/// `adapter_unqualified`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    /// The embedded nanocode harness on the OpenAI Responses API.
    NanocodeOpenai,
    /// The embedded nanocode harness on the Anthropic Messages API.
    NanocodeAnthropic,
}

impl AdapterKind {
    /// Every kind, in a stable order. Used by the qualification matrix so a
    /// new kind cannot be added without a row.
    pub const ALL: [Self; 2] = [Self::NanocodeOpenai, Self::NanocodeAnthropic];

    /// Stable snake_case label, identical to the serde representation.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::NanocodeOpenai => "nanocode_openai",
            Self::NanocodeAnthropic => "nanocode_anthropic",
        }
    }

    /// Whether this build serves a turn of this kind under a credential of
    /// `mode`. False for exactly one pair: [`Self::NanocodeAnthropic`] under
    /// `subscription`. kata holds no Claude subscription login in this build
    /// (`kata login anthropic` takes `--api-key` only), and a harness kind
    /// lifts no host login, so no source can serve it. The `oci` CHECK and
    /// the capsule assembly refuse it
    /// [`CREDENTIAL_MODE_UNSUPPORTED`](crate::execution_contract::CREDENTIAL_MODE_UNSUPPORTED),
    /// and the worker's `kata_login` load still refuses it after them. No
    /// wildcard arm.
    #[must_use]
    pub const fn serves_credential_mode(self, mode: crate::metering::CredentialMode) -> bool {
        match self {
            Self::NanocodeAnthropic => matches!(mode, crate::metering::CredentialMode::ApiKey),
            Self::NanocodeOpenai => true,
        }
    }

    /// Whether this kind's protocol carries a STRICT structured-output schema
    /// for the turn's answer ([`crate::strict_output_schema`]), so a stage's
    /// `produces=` contract reaches the model as a schema and not only as
    /// prompt text. Measured per protocol, no model call made:
    ///
    /// * `NanocodeOpenai` — nanocode's public `OpenAiBuilder::strict_json_schema`
    ///   (`StrictJsonSchema { type: "json_schema", strict: true, name, schema }`
    ///   as the Responses `text.format`, nanocode `8ec3b215`); unpatched.
    /// * `NanocodeAnthropic` — no: nanocode's Messages client's
    ///   `OutputConfig` carries `effort` only (nanocode `8ec3b215`).
    ///
    /// Capsule assembly fills [`AgentTurnSpec::output_schema`] only for a kind
    /// answering true, and `Capsule::new` refuses a schema on any other
    /// (`capsule_agent_output_schema_uncarried`). No wildcard arm.
    ///
    /// [`AgentTurnSpec::output_schema`]: crate::execution_contract::AgentTurnSpec::output_schema
    #[must_use]
    pub const fn carries_strict_output_schema(self) -> bool {
        match self {
            Self::NanocodeOpenai => true,
            Self::NanocodeAnthropic => false,
        }
    }

    /// Inverse of [`Self::as_label`]. `None` for anything that names no admitted
    /// adapter contract — including every [`BackendType`] label, which is the
    /// point of the two keys being separate.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_label() == label)
    }

    /// The [`BillingBackend`] an adapter's metering bills against — the
    /// `[[pricing.models]]` rate key and the `Unavailable` shape's `backend`
    /// label, when this adapter's vendor has one.
    ///
    /// `NanocodeAnthropic` meters as `BillingBackend::Anthropic`, Anthropic's
    /// list prices for the Claude 5 family. Every kind's adapter reads every
    /// token class its vendor bills (input, output, cache read, cache write)
    /// off the vendor's own per-turn report — every `model.call.completed`'s
    /// counts, summed, disjoint — so no class is charged at zero.
    ///
    /// `NanocodeOpenai` calls OpenAI's models, but it is `None`: kata carries no
    /// OpenAI price row it has re-verified for the models a `nanocode_openai`
    /// turn runs, and a kind does not start billing on rates nobody re-checked.
    /// So every turn it runs meters `Unavailable` (tokens kept) even on an
    /// `api_key` credential — the reason a hard dollar bound covering such a
    /// stage refuses at CHECK (`cost_bound_unenforceable_unpriced_adapter`)
    /// rather than halting after the spend. Verified OpenAI rows, and the rate
    /// key they would carry, are what move it to `Some`, and that commit
    /// re-pins `only_a_nanocode_anthropic_api_key_turn_is_priced`. The
    /// kind→rate mapping lives here alone, never at the metering call site.
    #[must_use]
    pub const fn billing_backend(self) -> Option<BillingBackend> {
        match self {
            Self::NanocodeAnthropic => Some(BillingBackend::Anthropic),
            Self::NanocodeOpenai => None,
        }
    }
}

/// One AGENT capsule turn's report, carried on
/// `WorkerMessage::CompletedCapsule.agent` — the facts the protocol surface
/// produced that a `/out` tree cannot hold.
///
/// Fields:
///
/// * `response` — the turn's response text, published by the worker as a
///   Private CAS blob and named by its [`ArtifactRef`]. A bare `ArtifactId`
///   would be insufficient: the adopting main reads the blob VERIFIED, which
///   needs the object address and the claimed length, both of which the ref
///   carries and the id folds.
/// * `usage` — the turn's [`StageUsage`](crate::metering::StageUsage) when the
///   vendor reported token counts in a form the adapter parsed — counts AND
///   the [`MeteredCost`](crate::metering::MeteredCost) the worker priced them
///   at, in one value, so the two cannot disagree across the wire. `None`
///   when the vendor reported none parseable: the acceptance writes
///   `Unavailable` then — never a zero — because a subscription-billed turn
///   and an unmeasured one are both unpriceable here and neither is free.
/// * `adapter` — the [`AdapterKind`] that ran the turn, echoed from the
///   capsule so a reader attributes the report without resolving the capsule.
/// * `model_reported` — the model the PROVIDER reported for this turn (the
///   model each of the harness's model calls reported, folded to the turn's
///   one identity), or `None` when it states none. The REQUESTED model is
///   already the capsule's identity and is deliberately NOT echoed here —
///   a field that claims the vendor's account must never borrow the request's
///   value, because then a rerouted model and a compliant one would be
///   indistinguishable. A reported model that differs from the request is
///   evidence, adopted rather than refused: the vendor is the authority on
///   which model ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTurnReport {
    /// The response text as a Private CAS blob — scrubbed of lifted values and
    /// bounded while it accumulates; response + drained stderr share the
    /// capsule's one `output_bytes`, verified as a pair at adoption.
    pub response: crate::execution_contract::ArtifactRef,
    /// The metered turn — counts + cost in one value — or `None` for
    /// "the vendor reported nothing parseable".
    pub usage: Option<crate::metering::StageUsage>,
    /// The adapter kind that ran the turn.
    pub adapter: AdapterKind,
    /// The model the VENDOR reported on the wire, or `None` when it stated
    /// none — evidence, not the requested value (see above).
    pub model_reported: Option<SmolStr>,
    /// The session's own event record — auto-served permissions, refused
    /// callbacks, foreign updates — serialized [`SessionEvidence`] as a
    /// Private CAS blob. `Some` on every report this build produces; the
    /// adoption refuses an `Agent` report that carries none, because a
    /// completed turn whose grant set dies with its session is exactly the
    /// durable blind spot the field exists to close.
    pub session_evidence: Option<crate::execution_contract::ArtifactRef>,
    /// Why the model stopped generating — the VENDOR's own word for the end
    /// of its turn (acp's `stopReason`),
    /// or `None` when the protocol states none. `null` means "the vendor
    /// reported none", never "this plane has no such concept".
    #[serde(default)]
    pub stop_reason: Option<SmolStr>,
}

/// The most events one session's evidence record holds. The adapters bound
/// their lists at this cap; what it drops is counted in
/// [`SessionEvidence::events_dropped`], never silently lost — a vendor that
/// asked 500 questions is recorded as having asked more than the record holds.
pub const SESSION_EVIDENCE_EVENTS: usize = 256;

/// The most bytes a serialized [`SessionEvidence`] blob may carry — the
/// bound the worker enforces at publish and the adoption re-enforces against
/// the recorded ref. 256 events of a few hundred bytes each sit far under it;
/// the cap exists so an artifact named in a durable row is a bounded claim.
pub const SESSION_EVIDENCE_BYTES: u64 = 256 * 1024;

/// One agent session's observed-event record — the durable form of the
/// design's "auto-allowed … recorded as evidence". The adapter collects
/// events in-process and [`kata_agent`]'s `AgentSession::take_evidence` drains
/// them; the worker publishes the serialized form as a Private blob and the
/// report names it. Nothing in an event is a request's PARAMS — method names,
/// ids, codes and outcomes only — because a capsule-chosen payload string in
/// kata's durable record is the channel the refusal exists to deny.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEvidence {
    /// The observed events in wire order.
    pub events: Vec<SessionEvidenceEvent>,
    /// Events the adapter's bound dropped — a nonzero count is itself
    /// evidence the vendor asked more than the record holds.
    pub events_dropped: u32,
    /// The commits the agent left on its capsule's disposable scratch branch —
    /// [`crate::scratch_commit::ScratchCommitReport`]s, empty on
    /// every turn whose capsule declared no `git_view` and on every
    /// adapter-constructed record: the session never OBSERVED them, because
    /// they are facts about the attempt's filesystem, not events on its wire.
    /// The WORKER reads them off the scratch gitdir after the container's
    /// teardown confirms nothing can still write — bounded at
    /// `kata_worker::git_view`'s commit bound, every text field scrubbed
    /// against the attempt's lifted credentials — and folds them in before
    /// this record serializes, so they land durable exactly once: inside the
    /// one Private blob the accepted completion's evidence row names.
    pub scratch_commits: Vec<crate::scratch_commit::ScratchCommitReport>,
}

/// One recorded observation: the embedded harness's model calls, tool calls,
/// tool results, Code Mode limit hits and turn-end steps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionEvidenceEvent {
    /// A harness event the adapter observed but could not fold, by its name —
    /// a `model.call.completed` whose payload did not decode, or a
    /// `run.error`.
    Notice { method: SmolStr },
    /// The embedded harness: the model called a tool, by the call's id.
    ToolCall { id: SmolStr },
    /// The embedded harness: one model call ended — `outcome` is `completed`
    /// or `failed` — and the model the provider reported for it.
    ModelCall { model: SmolStr, outcome: SmolStr },
    /// The embedded harness: one tool call's result, by its call id and the
    /// harness's status word (`completed`, `failed`, `cancelled`, or, for a
    /// call the Anthropic Messages kind's interruption left unknown,
    /// `unknown`). Never the output itself. Recorded on both kinds.
    ToolResult { id: SmolStr, status: SmolStr },
    /// The embedded harness: a Code Mode cell failed on one of kata's Code Mode
    /// limits — `which` is `wall`, `output`, `memory`, `stack` (the
    /// interpreter's stack limit) or `workers` (the process's live-worker cap
    /// refused the cell a worker) — read off the vendored guard's own report of
    /// the hit, a harness notification that the harness's truncation of the
    /// model's view of the cell does not reach, or for `workers` off the
    /// refused `exec` result; the turn went on. A wall or output hit is
    /// reported from the interpreter's own budget, every heap hit by the
    /// engine (djs ends it uncatchably), and a stack hit by djs's own error
    /// heading the failure; a stack hit the cell rethrows inside an error of
    /// its own is not reported, and a cell's own notification of a report's
    /// text is recorded as a hit.
    CodeModeLimit { which: SmolStr },
    /// The embedded harness: a Code Mode cell's interpreter PROCESS ended while
    /// the cell ran, and the cell failed with that end; the turn went on, and
    /// the next cell runs in a new interpreter process. `signal` names the
    /// signal it ended by (`SIGSEGV`, `SIGABRT`; `SIGKILL` when kata killed it,
    /// which the cell's error says), or is `None` when it exited instead, by a
    /// status the cell's error names. Read off the supervisor's own report of
    /// the end, a harness notification sent just before the cell's error, as
    /// [`Self::CodeModeLimit`] is read off the guard's: so a cell's own
    /// notification of a report's text is recorded too, though nothing ended.
    /// An interpreter that ends after its cell's terminal event ends no cell
    /// and is recorded nowhere.
    CodeModeInterpreterEnded { signal: Option<SmolStr> },
    /// The embedded harness: a step of the turn's end did not complete as
    /// planned. `step` is `kill_all`, and `outcome` is `wire_broken` (the
    /// toolhost's wire was already broken, so no `KillAll` could be sent) or
    /// `unconfirmed` (its `KillAll` got no `Done` in the grace); either way the
    /// toolhost's stdin was dropped, on which it kills every process it started.
    TurnEnd { step: SmolStr, outcome: SmolStr },
    /// The embedded harness: the Code Mode workers live in the hosting process
    /// once the turn's end has shut the harness down (its shutdown returned or
    /// its grace expired), read off the vendored engine's live-worker counter.
    /// Recorded at every turn end that built the harness. The count is
    /// process-wide, idle workers and another attempt's included, so it is
    /// never below the workers this turn left running and may exceed them;
    /// `0` says no cell of this turn outlives its outcome, and a nonzero count
    /// says one may: a worker counts until its interpreter process is reaped,
    /// so a nonzero count includes any whose host the shutdown did not
    /// terminate within its grace.
    CodeModeWorkersLive { live: u64 },
}

/// True if `label` names a deterministic, non-LLM command-executor backend.
///
/// This is the *label set* the routing/replay determinism check keys on.
/// Frontends compile `agent = "shell"` to `AgentSelector::Labelled("shell")`,
/// which lowers to the routing label checked here, so this function is what
/// makes the label-based determinism check in `kata-workflow`'s
/// `ExecutionProgramStage::is_deterministic_executor` sound. The set is sound
/// *only* because [`KataConfig::validate`](crate::config::KataConfig::validate)
/// reserves these names: an `[agents.<name>]` block for a deterministic label
/// must declare a deterministic backend, so the name cannot be rebound to an
/// LLM. Keep this in lockstep with [`BackendType::is_deterministic`].
#[must_use]
pub fn is_deterministic_agent_label(label: &str) -> bool {
    label == BackendType::Shell.label() || label == BackendType::WorkspaceEffect.label()
}

/// True if `label` names a backend whose validation-proof stage may be trusted
/// to self-certify a required criterion verdict (the promotion trust gate).
///
/// Strictly narrower than [`is_deterministic_agent_label`]: `workspace_effect`
/// is excluded because an effect stage emits no validation report. Keep in
/// lockstep with [`BackendType::is_validation_proof_eligible`].
#[must_use]
pub fn is_validation_proof_eligible_agent_label(label: &str) -> bool {
    label == BackendType::Shell.label()
}

// ── prompt protocol types ────────────────────────────────────────────

/// The embedded harness's credential as an opaque in-process value — loaded
/// (and refreshed when near expiry) by the worker before the container
/// launches, and carried to the adapter on the [`Prompt`]. It stays in the
/// worker process: the harness's model calls leave from there.
///
/// The refused set, stated: no `Serialize`, no `Deserialize`, no display of
/// the value, and nothing in the capsule identity holds it — the capsule
/// carries the REFERENCE ([`TurnCredentialRef`]) and the worker re-derives.
///
/// [`TurnCredentialRef`]: crate::execution_contract::TurnCredentialRef
///
/// Opaque because `kata-types` is the neutral crate every crate depends on and
/// must not name the harness's own auth type: the worker fills it with the
/// value `kata-agent-nanocode` defines, and the adapter downcasts it. Never
/// serialized ([`Prompt::credential`] is skipped), never displayed.
#[derive(Clone)]
pub struct HarnessCredential(std::sync::Arc<dyn std::any::Any + Send + Sync>);

impl HarnessCredential {
    /// Carry `value` to the adapter.
    #[must_use]
    pub fn new(value: impl std::any::Any + Send + Sync) -> Self {
        Self(std::sync::Arc::new(value))
    }

    /// The carried value, when it is a `T`.
    #[must_use]
    pub fn downcast_ref<T: std::any::Any>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

impl PartialEq for HarnessCredential {
    /// A harness credential is opaque, so identity is the only equality it
    /// can state: two are equal when they carry the same loaded value
    /// (`Arc::ptr_eq`). Comparing what they carry would need the type
    /// `kata-types` must not name.
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for HarnessCredential {}
impl std::fmt::Debug for HarnessCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HarnessCredential(<redacted>)")
    }
}

/// A prompt sent to an agent adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    /// The turn's text: the stage's rendered prompt, which the harness hands
    /// the model as the user's message. The harness's tools are kata's fixed
    /// host set and its instructions the adapter's own, so a prompt carries
    /// neither.
    pub text: String,
    /// Optional model hint (overrides the config default for this call).
    #[serde(default)]
    pub model_hint: Option<SmolStr>,
    /// Optional reasoning-effort hint — the capsule turn's
    /// `reasoning_effort` reaching the adapter, which delivers it through the
    /// harness's own reasoning setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort_hint: Option<SmolStr>,
    /// The strict structured-output schema the turn's answer is held to — the
    /// capsule turn's [`output_schema`] reaching the adapter. An adapter whose
    /// protocol carries one sends it verbatim; every other adapter refuses
    /// `agent_output_schema_unsupported` before any model call — a schema an
    /// adapter cannot deliver is never silently dropped.
    ///
    /// [`output_schema`]: crate::execution_contract::AgentTurnSpec::output_schema
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// The credential the worker resolved for this turn from the node's
    /// `[agents.<label>] credential`, carried in-process to the harness.
    /// Skipped on serialize by construction: a `Prompt` never carries the
    /// field's bytes anywhere durable.
    #[serde(skip)]
    #[serde(default)]
    pub credential: Option<HarnessCredential>,
}

#[cfg(test)]
mod tests {
    use super::{AdapterKind, BackendType, BillingBackend};

    /// **The kind × credential-mode pairs this build cannot serve are exactly
    /// `nanocode_anthropic` under `subscription`.** Every other kind serves
    /// both modes, and `nanocode_anthropic` serves `api_key`.
    ///
    /// **Would red if:** the refused set widened (an `api_key` Anthropic turn,
    /// or `nanocode_openai`'s ChatGPT login, refused) or emptied.
    #[test]
    fn the_unserved_credential_mode_is_exactly_nanocode_anthropic_subscription() {
        use crate::metering::CredentialMode;
        let unserved: Vec<_> = AdapterKind::ALL
            .into_iter()
            .flat_map(|kind| {
                [CredentialMode::ApiKey, CredentialMode::Subscription]
                    .into_iter()
                    .filter(move |mode| !kind.serves_credential_mode(*mode))
                    .map(move |mode| (kind, mode))
            })
            .collect();
        assert_eq!(
            unserved,
            [(AdapterKind::NanocodeAnthropic, CredentialMode::Subscription)]
        );
    }

    /// Every backend's `label()` must round-trip back through
    /// `from_label()` to the same variant — they are inverses, and the
    /// cache-key builder relies on that to recover a stage's backend.
    #[test]
    fn label_from_label_round_trips_for_every_variant() {
        for backend in [
            BackendType::Harness,
            BackendType::Shell,
            BackendType::WorkspaceEffect,
        ] {
            assert_eq!(
                BackendType::from_label(backend.label()),
                Some(backend),
                "label/from_label must round-trip for {backend:?}"
            );
        }
    }

    /// Labels that name no backend (config aliases, the `Any` sentinel)
    /// resolve to `None`, not a wrong-but-plausible default.
    #[test]
    fn from_label_returns_none_for_unknown_labels() {
        assert_eq!(BackendType::from_label("planner"), None);
        assert_eq!(BackendType::from_label("any"), None);
        assert_eq!(BackendType::from_label(""), None);
    }

    /// A harness credential is opaque, so its equality is identity: a clone of
    /// one loaded value is equal to it; a second value carrying the same
    /// contents is not. The carried value downcasts to its own type and to no
    /// other.
    #[test]
    fn a_harness_credential_equals_only_the_same_loaded_value() {
        use super::HarnessCredential;

        let loaded = HarnessCredential::new(String::from("sk-loaded"));
        let credential = loaded.clone();
        assert_eq!(loaded.clone(), credential);
        assert_ne!(
            HarnessCredential::new(String::from("sk-loaded")),
            credential,
            "equal contents in a second load are a different source"
        );
        assert_eq!(
            loaded.downcast_ref::<String>().map(String::as_str),
            Some("sk-loaded")
        );
        assert!(loaded.downcast_ref::<u32>().is_none());
    }

    /// Neither `Debug` nor a serialized `Prompt` carries a harness credential's
    /// value: `Debug` prints the arm, and the prompt's `credential` field is
    /// skipped on serialize.
    #[test]
    fn a_harness_credential_is_never_printed_or_serialized() {
        use super::{HarnessCredential, Prompt};

        let secret = "sk-harness-0123456789";
        let credential = HarnessCredential::new(secret.to_owned());
        assert_eq!(format!("{credential:?}"), "HarnessCredential(<redacted>)");
        let prompt = Prompt {
            text: String::new(),
            model_hint: None,
            effort_hint: None,
            output_schema: None,
            credential: Some(credential),
        };
        assert!(!format!("{prompt:?}").contains(secret));
        let json = serde_json::to_string(&prompt).expect("a prompt serializes");
        assert!(
            !json.contains(secret) && !json.contains("credential"),
            "{json}"
        );
    }

    /// The backend labels no build routes to — `claude_code`, `open_code`,
    /// `anthropic`, `open_ai_compat`, and `codex` (the spelling of the agent-entry
    /// `type` key that no longer exists) — are refused by serde's own
    /// unknown-variant error at every door that decodes a [`BackendType`]: a
    /// definition's `AgentSelector::Backend` and a worker's `agent_backend=<label>`
    /// capability; and every one but `anthropic` at the third door, a
    /// `[[pricing.models]]` row, whose key is a [`BillingBackend`]: `anthropic`
    /// names Anthropic's price list there and nowhere a stage could route.
    /// `harness` is the control at the two routing doors, which admit it; at the
    /// pricing door it is refused too (a backend is no rate key). The same
    /// spelling as an agent ALIAS (a `[agents.claude_code]` block, `agent =
    /// "claude_code"`) is a plain label and never decodes as a backend, so it is
    /// untouched.
    #[test]
    fn retired_backend_labels_are_refused_at_every_backend_decode_door() {
        use crate::config::PriceOverride;
        use crate::identity::{WorkerResource, WorkerResourceParseError};
        use crate::workflow::AgentSelector;

        let row = |label: &str| {
            format!(
                "backend = \"{label}\"\nmodel = \"m\"\ninput_rate_per_mtok = 1.0\n\
                 output_rate_per_mtok = 1.0\ncache_read_multiplier = 0.1\n\
                 cache_write_multiplier = 1.0\n"
            )
        };
        for label in [
            "claude_code",
            "open_code",
            "anthropic",
            "open_ai_compat",
            "codex",
        ] {
            let selector = serde_json::json!({ "kind": "backend", "data": label });
            let error = serde_json::from_value::<AgentSelector>(selector)
                .expect_err("a retired backend label is refused in a definition")
                .to_string();
            assert!(error.contains("unknown variant"), "{label}: {error}");

            if label == "anthropic" {
                assert_eq!(
                    toml::from_str::<PriceOverride>(&row(label))
                        .expect("a pricing row keys Anthropic's price list")
                        .backend,
                    BillingBackend::Anthropic
                );
            } else {
                let error = toml::from_str::<PriceOverride>(&row(label))
                    .expect_err("a retired backend label is refused in a pricing row")
                    .to_string();
                assert!(error.contains("unknown variant"), "{label}: {error}");
            }

            assert_eq!(
                format!("agent_backend={label}").parse::<WorkerResource>(),
                Err(WorkerResourceParseError::UnknownBackend(label.to_owned())),
                "{label}"
            );
            assert_eq!(BackendType::from_label(label), None, "{label}");
        }

        let selector = serde_json::json!({ "kind": "backend", "data": "harness" });
        assert_eq!(
            serde_json::from_value::<AgentSelector>(selector).unwrap(),
            AgentSelector::Backend(BackendType::Harness)
        );
        assert!(
            toml::from_str::<PriceOverride>(&row("harness")).is_err(),
            "a routing backend is no rate key"
        );
        assert_eq!(
            "agent_backend=harness".parse::<WorkerResource>(),
            Ok(WorkerResource::AgentBackend(BackendType::Harness))
        );
    }
}
