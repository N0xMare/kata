//! Checked orchestration policy extensions parsed beside a workflow definition.
//!
//! These types intentionally live in `kata-program` for now. They let parser,
//! checked-IR, preflight, and CLI/API surfaces agree on native orchestration
//! metadata without expanding the shared `kata-types` contract before the
//! scheduler consumes these fields.

use kata_types::params::WorkflowParamSpec;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

/// Parsed workflow plus native orchestration metadata that has not yet moved
/// into the shared runtime `WorkflowDefinition`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowExtensions {
    #[serde(default)]
    pub human_request_queue: HumanRequestQueue,
    #[serde(default)]
    pub external_input_channels: ExternalInputChannels,
    #[serde(default, skip_serializing_if = "MemorySelectors::is_empty")]
    pub memory_selectors: MemorySelectors,
    #[serde(default, skip_serializing_if = "MemoryWritebacks::is_empty")]
    pub memory_writebacks: MemoryWritebacks,
    #[serde(default, skip_serializing_if = "ValidationCriteria::is_empty")]
    pub validation_criteria: ValidationCriteria,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_pattern: Option<WorkflowPattern>,
    /// Typed workflow-invocation param declarations from
    /// `workflow(params={..})`. Empty for every pack that omits `params=`,
    /// skipped from serialization + the extension hash material when empty so
    /// packs without params are byte-identical.
    #[serde(default, skip_serializing_if = "WorkflowParams::is_empty")]
    pub params: WorkflowParams,
}

impl WorkflowExtensions {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn affects_execution_identity(&self) -> bool {
        self.human_request_queue.max_items != 0
            || !self.human_request_queue.requests.is_empty()
            || !self.external_input_channels.channels.is_empty()
            || !self.memory_selectors.selectors.is_empty()
            || !self.memory_writebacks.writebacks.is_empty()
            || !self.validation_criteria.criteria.is_empty()
            || self.workflow_pattern.is_some()
            || !self.params.is_empty()
    }
}

/// The declared typed invocation params of a workflow.
///
/// A thin ordered wrapper over [`WorkflowParamSpec`] (canonical name order set
/// at decode), so the checked extensions carry the param contract that the
/// executor resolves caller-supplied values against and the redaction boundary
/// reads the secret markers from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowParams {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<WorkflowParamSpec>,
}

impl WorkflowParams {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }
}

/// Operator requests attached to a checked workflow, advisory by default and
/// optionally blocking for durable scoped-stage parking.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanRequestQueue {
    /// Maximum number of requests allowed in this checked definition. `0`
    /// means the queue was omitted.
    pub max_items: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<HumanRequest>,
}

/// One operator request, advisory by default or blocking when explicitly set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanRequest {
    pub id: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<SmolStr>,
    pub priority: HumanRequestPriority,
    pub question: String,
    pub default_assumption: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// When `true`, the target `stage` PARKS (durably, via the
    /// approval-gate `AwaitingApproval` machinery) until this request is
    /// answered, then resumes with the answer rendered into its prompt.
    /// Advisory (`false`) requests never park. A blocking request requires a
    /// `stage` scope — there is nothing to park otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub blocking: bool,
    /// Optional self-heal deadline (milliseconds) for a
    /// `blocking` park. When set and exceeded with no operator answer, the
    /// periodic input-await sweep resumes the parked stage using
    /// `default_assumption` as the effective answer — so an unattended loop is
    /// never blocked forever. The deadline is anchored on the DURABLE
    /// `awaiting_approval_at_ms` ledger stamp (not a process-local timer), so it
    /// survives a daemon restart. `None` (the default) means no timeout:
    /// the park blocks until answered. Only meaningful with `blocking = true`; a
    /// `timeout_ms` on a non-blocking request is inert (nothing parks to time out)
    /// and is rejected at parse time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Operator-facing priority for a human request, whether advisory or blocking.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, strum::VariantArray,
)]
#[serde(rename_all = "snake_case")]
pub enum HumanRequestPriority {
    Low,
    #[default]
    Medium,
    High,
}

impl HumanRequestPriority {
    /// Every priority, lowest first (the derived `strum::VariantArray`): the DSL
    /// catalog's `human_request_priority` domain and the set
    /// `human_request(priority=)` parses through [`Self::from_label`].
    #[must_use]
    pub fn variants() -> &'static [Self] {
        <Self as strum::VariantArray>::VARIANTS
    }

    /// The priority whose [`Self::label`] is `label`, or `None`.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::variants()
            .iter()
            .copied()
            .find(|priority| priority.label() == label)
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Declared side-channel inputs that external processes may append during an
/// execution. Channels are prompt/context inputs only in v0; they do not grant
/// authority to change scheduling, approvals, sandboxing, or mutation policy.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalInputChannels {
    /// Maximum number of channels allowed in this checked definition. `0`
    /// means the section was omitted.
    pub max_channels: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<ExternalInputChannel>,
}

/// One declared external input channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalInputChannel {
    pub id: SmolStr,
    /// Optional stage scope. Omitted channels are global and visible to every
    /// stage that consumes external input context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<SmolStr>,
    /// Prompt namespace alias under `external_inputs.<expose_as>`.
    pub expose_as: SmolStr,
    /// Advisory channel kind. Kept string-shaped for v0 so frontends can
    /// experiment without expanding shared enums prematurely.
    pub kind: SmolStr,
    /// Payload schema label. v0 runtime accepts text plus optional JSON payload
    /// and treats this field as checked metadata for prompts/operators.
    pub schema: SmolStr,
    /// Per-channel append bound.
    pub max_items: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
}

/// Declared native-memory context selectors for a workflow.
///
/// Selectors are checked and hashed with the execution program so the controller
/// can build stage context packets from an explicit contract instead of ad hoc
/// prompt text. They do not mutate memory by themselves.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySelectors {
    /// Maximum number of selectors allowed in this checked definition. `0`
    /// means the section was omitted.
    pub max_selectors: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<MemorySelector>,
}

impl MemorySelectors {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.max_selectors == 0 && self.selectors.is_empty()
    }
}

/// One checked native-memory selector bound to an optional consumer stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySelector {
    pub id: SmolStr,
    /// Optional stage whose context packet consumes this selector. Omitted
    /// selectors are global workflow context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<SmolStr>,
    /// Prompt/context namespace alias under future `memory.<expose_as>`.
    pub expose_as: SmolStr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<SmolStr>,
    pub statuses: Vec<SmolStr>,
    pub max_objects: u32,
    pub required: bool,
    /// Optional deterministic text query applied after kind/status filtering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// Checked native-memory writeback declarations for workflow stages.
///
/// Runtime stage output is not allowed to mutate native memory unless a
/// declaration here authorizes the stage, output field, kinds, statuses, and
/// count bound. This keeps memory writes policy-aware while still letting
/// workflow packs emit reusable findings, decisions, artifacts, risks, and
/// follow-up tasks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryWritebacks {
    /// Maximum number of writeback declarations allowed in this checked
    /// definition. `0` means the section was omitted.
    pub max_writebacks: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writebacks: Vec<MemoryWriteback>,
}

impl MemoryWritebacks {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.max_writebacks == 0 && self.writebacks.is_empty()
    }
}

/// One checked memory-writeback channel bound to an optional producer stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryWriteback {
    pub id: SmolStr,
    /// Optional stage authorized to emit this writeback. Omitted declarations
    /// are global and can be emitted by any stage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<SmolStr>,
    /// Output field containing an array of memory object drafts.
    pub field: SmolStr,
    /// Allowed memory object kinds for rows emitted through this channel.
    pub kinds: Vec<SmolStr>,
    /// Allowed memory statuses for rows emitted through this channel.
    pub statuses: Vec<SmolStr>,
    /// Maximum rows accepted from this output field per stage completion.
    pub max_objects: u32,
    /// Whether missing rows from the output field should block terminal
    /// writeback reconciliation.
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Declared scope tier (`global`/`project`/`workflow`) a producer stage may
    /// write into, or `None` for own scope. Only the tier is authorable;
    /// concrete project/workflow keys are runtime context. Additive: skipped when
    /// `None`, so existing programs lower byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_tier: Option<SmolStr>,
}

/// Declared validation boundary for an autonomous workflow.
///
/// Criteria are parsed, hashed, lowered into checked IR, surfaced in
/// preflight/operator evidence, and consumed by controller promotion policy
/// once runtime validation evidence is available.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCriteria {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub criteria: Vec<ValidationCriterion>,
}

impl ValidationCriteria {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.criteria.is_empty()
    }
}

/// One validation criterion bound to an optional proof stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCriterion {
    pub id: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<SmolStr>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default = "default_validation_criterion_required")]
    pub required: bool,
}

fn default_validation_criterion_required() -> bool {
    true
}

/// Declared authoring pattern and any warning-first escape hatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowPattern {
    pub name: SmolStr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_tier: Option<SmolStr>,
    #[serde(default)]
    pub escape_hatch: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escape_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<SmolStr>,
}
