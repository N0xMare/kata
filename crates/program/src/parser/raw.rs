//! Raw serde deserialization structs for normalized JSON helper values.
//!
//! These `Raw*` types are the serde decode targets the value-shaped normalizers
//! (`super::normalize::normalize_*_value`, `normalize_extensions_from_json`)
//! deserialize `serde_json::Value` fragments into before lowering them to the
//! typed `WorkflowDefinition` / `WorkflowExtensions`. The Starlark evaluator's
//! native graph DSL builder is the live caller: it carries sandbox, budget, and
//! policy-extension sub-values in these normalized JSON shapes so the sole
//! executable frontend accepts one canonical set of forms.

use kata_types::MemoryObjectStatus;

use crate::policy::HumanRequestPriority;

/// Operator-facing Starlark shape for budget policy.
/// `mode` ∈ `{"unlimited", "warn", "halt"}`. `limit_usd` is required
/// for `warn` / `halt`, ignored for `unlimited`. `#[serde(default)]`
/// fields keep `mode = "unlimited"` decodable without `limit_usd`.
///
/// The wire-side limit unit is
/// USD-as-float; the normalizer converts to `limit_micro_usd: u64` for
/// in-runtime math.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawBudgetPolicy {
    pub(super) mode: String,
    #[serde(default)]
    pub(super) limit_usd: Option<f64>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawHumanRequestQueue {
    #[serde(default)]
    pub(super) max_items: Option<u32>,
    #[serde(default)]
    pub(super) requests: Vec<RawHumanRequest>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawHumanRequest {
    pub(super) id: String,
    #[serde(default)]
    pub(super) stage: Option<String>,
    #[serde(default)]
    pub(super) priority: HumanRequestPriority,
    pub(super) question: String,
    pub(super) default_assumption: String,
    #[serde(default)]
    pub(super) context: Option<String>,
    #[serde(default)]
    pub(super) blocking: bool,
    #[serde(default)]
    pub(super) timeout_ms: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawExternalInputChannels {
    #[serde(default)]
    pub(super) max_channels: Option<u32>,
    #[serde(default)]
    pub(super) channels: Vec<RawExternalInputChannel>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawExternalInputChannel {
    pub(super) id: String,
    #[serde(default)]
    pub(super) stage: Option<String>,
    #[serde(default)]
    pub(super) expose_as: Option<String>,
    #[serde(default = "default_external_input_kind")]
    pub(super) kind: String,
    #[serde(default = "default_external_input_schema")]
    pub(super) schema: String,
    #[serde(default)]
    pub(super) max_items: Option<u32>,
    #[serde(default)]
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) default_value: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawMemorySelectors {
    #[serde(default)]
    pub(super) max_selectors: Option<u32>,
    #[serde(default)]
    pub(super) selectors: Vec<RawMemorySelector>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawMemorySelector {
    pub(super) id: String,
    #[serde(default)]
    pub(super) stage: Option<String>,
    #[serde(default)]
    pub(super) expose_as: Option<String>,
    #[serde(default)]
    pub(super) kinds: Vec<String>,
    #[serde(default = "default_memory_selector_statuses")]
    pub(super) statuses: Vec<String>,
    #[serde(default)]
    pub(super) max_objects: Option<u32>,
    #[serde(default)]
    pub(super) required: Option<bool>,
    #[serde(default)]
    pub(super) query: Option<String>,
    #[serde(default)]
    pub(super) purpose: Option<String>,
}

fn default_memory_selector_statuses() -> Vec<String> {
    vec![MemoryObjectStatus::Active.label().to_string()]
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawMemoryWritebacks {
    #[serde(default)]
    pub(super) max_writebacks: Option<u32>,
    #[serde(default)]
    pub(super) writebacks: Vec<RawMemoryWriteback>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawMemoryWriteback {
    pub(super) id: String,
    #[serde(default)]
    pub(super) stage: Option<String>,
    #[serde(default = "default_memory_writeback_field")]
    pub(super) field: String,
    #[serde(default)]
    pub(super) kinds: Vec<String>,
    #[serde(default = "default_memory_writeback_statuses")]
    pub(super) statuses: Vec<String>,
    #[serde(default)]
    pub(super) max_objects: Option<u32>,
    #[serde(default)]
    pub(super) required: Option<bool>,
    #[serde(default)]
    pub(super) purpose: Option<String>,
    /// Declared scope tier (`global`/`project`/`workflow`), or unset for own
    /// scope. Only the tier is authorable; concrete keys are runtime.
    #[serde(default)]
    pub(super) scope_tier: Option<String>,
}

fn default_memory_writeback_field() -> String {
    "memory_writebacks".to_string()
}

fn default_memory_writeback_statuses() -> Vec<String> {
    vec![MemoryObjectStatus::Active.label().to_string()]
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawValidationCriteria {
    #[serde(default)]
    pub(super) criteria: Vec<RawValidationCriterion>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawValidationCriterion {
    pub(super) id: String,
    #[serde(default)]
    pub(super) stage: Option<String>,
    pub(super) description: String,
    #[serde(default)]
    pub(super) commands: Vec<String>,
    #[serde(default)]
    pub(super) evidence: Vec<String>,
    #[serde(default)]
    pub(super) required: Option<bool>,
}

fn default_external_input_kind() -> String {
    "advisory".to_string()
}

fn default_external_input_schema() -> String {
    "text".to_string()
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawWorkflowPattern {
    pub(super) name: String,
    #[serde(default)]
    pub(super) risk_tier: Option<String>,
    #[serde(default)]
    pub(super) escape_hatch: bool,
    #[serde(default)]
    pub(super) escape_reason: Option<String>,
    #[serde(default)]
    pub(super) capabilities: Vec<String>,
}
