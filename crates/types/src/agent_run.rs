//! BYO agent-run wire types — request and terminal result shapes for
//! `POST /api/v1/agents/run`.
//!
//! These are pure data types: no I/O, no locks. The `kata-api` crate owns
//! the handler that drives the run and populates `AgentRunResult`.
//!
//! The handler in `crates/api/src/rest/agents.rs` validates request shape
//! and returns this terminal result shape for supported local agent labels.
//! `AgentRunRequest`'s `allowed_tools` and `sandbox` fields plus the
//! `ByoSandboxRequest` type are the narrow external-client sandbox surface.

use regex::Regex;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use ulid::Ulid;

use crate::cache::TokenUsage;

// The structured-output SCHEMA-BOUND AUTHORITY. These are the single source of
// truth for every `output_schema` limit the agent-run validator enforces
// (`validate_agent_run_output_schema`), and they are `pub` so the DSL layer
// (`kata_program::dsl::schema`, `::catalog`) can MIRROR the exact bound at
// construction time and PUBLISH it in the machine-readable catalog rather than
// re-hardcoding a lookalike number that could silently drift. A drift guard in
// the DSL crate binds those mirrors back to these consts.

/// Maximum `output_schema` nesting depth (top-level node is depth 0).
pub const MAX_SCHEMA_DEPTH: usize = 4;
/// Maximum number of `properties` an object node may declare.
pub const MAX_SCHEMA_PROPERTIES: usize = 32;
/// Maximum number of `required` field names an object node may list.
pub const MAX_SCHEMA_REQUIRED: usize = 32;
/// Maximum `maxItems` an array node may carry (also the default `list_of` cap).
pub const MAX_ARRAY_ITEMS: u64 = 128;
/// Maximum `minLength`/`maxLength` a string node may carry.
pub const MAX_STRING_LENGTH: u64 = 64 * 1024;
/// Maximum arm count for an `enum`/`variant` node.
pub const MAX_ENUM_VARIANTS: usize = 64;
/// Maximum number of `allowed_tools` entries a request may carry.
pub const MAX_ALLOWED_TOOLS: usize = 64;
/// Maximum byte length of a single `allowed_tools` entry.
pub const MAX_TOOL_NAME_LEN: usize = 256;

/// Public BYO agent labels accepted by `POST /api/v1/agents/run`: the model
/// agents `kata init` declares — `default` and its role agents `reviewer` and
/// `gate` — each kata's embedded harness under the provider its block names.
///
/// Discovery and execution validation both use this list so read-only
/// capability responses cannot drift from the executable public policy. A
/// listed label still runs only where the main declares `[agents.<label>]`;
/// no worker-advertised `agent:<label>` enters either answer.
pub const SUPPORTED_AGENT_RUN_LABELS: &[&str] = &["default", "reviewer", "gate"];

// ── Capability discovery / preflight types ─────────────────────────────────

/// Request fields accepted by the public BYO agent-run surface.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRunFeatureFlags {
    /// `model_hint` may be supplied.
    pub model_hint: bool,
    /// `timeout_ms` may be supplied. False, and current servers reject non-null
    /// values — so an agent run is compiled with
    /// [`crate::workflow::DEFAULT_STAGE_TIMEOUT_MS`], the authoring default, and
    /// is BOUNDED even though the caller may not choose the bound.
    ///
    /// This path does not use the durable stop-ack (`attempt_stop_requests`): a
    /// deadline observed here asks no worker to stop, so it would abandon a run
    /// that keeps spending. Only wiring the two together may flip this flag.
    pub timeout_ms: bool,
    /// `output_schema` may be supplied.
    pub output_schema: bool,
    /// `allowed_tools` may be supplied.
    pub allowed_tools: bool,
    /// Narrow `sandbox` policy keys may be supplied.
    pub sandbox: AgentRunSandboxFeatureFlags,
}

impl Default for AgentRunFeatureFlags {
    fn default() -> Self {
        Self {
            model_hint: true,
            timeout_ms: false,
            output_schema: true,
            allowed_tools: true,
            sandbox: AgentRunSandboxFeatureFlags::default(),
        }
    }
}

/// Sandbox policy keys accepted by the public BYO agent-run surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRunSandboxFeatureFlags {
    /// `sandbox.exec` may be supplied.
    pub exec: bool,
    /// `sandbox.fs` may be supplied.
    pub fs: bool,
    /// `sandbox.net` may be supplied.
    pub net: bool,
}

impl Default for AgentRunSandboxFeatureFlags {
    fn default() -> Self {
        Self {
            exec: true,
            fs: true,
            net: true,
        }
    }
}

/// Live local capacity summary for agent-run capability data.
///
/// A slot is a live worker capsule placement can put the run on — one claiming
/// certified containment; no `agent:<label>` is demanded of it — counted only for
/// a label the main declares as `[agents.<label>]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRunLocalCapacity {
    /// True when at least one live local slot can accept this scope.
    pub available: bool,
    /// Number of live local slots that can accept this scope.
    pub live_slots: usize,
}

/// Per-label capability data for a public BYO agent backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRunAgentCapability {
    /// Public agent label, for example `"default"` or `"reviewer"`.
    pub label: SmolStr,
    /// Request fields accepted for this label.
    pub accepted_request: AgentRunFeatureFlags,
    /// Live local capacity for this label.
    pub local_capacity: AgentRunLocalCapacity,
}

/// Public read-only capability/preflight response for BYO agent runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRunCapabilities {
    /// Ordered public labels and their current capacity.
    pub agents: Vec<AgentRunAgentCapability>,
    /// Request fields accepted by this public surface.
    pub accepted_request: AgentRunFeatureFlags,
    /// Live local capacity across all supported public labels — the largest
    /// label's figure, since every declared label is placed on the same pool.
    pub local_capacity: AgentRunLocalCapacity,
}

// ── BYO sandbox types (narrow external-client surface) ──────────────────────

/// Execution isolation mode for a BYO agent run.
///
/// Only the host and rootless-OCI backends are exposed to external clients.
/// Any other spelling is rejected at parse time as an unknown variant, naming
/// the two that exist. `host` parses and CHECK refuses it
/// (`host_sandbox_unsupported_under_oci`): a stage's containment is its capsule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByoExecPolicy {
    /// No isolation — agent runs in the worker's own process tree.
    Host,
    /// A capsule in a rootless OCI container (the pinned youki) — the
    /// model-stage default.
    #[default]
    Oci,
}

/// Filesystem view for a BYO agent run.
///
/// Custom mounts are not exposed to external clients.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByoFsPolicy {
    /// No constraints — agent sees the worker's host filesystem.
    Host,
    /// The run's workspace, whose stage may land no change — lowered to
    /// [`crate::sandbox::FsPolicy::WorkspaceRo`], enforced at delta adoption,
    /// not by the mount. The model-stage default.
    #[default]
    WorkspaceRo,
    /// Per-run workspace directory mounted read-write.
    WorkspaceRw,
    /// No execution tree — lowered to [`crate::sandbox::FsPolicy::Scratch`]:
    /// `/work` is the canonical empty tree, and the run's delta there is
    /// recorded as evidence, never applied.
    Scratch,
}

/// Network egress policy for a BYO agent run.
///
/// Brokered and raw-host-with-profile forms are not exposed to external
/// clients; only host and offline are available.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByoNetPolicy {
    /// Operator's direct network — no filtering.
    Host,
    /// No network: the capsule reaches nothing, and the agent's model calls
    /// leave from the process hosting the worker — the model-stage default.
    #[default]
    Offline,
}

/// Narrow external-client sandbox specification for `POST /api/v1/agents/run`.
///
/// Maps to a [`SandboxDirective`] with empty env, no secrets, and no image.
/// Every field defaults to the model-stage default — `oci` / `workspace_ro` /
/// `offline` — and a request equal to that default (`{}`, or the three spelled
/// out) authors no sandbox, so it is the omitted field exactly, the same program
/// (see [`AgentRunRequest::sandbox`]). A field stated otherwise authors an inline
/// profile with that field and the defaults beside it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByoSandboxRequest {
    /// Execution isolation backend. Defaults to `oci`.
    #[serde(default)]
    pub exec: ByoExecPolicy,
    /// Filesystem view for the agent process. Defaults to `workspace_ro`.
    #[serde(default)]
    pub fs: ByoFsPolicy,
    /// Network egress policy. Defaults to `offline`.
    #[serde(default)]
    pub net: ByoNetPolicy,
}

// ── Identity ─────────────────────────────────────────────────────────────────

/// Stable external identifier for a BYO agent run.
///
/// Serialised as a base32 ULID string on the wire (e.g.
/// `"01HV0VZTBP7TX5DQ1V0G7WB3SK"`). Consistent with all other `*Id`
/// newtypes in this crate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct AgentRunId(pub Ulid);

/// Terminal status of a BYO agent run.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunStatus {
    /// The agent run completed normally.
    Completed,
    /// The agent run failed (agent error, infrastructure error, etc.).
    Failed,
    /// Reserved for a future stop-acknowledged timeout outcome. Current servers
    /// reject `timeout_ms` before accepting execution authority.
    TimedOut,
}

impl AgentRunStatus {
    /// True when the status is terminal (run cannot advance further).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        // All variants are terminal for now; kept explicit for future extension.
        matches!(self, Self::Completed | Self::Failed | Self::TimedOut)
    }
}

/// Output produced by a completed agent run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRunOutput {
    /// Textual output from the agent.
    pub content: String,
    /// Parsed JSON content when an `output_schema` was requested and
    /// validation succeeded. Omitted for runs with no schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsed: Option<serde_json::Value>,
    /// Token accounting. Uses the shared [`TokenUsage`] type.
    #[serde(default)]
    pub token_usage: TokenUsage,
    /// Cost in micro-USD for this run.
    #[serde(default)]
    pub cost_micro_usd: u64,
    /// Why the agent stopped generating, if reported.
    #[serde(default)]
    pub stop_reason: Option<SmolStr>,
}

/// Inbound request body for `POST /api/v1/agents/run`.
///
/// Unknown fields are refused, so a field this request does not carry — a host
/// path to run in among them — is the caller's 400 naming it, never silently
/// dropped. The agent runs in its capsule's workspace; no request field chooses
/// another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRunRequest {
    /// Instruction passed to the agent.
    pub prompt: String,
    /// Agent name, e.g. `"default"` or `"reviewer"`.
    pub agent: SmolStr,
    /// Preferred model; the agent may ignore this.
    #[serde(default)]
    pub model_hint: Option<SmolStr>,
    /// Optional wall-clock budget in milliseconds. When set, the
    /// value must be positive and the run may finish with
    /// [`AgentRunStatus::TimedOut`] if the budget is exceeded.
    ///
    /// # It is not optional downstream, and current servers reject it anyway
    ///
    /// `AgentRunFeatureFlags::timeout_ms` is `false`, so a non-null value is
    /// REFUSED at the boundary. `None` therefore
    /// reaches `compile_agent_run_execution_program`, which substitutes
    /// [`crate::workflow::DEFAULT_STAGE_TIMEOUT_MS`] — so an agent run is BOUNDED
    /// at one hour even though the caller may not choose the bound. The bound is
    /// required: the worker refuses an assignment with no wall clock, so an agent
    /// run compiled without one would not dispatch.
    ///
    /// The bound is not raisable from operator config either: no `[agents.*]`,
    /// `[runtime]` or environment knob sets a stage timeout, so the checked
    /// program's own value is the only wall clock. A caller who needs a different
    /// one needs this field to be honored.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Optional constrained JSON object schema for structured output.
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,
    /// Tools the agent is allowed to invoke. Each entry must be a
    /// non-empty string of at most 256 bytes. At most 64 entries
    /// are accepted. Omitting or sending `[]` preserves the current
    /// empty tool-list behavior.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Narrow sandbox policy for the agent run. Omitting it or sending
    /// `null` authors no sandbox: the run's synthetic model stage takes the
    /// same default as a Starlark model stage that authors none —
    /// `sandbox_profile()`, i.e. `oci`, a read-only workspace and
    /// `net = offline`, whose capsule reaches none of the node's `[node]
    /// egress_allow` (the agent's model calls leave from the process hosting
    /// the worker). Sending `{}`, or any request equal to that default, is the
    /// omitted field.
    #[serde(default)]
    pub sandbox: Option<ByoSandboxRequest>,
}

/// Terminal result returned by `POST /api/v1/agents/run`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRunResult {
    /// Stable external identifier for this run (ULID string).
    pub run_id: AgentRunId,
    /// Terminal status.
    pub status: AgentRunStatus,
    /// Agent name echoed from the request.
    pub agent: SmolStr,
    /// Present when `status == completed`; `None` otherwise.
    #[serde(default)]
    pub result: Option<AgentRunOutput>,
    /// Present when `status != completed`; `None` on success.
    #[serde(default)]
    pub error: Option<String>,
}

/// Validate the constrained `output_schema` subset supported by
/// `POST /api/v1/agents/run`.
///
/// This is intentionally narrower than full JSON Schema. The top-level
/// schema must be an object with `type = "object"`. Object schemas may
/// declare up to 32 named `properties`, a `required` string array, and
/// `additionalProperties = false` or omit it. Primitive leaves support
/// `string`, `number`, `integer`, `boolean`, and `null`; arrays require
/// an `items` schema plus `maxItems <= 128`.
///
/// VALUE CONSTRAINTS are optional additive keys: a `string` node may
/// carry a `pattern` (a compilable regex), `minLength`, and/or `maxLength`;
/// a `number`/`integer` node may carry a `minimum` and/or `maximum`
/// (`minimum <= maximum`). Each is enforced against the parsed value by
/// [`validate_agent_run_output_content`].
///
/// # Errors
///
/// Returns a deterministic external-client message when the schema is
/// outside the supported subset.
pub fn validate_agent_run_output_schema(schema: &serde_json::Value) -> Result<(), String> {
    validate_schema_node(schema, 0, "$", true)
}

/// Validate the public `allowed_tools` field accepted by
/// `POST /api/v1/agents/run`.
///
/// # Errors
///
/// Returns a deterministic external-client message when the tool list is
/// outside the bounded subset accepted by the BYO route.
pub fn validate_agent_run_allowed_tools(tools: &[String]) -> Result<(), String> {
    if tools.len() > MAX_ALLOWED_TOOLS {
        return Err(format!(
            "allowed_tools must contain at most {MAX_ALLOWED_TOOLS} entries"
        ));
    }

    for (idx, tool) in tools.iter().enumerate() {
        if tool.trim().is_empty() {
            return Err(format!("allowed_tools[{idx}] must not be empty"));
        }
        if tool.len() > MAX_TOOL_NAME_LEN {
            return Err(format!(
                "allowed_tools[{idx}] must be at most {MAX_TOOL_NAME_LEN} bytes"
            ));
        }
    }

    Ok(())
}

/// Parse and validate agent text against the constrained
/// `output_schema` subset.
///
/// The returned value is the parsed JSON content that may be surfaced
/// as `AgentRunOutput::parsed`; callers keep the raw text separately.
///
/// A `null` on an OPTIONAL property (one absent from its object's `required`)
/// means the property is absent: it is removed from the parsed document before
/// validation, at every depth. That is the strict structured-output spelling
/// of "optional" ([`crate::strict_output_schema`] sends optional properties
/// required-and-nullable), and it holds wherever a stage's `output_schema` is
/// validated — an agent stage on any adapter and a shell stage alike — so a
/// stage's parsed document does not depend on whether its vendor was sent a
/// schema. A `null` on a REQUIRED property is still a value, checked against
/// its type. Workflow params are not read this way:
/// [`validate_param_value_against_schema`] checks a `null` param against its
/// type, required or not.
///
/// # Errors
///
/// Returns a deterministic validation message when the text is not JSON
/// or does not satisfy the schema subset.
pub fn validate_agent_run_output_content(
    content: &str,
    schema: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    validate_agent_run_output_schema(schema)?;
    let cleaned = strip_json_code_fence(content);
    let mut parsed: serde_json::Value = serde_json::from_str(cleaned).map_err(|err| {
        format!("output did not satisfy output_schema: content is not valid JSON: {err}")
    })?;
    drop_null_optionals(&mut parsed, schema);
    validate_value_against_schema(&parsed, schema, "$")?;
    Ok(parsed)
}

/// Remove every `null` that sits on an optional property, walking `value`
/// along `schema` (objects, array items, a variant's one arm). A value whose
/// shape does not match its node is left alone: validation reports it.
fn drop_null_optionals(value: &mut serde_json::Value, schema: &serde_json::Value) {
    let Some(node) = schema.as_object() else {
        return;
    };
    match node.get("type").and_then(serde_json::Value::as_str) {
        Some("object") => {
            let Some(object) = value.as_object_mut() else {
                return;
            };
            let Some(properties) = node
                .get("properties")
                .and_then(serde_json::Value::as_object)
            else {
                return;
            };
            let required = node.get("required").and_then(serde_json::Value::as_array);
            let is_required =
                |name: &str| required.is_some_and(|names| names.iter().any(|n| n == name));
            object.retain(|name, child| {
                !(child.is_null() && properties.contains_key(name) && !is_required(name))
            });
            for (name, child) in object.iter_mut() {
                if let Some(child_schema) = properties.get(name) {
                    drop_null_optionals(child, child_schema);
                }
            }
        }
        Some("array") => {
            let (Some(items), Some(array)) = (node.get("items"), value.as_array_mut()) else {
                return;
            };
            for item in array {
                drop_null_optionals(item, items);
            }
        }
        Some("variant") => {
            let (Some(arms), Some(object)) = (
                node.get("variants").and_then(serde_json::Value::as_object),
                value.as_object_mut(),
            ) else {
                return;
            };
            for (tag, payload) in object.iter_mut() {
                if let Some(arm) = arms.get(tag) {
                    drop_null_optionals(payload, arm);
                }
            }
        }
        _ => {}
    }
}

/// Validate an already-parsed value against a constrained schema NODE
/// that need NOT be a top-level object.
///
/// A workflow invocation parameter's declared type is a single primitive / enum
/// / array / variant / object node (exactly what the DSL `field(..)` /
/// `string(..)` / `integer(..)` / `enum(..)` builtins lower to), not necessarily
/// an object — so this drops the top-level-object requirement of
/// [`validate_agent_run_output_content`] while enforcing the SAME constrained
/// subset and emitting the SAME deterministic messages. Schema-shape problems
/// are reported with the `output_schema …` prefix; value failures with the
/// `output did not satisfy output_schema …` prefix, so callers can distinguish a
/// bad declaration from a bad value.
///
/// # Errors
///
/// Returns a deterministic message when the schema node is outside the accepted
/// subset or the value does not satisfy it.
pub fn validate_param_value_against_schema(
    value: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), String> {
    validate_schema_node(schema, 0, "$", false)?;
    validate_value_against_schema(value, schema, "$")
}

/// Validate that a workflow-param's declared SCHEMA node is within the
/// supported constrained subset, without a value to check it against.
///
/// The schema-only companion to [`validate_param_value_against_schema`], used by
/// the checked-program verifier to reject a program whose declared param type is
/// outside the subset (a belt-and-suspenders over the author-time DSL decode).
///
/// # Errors
///
/// Returns a deterministic message when the schema node is outside the subset.
pub fn validate_param_schema(schema: &serde_json::Value) -> Result<(), String> {
    validate_schema_node(schema, 0, "$", false)
}

fn validate_schema_node(
    schema: &serde_json::Value,
    depth: usize,
    path: &str,
    top_level: bool,
) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!(
            "output_schema {path} exceeds maximum nesting depth {MAX_SCHEMA_DEPTH}"
        ));
    }
    let obj = schema
        .as_object()
        .ok_or_else(|| format!("output_schema {path} must be a schema object"))?;
    reject_unknown_schema_keys(obj, path)?;

    let ty = obj
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("output_schema {path}.type must be a string"))?;
    if top_level && ty != "object" {
        return Err("output_schema top-level type must be \"object\"".to_string());
    }

    match ty {
        "object" => validate_object_schema(obj, depth, path),
        "array" => validate_array_schema(obj, depth, path),
        "string" => validate_string_schema(obj, path),
        "variant" => validate_variant_schema(obj, depth, path),
        "number" | "integer" => validate_number_schema(obj, path),
        "boolean" | "null" => validate_leaf_schema(obj, path, ty),
        other => Err(format!(
            "output_schema {path}.type {other:?} is not supported"
        )),
    }
}

fn reject_unknown_schema_keys(
    obj: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), String> {
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "type"
                | "properties"
                | "required"
                | "additionalProperties"
                | "items"
                | "minLength"
                | "maxLength"
                | "minItems"
                | "maxItems"
                | "minimum"
                | "maximum"
                | "pattern"
                | "enum"
                | "variants"
                | "title"
                | "description"
        ) {
            return Err(format!("output_schema {path}.{key} is not supported"));
        }
    }
    Ok(())
}

fn validate_object_schema(
    obj: &serde_json::Map<String, serde_json::Value>,
    depth: usize,
    path: &str,
) -> Result<(), String> {
    validate_metadata(obj, path)?;
    reject_keys_for_type(
        obj,
        path,
        &[
            "items",
            "minItems",
            "maxItems",
            "minLength",
            "maxLength",
            "minimum",
            "maximum",
            "pattern",
            "enum",
            "variants",
        ],
    )?;
    if let Some(value) = obj.get("additionalProperties")
        && value != &serde_json::Value::Bool(false)
    {
        return Err(format!(
            "output_schema {path}.additionalProperties must be false when provided"
        ));
    }

    let properties = match obj.get("properties") {
        Some(value) => Some(
            value
                .as_object()
                .ok_or_else(|| format!("output_schema {path}.properties must be an object"))?,
        ),
        None => None,
    };
    if let Some(properties) = properties {
        if properties.len() > MAX_SCHEMA_PROPERTIES {
            return Err(format!(
                "output_schema {path}.properties exceeds maximum property count {MAX_SCHEMA_PROPERTIES}"
            ));
        }
        for (name, child) in properties {
            validate_property_name(name, path)?;
            validate_schema_node(
                child,
                depth + 1,
                &format!("{path}.properties.{name}"),
                false,
            )?;
        }
    }

    if let Some(required) = obj.get("required") {
        let required = required
            .as_array()
            .ok_or_else(|| format!("output_schema {path}.required must be an array"))?;
        if required.len() > MAX_SCHEMA_REQUIRED {
            return Err(format!(
                "output_schema {path}.required exceeds maximum count {MAX_SCHEMA_REQUIRED}"
            ));
        }
        for item in required {
            let Some(name) = item.as_str() else {
                return Err(format!(
                    "output_schema {path}.required entries must be strings"
                ));
            };
            validate_property_name(name, path)?;
            let Some(properties) = properties else {
                return Err(format!(
                    "output_schema {path}.required includes undeclared property {name:?}"
                ));
            };
            if !properties.contains_key(name) {
                return Err(format!(
                    "output_schema {path}.required includes undeclared property {name:?}"
                ));
            }
        }
    }

    Ok(())
}

fn validate_array_schema(
    obj: &serde_json::Map<String, serde_json::Value>,
    depth: usize,
    path: &str,
) -> Result<(), String> {
    validate_metadata(obj, path)?;
    reject_keys_for_type(
        obj,
        path,
        &[
            "properties",
            "required",
            "additionalProperties",
            "minLength",
            "maxLength",
            "minimum",
            "maximum",
            "pattern",
            "enum",
            "variants",
        ],
    )?;
    let items = obj
        .get("items")
        .ok_or_else(|| format!("output_schema {path}.items is required for arrays"))?;
    validate_schema_node(items, depth + 1, &format!("{path}.items"), false)?;
    let max_items = obj
        .get("maxItems")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("output_schema {path}.maxItems is required for arrays"))?;
    if max_items > MAX_ARRAY_ITEMS {
        return Err(format!(
            "output_schema {path}.maxItems must be <= {MAX_ARRAY_ITEMS}"
        ));
    }
    if let Some(min_items) = obj.get("minItems") {
        let min_items = min_items
            .as_u64()
            .ok_or_else(|| format!("output_schema {path}.minItems must be an integer"))?;
        if min_items > max_items {
            return Err(format!("output_schema {path}.minItems must be <= maxItems"));
        }
    }
    Ok(())
}

fn validate_string_schema(
    obj: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), String> {
    validate_metadata(obj, path)?;
    reject_keys_for_type(
        obj,
        path,
        &[
            "properties",
            "required",
            "additionalProperties",
            "items",
            "minItems",
            "maxItems",
            "minimum",
            "maximum",
            "variants",
        ],
    )?;
    if let Some(enum_value) = obj.get("enum") {
        validate_enum_variants(enum_value, path)?;
    }
    if let Some(pattern_value) = obj.get("pattern") {
        let pattern = pattern_value
            .as_str()
            .ok_or_else(|| format!("output_schema {path}.pattern must be a string"))?;
        Regex::new(pattern).map_err(|err| {
            format!("output_schema {path}.pattern is not a valid regular expression: {err}")
        })?;
    }
    let min = match obj.get("minLength") {
        Some(value) => Some(
            value
                .as_u64()
                .ok_or_else(|| format!("output_schema {path}.minLength must be an integer"))?,
        ),
        None => None,
    };
    if let Some(min) = min
        && min > MAX_STRING_LENGTH
    {
        return Err(format!(
            "output_schema {path}.minLength must be <= {MAX_STRING_LENGTH}"
        ));
    }
    let max = match obj.get("maxLength") {
        Some(value) => {
            let max = value
                .as_u64()
                .ok_or_else(|| format!("output_schema {path}.maxLength must be an integer"))?;
            if max > MAX_STRING_LENGTH {
                return Err(format!(
                    "output_schema {path}.maxLength must be <= {MAX_STRING_LENGTH}"
                ));
            }
            Some(max)
        }
        None => None,
    };
    if let (Some(min), Some(max)) = (min, max)
        && min > max
    {
        return Err(format!(
            "output_schema {path}.minLength must be <= maxLength"
        ));
    }
    Ok(())
}

fn validate_leaf_schema(
    obj: &serde_json::Map<String, serde_json::Value>,
    path: &str,
    _ty: &str,
) -> Result<(), String> {
    validate_metadata(obj, path)?;
    reject_keys_for_type(
        obj,
        path,
        &[
            "properties",
            "required",
            "additionalProperties",
            "items",
            "minItems",
            "maxItems",
            "minLength",
            "maxLength",
            "minimum",
            "maximum",
            "pattern",
            "enum",
            "variants",
        ],
    )
}

/// Validate a `number`/`integer` schema node: an optional inclusive `minimum`
/// and/or `maximum` numeric bound, `minimum <= maximum` when both are present.
fn validate_number_schema(
    obj: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), String> {
    validate_metadata(obj, path)?;
    reject_keys_for_type(
        obj,
        path,
        &[
            "properties",
            "required",
            "additionalProperties",
            "items",
            "minItems",
            "maxItems",
            "minLength",
            "maxLength",
            "pattern",
            "enum",
            "variants",
        ],
    )?;
    let minimum = read_optional_number(obj, "minimum", path)?;
    let maximum = read_optional_number(obj, "maximum", path)?;
    if let (Some(min), Some(max)) = (minimum, maximum)
        && min > max
    {
        return Err(format!("output_schema {path}.minimum must be <= maximum"));
    }
    Ok(())
}

/// Read an optional numeric constraint bound (`minimum`/`maximum`) as an `f64`.
/// Absent keys are `None`; a present non-number is a schema error.
fn read_optional_number(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    path: &str,
) -> Result<Option<f64>, String> {
    match obj.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| format!("output_schema {path}.{key} must be a number")),
    }
}

/// Validate a `variant` schema node: a discriminated union of `tag -> payload
/// schema`. Values are externally tagged single-key objects `{ "<tag>": payload }`.
fn validate_variant_schema(
    obj: &serde_json::Map<String, serde_json::Value>,
    depth: usize,
    path: &str,
) -> Result<(), String> {
    validate_metadata(obj, path)?;
    reject_keys_for_type(
        obj,
        path,
        &[
            "properties",
            "required",
            "additionalProperties",
            "items",
            "minItems",
            "maxItems",
            "minLength",
            "maxLength",
            "minimum",
            "maximum",
            "pattern",
            "enum",
        ],
    )?;
    let variants = obj
        .get("variants")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            format!("output_schema {path}.variants must be an object of tag -> payload schema")
        })?;
    if variants.is_empty() {
        return Err(format!(
            "output_schema {path}.variants must declare at least one arm"
        ));
    }
    if variants.len() > MAX_ENUM_VARIANTS {
        return Err(format!(
            "output_schema {path}.variants must declare <= {MAX_ENUM_VARIANTS} arms"
        ));
    }
    for (tag, arm) in variants {
        validate_property_name(tag, &format!("{path}.variants"))?;
        validate_schema_node(arm, depth + 1, &format!("{path}.variants.{tag}"), false)?;
    }
    Ok(())
}

/// Validate the `enum` constraint on a string node: a non-empty, bounded, unique
/// list of string variants.
fn validate_enum_variants(value: &serde_json::Value, path: &str) -> Result<(), String> {
    let variants = value
        .as_array()
        .ok_or_else(|| format!("output_schema {path}.enum must be an array of string variants"))?;
    if variants.is_empty() {
        return Err(format!(
            "output_schema {path}.enum must list at least one variant"
        ));
    }
    if variants.len() > MAX_ENUM_VARIANTS {
        return Err(format!(
            "output_schema {path}.enum must list <= {MAX_ENUM_VARIANTS} variants"
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for variant in variants {
        let name = variant
            .as_str()
            .ok_or_else(|| format!("output_schema {path}.enum variants must be strings"))?;
        if name.is_empty() {
            return Err(format!(
                "output_schema {path}.enum variants must not be empty"
            ));
        }
        if !seen.insert(name) {
            return Err(format!(
                "output_schema {path}.enum has duplicate variant {name:?}"
            ));
        }
    }
    Ok(())
}

fn validate_metadata(
    obj: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), String> {
    for key in ["title", "description"] {
        if let Some(value) = obj.get(key)
            && !value.is_string()
        {
            return Err(format!("output_schema {path}.{key} must be a string"));
        }
    }
    Ok(())
}

fn reject_keys_for_type(
    obj: &serde_json::Map<String, serde_json::Value>,
    path: &str,
    keys: &[&str],
) -> Result<(), String> {
    for key in keys {
        if obj.contains_key(*key) {
            return Err(format!(
                "output_schema {path}.{key} is not valid for this schema type"
            ));
        }
    }
    Ok(())
}

fn validate_property_name(name: &str, path: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!(
            "output_schema {path} property names must not be empty"
        ));
    }
    if name.len() > 128 {
        return Err(format!(
            "output_schema {path} property names must be <= 128 bytes"
        ));
    }
    Ok(())
}

fn validate_value_against_schema(
    value: &serde_json::Value,
    schema: &serde_json::Value,
    path: &str,
) -> Result<(), String> {
    let obj = schema
        .as_object()
        .expect("schema already validated as an object");
    let ty = obj
        .get("type")
        .and_then(serde_json::Value::as_str)
        .expect("schema already validated with type");

    match ty {
        "object" => validate_object_value(value, obj, path),
        "array" => validate_array_value(value, obj, path),
        "string" => validate_string_value(value, obj, path),
        "variant" => validate_variant_value(value, obj, path),
        "number" => validate_number_value(value, obj, path, false),
        "integer" => validate_number_value(value, obj, path, true),
        "boolean" => require_kind(value.is_boolean(), path, "boolean", value),
        "null" => require_kind(value.is_null(), path, "null", value),
        _ => unreachable!("schema type was validated"),
    }
}

fn validate_object_value(
    value: &serde_json::Value,
    schema: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), String> {
    let obj = value.as_object().ok_or_else(|| {
        format!(
            "output did not satisfy output_schema: {path} expected object but got {}",
            json_value_kind(value)
        )
    })?;
    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object);
    if let Some(required) = schema.get("required").and_then(serde_json::Value::as_array) {
        for item in required {
            let name = item.as_str().expect("required entry was validated");
            if !obj.contains_key(name) {
                return Err(format!(
                    "output did not satisfy output_schema: {path} missing required property {name:?}"
                ));
            }
        }
    }
    if let Some(properties) = properties {
        for key in obj.keys() {
            if !properties.contains_key(key) {
                return Err(format!(
                    "output did not satisfy output_schema: {path} has undeclared property {key:?}"
                ));
            }
        }
        for (key, child_schema) in properties {
            if let Some(child_value) = obj.get(key) {
                validate_value_against_schema(child_value, child_schema, &format!("{path}.{key}"))?;
            }
        }
    } else if !obj.is_empty() {
        return Err(format!(
            "output did not satisfy output_schema: {path} has undeclared properties"
        ));
    }
    Ok(())
}

fn validate_array_value(
    value: &serde_json::Value,
    schema: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), String> {
    let array = value.as_array().ok_or_else(|| {
        format!(
            "output did not satisfy output_schema: {path} expected array but got {}",
            json_value_kind(value)
        )
    })?;
    let item_count = u64::try_from(array.len()).map_err(|_| {
        format!("output did not satisfy output_schema: {path} has too many items to validate")
    })?;
    if let Some(min) = schema.get("minItems").and_then(serde_json::Value::as_u64)
        && item_count < min
    {
        return Err(format!(
            "output did not satisfy output_schema: {path} expected at least {min} items"
        ));
    }
    let max = schema
        .get("maxItems")
        .and_then(serde_json::Value::as_u64)
        .expect("array maxItems was validated");
    if item_count > max {
        return Err(format!(
            "output did not satisfy output_schema: {path} expected at most {max} items"
        ));
    }
    let items = schema
        .get("items")
        .expect("array items schema was validated");
    for (idx, item) in array.iter().enumerate() {
        validate_value_against_schema(item, items, &format!("{path}[{idx}]"))?;
    }
    Ok(())
}

fn validate_string_value(
    value: &serde_json::Value,
    schema: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), String> {
    let s = value.as_str().ok_or_else(|| {
        format!(
            "output did not satisfy output_schema: {path} expected string but got {}",
            json_value_kind(value)
        )
    })?;
    let char_count = u64::try_from(s.chars().count()).map_err(|_| {
        format!("output did not satisfy output_schema: {path} has too many characters to validate")
    })?;
    if let Some(min) = schema.get("minLength").and_then(serde_json::Value::as_u64)
        && char_count < min
    {
        return Err(format!(
            "output did not satisfy output_schema: {path} expected length >= {min}"
        ));
    }
    if let Some(max) = schema.get("maxLength").and_then(serde_json::Value::as_u64)
        && char_count > max
    {
        return Err(format!(
            "output did not satisfy output_schema: {path} expected length <= {max}"
        ));
    }
    if let Some(variants) = schema.get("enum").and_then(serde_json::Value::as_array) {
        let matched = variants.iter().any(|variant| variant.as_str() == Some(s));
        if !matched {
            let allowed: Vec<&str> = variants
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect();
            return Err(format!(
                "output did not satisfy output_schema: {path} value {s:?} is not one of {allowed:?}"
            ));
        }
    }
    if let Some(pattern) = schema.get("pattern").and_then(serde_json::Value::as_str) {
        // The schema was validated first (every public entry point runs
        // `validate_agent_run_output_schema` before touching values), so the
        // pattern is known-compilable; the `map_err` is defensive.
        let regex = Regex::new(pattern).map_err(|err| {
            format!("output_schema {path}.pattern is not a valid regular expression: {err}")
        })?;
        if !regex.is_match(s) {
            return Err(format!(
                "output did not satisfy output_schema: {path} value {s:?} does not match pattern {pattern:?}"
            ));
        }
    }
    Ok(())
}

/// Validate a JSON number/integer value against its schema's optional inclusive
/// `minimum`/`maximum` bounds. `integer_required` selects the integer kind
/// check (a fractional value is rejected before the range check).
fn validate_number_value(
    value: &serde_json::Value,
    schema: &serde_json::Map<String, serde_json::Value>,
    path: &str,
    integer_required: bool,
) -> Result<(), String> {
    let (ok_kind, expected) = if integer_required {
        (
            value.as_i64().is_some() || value.as_u64().is_some(),
            "integer",
        )
    } else {
        (value.is_number(), "number")
    };
    require_kind(ok_kind, path, expected, value)?;
    // Safe after `require_kind`: the value is a JSON number, so `as_f64` is
    // `Some` (integers convert exactly within the f64 mantissa; beyond that the
    // bound comparison degrades gracefully to nearest-representable).
    let actual = value.as_f64().expect("value validated as a number");
    if let Some(min) = schema.get("minimum").and_then(serde_json::Value::as_f64)
        && actual < min
    {
        return Err(format!(
            "output did not satisfy output_schema: {path} value {actual} is below minimum {min}"
        ));
    }
    if let Some(max) = schema.get("maximum").and_then(serde_json::Value::as_f64)
        && actual > max
    {
        return Err(format!(
            "output did not satisfy output_schema: {path} value {actual} is above maximum {max}"
        ));
    }
    Ok(())
}

/// Validate an externally-tagged discriminated-union value `{ "<tag>": payload }`
/// against a `variant` schema node.
fn validate_variant_value(
    value: &serde_json::Value,
    schema: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), String> {
    let obj = value.as_object().ok_or_else(|| {
        format!(
            "output did not satisfy output_schema: {path} expected a single-key variant object but got {}",
            json_value_kind(value)
        )
    })?;
    if obj.len() != 1 {
        return Err(format!(
            "output did not satisfy output_schema: {path} variant must be a single-key object {{\"<tag>\": payload}}, got {} keys",
            obj.len()
        ));
    }
    let (tag, payload) = obj
        .iter()
        .next()
        .expect("variant object has exactly one key");
    let variants = schema
        .get("variants")
        .and_then(serde_json::Value::as_object)
        .expect("variant schema variants validated");
    let arm = variants.get(tag).ok_or_else(|| {
        let allowed: Vec<&str> = variants.keys().map(String::as_str).collect();
        format!(
            "output did not satisfy output_schema: {path} variant tag {tag:?} is not one of {allowed:?}"
        )
    })?;
    validate_value_against_schema(payload, arm, &format!("{path}.{tag}"))
}

fn require_kind(
    ok: bool,
    path: &str,
    expected: &str,
    value: &serde_json::Value,
) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!(
            "output did not satisfy output_schema: {path} expected {expected} but got {}",
            json_value_kind(value)
        ))
    }
}

fn strip_json_code_fence(content: &str) -> &str {
    let trimmed = content.trim();
    let without_open = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed);
    let without_open = without_open.trim_start();
    let without_close = without_open.strip_suffix("```").unwrap_or(without_open);
    without_close.trim()
}

fn json_value_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(number) => {
            if number.is_u64() || number.is_i64() {
                "integer"
            } else {
                "number"
            }
        }
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
