//! Pure JSON helpers for the structured-output validator.
//!
//! Carved out of `runner.rs` during the runner-split refactor. None
//! of these functions touch runner state, the dispatcher, or the
//! ledger; they are deterministic transforms over `serde_json::Value`
//! invoked from `dispatch::inject_parsed_if_declared`.

use kata_types::error::{KataError, KataResult};
use smol_str::SmolStr;
use tracing::debug;

/// Tolerantly strip a leading/trailing markdown code fence from an
/// agent-produced JSON string. CLI agents (Claude Code, Codex) tend
/// to wrap structured output in ```json ... ``` fences even when the
/// prompt explicitly says "emit raw JSON, no fence". Strict
/// `serde_json::from_str` fails on the leading backticks, which
/// would manifest as "every structured-output stage errors on its very
/// first run".
///
/// The stripper handles these patterns:
/// * `` ```json\n{...}\n``` ``
/// * `` ```\n{...}\n``` ``
/// * leading/trailing whitespace around any of the above
/// * raw `{...}` or `[...]` pass through unchanged
///
/// If no recognisable fence is present, the input is returned
/// untrimmed so a legitimate parse error in step-2 of
/// `inject_parsed_if_declared` still surfaces a useful JSON error
/// message pointing at the original content.
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

/// Pure side-effect-free validation + injection for a stage whose
/// `outputs` table is non-empty. Callers (currently only
/// [`crate::runner::WorkflowRunner::inject_parsed_if_declared`]) use
/// the returned envelope to amend the ledger.
///
/// Steps:
///   1. envelope must carry a `content` string;
///   2. the content (fence-stripped) must parse as JSON;
///   3. the parsed form must be a JSON object;
///   4. every declared output `name` must be present on that object;
///   5. every declared output `ty` must match the value's JSON type
///      — a declared type is enforced, so a stage that declares
///      `failures = "json"` and receives a string fails validation.
///
/// See [`declared_type_check_mismatch`] for the supported types and their JSON
/// semantics.
pub(crate) fn validate_and_inject_parsed(
    stage_name: &SmolStr,
    outputs: &[kata_types::workflow::StageOutput],
    envelope: serde_json::Value,
) -> KataResult<serde_json::Value> {
    // Step 1: envelope must carry a `content` string.
    let content = envelope
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            KataError::Validation(format!(
                "structured-output stage \"{stage_name}\" failed schema \
             validation: envelope is missing a string \"content\" field"
            ))
        })?;

    // Step 2: content must parse as JSON. Apply a tolerant pre-pass
    // that strips markdown code fences — CLI agents wrap JSON in
    // fences more often than they emit raw JSON, even when the
    // prompt says otherwise. Preserves the original `content` on
    // the envelope for template access via `{{ stages.x.content }}`.
    let cleaned = strip_json_code_fence(content);
    let parsed: serde_json::Value = serde_json::from_str(cleaned).map_err(|e| {
        KataError::Validation(format!(
            "structured-output stage \"{stage_name}\" failed schema \
             validation: content is not valid JSON: {e}"
        ))
    })?;

    // Step 3: top-level must be an object.
    let parsed_obj = parsed.as_object().ok_or_else(|| {
        KataError::Validation(format!(
            "structured-output stage \"{stage_name}\" failed schema \
             validation: parsed content is not an object (declared \
             outputs require a JSON object at the top level)"
        ))
    })?;

    // Steps 4 + 5: presence + type check, walk outputs once.
    for declared in outputs {
        let Some(value) = parsed_obj.get(declared.name.as_str()) else {
            return Err(KataError::Validation(format!(
                "structured-output stage \"{stage_name}\" failed schema \
                 validation: missing declared field \"{}\"",
                declared.name
            )));
        };
        if let Some(actual) = declared_type_check_mismatch(declared.ty.as_str(), value) {
            return Err(KataError::Validation(format!(
                "structured-output stage \"{stage_name}\" failed schema \
                 validation: field \"{name}\" expected type \"{ty}\" but got {actual}",
                name = declared.name,
                ty = declared.ty,
            )));
        }
    }

    // Step 6: inject the parsed value alongside the existing
    // envelope fields. `envelope` is a Value::Object in practice
    // (`capsule_result_output` always builds it via `serde_json::json!({...})`)
    // but defend against a non-object envelope by returning the
    // raw parsed-in form only on the object path.
    let mut augmented = envelope;
    if let Some(map) = augmented.as_object_mut() {
        map.insert("parsed".to_string(), parsed);
    }
    Ok(augmented)
}

/// Validate + inject for a stage that carries a rich
/// constrained-JSON-Schema `output_schema` (lowered from a
/// `produces=contract(..)` declaration). When present, this
/// schema is *authoritative* over the flat `StageOutput{name,ty}`
/// presence/type check in [`validate_and_inject_parsed`] — a stage may
/// declare both, but the rich validator is the one the runner enforces.
///
/// Steps (mirrors the flat helper so the caller's retry plumbing is
/// identical regardless of which validator fired):
///   1. envelope must carry a `content` string;
///   2. the content is validated against `schema` via
///      [`kata_types::agent_run::validate_agent_run_output_content`],
///      which strips markdown code fences, parses the JSON, and checks
///      it against the constrained-schema subset. The returned `Value`
///      is the parsed content;
///   3. the parsed value is injected under `"parsed"` alongside the
///      existing envelope fields, leaving `content` untouched.
///
/// On any violation the validator's descriptive message is wrapped in a
/// `KataError::Validation` that names the stage. The caller renders that
/// message verbatim into the `validate_retries` feedback template, so
/// the schema-violation reason reaches the retried agent prompt.
pub(crate) fn validate_and_inject_rich_schema(
    stage_name: &SmolStr,
    schema: &serde_json::Value,
    envelope: serde_json::Value,
) -> KataResult<serde_json::Value> {
    // Step 1: envelope must carry a `content` string. Mirror the flat
    // helper's message shape so downstream assertions and operators see
    // a consistent "stage X failed schema validation: ..." prefix.
    let content = envelope
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            KataError::Validation(format!(
                "structured-output stage \"{stage_name}\" failed schema \
             validation: envelope is missing a string \"content\" field"
            ))
        })?;

    // Step 2: validate the raw content against the rich schema. The
    // shared `kata_types` entry point owns fence-stripping + parsing +
    // the constrained-subset check, so the runner and the
    // `/agents/run` API enforce byte-identical semantics.
    let parsed = kata_types::agent_run::validate_agent_run_output_content(content, schema)
        .map_err(|e| {
            KataError::Validation(format!(
                "structured-output stage \"{stage_name}\" failed schema \
                 validation: {e}"
            ))
        })?;

    // Step 3: inject the parsed value alongside the existing envelope
    // fields, defending against a non-object envelope exactly as the
    // flat helper does.
    let mut augmented = envelope;
    if let Some(map) = augmented.as_object_mut() {
        map.insert("parsed".to_string(), parsed);
    }
    Ok(augmented)
}

/// Return `Some(<the value's actual JSON type>)` when `value` does not satisfy the
/// declared `ty`, or `None` when it does. Unknown types (outside the
/// table below) pass through with a `tracing::debug!` — kata does not
/// own the type grammar, and breaking an author who's using a custom
/// tag like `"uuid"` or `"iso-datetime"` for documentation-only
/// purposes would break the contract that any `ty` is accepted.
///
/// Supported types:
///
/// | `ty`                         | Accepts (`serde_json::Value`)          |
/// |------------------------------|----------------------------------------|
/// | `u32`, `u64`                 | `Number` where `.is_u64()`             |
/// | `i32`, `i64`                 | `Number` where `.is_i64()`             |
/// | `f32`, `f64`, `number`       | `Number`                               |
/// | `string`                     | `String`                               |
/// | `bool`, `boolean`            | `Bool`                                 |
/// | `array`                      | `Array`                                |
/// | `object`                     | `Object`                               |
/// | `json`                       | any value (free-form)                  |
/// | `null`                       | `Null`                                 |
/// | anything else                | pass through (debug log, no error)     |
fn declared_type_check_mismatch(ty: &str, value: &serde_json::Value) -> Option<&'static str> {
    let ok = match ty {
        "u32" | "u64" => value.is_u64(),
        "i32" | "i64" => value.is_i64(),
        "f32" | "f64" | "number" => value.is_number(),
        "string" => value.is_string(),
        "bool" | "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "null" => value.is_null(),
        // `json` is pure documentation — explicitly any-valued.
        "json" => true,
        unknown => {
            debug!(
                ty = unknown,
                "structured-output: declared type not in the built-in table \
                 — passing through without enforcement (treat as documentation)"
            );
            true
        }
    };
    if ok {
        None
    } else {
        Some(json_value_kind(value))
    }
}

/// Short human-readable tag for the shape of `value`. Used in the
/// `KataError::Validation` message produced by
/// [`declared_type_check_mismatch`].
fn json_value_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(n) => {
            if n.is_u64() {
                "u64"
            } else if n.is_i64() {
                "i64"
            } else {
                "f64"
            }
        }
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
