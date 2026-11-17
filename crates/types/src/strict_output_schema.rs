//! A stage's output contract rendered as a STRICT structured-output JSON Schema
//! — the dialect OpenAI's Responses API enforces under `text.format =
//! {type: "json_schema", strict: true}`, which nanocode's
//! `OpenAiBuilder::strict_json_schema` sends.
//!
//! # One source
//!
//! The input is the stage's `output_schema` — the constrained schema
//! [`crate::agent_run::validate_agent_run_output_content`] validates the turn's
//! answer against. Nothing here is a second spelling of the contract: the
//! strict schema is a pure function of that value, and kata's own validation
//! (plus `validate_retries`) stays the trust boundary. The strict schema is an
//! aid to the model, never a reason to accept an answer.
//!
//! # The mapping
//!
//! | kata node | strict node |
//! |---|---|
//! | `object` | `type`, `properties`, `required` = EVERY property, `additionalProperties: false` |
//! | `object` with no properties (an empty `contract(..)`; kata accepts only `{}` on it) | the closed empty object, `properties: {}`, `required: []` |
//! | a property absent from kata's `required` | `anyOf: [<node>, {type: "null"}]` (nullable) |
//! | `array` | `type`, `items`, `minItems`, `maxItems` |
//! | `string` | `type`, `enum` |
//! | `number` / `integer` | `type`, `minimum`, `maximum` |
//! | `boolean` / `null` | `type` |
//! | `variant` | `anyOf` of one closed single-key object per tag |
//! | `description` | kept |
//! | `title` | dropped (an annotation; no validation effect) |
//!
//! # What the strict schema states differently — and why kata still agrees
//!
//! * **RELAXED** — `minLength`, `maxLength` and `pattern` are not sent as
//!   keywords. The strict dialect does not list the two length keywords, and
//!   its `pattern` is not kata's Rust-`regex` dialect; a keyword the provider
//!   rejects fails the whole request, which would turn an aid into an outage.
//!   Each relaxed bound is restated in the node's `description` (`kata
//!   enforces: maxLength 4000`), so the model is still told, and kata's
//!   validator still refuses an answer that breaks it (a `validate_retries`
//!   retry). On those keywords the strict schema accepts MORE than the
//!   contract.
//! * **OPTIONAL = NULLABLE** — strict mode requires every property. An
//!   optional property is therefore sent required-and-nullable, and kata's
//!   validator treats a `null` on an optional property as the property being
//!   absent (it is removed from the parsed document; see
//!   [`crate::agent_run::validate_agent_run_output_content`]). Omitting an
//!   optional property, which kata accepts, is the one document the strict
//!   schema refuses.
//! * **INTEGER** — JSON Schema's `integer` admits `2.0`; kata's does not.
//! * **ORDER** — properties are sent in NAME order, not the order the contract
//!   declares them. The input is the lowered `output_schema`, whose objects
//!   are `BTreeMap`-backed (serde_json without `preserve_order`), so the
//!   declaration order is already gone; the prompt's `json_skeleton` keeps it,
//!   rendering from the contract itself. Strict decoding generates fields in
//!   schema order, so a constrained model writes them alphabetically. No
//!   document is accepted or refused differently on account of order.
//!
//! # What cannot be expressed strictly — no schema is sent
//!
//! [`strict_output_schema`] refuses, and the turn is sent with NO schema (the
//! prompt-side `json_only(json_skeleton(..))` text and kata's validation carry
//! it alone, exactly as before this module existed), when the contract
//! contains ([`NotStrict`]):
//!
//! * more than [`MAX_STRICT_NESTING`] schema levels along one path, counting
//!   every node — `anyOf` wrappers and their branches included
//!   (`TooDeep`). UNREACHABLE at kata's own depth bound
//!   ([`crate::agent_run::MAX_SCHEMA_DEPTH`] = 4): an optional property costs
//!   one extra level and a variant one extra level, and the deepest contract
//!   kata admits renders at nine. The refusal stands for a raised bound;
//!   `the_deepest_contract_kata_admits_renders_within_the_nesting_limit`
//!   pins the nine;
//! * more than [`MAX_STRICT_PROPERTIES`] object properties in total, each
//!   variant tag's single-key wrapper property included (`TooManyProperties`);
//! * more than [`MAX_STRICT_ENUM_VALUES`] enum values in total
//!   (`TooManyEnumValues`);
//! * more than [`MAX_STRICT_NAME_CHARS`] characters of property names, variant
//!   tags and enum values in total (`TooManyNameChars`);
//! * a value outside kata's own subset (`OutsideSubset`) — unreachable from a
//!   checked program, refused rather than guessed at.
//!
//! The four bounds are the provider's documented strict-mode limits. Its fifth,
//! per-property one (a total-length limit on a single string enum that applies
//! only past 250 values) is not a refusal here because kata caps
//! an enum at [`crate::agent_run::MAX_ENUM_VARIANTS`] = 64 values, so no
//! admitted contract reaches it. The closed empty object's acceptance by the
//! provider is NOT measured on the wire (that needs a model turn): it is the
//! spelling strict function tools take for "no arguments", and kata sends it
//! for the typed-routing idiom `variant({"ship": contract("Ship", {}), ..})`.
//! Nothing is ever sent as a PARTIAL schema: a contract is rendered whole or
//! not at all.

use serde_json::{Map, Value};

use crate::agent_run::validate_agent_run_output_schema;

/// The provider's strict-mode nesting limit, applied to EVERY schema node on a
/// path (root = 1), `anyOf` wrappers and branches included — at least as
/// strict as the provider's own count, whichever levels it counts.
pub const MAX_STRICT_NESTING: usize = 10;
/// The provider's strict-mode limit on object properties across the schema.
pub const MAX_STRICT_PROPERTIES: usize = 5000;
/// The provider's strict-mode limit on enum values across the schema.
pub const MAX_STRICT_ENUM_VALUES: usize = 1000;
/// The provider's strict-mode limit on the summed length (in characters) of
/// every property name, variant tag and enum value.
pub const MAX_STRICT_NAME_CHARS: usize = 120_000;

/// Why a contract has no strict rendering. The turn then carries no schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotStrict {
    /// A path reaches `levels` schema levels, past [`MAX_STRICT_NESTING`].
    TooDeep { levels: usize },
    /// `count` object properties in total, past [`MAX_STRICT_PROPERTIES`].
    TooManyProperties { count: usize },
    /// `count` enum values in total, past [`MAX_STRICT_ENUM_VALUES`].
    TooManyEnumValues { count: usize },
    /// `count` name characters in total, past [`MAX_STRICT_NAME_CHARS`].
    TooManyNameChars { count: usize },
    /// The value is not a schema kata's own validator accepts.
    OutsideSubset { reason: String },
}

impl std::fmt::Display for NotStrict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooDeep { levels } => write!(
                f,
                "a path reaches {levels} schema levels; strict mode allows {MAX_STRICT_NESTING}"
            ),
            Self::TooManyProperties { count } => write!(
                f,
                "{count} object properties; strict mode allows {MAX_STRICT_PROPERTIES}"
            ),
            Self::TooManyEnumValues { count } => write!(
                f,
                "{count} enum values; strict mode allows {MAX_STRICT_ENUM_VALUES}"
            ),
            Self::TooManyNameChars { count } => write!(
                f,
                "{count} characters of names and enum values; strict mode allows \
                 {MAX_STRICT_NAME_CHARS}"
            ),
            Self::OutsideSubset { reason } => {
                write!(f, "not a schema kata's validator accepts: {reason}")
            }
        }
    }
}

impl std::error::Error for NotStrict {}

/// The refusal an adapter answers, before any model call, to a prompt carrying
/// an output schema its protocol has no channel for
/// ([`crate::agent::AdapterKind::carries_strict_output_schema`] false). `Capsule::new`
/// refuses such a capsule first; this is the adapter's own door for a prompt
/// built by hand.
#[must_use]
pub fn output_schema_unsupported(protocol: &str) -> String {
    format!(
        "agent_output_schema_unsupported: the prompt carries an output schema and the \
         {protocol} protocol has no channel for one; it is refused rather than dropped, which \
         would run the turn without a constraint the caller stated"
    )
}

/// Render a stage's output contract (a top-level kata `output_schema`) as the
/// strict structured-output schema described in the module doc, or say why it
/// has none.
///
/// # Errors
///
/// [`NotStrict`] for exactly the shapes listed in the module doc.
pub fn strict_output_schema(contract: &Value) -> Result<Value, NotStrict> {
    validate_agent_run_output_schema(contract)
        .map_err(|reason| NotStrict::OutsideSubset { reason })?;
    let mut tally = Tally::default();
    let rendered = render(contract, "$", 1, &mut tally)?;
    if tally.properties > MAX_STRICT_PROPERTIES {
        return Err(NotStrict::TooManyProperties {
            count: tally.properties,
        });
    }
    if tally.enum_values > MAX_STRICT_ENUM_VALUES {
        return Err(NotStrict::TooManyEnumValues {
            count: tally.enum_values,
        });
    }
    if tally.name_chars > MAX_STRICT_NAME_CHARS {
        return Err(NotStrict::TooManyNameChars {
            count: tally.name_chars,
        });
    }
    Ok(rendered)
}

#[derive(Default)]
struct Tally {
    properties: usize,
    enum_values: usize,
    name_chars: usize,
}

impl Tally {
    fn name(&mut self, name: &str) {
        self.name_chars += name.chars().count();
    }
}

fn level(levels: usize) -> Result<(), NotStrict> {
    if levels > MAX_STRICT_NESTING {
        return Err(NotStrict::TooDeep { levels });
    }
    Ok(())
}

/// One kata node at `levels` (root = 1). The node was validated by
/// [`validate_agent_run_output_schema`], so its `type` and shape keys are known
/// good; a missing one is still refused, never unwrapped.
fn render(node: &Value, path: &str, levels: usize, tally: &mut Tally) -> Result<Value, NotStrict> {
    level(levels)?;
    let outside = |what: &str| NotStrict::OutsideSubset {
        reason: format!("{path}: {what}"),
    };
    let obj = node.as_object().ok_or_else(|| outside("not an object"))?;
    let ty = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| outside("no type"))?;
    let mut out = Map::new();
    let mut relaxed: Vec<String> = Vec::new();
    match ty {
        "object" => {
            // kata closes an object with no `properties` key exactly as one
            // declaring `properties: {}`: only `{}` passes.
            let no_properties = Map::new();
            let properties = obj
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or(&no_properties);
            let required: Vec<&str> = obj
                .get("required")
                .and_then(Value::as_array)
                .map(|names| names.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut rendered = Map::new();
            for (name, child) in properties {
                tally.properties += 1;
                tally.name(name);
                let child_path = format!("{path}.{name}");
                let strict = if required.contains(&name.as_str()) {
                    render(child, &child_path, levels + 1, tally)?
                } else {
                    nullable(child, &child_path, levels, tally)?
                };
                rendered.insert(name.clone(), strict);
            }
            out.insert("type".into(), Value::from("object"));
            out.insert(
                "required".into(),
                Value::Array(rendered.keys().cloned().map(Value::String).collect()),
            );
            out.insert("properties".into(), Value::Object(rendered));
            out.insert("additionalProperties".into(), Value::Bool(false));
        }
        "array" => {
            let items = obj.get("items").ok_or_else(|| outside("no items"))?;
            out.insert("type".into(), Value::from("array"));
            out.insert(
                "items".into(),
                render(items, &format!("{path}[]"), levels + 1, tally)?,
            );
            for key in ["minItems", "maxItems"] {
                if let Some(bound) = obj.get(key) {
                    out.insert(key.into(), bound.clone());
                }
            }
        }
        "string" => {
            out.insert("type".into(), Value::from("string"));
            if let Some(variants) = obj.get("enum").and_then(Value::as_array) {
                tally.enum_values += variants.len();
                for variant in variants.iter().filter_map(Value::as_str) {
                    tally.name(variant);
                }
                out.insert("enum".into(), Value::Array(variants.clone()));
            }
            for key in ["minLength", "maxLength", "pattern"] {
                if let Some(bound) = obj.get(key) {
                    relaxed.push(format!("{key} {bound}"));
                }
            }
        }
        "number" | "integer" => {
            out.insert("type".into(), Value::from(ty));
            for key in ["minimum", "maximum"] {
                if let Some(bound) = obj.get(key) {
                    out.insert(key.into(), bound.clone());
                }
            }
        }
        "boolean" | "null" => {
            out.insert("type".into(), Value::from(ty));
        }
        "variant" => {
            let arms = obj
                .get("variants")
                .and_then(Value::as_object)
                .ok_or_else(|| outside("no variants"))?;
            let mut branches = Vec::with_capacity(arms.len());
            for (tag, arm) in arms {
                // A branch is an object level, its one property a level below.
                level(levels + 1)?;
                tally.properties += 1;
                tally.name(tag);
                let payload = render(arm, &format!("{path}.{tag}"), levels + 2, tally)?;
                let mut properties = Map::new();
                properties.insert(tag.clone(), payload);
                branches.push(serde_json::json!({
                    "type": "object",
                    "properties": properties,
                    "required": [tag],
                    "additionalProperties": false,
                }));
            }
            out.insert("anyOf".into(), Value::Array(branches));
        }
        other => return Err(outside(&format!("type {other:?}"))),
    }
    let description = obj.get("description").and_then(Value::as_str);
    let restated = (!relaxed.is_empty()).then(|| format!("kata enforces: {}", relaxed.join(", ")));
    let description = match (description, restated) {
        (Some(doc), Some(restated)) => Some(format!("{doc} ({restated})")),
        (Some(doc), None) => Some(doc.to_owned()),
        (None, restated) => restated,
    };
    if let Some(description) = description {
        out.insert("description".into(), Value::String(description));
    }
    Ok(Value::Object(out))
}

/// An optional property's strict spelling: `anyOf: [<node>, {type: "null"}]`,
/// or the node itself when it already IS `null`. The wrapper takes the level
/// the property would have; its branches sit one below.
fn nullable(
    child: &Value,
    path: &str,
    parent_levels: usize,
    tally: &mut Tally,
) -> Result<Value, NotStrict> {
    if child.get("type").and_then(Value::as_str) == Some("null") {
        return render(child, path, parent_levels + 1, tally);
    }
    level(parent_levels + 1)?;
    let inner = render(child, path, parent_levels + 2, tally)?;
    Ok(serde_json::json!({ "anyOf": [inner, { "type": "null" }] }))
}

#[cfg(test)]
mod tests {
    use super::{MAX_STRICT_NESTING, NotStrict, Tally, render};

    /// The nesting refusal fires exactly past the limit. kata's depth bound
    /// cannot reach it, so the mechanism is driven from its level argument.
    #[test]
    fn a_node_past_the_nesting_limit_is_refused() {
        let leaf = serde_json::json!({"type": "string"});
        assert!(render(&leaf, "$", MAX_STRICT_NESTING, &mut Tally::default()).is_ok());
        assert_eq!(
            render(&leaf, "$", MAX_STRICT_NESTING + 1, &mut Tally::default()),
            Err(NotStrict::TooDeep {
                levels: MAX_STRICT_NESTING + 1
            })
        );
        let optional = serde_json::json!({"type": "object", "properties": {"a": leaf}});
        assert_eq!(
            render(
                &optional,
                "$",
                MAX_STRICT_NESTING - 1,
                &mut Tally::default()
            ),
            Err(NotStrict::TooDeep {
                levels: MAX_STRICT_NESTING + 1
            }),
            "an optional property's nullable wrapper counts as a level"
        );
    }
}
