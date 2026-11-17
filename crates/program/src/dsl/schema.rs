//! JSON-schema codegen for the native Starlark contract DSL.
//!
//! Maps the DSL's typed [`DslType`] tree onto the constrained JSON-Schema
//! subset that `kata_types::agent_run::validate_agent_run_output_schema`
//! accepts. The mapping is intentionally total over [`DslType`] and produces
//! schema nodes in *exactly* the shape the validator recognizes:
//!
//! | DSL constructor        | schema node                                            |
//! | ---------------------- | ------------------------------------------------------ |
//! | `contract(name, {..})` | `{"type":"object","properties":{..},"required":[..],"additionalProperties":false}` |
//! | primitive `"string"`   | `{"type":"string"}`                                    |
//! | primitive `"number"`   | `{"type":"number"}`                                    |
//! | primitive `"integer"`  | `{"type":"integer"}`                                   |
//! | primitive `"bool"`     | `{"type":"boolean"}` (note: DSL spells it `bool`)      |
//! | primitive `"null"`     | `{"type":"null"}`                                      |
//! | `enum(a, b, ..)`       | `{"type":"string","enum":[a, b, ..]}`                  |
//! | `list_of(elem)`        | `{"type":"array","items":<elem>,"maxItems":128}`       |
//! | `variant({tag: ty})`   | `{"type":"variant","variants":{tag: <ty>, ..}}`        |
//! | `number(min=,max=)`    | `{"type":"number","minimum":..,"maximum":..}`          |
//! | `integer(min=,max=)`   | `{"type":"integer","minimum":..,"maximum":..}`         |
//! | `string(pattern=,min_length=,max_length=)` | `{"type":"string","pattern":..,"minLength":..,"maxLength":..}` |
//!
//! Default `list_of` capacity is [`DEFAULT_LIST_MAX_ITEMS`] (128), the
//! validator's hard ceiling on `maxItems`.
//!
//! **VALUE CONSTRAINTS** — the numeric (`min`/`max`) and string
//! (`pattern`/`min_length`/`max_length`) constraint kwargs are OPTIONAL and
//! ADDITIVE: a primitive with no constraint carries
//! [`PrimitiveConstraints::default`] and lowers to the bare `{"type": <t>}`
//! node exactly as before (so constraint-free contracts stay hash-stable).
//! When present, a constraint lowers to the corresponding JSON-Schema key and
//! is ENFORCED by the structured-output validator against a stage's emitted
//! value; a violation is a validation error naming the field + constraint.
//!
//! **Every bound the validator enforces is mirrored here at construction
//! time**, so a contract that would emit a validator-rejected schema fails the
//! moment it is authored (a clear Starlark error) rather than deferring the
//! failure to a later validation pass. The mirrored bounds are: nesting depth
//! ([`MAX_CONTRACT_DEPTH`]), object property count ([`MAX_CONTRACT_PROPERTIES`])
//! and property-name shape ([`MAX_NAME_LEN`]), enum/variant arm count
//! ([`MAX_CONTRACT_VARIANTS`]) with non-empty/unique enum members,
//! non-empty/bounded variant tags, and — for value constraints — a numeric
//! `min <= max`, a `min_length <= max_length` within [`MAX_STRING_LENGTH`], and
//! a compilable `pattern` regex. The invariant
//! `validate_agent_run_output_schema(contract_schema(c)) == Ok(())` holds for
//! every `Contract` the builtins admit.

use serde_json::{Map, Value, json};

/// Default `maxItems` for a `list_of(..)` array node.
///
/// BOUND to the single authority — [`kata_types::agent_run::MAX_ARRAY_ITEMS`],
/// the ceiling the agent-run validator enforces — so this is both the default
/// *and* the maximum a generated list schema may carry, and it can never drift
/// from the validator's cap or the catalog's published `list_of` limit (a
/// cross-crate equality drift guard pins all three).
pub(crate) const DEFAULT_LIST_MAX_ITEMS: u64 = kata_types::agent_run::MAX_ARRAY_ITEMS;

/// Maximum nesting depth a generated contract schema may reach.
///
/// Mirrors `kata_types::agent_run`'s `MAX_SCHEMA_DEPTH`. The validator
/// counts the top-level node as depth 0 and fails once a child node would
/// land at depth `> 4`, i.e. it admits 5 levels of nodes (depth 0..=4).
pub(crate) const MAX_CONTRACT_DEPTH: usize = 4;

/// Maximum number of fields an object contract may declare.
///
/// Mirrors `kata_types::agent_run`'s `MAX_SCHEMA_PROPERTIES` (and, since
/// `required ⊆ properties`, transitively its `MAX_SCHEMA_REQUIRED`).
pub(crate) const MAX_CONTRACT_PROPERTIES: usize = 32;

/// Maximum number of arms an `enum(..)` or `variant({..})` may declare.
///
/// Mirrors `kata_types::agent_run`'s `MAX_ENUM_VARIANTS`.
pub(crate) const MAX_CONTRACT_VARIANTS: usize = 64;

/// Maximum byte length of a property name or variant tag.
///
/// Mirrors the validator's `validate_property_name` limit.
pub(crate) const MAX_NAME_LEN: usize = 128;

/// The typed DSL tree produced by the `contract`/`field`/`enum`/`list_of`/
/// `variant` builtins, prior to schema codegen.
///
/// This is the single source of truth a `Contract` custom value carries; the
/// generated `serde_json::Value` is derived from it once at construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DslType {
    /// A JSON primitive leaf, carrying any author-declared VALUE CONSTRAINTS
    /// (numeric range / string pattern+length). A bare-string primitive
    /// (`field("string")`) carries [`PrimitiveConstraints::default`] (all
    /// `None`) and lowers byte-identically to the pre-constraint schema.
    Primitive(Primitive, PrimitiveConstraints),
    /// A bare-string enumeration: `enum("a", "b", ..)`.
    Enum(Vec<String>),
    /// A homogeneous list: `list_of(<element>)`.
    List(Box<DslType>),
    /// A discriminated union: `variant({"<tag>": <payload>, ..})`.
    ///
    /// Arms are kept in author-declared (insertion) order in this tree; the
    /// generated schema's `variants` map is keyed by tag (JSON object key
    /// order is not significant for validation).
    Variant(Vec<(String, DslType)>),
    /// A nested object contract.
    Object(ContractShape),
}

/// JSON primitive leaf kinds the DSL exposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Primitive {
    String,
    Number,
    Integer,
    Boolean,
    Null,
}

impl Primitive {
    /// Parse a DSL primitive spelling. `bool` maps to JSON `boolean`.
    pub(crate) fn parse(spelling: &str) -> Option<Self> {
        match spelling {
            "string" => Some(Self::String),
            "number" => Some(Self::Number),
            "integer" => Some(Self::Integer),
            "bool" => Some(Self::Boolean),
            "null" => Some(Self::Null),
            _ => None,
        }
    }

    /// JSON-Schema `type` token for this primitive.
    pub(crate) fn schema_type(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Null => "null",
        }
    }
}

/// Author-declared VALUE CONSTRAINTS attached to a primitive leaf.
///
/// Every field is optional; the all-`None` [`Default`] is the constraint-free
/// primitive that lowers to a bare `{"type": <t>}` node (byte-identical to the
/// pre-constraint schema, so `program_hash`/`contract_hash` are unchanged for
/// constraint-free contracts). The numeric bounds apply to `number`/`integer`;
/// the string bounds apply to `string`. The `number()`/`integer()`/`string()`
/// builtins are the only source of a non-default value, and they only populate
/// the fields valid for their primitive.
///
/// The numeric bounds are stored as [`serde_json::Number`] so an author's exact
/// `int`/`float` literal round-trips into the lowered JSON `minimum`/`maximum`
/// unchanged; `Number` is `Eq`/`Hash`, keeping [`DslType`] `Eq`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PrimitiveConstraints {
    /// JSON-Schema `minimum` (inclusive lower bound; `number`/`integer`).
    pub(crate) minimum: Option<serde_json::Number>,
    /// JSON-Schema `maximum` (inclusive upper bound; `number`/`integer`).
    pub(crate) maximum: Option<serde_json::Number>,
    /// JSON-Schema `pattern` (a regular expression; `string`).
    pub(crate) pattern: Option<String>,
    /// JSON-Schema `minLength` (`string`).
    pub(crate) min_length: Option<u64>,
    /// JSON-Schema `maxLength` (`string`).
    pub(crate) max_length: Option<u64>,
}

impl PrimitiveConstraints {
    /// True when no constraint is set — the lowered node is a bare `{"type": t}`.
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Mirror of `kata_types::agent_run`'s `MAX_STRING_LENGTH` — the validator's
/// ceiling on a `minLength`/`maxLength` bound. Mirrored here so a
/// `string(max_length = ..)` over the ceiling fails at construction rather than
/// at a later validation pass (see the module invariant).
pub(crate) const MAX_STRING_LENGTH: u64 = 64 * 1024;

/// A single contract field: its declared type plus shape metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContractField {
    pub(crate) name: String,
    pub(crate) ty: DslType,
    pub(crate) required: bool,
    pub(crate) doc: Option<String>,
}

/// The structural body of a contract: an ordered list of fields plus the
/// contract's name. Used both for the top-level `Contract` value and for
/// nested object fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContractShape {
    pub(crate) name: String,
    pub(crate) fields: Vec<ContractField>,
}

/// Error raised when a contract would lower to a schema the agent-run
/// validator rejects (depth, property/variant counts, name/tag shape).
/// Surfaced to Starlark authors as an evaluation error.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub(crate) struct ContractSchemaError {
    message: String,
}

impl ContractSchemaError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Generate the constrained JSON-Schema object node for a contract.
///
/// The top-level node is always `type: "object"` with
/// `additionalProperties: false`, as the validator requires of the root.
///
/// # Errors
///
/// Returns [`ContractSchemaError`] when any node would violate a validator
/// bound (nesting depth, property/variant count, or name/tag shape).
pub(crate) fn contract_schema(shape: &ContractShape) -> Result<Value, ContractSchemaError> {
    object_schema(shape, 0, "$")
}

/// Lower a single DSL type to its constrained JSON-Schema NODE, for a
/// workflow-invocation param's declared type.
///
/// Unlike [`contract_schema`], the result need not be an object — a param's type
/// is exactly one `field(..)` type node (a primitive/enum/list/variant/object).
/// The node is validated by the same
/// [`kata_types::agent_run::validate_param_value_against_schema`] the resolver
/// uses, keeping the "a lowered schema is always validator-accepted" invariant.
pub(crate) fn param_type_schema(ty: &DslType) -> Result<Value, ContractSchemaError> {
    type_schema(ty, 0, "$")
}

/// Generate a schema node for an arbitrary DSL type at `depth`.
fn type_schema(ty: &DslType, depth: usize, path: &str) -> Result<Value, ContractSchemaError> {
    if depth > MAX_CONTRACT_DEPTH {
        return Err(depth_error(path));
    }
    match ty {
        DslType::Primitive(primitive, constraints) => {
            primitive_schema(*primitive, constraints, path)
        }
        DslType::Enum(variants) => {
            if variants.len() > MAX_CONTRACT_VARIANTS {
                return Err(ContractSchemaError::new(format!(
                    "enum at {path} declares {} variants, exceeding the maximum of {MAX_CONTRACT_VARIANTS}",
                    variants.len()
                )));
            }
            let mut seen = std::collections::BTreeSet::new();
            for variant in variants {
                if variant.is_empty() {
                    return Err(ContractSchemaError::new(format!(
                        "enum at {path} has an empty variant; enum variants must be non-empty strings"
                    )));
                }
                if !seen.insert(variant.as_str()) {
                    return Err(ContractSchemaError::new(format!(
                        "enum at {path} has duplicate variant {variant:?}"
                    )));
                }
            }
            Ok(json!({ "type": "string", "enum": variants }))
        }
        DslType::List(element) => {
            let items = type_schema(element, depth + 1, &format!("{path}.items"))?;
            Ok(json!({
                "type": "array",
                "items": items,
                "maxItems": DEFAULT_LIST_MAX_ITEMS,
            }))
        }
        DslType::Variant(arms) => {
            if arms.len() > MAX_CONTRACT_VARIANTS {
                return Err(ContractSchemaError::new(format!(
                    "variant at {path} declares {} arms, exceeding the maximum of {MAX_CONTRACT_VARIANTS}",
                    arms.len()
                )));
            }
            let mut variants = Map::new();
            for (tag, arm) in arms {
                check_name(tag, &format!("{path}.variants"), "variant tag")?;
                let arm_schema = type_schema(arm, depth + 1, &format!("{path}.variants.{tag}"))?;
                variants.insert(tag.clone(), arm_schema);
            }
            Ok(json!({ "type": "variant", "variants": variants }))
        }
        DslType::Object(shape) => object_schema(shape, depth, path),
    }
}

/// Generate a primitive leaf node, folding in any author-declared VALUE
/// CONSTRAINTS and validating them against the same bounds the agent-run
/// validator enforces (the module invariant: a lowered schema is always
/// validator-accepted).
///
/// A constraint-free primitive lowers to the bare `{"type": <t>}` node, so
/// constraint-free contracts stay byte-identical (hash-stable). The
/// `number()`/`integer()`/`string()` builtins only populate the fields valid
/// for their primitive, so the numeric bounds land only on `number`/`integer`
/// and the string bounds only on `string`.
fn primitive_schema(
    primitive: Primitive,
    constraints: &PrimitiveConstraints,
    path: &str,
) -> Result<Value, ContractSchemaError> {
    if constraints.is_empty() {
        // Fast path: byte-identical to the pre-constraint lowering.
        return Ok(json!({ "type": primitive.schema_type() }));
    }
    // min <= max for the numeric range (compared as f64; author literals are
    // finite Starlark numbers, so `as_f64` is always `Some`).
    if let (Some(min), Some(max)) = (&constraints.minimum, &constraints.maximum)
        && let (Some(min_f), Some(max_f)) = (min.as_f64(), max.as_f64())
        && min_f > max_f
    {
        return Err(ContractSchemaError::new(format!(
            "numeric constraint at {path} declares min ({min}) greater than max ({max})"
        )));
    }
    // Length bounds within the validator's ceiling, and min_length <= max_length.
    for (label, bound) in [
        ("min_length", constraints.min_length),
        ("max_length", constraints.max_length),
    ] {
        if let Some(bound) = bound
            && bound > MAX_STRING_LENGTH
        {
            return Err(ContractSchemaError::new(format!(
                "string {label} constraint at {path} is {bound}, exceeding the maximum of {MAX_STRING_LENGTH}"
            )));
        }
    }
    if let (Some(min_len), Some(max_len)) = (constraints.min_length, constraints.max_length)
        && min_len > max_len
    {
        return Err(ContractSchemaError::new(format!(
            "string constraint at {path} declares min_length ({min_len}) greater than max_length ({max_len})"
        )));
    }
    // A `pattern` must be a compilable regex; reject a malformed one here so the
    // failure surfaces at authoring, not at a later structured-output pass.
    if let Some(pattern) = &constraints.pattern {
        regex::Regex::new(pattern).map_err(|err| {
            ContractSchemaError::new(format!(
                "string pattern at {path} is not a valid regular expression: {err}"
            ))
        })?;
    }
    let mut node = Map::new();
    node.insert(
        "type".to_owned(),
        Value::String(primitive.schema_type().to_owned()),
    );
    if let Some(min) = &constraints.minimum {
        node.insert("minimum".to_owned(), Value::Number(min.clone()));
    }
    if let Some(max) = &constraints.maximum {
        node.insert("maximum".to_owned(), Value::Number(max.clone()));
    }
    if let Some(min_len) = constraints.min_length {
        node.insert("minLength".to_owned(), json!(min_len));
    }
    if let Some(max_len) = constraints.max_length {
        node.insert("maxLength".to_owned(), json!(max_len));
    }
    if let Some(pattern) = &constraints.pattern {
        node.insert("pattern".to_owned(), Value::String(pattern.clone()));
    }
    Ok(Value::Object(node))
}

/// Generate an `object` schema node for a [`ContractShape`] at `depth`.
fn object_schema(
    shape: &ContractShape,
    depth: usize,
    path: &str,
) -> Result<Value, ContractSchemaError> {
    if depth > MAX_CONTRACT_DEPTH {
        return Err(depth_error(path));
    }
    if shape.fields.len() > MAX_CONTRACT_PROPERTIES {
        return Err(ContractSchemaError::new(format!(
            "contract at {path} declares {} fields, exceeding the maximum of {MAX_CONTRACT_PROPERTIES}",
            shape.fields.len()
        )));
    }
    let mut properties = Map::new();
    let mut required: Vec<String> = Vec::new();
    for field in &shape.fields {
        check_name(&field.name, &format!("{path}.properties"), "field name")?;
        let field_path = format!("{path}.properties.{}", field.name);
        let mut node = type_schema(&field.ty, depth + 1, &field_path)?;
        // Attach the optional doc string as a JSON-Schema `description`.
        // The validator accepts `description` on any node and ignores it
        // for value validation, so this is purely advisory metadata.
        if let Some(doc) = &field.doc
            && let Some(map) = node.as_object_mut()
        {
            map.insert("description".to_owned(), Value::String(doc.clone()));
        }
        properties.insert(field.name.clone(), node);
        if field.required {
            required.push(field.name.clone());
        }
    }
    // Canonical (sorted) required-set: `properties`/`variants` are already
    // BTreeMap-backed (order-independent), but a JSON array preserves order, so
    // two structurally-equal contracts authored with reordered fields would
    // otherwise generate unequal `required` arrays and be wrongly rejected by
    // the load-time type-checker's value-equality match.
    required.sort();
    let mut object = Map::new();
    object.insert("type".to_owned(), Value::String("object".to_owned()));
    object.insert("properties".to_owned(), Value::Object(properties));
    object.insert(
        "required".to_owned(),
        Value::Array(required.into_iter().map(Value::String).collect()),
    );
    object.insert("additionalProperties".to_owned(), Value::Bool(false));
    Ok(Value::Object(object))
}

/// Validate a property name or variant tag against the validator's shape
/// bounds: non-empty and at most [`MAX_NAME_LEN`] bytes.
fn check_name(name: &str, path: &str, kind: &str) -> Result<(), ContractSchemaError> {
    if name.is_empty() {
        return Err(ContractSchemaError::new(format!(
            "{kind} at {path} must not be empty"
        )));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ContractSchemaError::new(format!(
            "{kind} {name:?} at {path} exceeds the maximum length of {MAX_NAME_LEN} bytes"
        )));
    }
    Ok(())
}

/// Build the canonical depth-exceeded error for `path`.
fn depth_error(path: &str) -> ContractSchemaError {
    ContractSchemaError::new(format!(
        "contract nesting at {path} exceeds the maximum schema depth of {MAX_CONTRACT_DEPTH} \
         (the agent-run validator admits at most {} nested levels)",
        MAX_CONTRACT_DEPTH + 1,
    ))
}

// ── prompt-shape codegen (json_skeleton) + flat-outputs derivation ───────────

/// Render an illustrative, pretty-printed JSON SKELETON for a contract shape.
///
/// This is the SINGLE SOURCE for a stage's prompt JSON example: instead of an
/// author hand-restating the JSON shape in a `json_only("""{...}""")` block AND
/// declaring the same fields as a `produces=contract(..)`, the `produces=`
/// contract's [`ContractShape`] renders the example directly. The generated
/// text is PURELY ILLUSTRATIVE — it is never fed to the closed structured-output
/// validator (the placeholders like `"<string>"` are not real values), so it can
/// never itself trip a validation error.
///
/// Keys are emitted in DECLARATION order (the authored `contract(..)` field
/// order), so the rendered example reads top-to-bottom like the authored schema.
/// This is why the renderer walks the [`ContractShape`]/[`DslType`] tree by hand
/// rather than serializing the generated `serde_json::Value` (whose object keys
/// are `BTreeMap`-sorted, losing declaration order).
///
/// Placeholder mapping (total over [`DslType`]):
///
/// | DSL type            | skeleton                                   |
/// | ------------------- | ------------------------------------------ |
/// | `string`            | `"<string>"`                               |
/// | `number`            | `0`                                        |
/// | `integer`           | `0`                                        |
/// | `bool`              | `false`                                    |
/// | `null`              | `null`                                     |
/// | `enum(a, b, c)`     | `"a|b|c"` (pipe-joined choice hint)        |
/// | `list_of(elem)`     | `[<elem skeleton>]`                         |
/// | `variant({t: arm})` | `{"<t>": <first arm skeleton>}` (first arm)|
/// | nested `contract`   | `{field: <skeleton>, ..}` (declaration ord)|
pub(crate) fn contract_skeleton(shape: &ContractShape) -> String {
    let mut out = String::new();
    render_object_skeleton(shape, 0, &mut out);
    out
}

/// Push `s` as a properly JSON-escaped string LITERAL (surrounding quotes
/// included), so a field name / enum choice-hint / variant tag containing a
/// JSON metacharacter (`"`, `\`, a control char) can never render invalid JSON.
/// The skeleton is the SINGLE-SOURCE prompt example, so malformed JSON
/// would otherwise reach the model.
fn push_json_string(s: &str, out: &mut String) {
    // `serde_json::to_string(&str)` is infallible in practice; the closure is a
    // defensive fallback that still emits a quoted, backslash/quote-escaped
    // literal so the output stays valid JSON.
    let escaped = serde_json::to_string(s)
        .unwrap_or_else(|_| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")));
    out.push_str(&escaped);
}

/// Render the skeleton for an arbitrary [`DslType`] at the given indentation.
fn render_type_skeleton(ty: &DslType, indent: usize, out: &mut String) {
    match ty {
        DslType::Primitive(primitive, _) => out.push_str(primitive_placeholder(*primitive)),
        DslType::Enum(variants) => {
            // A pipe-joined choice hint (`"a|b|c"`) — an illustrative single
            // string, never a real emitted value. JSON-escaped so a variant
            // carrying a metacharacter can't produce invalid JSON.
            push_json_string(&variants.join("|"), out);
        }
        DslType::List(element) => {
            // `[\n  <elem>\n]` — a single illustrative element.
            out.push_str("[\n");
            push_indent(indent + 1, out);
            render_type_skeleton(element, indent + 1, out);
            out.push('\n');
            push_indent(indent, out);
            out.push(']');
        }
        DslType::Variant(arms) => {
            // Illustrate the FIRST arm only: `{"<tag>": <arm>}`. A variant has no
            // single canonical value, so the example shows the tagged-object
            // shape with one representative tag.
            match arms.first() {
                Some((tag, arm)) => {
                    out.push_str("{\n");
                    push_indent(indent + 1, out);
                    push_json_string(tag, out);
                    out.push_str(": ");
                    render_type_skeleton(arm, indent + 1, out);
                    out.push('\n');
                    push_indent(indent, out);
                    out.push('}');
                }
                // `variant(..)` construction rejects an empty arm set, so this is
                // unreachable for authored contracts; render an empty object.
                None => out.push_str("{}"),
            }
        }
        DslType::Object(shape) => render_object_skeleton(shape, indent, out),
    }
}

/// Render an object skeleton `{field: <skeleton>, ..}` in DECLARATION order.
fn render_object_skeleton(shape: &ContractShape, indent: usize, out: &mut String) {
    if shape.fields.is_empty() {
        out.push_str("{}");
        return;
    }
    out.push_str("{\n");
    for (idx, field) in shape.fields.iter().enumerate() {
        push_indent(indent + 1, out);
        push_json_string(&field.name, out);
        out.push_str(": ");
        render_type_skeleton(&field.ty, indent + 1, out);
        if idx + 1 < shape.fields.len() {
            out.push(',');
        }
        out.push('\n');
    }
    push_indent(indent, out);
    out.push('}');
}

/// Two-space-per-level indentation.
fn push_indent(indent: usize, out: &mut String) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

/// Illustrative placeholder token for a JSON primitive leaf.
fn primitive_placeholder(primitive: Primitive) -> &'static str {
    match primitive {
        Primitive::String => "\"<string>\"",
        Primitive::Number | Primitive::Integer => "0",
        Primitive::Boolean => "false",
        Primitive::Null => "null",
    }
}

/// Derive the flat `outputs=` table (a `{name: coarse-type-label}` list, in the
/// generated schema's property order) from a `produces=` contract's generated
/// object schema.
///
/// This is the SINGLE-SOURCE derivation: a stage that declares `produces=`
/// but omits `outputs=` gains a flat table computed from the SAME schema, so an
/// author writes the shape ONCE. The coarse labels are the ones the runtime's
/// declared-type check recognizes (`runner/json.rs`): `object`/`array`/`string`/
/// `number`/`integer`/`bool`/`null`; a `variant(..)` field renders at runtime as
/// a tagged JSON object, so it maps to `object`. The flat table is documentation
/// / tooling only when a rich `output_schema` is present (the schema is the
/// authoritative closed validator), so a label the flat grammar treats as
/// pass-through (e.g. `integer`) is harmless.
///
/// Returns an empty vec when `schema` is not an object schema with a
/// `properties` map (a degenerate/absent schema derives nothing).
pub(crate) fn derive_flat_outputs_from_schema(schema: &Value) -> Vec<(String, String)> {
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    props
        .iter()
        .map(|(name, node)| (name.clone(), coarse_type_label(node).to_owned()))
        .collect()
}

/// The coarse flat-`outputs=` type label for a generated schema property node.
fn coarse_type_label(node: &Value) -> &'static str {
    match schema_type(node) {
        // A `variant` renders at runtime as a tagged `{tag: value}` JSON object,
        // so it shares the `object` label.
        Some("object" | "variant") => "object",
        Some("array") => "array",
        Some("string") => "string",
        Some("number") => "number",
        Some("integer") => "integer",
        Some("boolean") => "bool",
        Some("null") => "null",
        // Anything outside the DSL subset — treat as free-form `json`.
        _ => "json",
    }
}

// ── width+depth structural subtyping over the contract schema subset ─────────

/// SOUNDNESS-CRITICAL structural subtyping over the constrained contract
/// JSON-Schema subset (exactly the node shapes [`contract_schema`] emits).
///
/// Returns `true` iff `produced` is a **subtype** of `consumed` — i.e. a
/// producer whose output conforms to `produced` is guaranteed to deliver,
/// for every field/element/tag the consumer actually reads, a value the
/// consumer's `consumed` contract expects. A superset producer is therefore
/// accepted where `serde_json::Value` equality would refuse it.
///
/// # Operational model (why width is sound)
///
/// A consumer reads the upstream's `parsed` envelope FIELD BY FIELD (e.g. via a
/// `{{ stages.X.parsed.field }}` template) — the `consumes=` contract is NOT a
/// runtime-enforced *closed* validator (see
/// `kata_types::workflow::StageDefinition::input_schema`: input schemas are not
/// runtime-significant). So this is **record subtyping**: the consumer cares only
/// that each field it declares is PRESENT (when required) and TYPE-COMPATIBLE;
/// extra producer fields are simply never read (WIDTH — sound). The producer's
/// own `produces=` schema *is* a closed runtime validator, so the producer emits
/// exactly its declared, type-correct shape — the premise that makes the
/// per-field guarantees hold.
///
/// # Soundness directions (the false-accept-is-a-type-hole invariant)
///
/// * **object** — for every field the consumer REQUIRES: the producer must
///   GUARANTEE it (present in `produced.properties` AND in `produced.required`)
///   and DEPTH-match it. A merely-OPTIONAL producer field can be omitted at
///   runtime, so a required consumer read of it would dangle → such a pairing is
///   correctly REJECTED (stronger than bare membership, deliberately). A
///   consumer-OPTIONAL field is depth-checked only if the producer has it.
///   WIDTH: extra producer fields are ignored (sound, see above).
/// * **array** — DEPTH on `items`; the producer's length range must be a SUBSET
///   of the consumer's (`produced.minItems ≥ consumed.minItems` AND
///   `produced.maxItems ≤ consumed.maxItems`, absent min = 0, absent max = ∞):
///   every array the producer can emit lies within the consumer's accepted
///   bounds. (Codegen always emits `maxItems = 128` and no `minItems`, so DSL
///   contracts are always equal-bounds → never false-rejected.)
/// * **string** — a consumer `enum` accepts ONLY its listed values, so the
///   producer must also be an `enum` whose value set is a SUBSET of the
///   consumer's (`produced ⊆ consumed`): a producer that can emit only a subset
///   of the consumer's tags is safe; one that can emit MORE (incl. an
///   unconstrained string vs an enum consumer) is UNSOUND → REJECTED. A
///   plain-string consumer accepts any string. Independently of the value set,
///   the producer's LENGTH range must be a subset of the consumer's
///   (`produced.minLength ≥ consumed.minLength`, absent = 0;
///   `produced.maxLength ≤ consumed.maxLength`, absent = ∞), and a consumer
///   `pattern` is satisfied ONLY by a producer declaring the IDENTICAL pattern
///   (regex language inclusion is undecidable in general; exact equality is the
///   sound floor).
/// * **variant** — the producer's tag set must be a SUBSET of the consumer's
///   (`produced ⊆ consumed`) with a DEPTH check per shared tag: every tag the
///   producer can emit is one the consumer routes/handles; a producer tag the
///   consumer does NOT handle is UNSOUND → REJECTED. Consumer tags the producer
///   never emits are unused capacity (like object width) — fine.
/// * **number/integer** — `type` match with the one widening `integer ⊆ number`
///   (every JSON integer IS a number, so an `integer` producer satisfies a
///   `number` consumer; a `number` producer does NOT satisfy an `integer`
///   consumer — it may emit `1.5`), PLUS the producer's value range must be a
///   subset of the consumer's (`produced.minimum ≥ consumed.minimum` and
///   `produced.maximum ≤ consumed.maximum`, an absent bound meaning unbounded
///   on that side, so a bounded consumer never accepts an unbounded producer).
/// * **boolean/null** — exact `type` match; neither carries a value constraint.
///
/// # Every author-writable constraint is compared
///
/// `minimum` / `maximum` / `minLength` / `maxLength` / `pattern` are not
/// decoration: `contract_schema` emits them from `number(min=,max=)` /
/// `integer(min=,max=)` / `string(pattern=,min_length=,max_length=)`, and the
/// structured-output validator ENFORCES them against a stage's emitted value. A
/// consumer that declares one is therefore promising its stage something, and a
/// subtype check that dropped it would hand `check_contracts` a producer whose
/// every legal output the consumer's own contract forbids — e.g. a producer
/// `integer(min=-1000,max=1000)` against a consumer `integer(min=1,max=5)`, or
/// a producer `string(max_length=5)` against a consumer `string(min_length=10)`.
/// Both are rejected.
///
/// The advisory `description` annotation (codegen attaches it from a field's doc
/// string; the validator ignores it for value validation) is IGNORED here — doc
/// drift between a `produces=` and a `consumes=` must not break a valid pair.
///
/// # Conservative fallback
///
/// Any node whose `type` token is unrecognized (outside the DSL subset — e.g. a
/// hand-authored schema with `$ref`/`allOf`), or a structurally-degenerate node
/// (an `object` with no `properties` map, a malformed `variant`), falls back to
/// exact `serde_json::Value` equality. Exact equality NEVER false-accepts, so an
/// unknown shape can only ever be MORE strict than subtyping — never a type hole.
pub(crate) fn is_subtype(produced: &Value, consumed: &Value) -> bool {
    let (Some(produced_ty), Some(consumed_ty)) = (schema_type(produced), schema_type(consumed))
    else {
        // A node without a recognizable string `type` is outside the DSL subset.
        // Exact equality is the soundness-safe floor (never a false-accept).
        return produced == consumed;
    };
    match consumed_ty {
        "object" => produced_ty == "object" && is_subtype_object(produced, consumed),
        "array" => produced_ty == "array" && is_subtype_array(produced, consumed),
        "string" => produced_ty == "string" && is_subtype_string(produced, consumed),
        "variant" => produced_ty == "variant" && is_subtype_variant(produced, consumed),
        // `integer ⊆ number`: an integer producer satisfies a number consumer.
        "number" => {
            matches!(produced_ty, "number" | "integer") && is_subtype_numeric(produced, consumed)
        }
        "integer" => produced_ty == "integer" && is_subtype_numeric(produced, consumed),
        "boolean" => produced_ty == "boolean",
        "null" => produced_ty == "null",
        // Unrecognized consumer `type` token — conservative exact equality.
        _ => produced == consumed,
    }
}

/// Object (record) subtyping: required-presence + per-field depth, ignoring
/// extra producer fields (width). See [`is_subtype`] for the soundness argument.
fn is_subtype_object(produced: &Value, consumed: &Value) -> bool {
    let Some(consumed_props) = consumed.get("properties").and_then(Value::as_object) else {
        // A `{"type":"object"}` carrying no `properties` map is degenerate (the
        // DSL always emits one, possibly empty). Conservative exact equality.
        return produced == consumed;
    };
    // Robustness: a present-but-non-array `required` is malformed (the DSL never
    // emits one). `required_set` would silently treat it as "no required fields" —
    // failing OPEN (the unsound direction: consumer-required fields look optional).
    // Fall back to conservative exact equality, mirroring the degenerate-object
    // guard above. Unreachable for codegen schemas; defends hand-authored JSON.
    if has_malformed_required(consumed) || has_malformed_required(produced) {
        return produced == consumed;
    }
    let consumed_required = required_set(consumed);
    let produced_props = produced.get("properties").and_then(Value::as_object);
    let produced_required = required_set(produced);
    for (field_name, consumed_field) in consumed_props {
        match produced_props.and_then(|m| m.get(field_name)) {
            Some(produced_field) => {
                // DEPTH: the producer's field type must be a subtype of what the
                // consumer expects to read for this field.
                if !is_subtype(produced_field, consumed_field) {
                    return false;
                }
                // PRESENCE: a consumer-REQUIRED field must be GUARANTEED by the
                // producer (produced-required), not merely declared-optional — an
                // optional producer field may be absent at runtime.
                if consumed_required.contains(field_name.as_str())
                    && !produced_required.contains(field_name.as_str())
                {
                    return false;
                }
            }
            None => {
                // The producer lacks this field entirely. Fine if the consumer
                // treats it as OPTIONAL; UNSOUND if the consumer REQUIRES it.
                if consumed_required.contains(field_name.as_str()) {
                    return false;
                }
            }
        }
    }
    // WIDTH: producer fields the consumer never names are ignored (sound — the
    // consumes contract is not a runtime closed validator).
    true
}

/// Array subtyping: depth on `items` + producer length range ⊆ consumer range.
fn is_subtype_array(produced: &Value, consumed: &Value) -> bool {
    match (produced.get("items"), consumed.get("items")) {
        (Some(produced_items), Some(consumed_items)) => {
            if !is_subtype(produced_items, consumed_items) {
                return false;
            }
        }
        // The DSL always emits `items`. A node missing it on exactly one side is
        // degenerate; require both absent (exact) rather than guess.
        (None, None) => {}
        _ => return false,
    }
    // produced.minItems ≥ consumed.minItems (absent = 0).
    let produced_min = uint_field(produced, "minItems").unwrap_or(0);
    let consumed_min = uint_field(consumed, "minItems").unwrap_or(0);
    if produced_min < consumed_min {
        return false;
    }
    // produced.maxItems ≤ consumed.maxItems (absent = ∞).
    match (
        uint_field(produced, "maxItems"),
        uint_field(consumed, "maxItems"),
    ) {
        (_, None) => true,        // consumer unbounded
        (None, Some(_)) => false, // producer unbounded, consumer bounded
        (Some(produced_max), Some(consumed_max)) => produced_max <= consumed_max,
    }
}

/// Numeric (`number` / `integer`) subtyping: the producer's admissible VALUE
/// RANGE must be contained in the consumer's.
///
/// `minimum` / `maximum` are the inclusive JSON-Schema bounds `contract_schema`
/// emits for `number(min=..,max=..)` / `integer(min=..,max=..)`, and the
/// structured-output validator ENFORCES them on the producer's emitted value —
/// so they are part of what a `consumes=` contract promises its stage, not
/// decoration.
///
/// An absent bound means unbounded on that side, so:
/// * consumer unbounded → any producer bound is fine;
/// * consumer bounded, producer unbounded → REJECT (the producer may emit a
///   value outside the consumer's declared range);
/// * both bounded → `produced_min >= consumed_min`, `produced_max <=
///   consumed_max`.
///
/// A bound that is present but not representable as `f64` (impossible for
/// `contract_schema` output; reachable in hand-authored JSON) falls back to
/// exact node equality, which never false-accepts.
fn is_subtype_numeric(produced: &Value, consumed: &Value) -> bool {
    let (Ok(produced_min), Ok(consumed_min), Ok(produced_max), Ok(consumed_max)) = (
        float_bound(produced, "minimum"),
        float_bound(consumed, "minimum"),
        float_bound(produced, "maximum"),
        float_bound(consumed, "maximum"),
    ) else {
        // An uncomparable bound on either side — conservative exact equality.
        return produced == consumed;
    };
    // `minimum`: the producer's floor must be at least as high as the consumer's.
    // An absent producer floor is unbounded below, which never satisfies one.
    if let Some(consumed_min) = consumed_min
        && produced_min.is_none_or(|produced_min| produced_min < consumed_min)
    {
        return false;
    }
    // `maximum`: the producer's ceiling must be no higher than the consumer's.
    if let Some(consumed_max) = consumed_max
        && produced_max.is_none_or(|produced_max| produced_max > consumed_max)
    {
        return false;
    }
    true
}

/// A numeric bound as `f64`: `Ok(None)` when the key is absent, `Err(())` when
/// it is present but not a comparable number (caller falls back to exact
/// equality).
fn float_bound(node: &Value, key: &str) -> Result<Option<f64>, ()> {
    match node.get(key) {
        None => Ok(None),
        Some(value) => value.as_f64().map(Some).ok_or(()),
    }
}

/// String subtyping: enum value-set refinement + length-range and `pattern`
/// subset.
fn is_subtype_string(produced: &Value, consumed: &Value) -> bool {
    // `pattern` is enforced by the structured-output validator, so a consumer
    // that declares one is promising its stage a value matching it. Regex
    // language inclusion is not decidable in general, so the sound floor is
    // exact pattern equality: a consumer pattern is satisfied ONLY by a producer
    // declaring the identical pattern. A consumer without a pattern accepts any.
    match (
        consumed.get("pattern").and_then(Value::as_str),
        produced.get("pattern").and_then(Value::as_str),
    ) {
        (None, _) => {}
        (Some(consumed_pattern), Some(produced_pattern))
            if consumed_pattern == produced_pattern => {}
        (Some(_), _) => return false,
    }
    if !is_subtype_string_length(produced, consumed) {
        return false;
    }
    if let Some(consumed_enum) = consumed.get("enum").and_then(Value::as_array) {
        // The consumer accepts ONLY its enumerated values.
        let Some(produced_enum) = produced.get("enum").and_then(Value::as_array) else {
            // Unconstrained string producer vs an enum consumer: the producer can
            // emit a value the consumer does not accept → UNSOUND.
            return false;
        };
        // produced value set ⊆ consumed value set (by exact JSON equality).
        return produced_enum
            .iter()
            .all(|produced_value| consumed_enum.contains(produced_value));
    }
    // Plain-string consumer: any string producer (enum or plain) satisfies the
    // value set, and the length range was already checked above.
    true
}

/// String LENGTH-range subtyping: the producer's admissible length interval must
/// be contained in the consumer's.
///
/// Both `minLength` and `maxLength` are validator-enforced, so both are part of
/// what a `consumes=` contract promises. `minLength` absent means `0` — a real
/// floor, not "unbounded" — so a producer that omits it is unbounded BELOW the
/// consumer's floor exactly when the consumer declares one above zero. This is
/// the string analogue of the array `minItems`/`maxItems` pair in
/// [`is_subtype_array`].
fn is_subtype_string_length(produced: &Value, consumed: &Value) -> bool {
    // produced.minLength >= consumed.minLength (absent = 0).
    if uint_field(produced, "minLength").unwrap_or(0)
        < uint_field(consumed, "minLength").unwrap_or(0)
    {
        return false;
    }
    // produced.maxLength <= consumed.maxLength (absent = ∞).
    match (
        uint_field(produced, "maxLength"),
        uint_field(consumed, "maxLength"),
    ) {
        (_, None) => true,        // consumer unbounded
        (None, Some(_)) => false, // producer unbounded, consumer bounded
        (Some(produced_max), Some(consumed_max)) => produced_max <= consumed_max,
    }
}

/// Variant (tagged-union) subtyping: producer tag set ⊆ consumer tag set, depth
/// per shared tag. See [`is_subtype`] for the tag-direction soundness argument.
fn is_subtype_variant(produced: &Value, consumed: &Value) -> bool {
    let (Some(produced_variants), Some(consumed_variants)) = (
        produced.get("variants").and_then(Value::as_object),
        consumed.get("variants").and_then(Value::as_object),
    ) else {
        // Malformed variant node (no `variants` map) — conservative exact equality.
        return produced == consumed;
    };
    for (tag, produced_arm) in produced_variants {
        match consumed_variants.get(tag) {
            // DEPTH per shared tag.
            Some(consumed_arm) => {
                if !is_subtype(produced_arm, consumed_arm) {
                    return false;
                }
            }
            // The producer can emit a tag the consumer does not handle → UNSOUND.
            None => return false,
        }
    }
    // Consumer tags the producer never emits are unused capacity — fine.
    true
}

/// The `type` discriminator of a contract schema node, if it is a JSON string.
fn schema_type(node: &Value) -> Option<&str> {
    node.get("type").and_then(Value::as_str)
}

/// The set of `required` field names declared on an object node (empty when the
/// node has no `required` array).
fn required_set(node: &Value) -> std::collections::BTreeSet<&str> {
    node.get("required")
        .and_then(Value::as_array)
        .map(|array| array.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// True when `node` carries a `required` key that is present but NOT an array —
/// a malformed object schema. `required_set` would silently read it as empty
/// (failing open), so callers fall back to exact equality instead.
fn has_malformed_required(node: &Value) -> bool {
    matches!(node.get("required"), Some(value) if !value.is_array())
}

/// Read an unsigned-integer bound (e.g. `maxItems`, `maxLength`) from a node.
fn uint_field(node: &Value, key: &str) -> Option<u64> {
    node.get(key).and_then(Value::as_u64)
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod subtype_tests;
