//! Tests for `crates/types/src/strict_output_schema.rs`.
//!
//! The strict schema is judged by [`strict_accepts`], a JSON Schema evaluator
//! written HERE from the JSON Schema specification's semantics for exactly the
//! keywords strict mode admits. It shares no code with the renderer or with
//! kata's validator, and it PANICS on any keyword it does not implement, so a
//! rendered keyword can never be silently ignored by the oracle. kata's own
//! verdict comes from `validate_agent_run_output_content`, the function the
//! runner calls.

use kata_types::agent_run::validate_agent_run_output_content;
use kata_types::strict_output_schema::{NotStrict, strict_output_schema};
use serde_json::{Map, Value, json};

/// The keywords strict mode admits that a rendering may carry. A node with any
/// other key fails [`assert_strict_shape`] and panics [`strict_accepts`].
const STRICT_KEYWORDS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "enum",
    "minimum",
    "maximum",
    "anyOf",
    "description",
];

/// JSON Schema semantics (draft 2020-12) for the [`STRICT_KEYWORDS`]. `integer`
/// is "a number with a zero fractional part", as the specification defines it.
fn strict_accepts(schema: &Value, value: &Value) -> bool {
    let node = schema.as_object().expect("a schema node is an object");
    for key in node.keys() {
        assert!(
            STRICT_KEYWORDS.contains(&key.as_str()),
            "the oracle does not implement keyword {key:?}"
        );
    }
    if let Some(branches) = node.get("anyOf") {
        let branches = branches.as_array().expect("anyOf is an array");
        if !branches.iter().any(|branch| strict_accepts(branch, value)) {
            return false;
        }
    }
    if let Some(ty) = node.get("type") {
        let ok = match ty.as_str().expect("type is one string") {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "number" => value.is_number(),
            "integer" => value.as_f64().is_some_and(|n| n.fract() == 0.0),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            other => panic!("unknown type {other}"),
        };
        if !ok {
            return false;
        }
    }
    if let Some(variants) = node.get("enum")
        && !variants.as_array().unwrap().contains(value)
    {
        return false;
    }
    if let Some(n) = value.as_f64() {
        if node
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|m| n < m)
        {
            return false;
        }
        if node
            .get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|m| n > m)
        {
            return false;
        }
    }
    if let Some(array) = value.as_array() {
        let len = array.len() as u64;
        if node
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| len < m)
        {
            return false;
        }
        if node
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| len > m)
        {
            return false;
        }
        if let Some(items) = node.get("items")
            && !array.iter().all(|item| strict_accepts(items, item))
        {
            return false;
        }
    }
    if let Some(object) = value.as_object() {
        let properties = node.get("properties").and_then(Value::as_object);
        if let Some(required) = node.get("required").and_then(Value::as_array)
            && !required
                .iter()
                .all(|name| object.contains_key(name.as_str().unwrap()))
        {
            return false;
        }
        for (name, child) in object {
            match properties.and_then(|p| p.get(name)) {
                Some(child_schema) => {
                    if !strict_accepts(child_schema, child) {
                        return false;
                    }
                }
                None => {
                    if node.get("additionalProperties") == Some(&Value::Bool(false)) {
                        return false;
                    }
                }
            }
        }
    }
    true
}

/// Strict mode's structural rules: only [`STRICT_KEYWORDS`]; every object
/// lists EVERY property in `required` and carries `additionalProperties:
/// false`; the root is an object, not an `anyOf`.
fn assert_strict_shape(schema: &Value) {
    assert_eq!(schema["type"], "object", "the root is an object: {schema}");
    fn walk(node: &Value) {
        let map = node.as_object().expect("node is an object");
        for key in map.keys() {
            assert!(
                STRICT_KEYWORDS.contains(&key.as_str()),
                "keyword {key:?} is not strict: {node}"
            );
        }
        if map.get("type") == Some(&json!("object")) {
            assert_eq!(
                map.get("additionalProperties"),
                Some(&json!(false)),
                "{node}"
            );
            let properties = map["properties"].as_object().expect("properties");
            let mut required: Vec<&str> = map["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            required.sort_unstable();
            let mut names: Vec<&str> = properties.keys().map(String::as_str).collect();
            names.sort_unstable();
            assert_eq!(required, names, "every property is required: {node}");
            properties.values().for_each(walk);
        }
        if let Some(items) = map.get("items") {
            walk(items);
        }
        if let Some(branches) = map.get("anyOf") {
            branches.as_array().unwrap().iter().for_each(walk);
        }
    }
    walk(schema);
}

/// The `review` pack's contract, as `contract(..)` lowers it: required
/// fields, a bounded list of nested objects, enums, an integer range, length
/// bounds and a doc string.
fn review_contract() -> Value {
    json!({
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["approve", "request_changes", "comment"]},
            "summary": {"type": "string", "maxLength": 4000},
            "findings": {"type": "array", "maxItems": 128, "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "maxLength": 4096},
                    "line": {"type": "integer", "minimum": 0,
                             "description": "1-based line in the target head; 0 = whole file"},
                    "severity": {"type": "string", "enum": ["blocker", "major", "minor", "nit"]},
                    "message": {"type": "string", "maxLength": 2000},
                },
                "required": ["path", "line", "severity", "message"],
                "additionalProperties": false,
            }},
        },
        "required": ["verdict", "summary", "findings"],
        "additionalProperties": false,
    })
}

/// A contract exercising every other node kind: optional properties (a leaf,
/// an object, a list), a variant, a pattern, a min length, numbers, booleans,
/// nulls and a title.
fn mixed_contract() -> Value {
    json!({
        "type": "object",
        "title": "Mixed",
        "properties": {
            "id": {"type": "string", "pattern": "^[a-z]+$", "minLength": 2},
            "score": {"type": "number", "minimum": -1.5, "maximum": 1.5},
            "ok": {"type": "boolean"},
            "nothing": {"type": "null"},
            "maybe_nothing": {"type": "null"},
            "note": {"type": "string", "description": "free text"},
            "tags": {"type": "array", "minItems": 1, "maxItems": 3, "items": {"type": "string"}},
            "where": {"type": "object", "properties": {
                "file": {"type": "string"}, "line": {"type": "integer"}
            }, "required": ["file"]},
            "pick": {"type": "variant", "variants": {
                "fix": {"type": "object", "properties": {"patch": {"type": "string"}},
                        "required": ["patch"]},
                "skip": {"type": "null"},
            }},
        },
        "required": ["id", "score", "ok", "nothing", "pick"],
    })
}

/// The strict rendering of [`review_contract`], written out by hand from the
/// mapping table in the module doc — the expected bytes, not the renderer's.
#[test]
fn the_review_contract_renders_to_the_expected_strict_schema() {
    let expected = json!({
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["approve", "request_changes", "comment"]},
            "summary": {"type": "string", "description": "kata enforces: maxLength 4000"},
            "findings": {"type": "array", "maxItems": 128, "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "kata enforces: maxLength 4096"},
                    "line": {"type": "integer", "minimum": 0,
                             "description": "1-based line in the target head; 0 = whole file"},
                    "severity": {"type": "string", "enum": ["blocker", "major", "minor", "nit"]},
                    "message": {"type": "string", "description": "kata enforces: maxLength 2000"},
                },
                "required": ["line", "message", "path", "severity"],
                "additionalProperties": false,
            }},
        },
        "required": ["findings", "summary", "verdict"],
        "additionalProperties": false,
    });
    let rendered = strict_output_schema(&review_contract()).expect("the review contract is strict");
    assert_eq!(rendered, expected);
    assert_strict_shape(&rendered);
}

/// Optional properties become required-and-nullable, a variant becomes an
/// `anyOf` of closed single-key objects, `title` is dropped and the relaxed
/// string bounds are restated in the description.
#[test]
fn the_mixed_contract_renders_optional_as_nullable_and_variant_as_any_of() {
    let rendered = strict_output_schema(&mixed_contract()).expect("the mixed contract is strict");
    assert_strict_shape(&rendered);
    let properties = &rendered["properties"];
    assert_eq!(rendered.get("title"), None, "title is dropped");
    assert_eq!(
        properties["id"],
        json!({"type": "string", "description": "kata enforces: minLength 2, pattern \"^[a-z]+$\""})
    );
    assert_eq!(
        properties["note"],
        json!({"anyOf": [{"type": "string", "description": "free text"}, {"type": "null"}]})
    );
    assert_eq!(
        properties["maybe_nothing"],
        json!({"type": "null"}),
        "an optional null-typed property is already nullable"
    );
    assert_eq!(
        properties["where"],
        json!({"anyOf": [{
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "line": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
            },
            "required": ["file", "line"],
            "additionalProperties": false,
        }, {"type": "null"}]})
    );
    assert_eq!(
        properties["pick"],
        json!({"anyOf": [
            {"type": "object", "properties": {"fix": {
                "type": "object", "properties": {"patch": {"type": "string"}},
                "required": ["patch"], "additionalProperties": false,
            }}, "required": ["fix"], "additionalProperties": false},
            {"type": "object", "properties": {"skip": {"type": "null"}},
             "required": ["skip"], "additionalProperties": false},
        ]})
    );
}

/// The verdict of each side on one document.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Verdict {
    /// Both accept.
    Both,
    /// Both refuse.
    Neither,
    /// Only kata accepts: an omitted optional property (strict mode requires
    /// every property).
    KataOnly,
    /// Only the strict schema accepts: a relaxed bound (`minLength`,
    /// `maxLength`, `pattern`) or JSON Schema's `integer` admitting `2.0`.
    StrictOnly,
}

fn verdict_of(contract: &Value, document: &Value) -> Verdict {
    let strict = strict_output_schema(contract).expect("corpus contracts are strict");
    let kata = validate_agent_run_output_content(&document.to_string(), contract).is_ok();
    match (kata, strict_accepts(&strict, document)) {
        (true, true) => Verdict::Both,
        (false, false) => Verdict::Neither,
        (true, false) => Verdict::KataOnly,
        (false, true) => Verdict::StrictOnly,
    }
}

/// The corpus: the two sides agree on every document except the stated
/// differences, and each stated difference goes the stated way.
#[test]
fn the_strict_schema_accepts_what_the_contract_accepts_except_the_stated_differences() {
    let finding = json!({"path": "a.rs", "line": 3, "severity": "major", "message": "m"});
    let review = review_contract();
    let review_rows: Vec<(&str, Value, Verdict)> = vec![
        (
            "minimal",
            json!({"verdict": "approve", "summary": "", "findings": []}),
            Verdict::Both,
        ),
        (
            "one finding",
            json!({"verdict": "comment", "summary": "s", "findings": [finding]}),
            Verdict::Both,
        ),
        (
            "line 0",
            json!({"verdict": "comment", "summary": "s", "findings": [
            {"path": "a", "line": 0, "severity": "nit", "message": "m"}]}),
            Verdict::Both,
        ),
        (
            "bad enum",
            json!({"verdict": "lgtm", "summary": "s", "findings": []}),
            Verdict::Neither,
        ),
        (
            "missing required",
            json!({"verdict": "approve", "findings": []}),
            Verdict::Neither,
        ),
        (
            "extra property",
            json!({"verdict": "approve", "summary": "s", "findings": [], "x": 1}),
            Verdict::Neither,
        ),
        (
            "nested extra",
            json!({"verdict": "approve", "summary": "s", "findings": [
            {"path": "a", "line": 1, "severity": "nit", "message": "m", "fix": "y"}]}),
            Verdict::Neither,
        ),
        (
            "negative line",
            json!({"verdict": "approve", "summary": "s", "findings": [
            {"path": "a", "line": -1, "severity": "nit", "message": "m"}]}),
            Verdict::Neither,
        ),
        (
            "fractional line",
            json!({"verdict": "approve", "summary": "s", "findings": [
            {"path": "a", "line": 1.5, "severity": "nit", "message": "m"}]}),
            Verdict::Neither,
        ),
        (
            "string line",
            json!({"verdict": "approve", "summary": "s", "findings": [
            {"path": "a", "line": "1", "severity": "nit", "message": "m"}]}),
            Verdict::Neither,
        ),
        (
            "too many findings",
            json!({"verdict": "approve", "summary": "s",
            "findings": vec![finding.clone(); 129]}),
            Verdict::Neither,
        ),
        (
            "128 findings",
            json!({"verdict": "approve", "summary": "s",
            "findings": vec![finding.clone(); 128]}),
            Verdict::Both,
        ),
        (
            "null required",
            json!({"verdict": "approve", "summary": null, "findings": []}),
            Verdict::Neither,
        ),
        ("not an object", json!(["approve"]), Verdict::Neither),
        // Stated: a relaxed bound.
        (
            "summary past maxLength",
            json!({"verdict": "approve", "summary": "x".repeat(4001),
            "findings": []}),
            Verdict::StrictOnly,
        ),
        (
            "summary at maxLength",
            json!({"verdict": "approve", "summary": "x".repeat(4000),
            "findings": []}),
            Verdict::Both,
        ),
        // Stated: JSON Schema's integer admits a zero fraction; kata's does not.
        (
            "line 3.0",
            json!({"verdict": "approve", "summary": "s", "findings": [
            {"path": "a", "line": 3.0, "severity": "nit", "message": "m"}]}),
            Verdict::StrictOnly,
        ),
    ];
    let mixed = mixed_contract();
    let base = json!({"id": "ab", "score": 0.5, "ok": true, "nothing": null, "maybe_nothing": null,
        "note": "n", "tags": ["t"], "where": {"file": "f", "line": 1}, "pick": {"skip": null}});
    let with = |key: &str, value: Value| {
        let mut document = base.clone();
        document[key] = value;
        document
    };
    let without = |key: &str| {
        let mut document = base.clone();
        document.as_object_mut().unwrap().remove(key);
        document
    };
    let mixed_rows: Vec<(&str, Value, Verdict)> = vec![
        ("full", base.clone(), Verdict::Both),
        (
            "optional note null",
            with("note", Value::Null),
            Verdict::Both,
        ),
        (
            "optional where null",
            with("where", Value::Null),
            Verdict::Both,
        ),
        (
            "nested optional null",
            with("where", json!({"file": "f", "line": null})),
            Verdict::Both,
        ),
        (
            "variant fix",
            with("pick", json!({"fix": {"patch": "p"}})),
            Verdict::Both,
        ),
        (
            "variant two tags",
            with("pick", json!({"fix": {"patch": "p"}, "skip": null})),
            Verdict::Neither,
        ),
        (
            "variant unknown tag",
            with("pick", json!({"redo": null})),
            Verdict::Neither,
        ),
        (
            "variant bad payload",
            with("pick", json!({"fix": {"patch": 1}})),
            Verdict::Neither,
        ),
        (
            "score below minimum",
            with("score", json!(-2)),
            Verdict::Neither,
        ),
        ("score at maximum", with("score", json!(1.5)), Verdict::Both),
        ("tags empty", with("tags", json!([])), Verdict::Neither),
        (
            "tags too many",
            with("tags", json!(["a", "b", "c", "d"])),
            Verdict::Neither,
        ),
        (
            "nothing not null",
            with("nothing", json!(0)),
            Verdict::Neither,
        ),
        (
            "required null-typed missing",
            without("nothing"),
            Verdict::Neither,
        ),
        (
            "optional note wrong type",
            with("note", json!(1)),
            Verdict::Neither,
        ),
        ("ok as string", with("ok", json!("true")), Verdict::Neither),
        // Stated: an omitted optional property.
        ("optional note omitted", without("note"), Verdict::KataOnly),
        (
            "optional where omitted",
            without("where"),
            Verdict::KataOnly,
        ),
        (
            "nested optional omitted",
            with("where", json!({"file": "f"})),
            Verdict::KataOnly,
        ),
        (
            "optional null-typed omitted",
            without("maybe_nothing"),
            Verdict::KataOnly,
        ),
        // Stated: a relaxed pattern and minLength.
        (
            "id breaks pattern",
            with("id", json!("AB")),
            Verdict::StrictOnly,
        ),
        (
            "id under minLength",
            with("id", json!("a")),
            Verdict::StrictOnly,
        ),
    ];
    let mut wrong = Vec::new();
    for (contract, rows) in [(&review, review_rows), (&mixed, mixed_rows)] {
        for (name, document, expected) in rows {
            let actual = verdict_of(contract, &document);
            if actual != expected {
                wrong.push(format!("{name}: expected {expected:?}, got {actual:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The closed empty object — an empty `contract(..)` as it lowers — at the
/// root and as the arms of the typed-routing idiom `variant({"ship":
/// contract("Ship", {}), "hold": contract("Hold", {})})`: rendered, written
/// out by hand, and agreeing with kata on every document of its corpus.
#[test]
fn an_empty_contract_renders_as_the_closed_empty_object() {
    let empty = || json!({"type": "object", "properties": {}, "required": [], "additionalProperties": false});
    let closed_empty =
        json!({"type": "object", "properties": {}, "required": [], "additionalProperties": false});
    assert_eq!(strict_output_schema(&empty()), Ok(closed_empty.clone()));
    assert_eq!(verdict_of(&empty(), &json!({})), Verdict::Both);
    assert_eq!(verdict_of(&empty(), &json!({"x": 1})), Verdict::Neither);

    let routing = json!({
        "type": "object",
        "properties": {"verdict": {"type": "variant", "variants": {"ship": empty(), "hold": empty()}}},
        "required": ["verdict"],
        "additionalProperties": false,
    });
    let branch = |tag: &str| {
        json!({"type": "object", "properties": {tag: closed_empty.clone()},
               "required": [tag], "additionalProperties": false})
    };
    let rendered = strict_output_schema(&routing).expect("the routing idiom is strict");
    assert_eq!(
        rendered,
        json!({
            "type": "object",
            "properties": {"verdict": {"anyOf": [branch("hold"), branch("ship")]}},
            "required": ["verdict"],
            "additionalProperties": false,
        })
    );
    assert_strict_shape(&rendered);
    for (document, expected) in [
        (json!({"verdict": {"ship": {}}}), Verdict::Both),
        (json!({"verdict": {"hold": {}}}), Verdict::Both),
        (json!({"verdict": {"ship": {"x": 1}}}), Verdict::Neither),
        (json!({"verdict": {}}), Verdict::Neither),
        (
            json!({"verdict": {"ship": {}, "hold": {}}}),
            Verdict::Neither,
        ),
        (json!({"verdict": {"other": {}}}), Verdict::Neither),
    ] {
        assert_eq!(verdict_of(&routing, &document), expected, "{document}");
    }
}

/// An object node with no `properties` key is closed in kata exactly like
/// `properties: {}` — only `{}` passes — so it renders as the same closed
/// empty object, at the root and nested.
#[test]
fn an_object_with_no_properties_key_renders_as_the_closed_empty_object() {
    let bare = json!({"type": "object"});
    let closed_empty =
        json!({"type": "object", "properties": {}, "required": [], "additionalProperties": false});
    assert_eq!(strict_output_schema(&bare), Ok(closed_empty.clone()));
    assert_eq!(verdict_of(&bare, &json!({})), Verdict::Both);
    assert_eq!(verdict_of(&bare, &json!({"x": 1})), Verdict::Neither);
    let nested = json!({"type": "object", "properties": {"inner": {"type": "object"}}, "required": ["inner"]});
    assert_eq!(
        strict_output_schema(&nested).expect("strict")["properties"]["inner"],
        closed_empty
    );
}

/// ORDER — the sent bytes name properties in NAME order whatever order the
/// contract's text gave them; the declaration order does not reach the
/// strict schema (the module doc's fourth stated difference).
#[test]
fn the_strict_schema_names_properties_in_name_order() {
    let contract: Value = serde_json::from_str(
        r#"{"type": "object", "properties": {"zeta": {"type": "string"}, "alpha": {"type": "string"}},
            "required": ["zeta", "alpha"], "additionalProperties": false}"#,
    )
    .expect("the contract parses");
    let bytes = serde_json::to_string(&strict_output_schema(&contract).expect("strict"))
        .expect("the schema encodes");
    let at = |name: &str| {
        bytes
            .find(&format!("\"{name}\":"))
            .expect("the property is named")
    };
    assert!(at("alpha") < at("zeta"), "{bytes}");
    assert!(bytes.contains(r#""required":["alpha","zeta"]"#), "{bytes}");
}

fn object_of(properties: Map<String, Value>) -> Value {
    let required: Vec<Value> = properties.keys().cloned().map(Value::String).collect();
    json!({"type": "object", "properties": properties, "required": required})
}

/// `TooManyProperties` — 32 × 32 × 32 leaves under kata's per-object bound
/// are 33 824 properties in total.
#[test]
fn more_properties_than_strict_mode_allows_is_not_strict() {
    let level = |child: &Value| -> Value {
        object_of(
            (0..32)
                .map(|i| (format!("p{i:02}"), child.clone()))
                .collect(),
        )
    };
    let contract = level(&level(&level(&json!({"type": "boolean"}))));
    let count = 32 + 32 * 32 + 32 * 32 * 32;
    assert!(count > 5000);
    assert_eq!(
        strict_output_schema(&contract),
        Err(NotStrict::TooManyProperties { count })
    );
}

/// `TooManyEnumValues` — 32 enums of 64 values each.
#[test]
fn more_enum_values_than_strict_mode_allows_is_not_strict() {
    let values: Vec<String> = (0..64).map(|i| format!("v{i}")).collect();
    let contract = object_of(
        (0..32)
            .map(|i| (format!("e{i}"), json!({"type": "string", "enum": values})))
            .collect(),
    );
    let count = 32 * 64;
    assert!(count > 1000);
    assert_eq!(
        strict_output_schema(&contract),
        Err(NotStrict::TooManyEnumValues { count })
    );
}

/// `TooManyNameChars` — 32 + 32 × 32 property names of 120 characters.
#[test]
fn more_name_characters_than_strict_mode_allows_is_not_strict() {
    let name = |i: usize| format!("{i:04}{}", "n".repeat(116));
    let inner = object_of(
        (0..32)
            .map(|i| (name(i), json!({"type": "integer"})))
            .collect(),
    );
    let contract = object_of((0..32).map(|i| (name(i), inner.clone())).collect());
    let count = (32 + 32 * 32) * 120;
    assert!(count > 120_000);
    assert_eq!(
        strict_output_schema(&contract),
        Err(NotStrict::TooManyNameChars { count })
    );
}

/// What strict mode counts against its totals, read off a RENDERED schema —
/// the value that is sent — by walking every node, `anyOf` branches and array
/// `items` included: every key of every `properties` map (a variant's
/// single-key wrapper included) is a property and its name's characters, and
/// every `enum` value is an enum value and its characters. It shares no code
/// with the renderer's own tally.
#[derive(Debug, Default, PartialEq, Eq)]
struct Sent {
    properties: usize,
    enum_values: usize,
    name_chars: usize,
}

fn sent(rendered: &Value) -> Sent {
    fn walk(node: &Value, sent: &mut Sent) {
        if let Some(properties) = node.get("properties").and_then(Value::as_object) {
            for (name, child) in properties {
                sent.properties += 1;
                sent.name_chars += name.chars().count();
                walk(child, sent);
            }
        }
        if let Some(values) = node.get("enum").and_then(Value::as_array) {
            for value in values {
                sent.enum_values += 1;
                sent.name_chars += value.as_str().expect("an enum value").chars().count();
            }
        }
        if let Some(items) = node.get("items") {
            walk(items, sent);
        }
        for branch in node
            .get("anyOf")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            walk(branch, sent);
        }
    }
    let mut total = Sent::default();
    walk(rendered, &mut total);
    total
}

/// A kata-admitted contract of EXACTLY `total` properties, counted as strict
/// mode counts them: 32 root objects × 32 mid objects (1 056 properties), one
/// variant of 64 tags (65 more: its property and one wrapper property per tag),
/// and boolean leaves for the rest, at most 32 per mid object.
fn contract_of_properties(total: usize) -> Value {
    let mut leaves = total - 32 - 32 * 32 - 65;
    let mids = |root: usize, leaves: &mut usize| -> Value {
        object_of(
            (0..32)
                .map(|mid| {
                    let mut properties: Map<String, Value> = Map::new();
                    if root == 0 && mid == 0 {
                        let arms: Map<String, Value> = (0..64)
                            .map(|tag| (format!("t{tag:02}"), json!({"type": "boolean"})))
                            .collect();
                        properties.insert("v".into(), json!({"type": "variant", "variants": arms}));
                    }
                    while properties.len() < 32 && *leaves > 0 {
                        properties.insert(
                            format!("l{:02}", properties.len()),
                            json!({"type": "boolean"}),
                        );
                        *leaves -= 1;
                    }
                    (format!("m{mid:02}"), object_of(properties))
                })
                .collect(),
        )
    };
    let contract = object_of(
        (0..32)
            .map(|root| (format!("r{root:02}"), mids(root, &mut leaves)))
            .collect(),
    );
    assert_eq!(leaves, 0, "the shape holds {total} properties");
    contract
}

/// `TooManyProperties` at its edge: exactly 5 000 properties — variant tags
/// included — render, and the rendered schema carries exactly 5 000; 5 001 are
/// refused with that count.
#[test]
fn exactly_five_thousand_properties_render_and_one_more_is_not_strict() {
    let at_bound = contract_of_properties(5000);
    let rendered = strict_output_schema(&at_bound).expect("5 000 properties are strict");
    assert_strict_shape(&rendered);
    assert_eq!(sent(&rendered).properties, 5000);
    assert_eq!(
        strict_output_schema(&contract_of_properties(5001)),
        Err(NotStrict::TooManyProperties { count: 5001 })
    );
}

/// A kata-admitted contract of EXACTLY `total` enum values: 64-value enums,
/// the last one short, each an OPTIONAL property (rendered as an `anyOf`).
fn contract_of_enum_values(total: usize) -> Value {
    let properties: Map<String, Value> = (0..total.div_ceil(64))
        .map(|i| {
            let values: Vec<String> = (i * 64..total.min((i + 1) * 64))
                .map(|v| format!("v{v}"))
                .collect();
            (
                format!("e{i:02}"),
                json!({"type": "string", "enum": values}),
            )
        })
        .collect();
    json!({"type": "object", "properties": properties})
}

/// `TooManyEnumValues` at its edge: exactly 1 000 render, and the rendered
/// schema carries exactly 1 000; 1 001 are refused with that count.
#[test]
fn exactly_one_thousand_enum_values_render_and_one_more_is_not_strict() {
    let rendered =
        strict_output_schema(&contract_of_enum_values(1000)).expect("1 000 enum values are strict");
    assert_strict_shape(&rendered);
    assert_eq!(sent(&rendered).enum_values, 1000);
    assert_eq!(
        strict_output_schema(&contract_of_enum_values(1001)),
        Err(NotStrict::TooManyEnumValues { count: 1001 })
    );
}

/// A kata-admitted contract whose property names, variant tags and enum values
/// sum to EXACTLY `total` characters: an enum of 64 values and a variant of 64
/// tags (100 characters each), then 128-character names (kata's per-name
/// bound) under 30 mid objects, the last one short.
fn contract_of_name_chars(total: usize) -> Value {
    let padded = |prefix: String, len: usize| format!("{prefix}{}", "n".repeat(len - prefix.len()));
    let values: Vec<String> = (0..64).map(|i| padded(format!("{i:02}"), 100)).collect();
    let arms: Map<String, Value> = (0..64)
        .map(|i| (padded(format!("{i:02}"), 100), json!({"type": "boolean"})))
        .collect();
    let mut root: Map<String, Value> = Map::new();
    root.insert("e".into(), json!({"type": "string", "enum": values}));
    root.insert("v".into(), json!({"type": "variant", "variants": arms}));
    let mut left = total - 2 - 64 * 100 - 64 * 100 - 30 * 128;
    for mid in 0..30 {
        let mut leaves: Map<String, Value> = Map::new();
        while leaves.len() < 32 && left > 0 {
            let len = left.min(128);
            leaves.insert(
                padded(format!("{:02}", leaves.len()), len.max(2)),
                json!({"type": "integer"}),
            );
            left -= len;
        }
        root.insert(padded(format!("m{mid:02}"), 128), object_of(leaves));
    }
    assert_eq!(left, 0, "the shape holds {total} characters");
    object_of(root)
}

/// `TooManyNameChars` at its edge: exactly 120 000 characters of property
/// names, variant tags and enum values render, and the rendered schema
/// carries exactly 120 000; 120 001 are refused with that count.
#[test]
fn exactly_one_hundred_twenty_thousand_name_characters_render_and_one_more_is_not_strict() {
    let rendered = strict_output_schema(&contract_of_name_chars(120_000))
        .expect("120 000 name characters are strict");
    assert_strict_shape(&rendered);
    assert_eq!(sent(&rendered).name_chars, 120_000);
    assert_eq!(
        strict_output_schema(&contract_of_name_chars(120_001)),
        Err(NotStrict::TooManyNameChars { count: 120_001 })
    );
}

/// `OutsideSubset` — a value kata's own validator refuses is refused, never
/// rendered by guess.
#[test]
fn a_schema_outside_the_kata_subset_is_not_strict() {
    for schema in [
        json!({"type": "string"}),
        json!({"type": "object", "properties": {"a": {"type": "date"}}}),
        json!({"type": "object", "properties": {"a": {"type": "string", "format": "uri"}}}),
    ] {
        assert!(
            matches!(
                strict_output_schema(&schema),
                Err(NotStrict::OutsideSubset { .. })
            ),
            "{schema}"
        );
    }
}

/// kata's depth bound keeps every contract inside strict mode's nesting
/// limit: the deepest contract kata admits — every level an optional variant
/// or an optional property — renders at nine levels, under the ten allowed.
#[test]
fn the_deepest_contract_kata_admits_renders_within_the_nesting_limit() {
    let leaf = json!({"type": "string"});
    let optional_variant = |payload: Value| {
        json!({"type": "object", "properties": {
            "v": {"type": "variant", "variants": {"t": payload}}
        }})
    };
    // root(0) -> optional variant(1) -> object payload(2) -> optional
    // variant(3) -> leaf payload(4): kata depth 4, the bound.
    let contract = optional_variant(optional_variant(leaf));
    let rendered = strict_output_schema(&contract).expect("the deepest contract is strict");
    fn levels(node: &Value) -> usize {
        let children: Vec<&Value> = node
            .get("properties")
            .and_then(Value::as_object)
            .map(|p| p.values().collect::<Vec<_>>())
            .into_iter()
            .flatten()
            .chain(node.get("items"))
            .chain(
                node.get("anyOf")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            )
            .collect();
        1 + children.into_iter().map(levels).max().unwrap_or(0)
    }
    assert_eq!(levels(&rendered), 9, "{rendered:#}");
    assert_strict_shape(&rendered);
    let deeper = optional_variant(optional_variant(optional_variant(
        json!({"type": "string"}),
    )));
    assert!(
        matches!(
            strict_output_schema(&deeper),
            Err(NotStrict::OutsideSubset { .. })
        ),
        "one level deeper is past kata's own depth bound"
    );
}
