//! Tests for the native Starlark contract DSL (`crates/program/src/dsl`).
//!
//! Each test evaluates a real `.star` snippet through
//! [`kata_contract_globals`], extracts the resulting [`Contract`]'s generated
//! schema, and asserts it (a) round-trips through the agent-run schema
//! validator and (b) accepts a representative value.

use kata_types::agent_run::{validate_agent_run_output_content, validate_agent_run_output_schema};
use serde_json::{Value as JsonValue, json};
use starlark::environment::{GlobalsBuilder, Module};
use starlark::eval::Evaluator;
use starlark::syntax::{AstModule, Dialect};

use super::{BoundValue, Contract, kata_contract_globals, kata_graph_globals};
use kata_types::bound::Bound;

/// Evaluate a `.star` snippet whose module result is a `Contract`, returning
/// the contract's generated JSON schema.
fn eval_contract_schema(source: &str) -> Result<JsonValue, String> {
    let ast = AstModule::parse("test.star", source.to_owned(), &Dialect::Standard)
        .map_err(|e| format!("parse error: {e}"))?;
    let globals = GlobalsBuilder::standard()
        .with(kata_contract_globals)
        .build();
    let module = Module::new();
    let mut eval = Evaluator::new(&module);
    let result = eval
        .eval_module(ast, &globals)
        .map_err(|e| format!("eval error: {e}"))?;
    let contract = Contract::from_value(result).ok_or_else(|| {
        format!(
            "module result was a {}, expected a contract",
            result.get_type()
        )
    })?;
    Ok(contract.schema.clone())
}

/// Evaluate a `.star` snippet and return the raw evaluation error message.
fn eval_contract_err(source: &str) -> String {
    match eval_contract_schema(source) {
        Ok(schema) => panic!("expected evaluation to fail, got schema {schema}"),
        Err(err) => err,
    }
}

/// A generated schema must satisfy the agent-run schema validator.
fn assert_schema_valid(schema: &JsonValue) {
    validate_agent_run_output_schema(schema).unwrap_or_else(|e| {
        panic!("generated schema rejected by validator: {e}\nschema: {schema}")
    });
}

/// A representative JSON value must validate against the generated schema.
fn assert_value_accepted(value: &JsonValue, schema: &JsonValue) {
    let content = serde_json::to_string(value).expect("serialize representative value");
    validate_agent_run_output_content(&content, schema).unwrap_or_else(|e| {
        panic!("representative value rejected: {e}\nvalue: {value}\nschema: {schema}")
    });
}

#[test]
fn contract_with_required_and_optional_fields() {
    let schema = eval_contract_schema(
        r#"
contract("X", {
    "a": field("string"),
    "n": field("integer", required = False),
})
"#,
    )
    .expect("evaluate contract");

    assert_eq!(
        schema,
        json!({
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "n": {"type": "integer"},
            },
            "required": ["a"],
            "additionalProperties": false,
        }),
        "field order preserved, only required field in `required`",
    );
    assert_schema_valid(&schema);
    assert_value_accepted(&json!({"a": "hello", "n": 7}), &schema);
    // The optional field may be omitted.
    assert_value_accepted(&json!({"a": "hello"}), &schema);
}

#[test]
fn enum_field_generates_string_enum() {
    let schema = eval_contract_schema(
        r#"
contract("Task", {
    "status": field(enum("draft", "review", "done")),
})
"#,
    )
    .expect("evaluate enum contract");

    assert_eq!(
        schema["properties"]["status"],
        json!({"type": "string", "enum": ["draft", "review", "done"]}),
    );
    assert_schema_valid(&schema);
    assert_value_accepted(&json!({"status": "review"}), &schema);
}

#[test]
fn list_of_field_generates_array() {
    let schema = eval_contract_schema(
        r#"
contract("Bag", {
    "tags": field(list_of("string")),
})
"#,
    )
    .expect("evaluate list contract");

    assert_eq!(
        schema["properties"]["tags"],
        json!({
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 128,
        }),
        "list_of defaults maxItems to the validator ceiling of 128",
    );
    assert_schema_valid(&schema);
    assert_value_accepted(&json!({"tags": ["a", "b", "c"]}), &schema);
}

#[test]
fn nested_contract_field_generates_object() {
    let schema = eval_contract_schema(
        r#"
contract("Outer", {
    "inner": field(contract("Inner", {
        "label": field("string"),
        "count": field("integer"),
    })),
})
"#,
    )
    .expect("evaluate nested contract");

    assert_eq!(
        schema["properties"]["inner"],
        json!({
            "type": "object",
            "properties": {
                "label": {"type": "string"},
                "count": {"type": "integer"},
            },
            "required": ["count", "label"],
            "additionalProperties": false,
        }),
    );
    assert_schema_valid(&schema);
    assert_value_accepted(&json!({"inner": {"label": "x", "count": 1}}), &schema);
}

#[test]
fn variant_field_generates_discriminated_union() {
    let schema = eval_contract_schema(
        r#"
contract("Action", {
    "op": field(variant({
        "text": contract("Text", {"body": field("string")}),
        "noop": contract("Noop", {}),
    })),
})
"#,
    )
    .expect("evaluate variant contract");

    assert_eq!(
        schema["properties"]["op"],
        json!({
            "type": "variant",
            "variants": {
                "text": {
                    "type": "object",
                    "properties": {"body": {"type": "string"}},
                    "required": ["body"],
                    "additionalProperties": false,
                },
                "noop": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": false,
                },
            },
        }),
    );
    assert_schema_valid(&schema);
    // Externally-tagged single-key variant value for the `text` arm.
    assert_value_accepted(&json!({"op": {"text": {"body": "hi"}}}), &schema);
    // Payload-less `noop` arm carries an empty object.
    assert_value_accepted(&json!({"op": {"noop": {}}}), &schema);
}

#[test]
fn bool_and_null_primitives_lower_correctly() {
    let schema = eval_contract_schema(
        r#"
contract("Flags", {
    "ok": field("bool"),
    "nothing": field("null"),
    "score": field("number"),
})
"#,
    )
    .expect("evaluate primitives contract");

    assert_eq!(schema["properties"]["ok"], json!({"type": "boolean"}));
    assert_eq!(schema["properties"]["nothing"], json!({"type": "null"}));
    assert_eq!(schema["properties"]["score"], json!({"type": "number"}));
    assert_schema_valid(&schema);
    assert_value_accepted(&json!({"ok": true, "nothing": null, "score": 1.5}), &schema);
}

#[test]
fn field_doc_becomes_description() {
    let schema = eval_contract_schema(
        r#"
contract("Doced", {
    "name": field("string", doc = "the entity name"),
})
"#,
    )
    .expect("evaluate documented contract");

    assert_eq!(
        schema["properties"]["name"],
        json!({"type": "string", "description": "the entity name"}),
    );
    assert_schema_valid(&schema);
    assert_value_accepted(&json!({"name": "x"}), &schema);
}

#[test]
fn too_deeply_nested_contract_is_rejected() {
    // Five levels of object nesting under the top-level object pushes a leaf
    // past the validator's depth ceiling, so construction must fail.
    let err = eval_contract_err(
        r#"
contract("L0", {
    "a": field(contract("L1", {
        "a": field(contract("L2", {
            "a": field(contract("L3", {
                "a": field(contract("L4", {
                    "a": field(contract("L5", {
                        "a": field("string"),
                    })),
                })),
            })),
        })),
    })),
})
"#,
    );
    assert!(
        err.contains("exceeds the maximum schema depth"),
        "expected depth-limit error, got: {err}",
    );
}

#[test]
fn unknown_primitive_is_rejected() {
    let err = eval_contract_err(
        r#"
contract("Bad", {"x": field("stringy")})
"#,
    );
    assert!(
        err.contains("unknown primitive type"),
        "expected unknown-primitive error, got: {err}",
    );
}

#[test]
fn non_field_dict_value_is_rejected() {
    let err = eval_contract_err(
        r#"
contract("Bad", {"x": "string"})
"#,
    );
    assert!(
        err.contains("must be a field(..) value"),
        "expected non-field error, got: {err}",
    );
}

#[test]
fn empty_enum_is_rejected() {
    let err = eval_contract_err(
        r#"
contract("Bad", {"x": field(enum())})
"#,
    );
    assert!(
        err.contains("at least one string variant"),
        "expected empty-enum error, got: {err}",
    );
}

#[test]
fn deepest_allowed_contract_validates() {
    // Four levels of object nesting under the top-level object keeps the
    // deepest leaf at the validator's maximum admissible depth.
    let schema = eval_contract_schema(
        r#"
contract("L0", {
    "a": field(contract("L1", {
        "a": field(contract("L2", {
            "a": field(contract("L3", {
                "a": field("string"),
            })),
        })),
    })),
})
"#,
    )
    .expect("evaluate max-depth contract");
    assert_schema_valid(&schema);
    assert_value_accepted(&json!({"a": {"a": {"a": {"a": "deep"}}}}), &schema);
}

// ── Bound enforcement at construction (mirrors the agent-run validator) ──────

#[test]
fn empty_field_name_is_rejected() {
    let err = eval_contract_err(r#"contract("X", {"": field("string")})"#);
    assert!(err.contains("must not be empty"), "got: {err}");
}

#[test]
fn too_many_fields_is_rejected() {
    let err =
        eval_contract_err(r#"contract("Wide", {str(i): field("string") for i in range(33)})"#);
    assert!(err.contains("exceeding the maximum of 32"), "got: {err}");
}

#[test]
fn enum_with_empty_variant_is_rejected() {
    let err = eval_contract_err(r#"contract("X", {"x": field(enum("a", ""))})"#);
    assert!(err.contains("empty variant"), "got: {err}");
}

#[test]
fn enum_with_duplicate_variant_is_rejected() {
    let err = eval_contract_err(r#"contract("X", {"x": field(enum("a", "a"))})"#);
    assert!(err.contains("duplicate variant"), "got: {err}");
}

#[test]
fn too_many_enum_variants_is_rejected() {
    let err =
        eval_contract_err(r#"contract("X", {"x": field(enum(*[str(i) for i in range(65)]))})"#);
    assert!(err.contains("exceeding the maximum of 64"), "got: {err}");
}

#[test]
fn empty_variant_tag_is_rejected() {
    let err = eval_contract_err(r#"contract("X", {"x": field(variant({"": contract("E", {})}))})"#);
    assert!(err.contains("variant tag"), "got: {err}");
    assert!(err.contains("must not be empty"), "got: {err}");
}

// ── time_bound() / cost_bound() construction ─────────────────────────────────

/// Evaluate a `.star` snippet whose module result is a [`BoundValue`] (from
/// `time_bound(..)` / `cost_bound(..)`), returning the carried typed [`Bound`].
fn eval_bound(source: &str) -> Result<Bound, String> {
    let ast = AstModule::parse("bound.star", source.to_owned(), &Dialect::Standard)
        .map_err(|e| format!("parse error: {e}"))?;
    let globals = GlobalsBuilder::standard().with(kata_graph_globals).build();
    let module = Module::new();
    let mut eval = Evaluator::new(&module);
    let result = eval
        .eval_module(ast, &globals)
        .map_err(|e| format!("eval error: {e}"))?;
    let bound = BoundValue::from_value(result).ok_or_else(|| {
        format!(
            "module result was a {}, expected a bound",
            result.get_type()
        )
    })?;
    Ok(bound.bound)
}

/// Evaluate a bound snippet expecting a construction error, returning its text.
fn eval_bound_err(source: &str) -> String {
    match eval_bound(source) {
        Ok(bound) => panic!("expected evaluation to fail, got bound {bound:?}"),
        Err(err) => err,
    }
}

#[test]
fn time_bound_constructs_positive_ms() {
    assert_eq!(
        eval_bound("time_bound(60000)").unwrap(),
        Bound::Time { ms: 60000 }
    );
    // Named arg works too.
    assert_eq!(
        eval_bound("time_bound(ms = 1)").unwrap(),
        Bound::Time { ms: 1 }
    );
}

#[test]
fn time_bound_rejects_non_positive() {
    let err = eval_bound_err("time_bound(0)");
    assert!(err.contains("ms must be > 0"), "got: {err}");
    let err = eval_bound_err("time_bound(-5)");
    assert!(err.contains("ms must be > 0"), "got: {err}");
}

#[test]
fn cost_bound_converts_usd_to_micro_usd() {
    // 1.5 USD == 1_500_000 micro-USD (cost unit conversion).
    assert_eq!(
        eval_bound("cost_bound(1.5)").unwrap(),
        Bound::Cost {
            micro_usd: 1_500_000
        }
    );
    // An integer literal is accepted ergonomically: 5 USD == 5_000_000 micro-USD.
    assert_eq!(
        eval_bound("cost_bound(5)").unwrap(),
        Bound::Cost {
            micro_usd: 5_000_000
        }
    );
}

#[test]
fn cost_bound_rejects_non_positive() {
    let err = eval_bound_err("cost_bound(0.0)");
    assert!(err.contains("usd must be a positive"), "got: {err}");
    let err = eval_bound_err("cost_bound(-1.0)");
    assert!(err.contains("usd must be a positive"), "got: {err}");
}

#[test]
fn cost_bound_rejects_non_number() {
    let err = eval_bound_err(r#"cost_bound("5")"#);
    assert!(err.contains("usd must be a number"), "got: {err}");
}

// ── VALUE CONSTRAINTS: number()/integer()/string() authoring + enforcement ────

/// A representative JSON value must be REJECTED by the generated schema, with
/// the returned validation message containing `needle` (the field/constraint).
fn assert_value_rejected(value: &JsonValue, schema: &JsonValue, needle: &str) {
    let content = serde_json::to_string(value).expect("serialize representative value");
    match validate_agent_run_output_content(&content, schema) {
        Ok(parsed) => panic!(
            "value was accepted but should be rejected\nvalue: {value}\nparsed: {parsed}\nschema: {schema}"
        ),
        Err(err) => assert!(
            err.contains(needle),
            "rejection message {err:?} did not mention {needle:?}\nvalue: {value}\nschema: {schema}",
        ),
    }
}

#[test]
fn numeric_and_string_constraints_lower_into_schema() {
    // The Done-bar authoring case: `number(min=0, max=100)` + a patterned
    // string compile and carry `minimum`/`maximum`/`pattern` in the schema.
    let schema = eval_contract_schema(
        r#"
contract("Bounded", {
    "score": field(number(min = 0, max = 100)),
    "count": field(integer(min = 1, max = 5)),
    "slug": field(string(pattern = "^[a-z]+$", min_length = 1, max_length = 32)),
})
"#,
    )
    .expect("evaluate value-constraint contract");

    assert_eq!(
        schema["properties"]["score"],
        json!({"type": "number", "minimum": 0, "maximum": 100}),
    );
    assert_eq!(
        schema["properties"]["count"],
        json!({"type": "integer", "minimum": 1, "maximum": 5}),
    );
    assert_eq!(
        schema["properties"]["slug"],
        json!({"type": "string", "pattern": "^[a-z]+$", "minLength": 1, "maxLength": 32}),
    );
    assert_schema_valid(&schema);
    assert_value_accepted(&json!({"score": 50, "count": 3, "slug": "abc"}), &schema);
}

#[test]
fn constraint_free_primitives_stay_byte_identical() {
    // ADDITIVITY guard: a contract with no constraints must lower to exactly
    // the pre-constraint schema (so program_hash/contract_hash are unchanged).
    let with_bare =
        eval_contract_schema(r#"contract("P", {"n": field("number"), "s": field("string")})"#)
            .expect("bare primitives");
    // The `number()`/`string()` builtins with no kwargs are also constraint-free
    // and must be byte-identical to the bare-string spelling.
    let with_builtins =
        eval_contract_schema(r#"contract("P", {"n": field(number()), "s": field(string())})"#)
            .expect("empty-constraint builtins");
    assert_eq!(
        with_bare, with_builtins,
        "an unconstrained number()/string() lowers identically to the bare spelling",
    );
    assert_eq!(
        with_bare["properties"]["n"],
        json!({"type": "number"}),
        "no constraint keys leak onto an unconstrained number",
    );
    assert_eq!(with_bare["properties"]["s"], json!({"type": "string"}));
}

#[test]
fn numeric_range_is_enforced_at_validation() {
    let schema =
        eval_contract_schema(r#"contract("R", {"score": field(number(min = 0, max = 100))})"#)
            .expect("range contract");
    // In-range value passes.
    assert_value_accepted(&json!({"score": 50}), &schema);
    // Above max is rejected, naming the field + constraint.
    assert_value_rejected(&json!({"score": 150}), &schema, "maximum");
    // Below min is rejected too.
    assert_value_rejected(&json!({"score": -1}), &schema, "minimum");

    // VERIFIED-TO-FAIL-WITHOUT-THE-CONSTRAINT: the same out-of-range value that
    // was rejected above is ACCEPTED once the range constraint is removed, so
    // the rejection is caused by the constraint (not some unrelated check).
    let unconstrained = eval_contract_schema(r#"contract("R", {"score": field("number")})"#)
        .expect("unconstrained");
    assert_value_accepted(&json!({"score": 150}), &unconstrained);
}

#[test]
fn string_pattern_is_enforced_at_validation() {
    let schema =
        eval_contract_schema(r#"contract("S", {"slug": field(string(pattern = "^[a-z]+$"))})"#)
            .expect("pattern contract");
    // A matching value passes.
    assert_value_accepted(&json!({"slug": "abc"}), &schema);
    // A non-matching value (uppercase) is rejected, naming the pattern.
    assert_value_rejected(&json!({"slug": "ABC"}), &schema, "pattern");

    // VERIFIED-TO-FAIL-WITHOUT-THE-CONSTRAINT: "ABC" is a perfectly valid plain
    // string, so it passes once the pattern is dropped.
    let unconstrained =
        eval_contract_schema(r#"contract("S", {"slug": field("string")})"#).expect("unconstrained");
    assert_value_accepted(&json!({"slug": "ABC"}), &unconstrained);
}

#[test]
fn string_length_bounds_are_enforced_at_validation() {
    let schema = eval_contract_schema(
        r#"contract("L", {"name": field(string(min_length = 2, max_length = 4))})"#,
    )
    .expect("length contract");
    assert_value_accepted(&json!({"name": "abc"}), &schema);
    assert_value_rejected(&json!({"name": "a"}), &schema, "length");
    assert_value_rejected(&json!({"name": "abcde"}), &schema, "length");
}

#[test]
fn integer_range_rejects_out_of_bounds() {
    let schema = eval_contract_schema(r#"contract("I", {"n": field(integer(min = 1, max = 5))})"#)
        .expect("integer range contract");
    assert_value_accepted(&json!({"n": 3}), &schema);
    assert_value_rejected(&json!({"n": 9}), &schema, "maximum");
}

#[test]
fn number_min_greater_than_max_is_a_dsl_error() {
    let err = eval_contract_err(r#"contract("X", {"n": field(number(min = 100, max = 0))})"#);
    assert!(
        err.contains("min") && err.contains("max"),
        "expected a min>max DSL error, got: {err}",
    );
}

#[test]
fn string_min_length_greater_than_max_length_is_a_dsl_error() {
    let err =
        eval_contract_err(r#"contract("X", {"s": field(string(min_length = 5, max_length = 2))})"#);
    assert!(
        err.contains("min_length") && err.contains("max_length"),
        "expected a min_length>max_length DSL error, got: {err}",
    );
}

#[test]
fn invalid_regex_pattern_is_a_dsl_error() {
    // An unbalanced group is not a compilable regex.
    let err = eval_contract_err(r#"contract("X", {"s": field(string(pattern = "(unclosed"))})"#);
    assert!(
        err.contains("not a valid regular expression"),
        "expected an invalid-regex DSL error, got: {err}",
    );
}

#[test]
fn non_number_bound_is_a_dsl_error() {
    let err = eval_contract_err(r#"contract("X", {"n": field(number(min = "zero"))})"#);
    assert!(
        err.contains("must be a number"),
        "expected a non-number bound DSL error, got: {err}",
    );
}

#[test]
fn constrained_primitive_works_as_list_element() {
    // A constrained primitive is a first-class type usable anywhere a plain
    // primitive is — here as a `list_of(..)` element.
    let schema = eval_contract_schema(
        r#"contract("Tags", {"codes": field(list_of(string(pattern = "^[a-z]+$")))})"#,
    )
    .expect("list-of-constrained contract");
    assert_eq!(
        schema["properties"]["codes"]["items"],
        json!({"type": "string", "pattern": "^[a-z]+$"}),
    );
    assert_schema_valid(&schema);
    assert_value_accepted(&json!({"codes": ["ab", "cd"]}), &schema);
    assert_value_rejected(&json!({"codes": ["ab", "C9"]}), &schema, "pattern");
}

/// Evaluate a `.star` snippet whose module result is a plain string, returning
/// it. Used to exercise the `json_skeleton(..)` prompt-shape builtin.
fn eval_string(source: &str) -> Result<String, String> {
    let ast = AstModule::parse("test.star", source.to_owned(), &Dialect::Standard)
        .map_err(|e| format!("parse error: {e}"))?;
    let globals = GlobalsBuilder::standard()
        .with(kata_contract_globals)
        .build();
    let module = Module::new();
    let mut eval = Evaluator::new(&module);
    let result = eval
        .eval_module(ast, &globals)
        .map_err(|e| format!("eval error: {e}"))?;
    result.unpack_str().map(str::to_owned).ok_or_else(|| {
        format!(
            "module result was a {}, expected a string",
            result.get_type()
        )
    })
}

/// Regression: `json_skeleton` must JSON-ESCAPE user
/// strings (enum variants, field names, variant tags) so a metacharacter can't
/// produce invalid JSON — the skeleton is the single-source prompt example, so
/// malformed JSON would otherwise reach the model. FAILS on a raw-quote
/// renderer (the embedded `"` breaks the JSON).
#[test]
fn json_skeleton_escapes_metacharacter_strings() {
    let rendered = eval_string(
        r#"json_skeleton(contract("C", {"tag": field(enum("a", "b\"c")), "wei\"rd": field("string")}))"#,
    )
    .expect("json_skeleton renders a string");
    serde_json::from_str::<JsonValue>(&rendered).unwrap_or_else(|e| {
        panic!("json_skeleton must emit valid JSON even with metacharacters: {e}\n{rendered}")
    });
}

/// Prompt-shape codegen: `json_skeleton(contract(..))` renders an
/// illustrative JSON example in declaration order that PARSES as JSON and carries
/// the contract's keys (an array placeholder for a list, an enum choice hint).
#[test]
fn json_skeleton_builtin_renders_contract_shape() {
    let rendered = eval_string(
        r#"json_skeleton(contract("C", {"v": field(enum("a", "b")), "items": field(list_of("string"))}))"#,
    )
    .expect("json_skeleton renders a string");
    // It parses as JSON.
    let value: JsonValue = serde_json::from_str(&rendered)
        .unwrap_or_else(|e| panic!("json_skeleton output is not valid JSON: {e}\n{rendered}"));
    let obj = value.as_object().expect("skeleton is a JSON object");
    assert!(
        obj.contains_key("v") && obj.contains_key("items"),
        "{rendered}"
    );
    // The enum renders as a pipe-joined choice hint.
    assert_eq!(obj["v"], json!("a|b"), "enum choice hint");
    // The list renders as a single-element array placeholder.
    assert_eq!(obj["items"], json!(["<string>"]), "array placeholder");
    // Declaration order preserved in the rendered TEXT (`v` before `items`);
    // parsing into a serde_json::Value would re-sort object keys, so assert on
    // the raw string.
    let v_at = rendered.find("\"v\"").expect("v key present");
    let items_at = rendered.find("\"items\"").expect("items key present");
    assert!(
        v_at < items_at,
        "keys are emitted in declaration order (v before items):\n{rendered}"
    );
}

/// Regression lock: a consumer whose `consumes=contract("PlanResult", {plan:
/// object})` is fed ONLY by an upstream that `produces=contract("Verdict",
/// {verdict: variant})` is rejected by the `workflow()` drain (`check_contracts`)
/// — `produces=` governs the edge, and a variant-verdict producer cannot satisfy
/// an object-plan consumer.
#[test]
fn verdict_producer_feeding_planresult_consumer_rejected() {
    let src = r#"
producer = stage(
    id = "producer",
    prompt = "emit a verdict",
    agent = "codex",
    produces = contract("Verdict", {
        "verdict": field(variant({
            "approve": contract("Approve", {}),
            "reject": contract("Reject", {}),
        })),
    }),
)
consumer = stage(
    id = "consumer",
    prompt = "consume a plan",
    agent = "codex",
    depends_on = [producer],
    consumes = contract("PlanResult", {
        "plan": field(contract("PlanBody", {"scope": field("string")})),
    }),
)
workflow("verdict-vs-planresult", root = [producer])
"#;
    let err = crate::execution_program::compile_starlark_execution_program(
        src,
        "verdict_vs_planresult.star",
        &[],
    )
    .expect_err("a Verdict producer cannot satisfy a PlanResult consumer");
    let msg = format!("{err}");
    assert!(
        msg.contains("PlanResult") && msg.contains("consumes"),
        "expected the check_contracts no-matching-upstream rejection; got: {msg}"
    );
}

// ── durable sleep + engine schedule DSL builtins ─────────────────────────────

use super::ScheduleValue;
use crate::schedule::{MissedPolicy, ScheduleTrigger};
use kata_types::workflow::{DurableSleepSpec, StageId};

/// Compile a workflow containing a `sleep(..)` NODE and return the
/// resolved durable-sleep marker lowered onto the named stage. `sleep()` is no
/// longer a consumed-by-nothing declaration: it registers a graph node, so a
/// working `sleep(..)` only exists inside a drained `workflow(..)`.
fn lowered_sleep(source: &str, stage_id: &str) -> Result<Option<DurableSleepSpec>, String> {
    let checked = crate::starlark_eval::evaluate_starlark_checked(source, "sleep.star")
        .map_err(|e| e.to_string())?;
    Ok(checked
        .definition()
        .stages
        .get(&StageId(smol_str::SmolStr::new(stage_id)))
        .ok_or_else(|| format!("stage {stage_id} missing from lowered definition"))?
        .durable_sleep)
}

/// The load-time error message from a `sleep()` misuse snippet.
fn sleep_load_err(source: &str) -> String {
    crate::starlark_eval::evaluate_starlark_checked(source, "sleep-err.star")
        .expect_err("expected a load-time error")
        .to_string()
}

/// Evaluate a `.star` snippet whose module result is a [`ScheduleValue`].
fn eval_schedule(source: &str) -> Result<crate::schedule::ScheduleSpec, String> {
    let ast = AstModule::parse("schedule.star", source.to_owned(), &Dialect::Standard)
        .map_err(|e| format!("parse error: {e}"))?;
    let globals = GlobalsBuilder::standard().with(kata_graph_globals).build();
    let module = Module::new();
    let mut eval = Evaluator::new(&module);
    let result = eval
        .eval_module(ast, &globals)
        .map_err(|e| format!("eval error: {e}"))?;
    let schedule = ScheduleValue::from_value(result).ok_or_else(|| {
        format!(
            "module result was a {}, expected a schedule",
            result.get_type()
        )
    })?;
    Ok(schedule.spec.clone())
}

#[test]
fn sleep_lowers_relative_and_absolute_between_stages() {
    // A `sleep()` between two shell stages lowers to a stage carrying
    // the resolved durable-sleep marker (relative and absolute forms).
    let rel = lowered_sleep(
        r#"
a = stage(id = "a", run = ":", agent = "shell")
nap = sleep(id = "nap", for_ms = 60000, depends_on = [a])
b = stage(id = "b", run = ":", agent = "shell", depends_on = [nap])
workflow("nap-rel", root = [a])
"#,
        "nap",
    )
    .unwrap();
    assert_eq!(rel, Some(DurableSleepSpec::For { ms: 60_000 }));

    let abs = lowered_sleep(
        r#"
a = stage(id = "a", run = ":", agent = "shell")
nap = sleep(id = "nap", until_ms = 1735689600000, depends_on = [a])
b = stage(id = "b", run = ":", agent = "shell", depends_on = [nap])
workflow("nap-abs", root = [a])
"#,
        "nap",
    )
    .unwrap();
    assert_eq!(
        abs,
        Some(DurableSleepSpec::Until {
            epoch_ms: 1_735_689_600_000
        })
    );

    // An ordinary shell stage carries NO durable-sleep marker.
    let plain = lowered_sleep(
        r#"
a = stage(id = "a", run = ":", agent = "shell")
nap = sleep(for_ms = 5, depends_on = [a])
b = stage(id = "b", run = ":", agent = "shell", depends_on = [nap])
workflow("nap-plain", root = [a])
"#,
        "a",
    )
    .unwrap();
    assert_eq!(plain, None);
}

#[test]
fn sleep_rejects_zero_both_and_negative() {
    // Load-time diagnostics for a bad duration.
    assert!(
        sleep_load_err("nap = sleep()\nworkflow(\"w\", root = [nap])\n").contains("exactly one")
    );
    assert!(
        sleep_load_err("nap = sleep(for_ms = 1, until_ms = 2)\nworkflow(\"w\", root = [nap])\n")
            .contains("not both")
    );
    assert!(
        sleep_load_err("nap = sleep(for_ms = -5)\nworkflow(\"w\", root = [nap])\n")
            .contains("positive")
    );
}

#[test]
fn sleep_as_workflow_root_is_rejected() {
    // A durable sleep may not be a workflow ROOT: a clear load-time
    // diagnostic points the author at the between-stages shape.
    let err = sleep_load_err(
        r#"
a = stage(id = "a", run = ":", agent = "shell")
nap = sleep(for_ms = 1000, depends_on = [a])
workflow("bad-root", root = [nap])
"#,
    );
    assert!(
        err.contains("cannot be a workflow root") && err.contains("BETWEEN stages"),
        "sleep-as-root must be explained; got: {err}"
    );
}

#[test]
fn schedule_builtin_expresses_nightly_bump_deps() {
    // The headline shape: "nightly, bump deps and open a candidate".
    let spec = eval_schedule(r#"schedule(id = "deps", submit = "deps-bump", cron = "0 2 * * *")"#)
        .unwrap();
    assert_eq!(spec.id, "deps");
    assert_eq!(spec.submit_pack, "deps-bump");
    assert_eq!(
        spec.trigger,
        ScheduleTrigger::Cron {
            expr: "0 2 * * *".to_owned()
        }
    );
    assert_eq!(spec.on_missed, MissedPolicy::FireOnceOnBoot);
}

#[test]
fn schedule_builtin_interval_and_skip_policy() {
    let spec = eval_schedule(
        r#"schedule(id = "poll", submit = "poll", every_ms = 3600000, on_missed = "skip")"#,
    )
    .unwrap();
    assert_eq!(
        spec.trigger,
        ScheduleTrigger::Interval {
            every_ms: 3_600_000
        }
    );
    assert_eq!(spec.on_missed, MissedPolicy::Skip);
}

#[test]
fn schedule_builtin_is_fail_closed() {
    // Malformed cron rejected at authoring time.
    assert!(
        eval_schedule(r#"schedule(id = "x", submit = "y", cron = "not a cron")"#)
            .unwrap_err()
            .contains("cron")
    );
    // Exactly one of every_ms/cron.
    assert!(
        eval_schedule(r#"schedule(id = "x", submit = "y")"#)
            .unwrap_err()
            .contains("exactly one")
    );
    assert!(
        eval_schedule(r#"schedule(id = "x", submit = "y", every_ms = 1, cron = "* * * * *")"#)
            .unwrap_err()
            .contains("not both")
    );
    // Unknown missed policy.
    assert!(
        eval_schedule(r#"schedule(id = "x", submit = "y", every_ms = 1, on_missed = "nope")"#)
            .unwrap_err()
            .contains("on_missed")
    );
}

// ── typed workflow(params={..}) decode ───────────────────────────────────────

/// Compile a `workflow(params={..})` pack and return the lowered typed param
/// specs (canonical name order).
fn lowered_params(source: &str) -> Result<Vec<kata_types::params::WorkflowParamSpec>, String> {
    let checked = crate::starlark_eval::evaluate_starlark_checked(source, "params.star")
        .map_err(|e| e.to_string())?;
    Ok(checked.extensions().params.params.clone())
}

/// The load-time error from a bad `workflow(params={..})` snippet.
fn params_load_err(source: &str) -> String {
    crate::starlark_eval::evaluate_starlark_checked(source, "params-err.star")
        .expect_err("expected a load-time params error")
        .to_string()
}

const PARAMS_PROLOGUE: &str = "s = stage(id = \"s\", agent = \"shell\", prompt = \"go\")\n";

#[test]
fn typed_params_lower_with_required_default_and_secret() {
    let source = format!(
        "{PARAMS_PROLOGUE}workflow(\"p\", root = s, params = {{\n\
            \"target\": field(\"string\"),\n\
            \"count\": field(integer(min = 1, max = 9), default = 3),\n\
            \"mode\": field(enum(\"fast\", \"slow\"), default = \"fast\"),\n\
            \"api_token\": field(\"string\", secret = True),\n\
        }})\n"
    );
    let params = lowered_params(&source).expect("compiles");
    // Canonical name order: api_token, count, mode, target.
    let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["api_token", "count", "mode", "target"]);

    let by_name = |n: &str| params.iter().find(|p| p.name == n).unwrap();
    // Required string, no default, not secret.
    let target = by_name("target");
    assert!(target.required && target.default.is_none() && !target.secret);
    assert_eq!(target.schema, json!({"type": "string"}));
    // Defaulted integer → optional with a default.
    let count = by_name("count");
    assert!(!count.required);
    assert_eq!(count.default, Some(json!(3)));
    assert_eq!(
        count.schema,
        json!({"type": "integer", "minimum": 1, "maximum": 9})
    );
    // Defaulted enum.
    let mode = by_name("mode");
    assert!(!mode.required);
    assert_eq!(mode.default, Some(json!("fast")));
    // Secret → required, no default, secret flag set.
    let token = by_name("api_token");
    assert!(token.required && token.default.is_none() && token.secret);
}

#[test]
fn flat_params_promote_to_required() {
    // The flat `{name: "type"}` shape promotes to REQUIRED typed params.
    let source = format!(
        "{PARAMS_PROLOGUE}workflow(\"p\", root = s, params = {{\"target_repo\": \"string\"}})\n"
    );
    let params = lowered_params(&source).expect("compiles");
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "target_repo");
    assert!(params[0].required);
    assert!(params[0].default.is_none());
    assert!(!params[0].secret);
    assert_eq!(params[0].schema, json!({"type": "string"}));
}

#[test]
fn param_default_must_satisfy_type() {
    let source = format!(
        "{PARAMS_PROLOGUE}workflow(\"p\", root = s, params = {{\"n\": field(integer(min = 1, max = 3), default = 9)}})\n"
    );
    let err = params_load_err(&source);
    assert!(err.contains("default="), "{err}");
}

#[test]
fn secret_param_may_not_carry_default() {
    let source = format!(
        "{PARAMS_PROLOGUE}workflow(\"p\", root = s, params = {{\"t\": field(\"string\", secret = True, default = \"x\")}})\n"
    );
    let err = params_load_err(&source);
    assert!(err.contains("secret"), "{err}");
}

#[test]
fn contract_field_rejects_param_only_kwargs() {
    // `default=`/`secret=` are param-only; a contract field that sets them is a
    // clear author-time error, not a silent drop.
    let err = eval_contract_err(r#"contract("C", {"f": field("string", secret = True)})"#);
    assert!(err.contains("default=/secret="), "{err}");
}

/// MINOR-6: a pack declaring more params than the bound refuses at LOAD
/// (`workflows check`), not at first submission.
#[test]
fn over_declared_params_refuse_at_load() {
    use std::fmt::Write as _;
    let entries: String =
        (0..=kata_types::params::MAX_INVOCATION_PARAMS).fold(String::new(), |mut out, i| {
            let _ = write!(out, "\"p{i}\": \"string\", ");
            out
        });
    let source = format!("{PARAMS_PROLOGUE}workflow(\"p\", root = s, params = {{{entries}}})\n");
    let err = params_load_err(&source);
    assert!(err.contains("maximum is"), "{err}");
}

#[test]
fn param_less_pack_has_no_params() {
    // Byte-stability: a pack without params= carries no param specs, so the
    // extensions (and therefore the program hash material) are unchanged.
    let source = format!("{PARAMS_PROLOGUE}workflow(\"p\", root = s)\n");
    assert!(lowered_params(&source).expect("compiles").is_empty());
}

// ── `field()`'s documented contradictions are REJECTED, not coerced ───────
//
// `field()`'s doc says that combining `default=` with `required=True` "is a
// contradiction rejected at author time", and `decode_param_field` is the only
// door that can reject it: `execution_program::verify`'s
// `param_required_with_default` (which names this exact rule) inspects the
// ALREADY-COERCED spec, so it can never fire for a DSL-authored pack. An author
// who writes `field("string", required=True, default="x")` intending a hard
// error must get that error at load, not a SILENTLY OPTIONAL param.

#[test]
fn an_explicit_required_true_beside_a_default_is_refused() {
    let source = format!(
        "{PARAMS_PROLOGUE}workflow(\"p\", root = s, params = {{\n\
            \"target\": field(\"string\", required = True, default = \"x\"),\n\
        }})\n"
    );
    let err = params_load_err(&source);
    assert!(
        err.contains("required=True") && err.contains("default="),
        "the refusal must name BOTH kwargs the author spelled: {err}"
    );
    assert!(
        err.contains("optional"),
        "the refusal must say WHY (a default makes the param optional): {err}"
    );
}

#[test]
fn an_explicit_required_false_beside_secret_is_refused() {
    let source = format!(
        "{PARAMS_PROLOGUE}workflow(\"p\", root = s, params = {{\n\
            \"api_token\": field(\"string\", secret = True, required = False),\n\
        }})\n"
    );
    let err = params_load_err(&source);
    assert!(
        err.contains("secret=True") && err.contains("required=False"),
        "the refusal must name both kwargs: {err}"
    );
}

#[test]
fn the_ordinary_defaulted_and_secret_spellings_are_untouched() {
    // The rejections turn on an EXPLICIT `required=`. `field(ty, default=..)`
    // and `field(ty, secret=True)` carry `required` only by its `True` default
    // and are the intended way to declare an optional / a secret param — they
    // must keep lowering exactly as before, or every existing pack breaks.
    let source = format!(
        "{PARAMS_PROLOGUE}workflow(\"p\", root = s, params = {{\n\
            \"count\": field(integer(min = 1, max = 9), default = 3),\n\
            \"api_token\": field(\"string\", secret = True),\n\
            \"target\": field(\"string\"),\n\
            \"note\": field(\"string\", required = False),\n\
        }})\n"
    );
    let params = lowered_params(&source).expect("compiles");
    let by_name = |n: &str| params.iter().find(|p| p.name == n).unwrap();
    let count = by_name("count");
    assert!(!count.required, "a defaulted param stays optional");
    assert_eq!(count.default, Some(json!(3)));
    let token = by_name("api_token");
    assert!(token.required && token.secret && token.default.is_none());
    assert!(by_name("target").required, "an unspelled required= is True");
    assert!(
        !by_name("note").required,
        "an explicit required=False alone is still honoured"
    );
}

#[test]
fn contract_fields_still_default_to_required() {
    // `Field::required` became `Option<bool>` for the param rules above;
    // `contract()` must keep reading an unspelled one as the documented `True`.
    let schema = eval_contract_schema(
        r#"
contract("X", {
    "a": field("string"),
    "b": field("string", required = False),
})
"#,
    )
    .expect("compiles");
    assert_eq!(schema["required"], json!(["a"]));
}

/// The load-time error from a bad graph-DSL snippet.
fn graph_load_err(source: &str) -> String {
    crate::starlark_eval::evaluate_starlark_checked(source, "graph-err.star")
        .expect_err("expected a load-time error")
        .to_string()
}

#[test]
fn sandbox_profile_still_accepts_the_contract_bearing_kwargs() {
    // The kwargs that describe the workflow rather than the node compile.
    let checked = crate::starlark_eval::evaluate_starlark_checked(
        r#"
s = stage(id = "s", agent = "shell", run = "true", sandbox = "vm")
t = stage(id = "t", agent = "shell", run = "true", sandbox = "rooted")
workflow(
    "profile-kwargs",
    root = [s, t],
    sandbox_profiles = {
        "vm": sandbox_profile(net = "host",
                              secrets = {"TOKEN": "env:CI_TOKEN"}, locked = True,
                              image = {"ref": "kata/rust:latest"},
                              toolchain = "store:1111111111111111111111111111111111111111111111111111111111111111"),
        "rooted": sandbox_profile(net = "host",
                              rootfs = "store:2222222222222222222222222222222222222222222222222222222222222222"),
    },
)
"#,
        "profile-kwargs.star",
    )
    .expect("compiles");
    let profile = checked
        .definition()
        .sandbox_profiles
        .get("vm")
        .expect("vm profile");
    assert!(profile.locked);
    assert_eq!(
        profile.image.as_ref().map(|i| i.reference.as_str()),
        Some("kata/rust:latest")
    );
    // The two requirement kwargs are the pair a starlark signature is most
    // likely to confuse: same type, same shape of value, adjacent positions.
    // Distinct addresses, so a swap is visible.
    //
    // They cannot be asserted on one call that passes both: a profile that
    // declares both is REFUSED — an addressed root already contains the
    // toolchain — so the two declarations are on two profiles in the same
    // pack. That keeps what this assertion is for (a swap between two adjacent
    // same-typed kwargs is visible) while respecting the refusal
    // (`starlark_eval::refuse_root_and_toolchain_pair`).
    assert_eq!(
        profile
            .toolchain
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("store:1111111111111111111111111111111111111111111111111111111111111111"),
        "the toolchain requirement must survive a call that passes every other kwarg too"
    );
    assert_eq!(
        profile.rootfs, None,
        "the profile that declared only a toolchain must carry no root"
    );
    let rooted = checked
        .definition()
        .sandbox_profiles
        .get("rooted")
        .expect("rooted profile");
    assert_eq!(
        rooted.rootfs.as_ref().map(ToString::to_string).as_deref(),
        Some("store:2222222222222222222222222222222222222222222222222222222222222222"),
        "the root filesystem requirement must land on its OWN field, not the toolchain's"
    );
    assert_eq!(
        rooted.toolchain, None,
        "…and must not populate the toolchain field on its way there"
    );
}

// ── `reads=` / `produces_files=` closures are checked at LOAD ─────────────
//
// Both are documented as "repo-relative globs". An absolute path or a `..`
// component points outside the execution worktree by construction, so it is
// refused at load, naming the stage, the kwarg and the pattern. Admitted, it
// would reach three resolvers that each handle it differently and none of which
// names the authoring line:
// the cache-side resolver warns with the pattern only, the ENFORCEMENT-side
// resolver drops it with no log at all (so the stage's read is simply denied
// EACCES at runtime), and the output-closure normalizer REBASES a leading `/`
// to the repo root. Worst case is an all-escaping closure: everything is
// dropped, the resolved closure is empty, and an empty closure is the "no
// declared inputs" signal — so a stage that explicitly declared one runs with
// no fence at all.

#[test]
fn an_absolute_reads_glob_is_refused_at_load() {
    let err = graph_load_err(
        "s = stage(id = \"s\", agent = \"shell\", run = \"true\", reads = [\"/etc/passwd\"])\n\
         workflow(\"abs-reads\", root = [s])\n",
    );
    assert!(err.contains("/etc/passwd"), "must name the pattern: {err}");
    assert!(err.contains("reads="), "must name the kwarg: {err}");
    assert!(err.contains("stage s"), "must name the stage: {err}");
}

#[test]
fn a_dotdot_reads_glob_is_refused_at_load() {
    let err = graph_load_err(
        "s = stage(id = \"s\", agent = \"shell\", run = \"true\", \
         reads = [\"src\", \"../gen/schema.json\"])\n\
         workflow(\"esc-reads\", root = [s])\n",
    );
    assert!(
        err.contains("../gen/schema.json"),
        "must name the offending pattern even when other entries are fine: {err}"
    );
}

#[test]
fn an_escaping_produces_files_glob_is_refused_at_load() {
    let err = graph_load_err(
        "s = stage(id = \"s\", agent = \"shell\", run = \"true\", \
         produces_files = [\"/etc/passwd\"])\n\
         workflow(\"abs-out\", root = [s])\n",
    );
    assert!(
        err.contains("produces_files="),
        "must name the kwarg: {err}"
    );
    assert!(err.contains("/etc/passwd"), "must name the pattern: {err}");
}

#[test]
fn repo_relative_closures_lower_verbatim_in_authored_order() {
    // The accepted list must pass through UNCHANGED — the closure is hashed, so
    // trimming, sorting, or deduping here would rotate the program hash of
    // every pack that already declares one.
    let checked = crate::starlark_eval::evaluate_starlark_checked(
        "s = stage(id = \"s\", agent = \"shell\", run = \"true\", \
         reads = [\"src\", \"build.config\", \"src\"], \
         produces_files = [\"out/**\", \"./rel\"])\n\
         workflow(\"ok-closure\", root = [s])\n",
        "ok-closure.star",
    )
    .expect("compiles");
    let stage = checked
        .definition()
        .stages
        .get(&kata_types::workflow::StageId("s".into()))
        .expect("stage s");
    assert_eq!(
        stage
            .reads
            .iter()
            .map(smol_str::SmolStr::as_str)
            .collect::<Vec<_>>(),
        ["src", "build.config", "src"],
        "authored order and duplicates preserved"
    );
    assert_eq!(
        stage
            .produces_files
            .iter()
            .map(smol_str::SmolStr::as_str)
            .collect::<Vec<_>>(),
        ["out/**", "./rel"]
    );
}

// ── `run=` IS the shell-command alias ───────────────────────────────────────
//
// `materialize_sandbox`'s rustdoc says a plain `run=` derives
// `Contained + Deterministic + Offline + ReadOnly`. That holds only because
// `resolve_run_alias_agent` sets the agent: a `run=` stage with no `agent=`
// lowering to `AgentSelector::Any` would be read by `classify_executor` as a
// MODEL executor — `net = host`, `Nondeterministic`, `DurableActivity`, and at
// run time a route to `[agents.default]`.

/// The DOC'S OWN SENTENCE, as a test: a `run=` stage that names no agent is a
/// SHELL stage, and its derived class is the confined-offline-deterministic
/// tuple the confined default promises.
///
/// COUNTERFACTUAL: delete `resolve_run_alias_agent`'s empty-agent arm and the
/// agent is `""`, the containment axis is `host_unconfined` and the determinism
/// axis is `nondeterministic` — watched RED before the arm existed.
#[test]
fn a_run_stage_that_names_no_agent_lowers_to_the_shell_executor() {
    let program = crate::execution_program::compile_starlark_execution_program(
        "s = stage(id = \"s\", run = \"true\")\nworkflow(\"plain-run\", root = [s])\n",
        "plain_run.star",
        &[],
    )
    .expect("a plain `run=` pack compiles");
    let stage = program
        .stages
        .get(&kata_types::workflow::StageId("s".into()))
        .expect("stage s");
    assert_eq!(
        stage.op.agent.as_str(),
        "shell",
        "`run=` with no `agent=` must lower to the shell executor, not to `any`"
    );
    let class = stage.execution_class;
    assert_eq!(
        class.containment,
        kata_types::execution_class::Containment::Contained,
        "the plain `run=` stage must be CONTAINED: {class:?}"
    );
    assert_eq!(
        class.determinism,
        kata_types::execution_class::Determinism::Deterministic,
        "the plain `run=` stage must be DETERMINISTIC: {class:?}"
    );
    assert_eq!(
        class.network,
        kata_types::execution_class::Network::Offline,
        "the plain `run=` stage must be OFFLINE: {class:?}"
    );
}

/// The other half of the alias: pairing the shell-command alias with a label
/// that lowers to a MODEL executor is refused BY NAME rather than silently
/// billed.
#[test]
fn run_paired_with_a_model_agent_is_refused_by_name() {
    let err = graph_load_err(
        "s = stage(id = \"s\", run = \"just test\", agent = \"codex\")\n\
         workflow(\"run-model\", root = [s])\n",
    );
    assert!(err.contains("run="), "must name the kwarg: {err}");
    assert!(err.contains("codex"), "must name the agent: {err}");
    assert!(
        err.contains("prompt=") && err.contains("shell"),
        "must name both recourses: {err}"
    );
}
