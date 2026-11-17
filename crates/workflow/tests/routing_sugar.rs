//! Typed routing SUGAR (`route` / `when` / `branch_if`) lowering goldens
//! and adversarial diagnostics.
//!
//! Every sugar builtin lowers through the SAME `register_branch` the raw
//! `branch()` uses, so each produces a BYTE-IDENTICAL `BranchRoute` IR (and the
//! same source-independent `normalized_definition_hash`) as the equivalent
//! hand-written `branch()`. The gate that admits the discriminant is generalized
//! to `variant(..)` OR string `enum(..)`; the existing variant path is unchanged
//! (a `branch()` diagnostic is regression-pinned verbatim below).

use kata_program::execution_program::compile_starlark_execution_program;

fn compile(src: &str) -> kata_program::execution_program::ExecutionProgram {
    compile_starlark_execution_program(src, "routing_sugar.star", &[])
        .unwrap_or_else(|err| panic!("pack must compile: {err}"))
}

fn compile_err(src: &str) -> String {
    compile_starlark_execution_program(src, "routing_sugar.star", &[])
        .expect_err("pack must fail to compile")
        .to_string()
}

/// Assert two packs lower to a byte-identical branch IR: the same
/// `branch_routes`, the same `normalized_definition_hash` (source-independent),
/// and the same condition-stage `contract_hash`.
fn assert_same_branch_ir(
    sugar: &kata_program::execution_program::ExecutionProgram,
    hand: &kata_program::execution_program::ExecutionProgram,
    condition: &str,
) {
    assert_eq!(
        sugar.branch_routes, hand.branch_routes,
        "sugar must lower to the byte-identical BranchRoute IR of the hand-written branch()"
    );
    assert_eq!(
        sugar.source.normalized_definition_hash, hand.source.normalized_definition_hash,
        "sugar must lower to the same normalized_definition_hash as branch()"
    );
    let cid = kata_types::workflow::StageId(smol_str::SmolStr::new(condition));
    assert_eq!(
        sugar.stages.get(&cid).map(|s| s.contract_hash),
        hand.stages.get(&cid).map(|s| s.contract_hash),
        "the condition stage's contract_hash must match"
    );
}

// ── Lowering goldens ─────────────────────────────────────────────────────────

/// `route(field=, arms=)` over a `variant(..)` == the equivalent
/// `branch(verdict_field=, arms=)`.
#[test]
fn route_lowers_identically_to_branch_variant() {
    let head = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "choice": field(variant({"first": contract("E", {}), "second": contract("E2", {})})),
}))
first = stage(id = "first", prompt = "f", agent = "worker")
second = stage(id = "second", prompt = "s", agent = "worker")
"#;
    let hand = compile(&format!(
        "{head}branch(on = decide, verdict_field = \"choice\", arms = {{\"first\": first, \"second\": second}})\nworkflow(\"wf\", root = decide)\n"
    ));
    let sugar = compile(&format!(
        "{head}route(on = decide, field = \"choice\", arms = {{\"first\": first, \"second\": second}})\nworkflow(\"wf\", root = decide)\n"
    ));
    assert_same_branch_ir(&sugar, &hand, "decide");
}

/// `when(field=, equals=, then=, otherwise=)` over a 2-value `enum(..)` ==
/// `branch(arms={equals: then, other: otherwise})`.
#[test]
fn when_lowers_identically_to_branch_enum() {
    let head = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "verdict": field(enum("approve", "reject")),
}))
ship = stage(id = "ship", prompt = "ship", agent = "worker")
hold = stage(id = "hold", prompt = "hold", agent = "worker")
"#;
    let hand = compile(&format!(
        "{head}branch(on = decide, verdict_field = \"verdict\", arms = {{\"approve\": ship, \"reject\": hold}})\nworkflow(\"wf\", root = decide)\n"
    ));
    let sugar = compile(&format!(
        "{head}when(on = decide, field = \"verdict\", equals = \"approve\", then = ship, otherwise = hold)\nworkflow(\"wf\", root = decide)\n"
    ));
    assert_same_branch_ir(&sugar, &hand, "decide");
}

/// `branch_if(field=, then=, otherwise=)` over a boolean-shaped 2-value string
/// `enum(..)` (VALUE-BASED binding: `then`→truthy `"true"`,
/// `otherwise`→falsy `"false"`) == `branch(arms={"true": then, "false": otherwise})`.
#[test]
fn branch_if_lowers_identically_to_branch_bool_enum() {
    let head = r#"
check = stage(id = "check", run = "echo", agent = "shell", produces = contract("C", {
    "ok": field(enum("true", "false")),
}))
proceed = stage(id = "proceed", prompt = "go", agent = "worker")
abort = stage(id = "abort", prompt = "stop", agent = "worker")
"#;
    let hand = compile(&format!(
        "{head}branch(on = check, verdict_field = \"ok\", arms = {{\"true\": proceed, \"false\": abort}})\nworkflow(\"wf\", root = check)\n"
    ));
    let sugar = compile(&format!(
        "{head}branch_if(on = check, field = \"ok\", then = proceed, otherwise = abort)\nworkflow(\"wf\", root = check)\n"
    ));
    assert_same_branch_ir(&sugar, &hand, "check");
}

/// REGRESSION (the inverted-docs counterexample): with `enum("false", "true")`
/// a POSITIONAL binding would fire `then` on `"false"` — inverted control flow. VALUE-BASED binding fires `then` on the
/// truthy `"true"` regardless of authored order: the sugar lowers identically
/// to `branch(arms={"true": then, "false": otherwise})`.
#[test]
fn branch_if_binds_then_to_truthy_regardless_of_authored_order() {
    let head = r#"
check = stage(id = "check", run = "echo", agent = "shell", produces = contract("C", {
    "ok": field(enum("false", "true")),
}))
proceed = stage(id = "proceed", prompt = "go", agent = "worker")
abort = stage(id = "abort", prompt = "stop", agent = "worker")
"#;
    let hand = compile(&format!(
        "{head}branch(on = check, verdict_field = \"ok\", arms = {{\"true\": proceed, \"false\": abort}})\nworkflow(\"wf\", root = check)\n"
    ));
    let sugar = compile(&format!(
        "{head}branch_if(on = check, field = \"ok\", then = proceed, otherwise = abort)\nworkflow(\"wf\", root = check)\n"
    ));
    assert_same_branch_ir(&sugar, &hand, "check");
}

/// REGRESSION: the `yes`/`no` boolean pair binds `then`→`"yes"` (truthy) in
/// BOTH authored orders — `enum("yes", "no")` and `enum("no", "yes")` lower the
/// identical IR as `branch(arms={"yes": then, "no": otherwise})`.
#[test]
fn branch_if_yes_no_binds_then_to_yes_in_any_authored_order() {
    for enum_values in ["\"yes\", \"no\"", "\"no\", \"yes\""] {
        let head = format!(
            r#"
check = stage(id = "check", run = "echo", agent = "shell", produces = contract("C", {{
    "ok": field(enum({enum_values})),
}}))
proceed = stage(id = "proceed", prompt = "go", agent = "worker")
abort = stage(id = "abort", prompt = "stop", agent = "worker")
"#
        );
        let hand = compile(&format!(
            "{head}branch(on = check, verdict_field = \"ok\", arms = {{\"yes\": proceed, \"no\": abort}})\nworkflow(\"wf\", root = check)\n"
        ));
        let sugar = compile(&format!(
            "{head}branch_if(on = check, field = \"ok\", then = proceed, otherwise = abort)\nworkflow(\"wf\", root = check)\n"
        ));
        assert_same_branch_ir(&sugar, &hand, "check");
    }
}

/// A raw `branch()` may now ALSO route on a string `enum(..)` (the generalized
/// gate), lowering the same IR a `variant` branch would.
#[test]
fn branch_admits_string_enum_discriminant() {
    let src = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "verdict": field(enum("approve", "reject")),
}))
ship = stage(id = "ship", prompt = "ship", agent = "worker")
hold = stage(id = "hold", prompt = "hold", agent = "worker")
branch(on = decide, verdict_field = "verdict", arms = {"approve": ship, "reject": hold})
workflow("wf", root = decide)
"#;
    let program = compile(src);
    assert_eq!(
        program.branch_routes.len(),
        1,
        "the enum branch route must lower"
    );
}

// ── Adversarial diagnostics (verbatim) ───────────────────────────────────────

const ENUM3_HEAD: &str = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "verdict": field(enum("a", "b", "c")),
}))
x = stage(id = "x", prompt = "x", agent = "worker")
y = stage(id = "y", prompt = "y", agent = "worker")
"#;

/// (1) `when()` on a 3-value discriminant is rejected — `when` is a two-way
/// predicate; use `route()` for N arms.
#[test]
fn adversarial_when_on_three_value_discriminant() {
    let msg = compile_err(&format!(
        "{ENUM3_HEAD}when(on = decide, field = \"verdict\", equals = \"a\", then = x, otherwise = y)\nworkflow(\"wf\", root = decide)\n"
    ));
    assert!(
        msg.contains(
            "when() requires a 2-value discriminant; field \"verdict\" on condition stage \
             \"decide\" has 3 values [a, b, c] — use route() for an N-arm discriminant"
        ),
        "got: {msg}"
    );
}

/// (2) `when(equals=..)` naming a value the discriminant does not declare.
#[test]
fn adversarial_when_is_not_a_declared_value() {
    let head = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "verdict": field(enum("approve", "reject")),
}))
x = stage(id = "x", prompt = "x", agent = "worker")
y = stage(id = "y", prompt = "y", agent = "worker")
"#;
    let msg = compile_err(&format!(
        "{head}when(on = decide, field = \"verdict\", equals = \"ghost\", then = x, otherwise = y)\nworkflow(\"wf\", root = decide)\n"
    ));
    assert!(
        msg.contains(
            "when() equals=\"ghost\" is not a value of field \"verdict\" on condition stage \
             \"decide\" (values: [approve, reject])"
        ),
        "got: {msg}"
    );
}

/// (3) `when()` without the REQUIRED `otherwise=` arm.
#[test]
fn adversarial_when_missing_otherwise() {
    let head = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "verdict": field(enum("approve", "reject")),
}))
x = stage(id = "x", prompt = "x", agent = "worker")
"#;
    let msg = compile_err(&format!(
        "{head}when(on = decide, field = \"verdict\", equals = \"approve\", then = x)\nworkflow(\"wf\", root = decide)\n"
    ));
    assert!(
        msg.contains(
            "when() requires otherwise= (the arm for the other value); a when() route is a \
             two-way predicate over a 2-value discriminant"
        ),
        "got: {msg}"
    );
}

/// (4) `branch_if()` on a `variant(..)` field (not a string enum) — use
/// `when()`/`route()`.
#[test]
fn adversarial_branch_if_on_variant() {
    let head = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "choice": field(variant({"first": contract("E", {}), "second": contract("E2", {})})),
}))
x = stage(id = "x", prompt = "x", agent = "worker")
y = stage(id = "y", prompt = "y", agent = "worker")
"#;
    let msg = compile_err(&format!(
        "{head}branch_if(on = decide, field = \"choice\", then = x, otherwise = y)\nworkflow(\"wf\", root = decide)\n"
    ));
    assert!(
        msg.contains(
            "branch_if() requires a 2-value STRING enum field; field \"choice\" on condition \
             stage \"decide\" is a variant(..) — use when()/route(). (A raw JSON bool is not \
             routable; model the boolean as enum(\"true\", \"false\").)"
        ),
        "got: {msg}"
    );
}

/// REGRESSION (review MAJOR): a 2-value enum that is NOT a recognized boolean
/// pair has no truthy side to bind, so `branch_if()` REFUSES with a precise
/// diagnostic naming the field + its values and pointing at `when(equals=..)` /
/// `route()`.
#[test]
fn adversarial_branch_if_non_boolean_pair_refuses() {
    let head = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "verdict": field(enum("a", "b")),
}))
x = stage(id = "x", prompt = "x", agent = "worker")
y = stage(id = "y", prompt = "y", agent = "worker")
"#;
    let msg = compile_err(&format!(
        "{head}branch_if(on = decide, field = \"verdict\", then = x, otherwise = y)\nworkflow(\"wf\", root = decide)\n"
    ));
    assert!(
        msg.contains(
            "branch_if() requires a boolean-shaped 2-value STRING enum — \
             enum(\"true\", \"false\") or enum(\"yes\", \"no\"), in any order; field \
             \"verdict\" on condition stage \"decide\" declares values [a, b] — use \
             when(on=, field=, equals=..) for an arbitrary 2-value discriminant, or route() \
             for N arms"
        ),
        "got: {msg}"
    );
}

/// (5) Routing sugar on a RAW JSON scalar field (a `bool`) — not a routable
/// discriminant.
#[test]
fn adversarial_routing_on_raw_bool_field() {
    let head = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "ok": field("bool"),
}))
x = stage(id = "x", prompt = "x", agent = "worker")
y = stage(id = "y", prompt = "y", agent = "worker")
"#;
    let msg = compile_err(&format!(
        "{head}branch_if(on = decide, field = \"ok\", then = x, otherwise = y)\nworkflow(\"wf\", root = decide)\n"
    ));
    assert!(
        msg.contains(
            "field \"ok\" on condition stage \"decide\" must be a variant(..) or a string enum(..) \
             discriminant; a raw JSON string/bool is not routable — model a boolean as a 2-value \
             enum(\"a\", \"b\")"
        ),
        "got: {msg}"
    );
}

// ── Regression-pin: the variant path's branch() diagnostic is byte-identical ──

/// The existing `branch()` exhaustiveness diagnostic over a `variant(..)` is
/// UNCHANGED verbatim (the generalized gate did not perturb the variant path).
#[test]
fn branch_variant_exhaustiveness_diagnostic_is_unchanged() {
    let src = r#"
decide = stage(id = "decide", run = "echo", agent = "shell", produces = contract("D", {
    "choice": field(variant({"first": contract("E", {}), "second": contract("E2", {})})),
}))
first = stage(id = "first", prompt = "f", agent = "worker")
branch(on = decide, verdict_field = "choice", arms = {"first": first})
workflow("wf", root = decide)
"#;
    let msg = compile_err(src);
    assert!(
        msg.contains(
            "branch() on condition stage \"decide\" is not exhaustive over verdict_field \
             \"choice\": missing arms for variant tags [second]. variant declares tags \
             [first, second]; branch declares arms [first]"
        ),
        "the variant-path exhaustiveness diagnostic must be byte-identical; got: {msg}"
    );
}
