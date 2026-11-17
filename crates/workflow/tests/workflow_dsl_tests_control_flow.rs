//! Native `workflow()` control-flow tests — `branch` verdict routing,
//! loop `bounds=`/`gate_verdict=` lowering, workspace-effect stages,
//! `max_concurrency`, and `subworkflow`.

use kata_program::execution_program::{VerifierStatus, compile_starlark_execution_program};
use kata_types::bound::Bound;
use kata_types::primitives::ContentHash;
use kata_types::workflow::StageId;

mod common;
use common::compile_star;

// ─────────────────────────────────────────────────────────────────────────────
// The `branch` control-flow primitive (typed verdict routing).
// ─────────────────────────────────────────────────────────────────────────────

/// A condition stage `produces=contract(..)` with a two-arm `variant(..)` verdict
/// field plus a matching `branch(..)` lowers a single `BranchRoute` into the
/// checked IR, in canonical (tag-sorted) order, with each arm target wired to
/// depend on the condition stage.
#[test]
fn branch_lowers_route_with_canonical_arm_order() {
    use kata_types::workflow::StageId;
    // Authored arm order is `second` then `first`; canonical order must be
    // `first` then `second` (tag-sorted) so author order never affects identity.
    let source = r#"
decide = stage(
    id = "decide",
    run = "echo",
    agent = "shell",
    produces = contract("D", {
        "choice": field(variant({
            "first": contract("E", {}),
            "second": contract("E2", {}),
        })),
    }),
)
first_stage = stage(id = "first", prompt = "first", agent = "worker")
second_stage = stage(id = "second", prompt = "second", agent = "worker")
branch(on = decide, verdict_field = "choice", arms = {
    "second": second_stage,
    "first": first_stage,
})
workflow("wf-branch", root = decide)
"#;
    let program = compile_star(source, "wf_branch.star");
    assert_eq!(
        program.branch_routes.len(),
        1,
        "exactly one branch route must lower"
    );
    let route = &program.branch_routes[0];
    assert_eq!(route.condition_stage, StageId("decide".into()));
    assert_eq!(route.verdict_field.as_str(), "choice");
    let tags: Vec<&str> = route.arms.iter().map(|a| a.tag.as_str()).collect();
    assert_eq!(
        tags,
        vec!["first", "second"],
        "arms must be in canonical tag-sorted order regardless of author order"
    );
    assert_eq!(route.arms[0].targets, vec![StageId("first".into())]);
    assert_eq!(route.arms[1].targets, vec![StageId("second".into())]);

    // Each arm target must depend on the condition stage (wired by branch()).
    let first = program
        .stages
        .get(&StageId("first".into()))
        .expect("first stage present");
    assert!(
        first.depends_on.contains(&StageId("decide".into())),
        "arm target `first` must depend on the condition stage `decide`"
    );
    let second = program
        .stages
        .get(&StageId("second".into()))
        .expect("second stage present");
    assert!(
        second.depends_on.contains(&StageId("decide".into())),
        "arm target `second` must depend on the condition stage `decide`"
    );
}

/// A branch missing an arm for a declared variant tag FAILS TO COMPILE with a
/// both-sides exhaustiveness error naming the missing tag.
#[test]
fn branch_missing_arm_is_rejected() {
    let source = r#"
decide = stage(
    id = "decide",
    run = "echo",
    agent = "shell",
    produces = contract("D", {
        "choice": field(variant({
            "first": contract("E", {}),
            "second": contract("E2", {}),
        })),
    }),
)
first_stage = stage(id = "first", prompt = "first", agent = "worker")
branch(on = decide, verdict_field = "choice", arms = {"first": first_stage})
workflow("wf-branch-missing", root = decide)
"#;
    let err = compile_starlark_execution_program(source, "wf_branch_missing.star", &[])
        .expect_err("a branch missing an arm for a variant tag must fail to compile");
    let msg = err.to_string();
    assert!(
        msg.contains("not exhaustive") && msg.contains("missing arms") && msg.contains("second"),
        "expected an exhaustiveness error naming the missing tag; got: {msg}"
    );
}

/// A branch naming a tag the variant does not declare FAILS TO COMPILE with a
/// both-sides exhaustiveness error naming the extra tag.
#[test]
fn branch_extra_arm_is_rejected() {
    let source = r#"
decide = stage(
    id = "decide",
    run = "echo",
    agent = "shell",
    produces = contract("D", {
        "choice": field(variant({"first": contract("E", {})})),
    }),
)
first_stage = stage(id = "first", prompt = "first", agent = "worker")
extra_stage = stage(id = "extra", prompt = "extra", agent = "worker")
branch(on = decide, verdict_field = "choice", arms = {
    "first": first_stage,
    "ghost": extra_stage,
})
workflow("wf-branch-extra", root = decide)
"#;
    let err = compile_starlark_execution_program(source, "wf_branch_extra.star", &[])
        .expect_err("a branch with an arm naming a non-existent tag must fail to compile");
    let msg = err.to_string();
    assert!(
        msg.contains("not exhaustive") && msg.contains("non-existent") && msg.contains("ghost"),
        "expected an exhaustiveness error naming the extra tag; got: {msg}"
    );
}

// ── loop gate_verdict ↔ variant-contract cross-check (load-time) ──────────────

/// A loop whose reviewer `produces=` declares the `verdict_field` as a
/// `variant(..)`, but whose `gate_verdict` OMITS one of the variant's tags,
/// FAILS TO COMPILE with a both-sides exhaustiveness error naming the missing
/// tag — the same certification a `branch` gets, applied to the loop gate.
///
/// NON-VACUOUS: a `validate_review_loops` that only checked the gate_verdict's
/// internal shape would compile this clean, and the unmatched tag would only
/// abort at RUNTIME.
#[test]
fn loop_gate_verdict_missing_variant_tag_fails_kata_check_at_load() {
    let source = r#"
worker = stage(id = "implement", prompt = "Implement", agent = "worker")
gate = stage(
    id = "review",
    run = "echo",
    agent = "shell",
    depends_on = [worker],
    produces = contract("Decision", {
        "decision": field(variant({
            "continue": contract("C", {}),
            "promote": contract("P", {}),
            "park": contract("K", {}),
            "stop": contract("S", {}),
        })),
    }),
)
loop(body = worker, gate = gate, max_iterations = 3, gate_verdict = {
    "field": "decision",
    "approve": ["promote"],
    "refine": ["continue"],
    "block": ["stop"],
})
workflow("wf-loop-gate-missing", root = worker)
"#;
    let err = compile_starlark_execution_program(source, "wf_loop_gate_missing.star", &[])
        .expect_err("a gate_verdict omitting a variant tag must fail to compile");
    let msg = err.to_string();
    assert!(
        msg.contains("not exhaustive")
            && msg.contains("omits variant tags")
            && msg.contains("park"),
        "expected an exhaustiveness error naming the missing tag; got: {msg}"
    );
}

/// A loop `gate_verdict` that routes a tag the reviewer's variant does NOT
/// declare FAILS TO COMPILE with a both-sides error naming the extra tag.
#[test]
fn loop_gate_verdict_extra_tag_fails_kata_check_at_load() {
    let source = r#"
worker = stage(id = "implement", prompt = "Implement", agent = "worker")
gate = stage(
    id = "review",
    run = "echo",
    agent = "shell",
    depends_on = [worker],
    produces = contract("Decision", {
        "decision": field(variant({
            "continue": contract("C", {}),
            "promote": contract("P", {}),
        })),
    }),
)
loop(body = worker, gate = gate, max_iterations = 3, gate_verdict = {
    "field": "decision",
    "approve": ["promote"],
    "refine": ["continue"],
    "block": ["ghost"],
})
workflow("wf-loop-gate-extra", root = worker)
"#;
    let err = compile_starlark_execution_program(source, "wf_loop_gate_extra.star", &[])
        .expect_err("a gate_verdict routing a non-existent variant tag must fail to compile");
    let msg = err.to_string();
    assert!(
        msg.contains("not exhaustive")
            && msg.contains("routes non-existent tags")
            && msg.contains("ghost"),
        "expected an exhaustiveness error naming the extra tag; got: {msg}"
    );
}

/// A loop `gate_verdict` whose tag union EXACTLY equals the reviewer's variant
/// tag set compiles clean — the positive certification path.
#[test]
fn loop_gate_verdict_exhaustive_over_variant_compiles() {
    let source = r#"
worker = stage(id = "implement", prompt = "Implement", agent = "worker")
gate = stage(
    id = "review",
    run = "echo",
    agent = "shell",
    depends_on = [worker],
    produces = contract("Decision", {
        "decision": field(variant({
            "continue": contract("C", {}),
            "promote": contract("P", {}),
            "park": contract("K", {}),
            "stop": contract("S", {}),
        })),
    }),
)
loop(body = worker, gate = gate, max_iterations = 3, gate_verdict = {
    "field": "decision",
    "approve": ["promote", "stop"],
    "refine": ["continue"],
    "block": ["park"],
})
workflow("wf-loop-gate-exact", root = worker)
"#;
    let program = compile_star(source, "wf_loop_gate_exact.star");
    assert_eq!(program.review_loops.len(), 1);
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "verifier diagnostics: {:?}",
        program.verifier.diagnostics
    );
}

/// SKIP condition: a loop whose reviewer declares the `verdict_field` as a BARE
/// STRING (not a `variant(..)`) is NOT cross-checked — the union may be any
/// custom vocabulary. This keeps existing non-variant custom-verdict loops (e.g.
/// `loop-custom-verdict-smoke`) valid.
#[test]
fn loop_gate_verdict_bare_string_verdict_field_skips_cross_check() {
    let source = r#"
worker = stage(id = "implement", prompt = "Implement", agent = "worker")
gate = stage(
    id = "review",
    run = "echo",
    agent = "shell",
    depends_on = [worker],
    produces = contract("Decision", {"decision": field("string")}),
)
loop(body = worker, gate = gate, max_iterations = 3, gate_verdict = {
    "field": "decision",
    "approve": ["promote"],
    "refine": ["again"],
    "block": ["stop"],
})
workflow("wf-loop-gate-bare-string", root = worker)
"#;
    let program = compile_star(source, "wf_loop_gate_bare_string.star");
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "a bare-string verdict_field must skip the variant cross-check; diagnostics: {:?}",
        program.verifier.diagnostics
    );
}

/// A branch whose `verdict_field` is not a `variant(..)` FAILS TO COMPILE — a
/// branch routes only on a discriminated-union verdict.
#[test]
fn branch_non_variant_field_is_rejected() {
    let source = r#"
decide = stage(
    id = "decide",
    run = "echo",
    agent = "shell",
    produces = contract("D", {"choice": field("string")}),
)
first_stage = stage(id = "first", prompt = "first", agent = "worker")
branch(on = decide, verdict_field = "choice", arms = {"first": first_stage})
workflow("wf-branch-nonvariant", root = decide)
"#;
    let err = compile_starlark_execution_program(source, "wf_branch_nonvariant.star", &[])
        .expect_err("a branch on a non-variant field must fail to compile");
    let msg = err.to_string();
    assert!(
        msg.contains("must be a variant"),
        "expected a non-variant verdict_field error; got: {msg}"
    );
}

/// A branch whose condition stage declares no `produces=` contract FAILS TO
/// COMPILE — there is no verdict field to route on.
#[test]
fn branch_condition_without_produces_is_rejected() {
    let source = r#"
decide = stage(id = "decide", run = "echo", agent = "shell")
first_stage = stage(id = "first", prompt = "first", agent = "worker")
branch(on = decide, verdict_field = "choice", arms = {"first": first_stage})
workflow("wf-branch-noproduces", root = decide)
"#;
    let err = compile_starlark_execution_program(source, "wf_branch_noproduces.star", &[])
        .expect_err("a branch whose condition declares no produces= must fail to compile");
    let msg = err.to_string();
    assert!(
        msg.contains("no produces= contract") || msg.contains("produces=contract"),
        "expected a no-produces error; got: {msg}"
    );
}

/// A `branch(..)` with an unknown arm target stage is a clean DSL error.
#[test]
fn branch_unknown_target_is_rejected() {
    let source = r#"
decide = stage(
    id = "decide",
    run = "echo",
    agent = "shell",
    produces = contract("D", {
        "choice": field(variant({"first": contract("E", {})})),
    }),
)
branch(on = decide, verdict_field = "choice", arms = {"first": "no_such_stage"})
workflow("wf-branch-badtarget", root = decide)
"#;
    let err = compile_starlark_execution_program(source, "wf_branch_badtarget.star", &[])
        .expect_err("a branch arm referencing an unknown stage must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown target stage"),
        "expected an unknown-target error; got: {msg}"
    );
}

/// A DIRECT rejoin — a stage depending on a
/// target of EACH of two arms — FAILS TO COMPILE. The settled fork is "no rejoins"
/// (arms must be disjoint); without this guard the rejoin stage would be silently
/// Skipped at runtime by the non-taken arm's `skip_dependents` cascade. The error
/// names the rejoin stage and both offending arms.
#[test]
fn branch_direct_rejoin_is_rejected() {
    let source = r#"
decide = stage(
    id = "decide",
    run = "echo",
    agent = "shell",
    produces = contract("D", {
        "choice": field(variant({
            "first": contract("E", {}),
            "second": contract("E2", {}),
        })),
    }),
)
first_stage = stage(id = "first", prompt = "first", agent = "worker")
second_stage = stage(id = "second", prompt = "second", agent = "worker")
closeout = stage(id = "closeout", prompt = "close", agent = "worker", depends_on = [first_stage, second_stage])
branch(on = decide, verdict_field = "choice", arms = {
    "first": first_stage,
    "second": second_stage,
})
workflow("wf-branch-direct-rejoin", root = decide)
"#;
    let err = compile_starlark_execution_program(source, "wf_branch_direct_rejoin.star", &[])
        .expect_err("a direct rejoin across two branch arms must fail to compile");
    let msg = err.to_string();
    assert!(
        msg.contains("must be disjoint")
            && msg.contains("rejoins are not supported")
            && msg.contains("closeout")
            && msg.contains("first")
            && msg.contains("second"),
        "expected a disjoint-arms rejoin error naming the rejoin stage and both arms; got: {msg}"
    );
}

/// A TRANSITIVE rejoin — a stage depending on a
/// CHILD of arm A and a CHILD of arm B (so the rejoin is two hops below the arm
/// targets, not a direct arm target) — FAILS TO COMPILE. This proves the guard
/// computes the full forward closure of each arm, not just direct arm targets.
#[test]
fn branch_transitive_rejoin_is_rejected() {
    let source = r#"
decide = stage(
    id = "decide",
    run = "echo",
    agent = "shell",
    produces = contract("D", {
        "choice": field(variant({
            "first": contract("E", {}),
            "second": contract("E2", {}),
        })),
    }),
)
first_stage = stage(id = "first", prompt = "first", agent = "worker")
second_stage = stage(id = "second", prompt = "second", agent = "worker")
first_child = stage(id = "first_child", prompt = "fc", agent = "worker", depends_on = [first_stage])
second_child = stage(id = "second_child", prompt = "sc", agent = "worker", depends_on = [second_stage])
closeout = stage(id = "closeout", prompt = "close", agent = "worker", depends_on = [first_child, second_child])
branch(on = decide, verdict_field = "choice", arms = {
    "first": first_stage,
    "second": second_stage,
})
workflow("wf-branch-transitive-rejoin", root = decide)
"#;
    let err = compile_starlark_execution_program(source, "wf_branch_transitive_rejoin.star", &[])
        .expect_err("a transitive rejoin two hops below the arm targets must fail to compile");
    let msg = err.to_string();
    assert!(
        msg.contains("must be disjoint")
            && msg.contains("rejoins are not supported")
            && msg.contains("closeout"),
        "expected a disjoint-arms rejoin error naming the transitive rejoin stage; got: {msg}"
    );
}

/// A `workflow()` with no `branch(..)` carries an empty branch_routes list AND
/// hashes byte-identically (normalized-definition hash) to the same workflow —
/// proving the field is additive and default-empty (no-branch packs unchanged).
#[test]
fn workflow_without_branch_has_empty_routes_and_stable_hash() {
    let a_src = r#"
impl = stage(id = "implement", prompt = "do it", agent = "worker")
workflow("wf-nobranch", root = impl)
"#;
    let a = compile_star(a_src, "wf_nobranch_a.star");
    assert!(
        a.branch_routes.is_empty(),
        "a workflow without branch() must have an empty branch_routes list"
    );
    // A second identical compile yields the identical normalized-definition hash.
    let b = compile_star(a_src, "wf_nobranch_b.star");
    assert_eq!(
        a.source.normalized_definition_hash, b.source.normalized_definition_hash,
        "identical no-branch workflows must hash identically (branch_routes is skip-if-empty)"
    );
}

// ── loop(bounds=) lowering ───────────────────────────────────────────────────

/// A loop source whose `gate` depends on the `body`, parametrized by an optional
/// `bounds=` clause so the byte-identical regression compares the exact same
/// graph with and without `bounds=`.
fn loop_with_bounds_clause(bounds_clause: &str) -> String {
    format!(
        r#"
worker = stage(id = "implement", prompt = "Implement", agent = "worker")
reviewer = stage(
    id = "review",
    prompt = "Review",
    agent = "worker",
    depends_on = [worker],
)
loop(body = worker, gate = reviewer, max_iterations = 3{bounds_clause})
workflow("wf-loop-bounds", root = worker)
"#
    )
}

/// HEADLINE. `loop(.., bounds=[cost_bound(..), time_bound(..)])` lowers the typed
/// loop-scope bounds onto the checked `ReviewLoop` in canonical order (`Time`
/// before `Cost`) regardless of author order, converting USD → micro-USD. The
/// iteration ceiling stays on `max_iterations`.
#[test]
fn loop_bounds_lower_onto_review_loop_in_canonical_order() {
    // Author order is Cost-then-Time; the lowered loop must canonicalize to
    // Time-then-Cost so author order never changes the definition hash.
    let source = loop_with_bounds_clause(", bounds = [cost_bound(1.5), time_bound(60000)]");
    let program = compile_star(&source, "wf_loop_bounds.star");

    assert_eq!(program.review_loops.len(), 1, "exactly one review loop");
    let lp = &program.review_loops[0];
    assert_eq!(lp.worker_stage.as_str(), "implement");
    assert_eq!(lp.reviewer_stage.as_str(), "review");
    assert_eq!(lp.max_iterations, 3);
    assert_eq!(
        lp.bounds,
        vec![
            Bound::Time { ms: 60000 },
            Bound::Cost {
                micro_usd: 1_500_000
            },
        ],
        "loop bounds must lower in canonical order (Time before Cost) with USD→micro-USD conversion"
    );
}

/// A `loop()` that omits `bounds=` carries an empty `ReviewLoop::bounds` list —
/// proving the field is additive and default-empty.
#[test]
fn loop_without_bounds_has_empty_loop_bounds() {
    let source = loop_with_bounds_clause("");
    let program = compile_star(&source, "wf_loop_no_bounds.star");
    assert_eq!(program.review_loops.len(), 1);
    assert!(
        program.review_loops[0].bounds.is_empty(),
        "a loop without bounds= must have an empty loop-scope bounds list"
    );
}

/// Two loop bounds of the same kind are rejected at the `loop()` call with a
/// clear per-kind-uniqueness error.
#[test]
fn loop_duplicate_bound_kind_is_rejected() {
    let source = loop_with_bounds_clause(", bounds = [time_bound(1000), time_bound(2000)]");
    let err = compile_starlark_execution_program(&source, "wf_loop_dup.star", &[])
        .expect_err("duplicate-kind loop bounds must be rejected at the loop() call");
    let msg = err.to_string();
    assert!(
        msg.contains("duplicate time bound") && msg.contains("loop() bounds= invalid"),
        "expected a per-kind-uniqueness error scoped to loop(); got: {msg}"
    );
}

/// A non-bound value in a loop's `bounds=` is a clean type error naming `loop()`.
#[test]
fn loop_bounds_rejects_non_bound_value() {
    let source = loop_with_bounds_clause(r#", bounds = ["time_bound"]"#);
    let err = compile_starlark_execution_program(&source, "wf_loop_badbound.star", &[])
        .expect_err("a non-bound entry in a loop's bounds= must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("loop() bounds= entries must be time_bound"),
        "expected a loop-scoped bounds type error; got: {msg}"
    );
}

/// BYTE-IDENTICAL REGRESSION. An empty / omitted loop `bounds=` leaves the
/// normalized-definition hash identical to the same loop with no `bounds=` kwarg
/// at all, because `ReviewLoop::bounds` is `skip_serializing_if = Vec::is_empty`
/// — so a review-loop pack without bounds hashes byte-identically. (`program_hash`
/// legitimately differs by the raw `.star` source bytes; the normalized
/// definition hash is the source-byte-independent identity the byte-identical
/// guarantee is defined against.)
#[test]
fn loop_empty_bounds_does_not_change_definition_hash() {
    let without = loop_with_bounds_clause("");
    let with_empty = loop_with_bounds_clause(", bounds = []");
    let a = compile_star(&without, "wf_loop_hash_a.star");
    let b = compile_star(&with_empty, "wf_loop_hash_b.star");
    assert_eq!(
        a.source.normalized_definition_hash, b.source.normalized_definition_hash,
        "an empty loop bounds= must not change the normalized definition hash"
    );
}

// ── loop(gate_verdict=) lowering ─────────────────────────────────────────────

/// A loop source parametrized by an optional `gate_verdict=` clause so the
/// byte-identical regression compares the exact same graph with and without it.
fn loop_with_gate_verdict_clause(clause: &str) -> String {
    format!(
        r#"
worker = stage(id = "implement", prompt = "Implement", agent = "worker")
reviewer = stage(
    id = "review",
    prompt = "Review",
    agent = "worker",
    depends_on = [worker],
)
loop(body = worker, gate = reviewer, max_iterations = 3{clause})
workflow("wf-loop-gate-verdict", root = worker)
"#
    )
}

/// HEADLINE. `loop(.., gate_verdict={"field": .., "approve": [..], ..})` lowers a
/// custom verdict vocabulary onto the checked `ReviewLoop::gate_verdict`.
#[test]
fn loop_gate_verdict_lowers_onto_review_loop() {
    let source = loop_with_gate_verdict_clause(
        r#", gate_verdict = {"field": "decision", "approve": ["promote"], "refine": ["again"], "block": ["stop"]}"#,
    );
    let program = compile_star(&source, "wf_loop_gv.star");
    assert_eq!(program.review_loops.len(), 1);
    let cfg = program.review_loops[0]
        .gate_verdict
        .as_ref()
        .expect("gate_verdict lowered");
    assert_eq!(cfg.verdict_field.as_str(), "decision");
    assert_eq!(cfg.approve, vec![smol_str::SmolStr::new("promote")]);
    assert_eq!(cfg.refine, vec![smol_str::SmolStr::new("again")]);
    assert_eq!(cfg.block, vec![smol_str::SmolStr::new("stop")]);
}

/// A `loop()` that omits `gate_verdict=` carries `None` — additive + default.
#[test]
fn loop_without_gate_verdict_is_none() {
    let source = loop_with_gate_verdict_clause("");
    let program = compile_star(&source, "wf_loop_no_gv.star");
    assert_eq!(program.review_loops.len(), 1);
    assert!(
        program.review_loops[0].gate_verdict.is_none(),
        "a loop without gate_verdict= must carry None"
    );
}

/// Overlapping tag-sets are rejected at the `loop()` call with a clear error.
#[test]
fn loop_gate_verdict_overlapping_tags_rejected() {
    let source = loop_with_gate_verdict_clause(
        r#", gate_verdict = {"field": "decision", "approve": ["x"], "refine": ["x"], "block": ["stop"]}"#,
    );
    let err = compile_starlark_execution_program(&source, "wf_loop_gv_overlap.star", &[])
        .expect_err("overlapping gate_verdict tag-sets must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("gate_verdict invalid") && msg.contains("appears in both"),
        "expected an overlapping-tag error; got: {msg}"
    );
}

/// An empty tag-set is rejected.
#[test]
fn loop_gate_verdict_empty_tagset_rejected() {
    let source = loop_with_gate_verdict_clause(
        r#", gate_verdict = {"field": "decision", "approve": [], "refine": ["again"], "block": ["stop"]}"#,
    );
    let err = compile_starlark_execution_program(&source, "wf_loop_gv_empty.star", &[])
        .expect_err("empty gate_verdict tag-set must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("gate_verdict invalid") && msg.contains("approve"),
        "expected an empty-tag-set error naming approve; got: {msg}"
    );
}

/// An empty field is rejected.
#[test]
fn loop_gate_verdict_empty_field_rejected() {
    let source = loop_with_gate_verdict_clause(
        r#", gate_verdict = {"field": "", "approve": ["a"], "refine": ["b"], "block": ["c"]}"#,
    );
    let err = compile_starlark_execution_program(&source, "wf_loop_gv_field.star", &[])
        .expect_err("empty gate_verdict field must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("gate_verdict invalid") && msg.contains("non-empty"),
        "expected an empty-field error; got: {msg}"
    );
}

/// BYTE-IDENTICAL REGRESSION. An omitted `gate_verdict=` leaves the
/// normalized-definition hash identical to the same loop with no `gate_verdict=`
/// — `ReviewLoop::gate_verdict` is `skip_serializing_if = Option::is_none`, so
/// a review-loop pack without a custom vocabulary hashes byte-identically.
#[test]
fn loop_no_gate_verdict_does_not_change_definition_hash() {
    // A loop with NO gate_verdict kwarg vs. the same loop is trivially equal; the
    // meaningful regression is that adding the field type to ReviewLoop did not
    // perturb the no-config hash. Compare a no-gate_verdict loop against the
    // canonical bounds-less loop builder (same graph, no gate_verdict).
    let a = compile_star(&loop_with_gate_verdict_clause(""), "wf_loop_gv_hash_a.star");
    let b = compile_star(&loop_with_bounds_clause(""), "wf_loop_gv_hash_b.star");
    // Different workflow names ⇒ hashes differ legitimately; instead assert the
    // gate_verdict field is absent from the serialized review loop (the true
    // byte-identical property). Re-serialize the lowered review loop.
    let _ = (a, b);
    let program = compile_star(&loop_with_gate_verdict_clause(""), "wf_loop_gv_hash_c.star");
    let json = serde_json::to_string(&program.review_loops[0]).expect("serialize review loop");
    assert!(
        !json.contains("gate_verdict"),
        "a loop without gate_verdict= must omit the field from serialization (byte-identical); got {json}"
    );
}

/// The terminal-effect relaxation is PROMOTE-ONLY: a `park` tears the
/// workspace down and parks the candidate off trunk, so `forge_export
/// depends_on park` is refused by the terminality rule, naming why.
#[test]
fn forge_export_may_not_depend_on_park() {
    let source = r#"
park = stage(id = "park", agent = "workspace_effect", op = "park")
publish = stage(
    id = "publish",
    agent = "workspace_effect",
    op = "forge_export",
    depends_on = ["park"],
)
workflow("wf-forge-park", root = [park, publish])
"#;
    let err = compile_starlark_execution_program(source, "wf_forge_on_park_dep.star", &[])
        .expect_err("forge_export may not depend on a park");
    let msg = err.to_string();
    assert!(
        msg.contains("forge_export") && msg.contains("promote") && msg.contains("park"),
        "error must explain the promote-only exception and name the park; got: {msg}"
    );
}

/// `forge_export_without_commit`, compiled from `body`: the refusal names the
/// export stage.
fn assert_without_commit(body: &str, file: &str) {
    let err = compile_starlark_execution_program(body, file, &[])
        .expect_err("a forge_export with no commit or promote ancestor is refused");
    let msg = err.to_string();
    assert!(
        msg.contains("forge_export_without_commit") && msg.contains("\"publish\""),
        "the refusal names the rule and the export; got: {msg}"
    );
}

/// THE COMMIT-ANCESTOR RULE, refused shape 1 — DIRECT: a `forge_export` that
/// depends on nothing has no `commit` or `promote` ancestor.
#[test]
fn forge_export_with_no_ancestor_is_refused() {
    assert_without_commit(
        r#"
publish = stage(id = "publish", agent = "workspace_effect", op = "forge_export")
workflow("wf-forge-alone", root = [publish], worktree_isolated = True)
"#,
        "wf_forge_alone.star",
    );
}

/// Refused shape 2 — THROUGH A SHELL: a writable shell stage the export
/// depends on is no `commit`, and nothing upstream of it is either.
#[test]
fn forge_export_after_only_a_shell_is_refused() {
    assert_without_commit(
        r#"
edit = stage(id = "edit", agent = "shell", run = "true")
publish = stage(
    id = "publish",
    agent = "workspace_effect",
    op = "forge_export",
    depends_on = ["edit"],
)
workflow("wf-forge-shell", root = [edit], worktree_isolated = True)
"#,
        "wf_forge_shell.star",
    );
}

/// Refused shape 3 — THROUGH A ROUTE ARM: the export is the `go` arm of a
/// route on a shell stage with no `commit` upstream.
#[test]
fn forge_export_as_a_route_arm_without_a_commit_is_refused() {
    assert_without_commit(
        r#"
_R = contract("R", {"status": field(enum("go", "stop"))})
check = stage(id = "check", agent = "shell", run = "printf '{\"status\": \"go\"}'", produces = _R)
publish = stage(
    id = "publish",
    agent = "workspace_effect",
    op = "forge_export",
    depends_on = ["check"],
)
halt = stage(id = "halt", agent = "shell", run = "true", depends_on = ["check"])
route(on = check, field = "status", arms = {"go": publish, "stop": halt})
workflow("wf-forge-route", root = [check], worktree_isolated = True)
"#,
        "wf_forge_route.star",
    );
}

/// Admitted: a `commit` the export depends on DIRECTLY, and a `commit` that is
/// a TRANSITIVE ancestor — through a shell stage and through a route arm. A
/// writable stage between the `commit` and the export is admitted at CHECK
/// and refused at run time when it changed the candidate
/// (`forge_export_uncommitted_candidate`).
#[test]
fn forge_export_with_a_commit_ancestor_is_admitted() {
    for (body, file) in [
        (
            r#"
snap = stage(id = "snap", agent = "workspace_effect", op = "commit")
publish = stage(id = "publish", agent = "workspace_effect", op = "forge_export", depends_on = ["snap"])
workflow("wf-forge-commit", root = [snap], worktree_isolated = True)
"#,
            "wf_forge_commit.star",
        ),
        (
            r#"
snap = stage(id = "snap", agent = "workspace_effect", op = "commit")
look = stage(id = "look", agent = "shell", run = "true", depends_on = ["snap"])
publish = stage(id = "publish", agent = "workspace_effect", op = "forge_export", depends_on = ["look"])
workflow("wf-forge-commit-shell", root = [snap], worktree_isolated = True)
"#,
            "wf_forge_commit_shell.star",
        ),
        (
            r#"
_R = contract("R", {"status": field(enum("go", "stop"))})
snap = stage(id = "snap", agent = "workspace_effect", op = "commit")
check = stage(id = "check", agent = "shell", run = "printf '{\"status\": \"go\"}'", produces = _R, depends_on = ["snap"])
publish = stage(id = "publish", agent = "workspace_effect", op = "forge_export", depends_on = ["check"])
halt = stage(id = "halt", agent = "shell", run = "true", depends_on = ["check"])
route(on = check, field = "status", arms = {"go": publish, "stop": halt})
workflow("wf-forge-commit-route", root = [snap], worktree_isolated = True)
"#,
            "wf_forge_commit_route.star",
        ),
    ] {
        compile_starlark_execution_program(body, file, &[])
            .unwrap_or_else(|err| panic!("{file}: a commit ancestor admits the export: {err}"));
    }
}

/// Forge-only kwargs on a non-`forge_export` op are rejected at construction.
#[test]
fn forge_kwargs_rejected_on_non_forge_effect_op() {
    let source = r#"
s = stage(id = "s", agent = "workspace_effect", op = "park", body = "b")
workflow("wf", root = s)
"#;
    let err = compile_starlark_execution_program(source, "wf_forge_on_park.star", &[])
        .expect_err("forge kwargs on op=park must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("body=") && msg.contains("forge_export"),
        "error should explain body= is forge_export-only; got: {msg}"
    );
}

/// A pack names no machine fact: `forge_export` has no `remote=` and no
/// `base=` keyword (the base is the run's frozen landable branch, the remote
/// is inherited), so either is refused at CHECK as an unknown keyword, naming
/// it.
#[test]
fn forge_export_takes_no_remote_or_base() {
    for kwarg in ["remote = \"origin\"", "base = \"main\""] {
        let source = format!(
            r#"
snap = stage(id = "snap", agent = "workspace_effect", op = "commit")
publish = stage(id = "publish", agent = "workspace_effect", op = "forge_export", depends_on = ["snap"], {kwarg})
workflow("wf-forge-kwarg", root = [snap], worktree_isolated = True)
"#
        );
        let err = compile_starlark_execution_program(&source, "wf_forge_kwarg.star", &[])
            .expect_err("a forge_export naming a remote or a base is refused");
        let name = kwarg.split(' ').next().unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains(name),
            "the refusal names the `{name}` keyword; got: {msg}"
        );
    }
}

/// Forge-only kwargs on a non-effect agent are rejected at construction.
#[test]
fn forge_kwargs_rejected_on_non_effect_agent() {
    let source = r#"
s = stage(id = "s", prompt = "hi", agent = "worker", title = "PR")
workflow("wf", root = s)
"#;
    let err = compile_starlark_execution_program(source, "wf_forge_on_worker.star", &[])
        .expect_err("forge kwargs on a non-effect agent must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("title=") && msg.contains("forge_export"),
        "error should explain title= is forge_export-only; got: {msg}"
    );
}

/// A non-effect agent carrying `op=` is rejected at construction.
#[test]
fn op_rejected_on_non_effect_agent() {
    let source = r#"
s = stage(id = "s", prompt = "hi", agent = "worker", op = "park")
workflow("wf", root = s)
"#;
    let err = compile_starlark_execution_program(source, "wf_bad_op.star", &[])
        .expect_err("op= on a non-effect agent must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("op=") && msg.contains("workspace-effect"),
        "error should explain op= is effect-only; got: {msg}"
    );
}

/// `agent="workspace_effect"` with no `op=` is rejected at construction.
#[test]
fn workspace_effect_without_op_rejected() {
    let source = r#"
s = stage(id = "s", agent = "workspace_effect")
workflow("wf", root = s)
"#;
    let err = compile_starlark_execution_program(source, "wf_no_op.star", &[])
        .expect_err("workspace_effect without op= must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("requires op="),
        "error should require op=; got: {msg}"
    );
}

/// An effect stage that also passes `prompt=`/`run=` is rejected (the directive
/// is synthesized, not author-supplied).
#[test]
fn workspace_effect_rejects_prompt() {
    let source = r#"
s = stage(id = "s", agent = "workspace_effect", op = "park", prompt = "nope")
workflow("wf", root = s)
"#;
    let err = compile_starlark_execution_program(source, "wf_effect_prompt.star", &[])
        .expect_err("effect stage must reject prompt=");
    assert!(
        err.to_string().contains("does not accept prompt="),
        "got: {err}"
    );
}

/// An invalid `op=` value is rejected.
#[test]
fn workspace_effect_invalid_op_rejected() {
    let source = r#"
s = stage(id = "s", agent = "workspace_effect", op = "bogus")
workflow("wf", root = s)
"#;
    let err = compile_starlark_execution_program(source, "wf_bad_opval.star", &[])
        .expect_err("invalid op value must be rejected");
    assert!(err.to_string().contains("invalid"), "got: {err}");
}

/// An effect stage emits only the fixed `{operation, ref_name, commit_sha}`
/// envelope, so an author-supplied `produces=` is a construction-time error.
#[test]
fn workspace_effect_rejects_produces() {
    let source = r#"
out = contract("Out", {"x": field("string")})
s = stage(id = "s", agent = "workspace_effect", op = "park", produces = out)
workflow("wf", root = s)
"#;
    let err = compile_starlark_execution_program(source, "wf_effect_produces.star", &[])
        .expect_err("effect stage must reject produces=");
    assert!(
        err.to_string().contains("does not accept produces="),
        "got: {err}"
    );
}

/// Symmetrically, an effect stage rejects `consumes=`.
#[test]
fn workspace_effect_rejects_consumes() {
    let source = r#"
inp = contract("In", {"y": field("string")})
s = stage(id = "s", agent = "workspace_effect", op = "park", consumes = inp)
workflow("wf", root = s)
"#;
    let err = compile_starlark_execution_program(source, "wf_effect_consumes.star", &[])
        .expect_err("effect stage must reject consumes=");
    assert!(
        err.to_string().contains("does not accept consumes="),
        "got: {err}"
    );
}

/// L2: an effect runs in-process and never spawns a subprocess, so `sandbox=`
/// is meaningless on it and rejected.
#[test]
fn workspace_effect_rejects_sandbox() {
    let source = r#"
s = stage(id = "s", agent = "workspace_effect", op = "park", sandbox = "build")
workflow("wf", root = s)
"#;
    let err = compile_starlark_execution_program(source, "wf_effect_sandbox.star", &[])
        .expect_err("effect stage must reject sandbox=");
    assert!(
        err.to_string().contains("does not accept sandbox="),
        "got: {err}"
    );
}

/// An effect stage is TERMINAL — park/promote tears down the worktree, so a
/// stage that `depends_on` it would dispatch into a torn-down workspace. Such a
/// dependency must be rejected at load time, naming both stages.
#[test]
fn workspace_effect_terminal_rejects_dependents() {
    let source = r#"
park = stage(id = "park", agent = "workspace_effect", op = "park")
after = stage(id = "after", prompt = "do", agent = "worker", depends_on = [park])
workflow("wf", root = [park, after])
"#;
    let err = compile_starlark_execution_program(source, "wf_effect_terminal.star", &[])
        .expect_err("a stage may not depends_on an effect stage");
    let msg = err.to_string();
    assert!(
        msg.contains("terminal") && msg.contains("park") && msg.contains("after"),
        "error must name both stages and explain terminality; got: {msg}"
    );
}

/// ARM 2 — a `depends_on` edge into a TERMINAL effect is still REFUSED, and the
/// message names THE OP and why THAT op is terminal.
///
/// Both terminal worktree-tearing ops are covered. A generic message would tell
/// a `commit` author about "park/promote", which is never their case; the
/// message splices `WorkspaceEffectOp::terminal_reason` — the single
/// classifier — so the refusal and the justification cannot drift apart.
#[test]
fn workspace_effect_terminal_ops_refuse_dependents_and_name_the_op() {
    for (op, expected_fragment) in [
        ("park", "force-creates its parked ref"),
        ("promote", "fast-forwards the trusted base ref"),
    ] {
        let source = format!(
            r#"
eff = stage(id = "eff", agent = "workspace_effect", op = "{op}")
after = stage(id = "after", prompt = "do", agent = "worker", depends_on = [eff])
workflow("wf-terminal", root = [eff, after])
"#
        );
        let err = compile_starlark_execution_program(&source, "wf_effect_terminal_op.star", &[])
            .err()
            .unwrap_or_else(|| panic!("a stage may not depends_on a terminal `{op}` effect"));
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("op=\"{op}\"")),
            "refusal must NAME the op so the author learns their own case; got: {msg}"
        );
        assert!(
            msg.contains(expected_fragment),
            "refusal must say why `{op}` specifically is terminal (expected {expected_fragment:?}); \
             got: {msg}"
        );
        assert!(
            msg.contains("eff") && msg.contains("after"),
            "refusal must name both stages; got: {msg}"
        );
    }
}

// ---- `parallel`: workflow(max_concurrency=N) ----

/// `workflow(max_concurrency=2)` lowers onto the checked program's
/// `max_concurrency` field.
#[test]
fn workflow_max_concurrency_lowers_onto_program() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
b = stage(id = "b", prompt = "b", agent = "worker")
workflow("wf-throttle", root = [a, b], max_concurrency = 2)
"#;
    let program = compile_star(source, "wf_throttle.star");
    assert_eq!(program.max_concurrency, Some(2));
}

/// Omitting `max_concurrency=` leaves the field `None`, and two compiles of one
/// source agree on the program hash. The throttle folds into program identity:
/// the same decoded program — one source, so one `source_hash` — re-derives a
/// DIFFERENT hash once its `max_concurrency` is set. Two source texts are never
/// compared, since `source_hash` alone would tell them apart.
#[test]
fn workflow_max_concurrency_absent_is_none_and_hash_stable() {
    let base = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
b = stage(id = "b", prompt = "b", agent = "worker")
workflow("wf-throttle", root = [a, b])
"#;
    let base_program = compile_star(base, "wf_base.star");
    assert_eq!(base_program.max_concurrency, None);
    assert_eq!(
        compile_star(base, "wf_base.star").program_hash,
        base_program.program_hash,
        "two compiles of one source agree on the program hash"
    );
    let rederive = kata_program::execution_program::rederive_program_hash;
    assert_eq!(rederive(&base_program), base_program.program_hash);
    let decoded: kata_program::execution_program::ExecutionProgram =
        serde_json::from_slice(&serde_json::to_vec(&base_program).expect("the program encodes"))
            .expect("the program decodes");
    let mut throttled = decoded.clone();
    throttled.max_concurrency = Some(2);
    assert_eq!(
        throttled.source.source_hash,
        base_program.source.source_hash
    );
    assert_eq!(rederive(&decoded), base_program.program_hash);
    assert_ne!(
        rederive(&throttled),
        base_program.program_hash,
        "max_concurrency=N must change the program hash of the same program"
    );
}

/// `workflow(max_concurrency=0)` is rejected at load time with a clear error.
#[test]
fn workflow_max_concurrency_zero_is_rejected() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
workflow("wf-bad", root = a, max_concurrency = 0)
"#;
    let err = compile_starlark_execution_program(source, "wf_bad.star", &[])
        .expect_err("max_concurrency = 0 must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("max_concurrency") && msg.contains(">= 1"),
        "error must explain the >= 1 requirement; got: {msg}"
    );
}

/// A negative `max_concurrency` is rejected the same way (the `-1` sentinel is
/// reserved for "unset"; an explicit negative is still an error).
#[test]
fn workflow_max_concurrency_negative_is_rejected() {
    let source = r#"
a = stage(id = "a", prompt = "a", agent = "worker")
workflow("wf-bad", root = a, max_concurrency = -5)
"#;
    let err = compile_starlark_execution_program(source, "wf_bad_neg.star", &[])
        .expect_err("a negative max_concurrency must be rejected");
    assert!(err.to_string().contains("max_concurrency"));
}

// ---------------------------------------------------------------------------
// The `subworkflow(pack=..)` AUTHORING path.
//
// These prove the marker survives the FULL parse → compile chain: a
// `subworkflow(pack="lib")` stage lowers, through `StageDefinition::subworkflow`
// and the compiler carry, onto the checked-IR `ExecutionProgramStage::subworkflow`
// (`SubworkflowSpec`) that the (already-built + certified) runtime diverts on.
// The whole point of the authoring layer is that this marker reaches the IR —
// the runtime does the rest given the marker.
// ---------------------------------------------------------------------------

/// A `subworkflow(pack="lib")` stage compiles to a checked stage whose
/// `subworkflow` marker is `Some(SubworkflowSpec { pack: "lib", bound: <lib compiled>, .. })`,
/// while a NORMAL upstream stage in the SAME program
/// lowers `subworkflow: None` (additivity). Also exercises `depends_on=` wiring
/// (the subworkflow stage depends on the normal stage → one edge).
#[test]
fn subworkflow_dsl_stage_lowers_marker_through_full_compile_chain() {
    let source = r#"
seed = stage(
    id = "seed",
    prompt = "produce a brief",
    agent = "worker",
)

child = subworkflow(
    id = "child",
    pack = "lib",
    depends_on = [seed],
)

workflow("wf-subworkflow", root = seed)
"#;

    let library = common::child_library(&[("lib", common::SHELL_CHILD_PACK)]);
    let program = compile_starlark_execution_program(
        source,
        "wf_subworkflow.star",
        &[library.path().to_path_buf()],
    )
    .expect("the parent compiles against a library holding its child");

    assert_eq!(
        program.verifier.status,
        VerifierStatus::Pass,
        "verifier diagnostics: {:?}",
        program.verifier.diagnostics
    );

    // The subworkflow stage carries the marker through to the checked IR, with the
    // child program BOUND at check.
    let child = program
        .stages
        .get(&StageId("child".into()))
        .expect("the `child` subworkflow stage is present");
    let spec = child
        .subworkflow
        .as_ref()
        .expect("the subworkflow marker must survive parse → compile onto the checked IR");
    assert_eq!(spec.pack.as_str(), "lib");
    assert!(spec.params.is_empty());
    assert_eq!(spec.bound.program().workflow_name.as_str(), "child-wf");
    assert_eq!(spec.bound.program_hash(), spec.bound.program().program_hash);
    assert_eq!(
        child.depends_on,
        vec![StageId("seed".into())],
        "subworkflow(depends_on=[seed]) wires the upstream dependency"
    );

    // Additivity: a NORMAL stage in the same program lowers no marker.
    let seed = program
        .stages
        .get(&StageId("seed".into()))
        .expect("the `seed` stage is present");
    assert_eq!(
        seed.subworkflow, None,
        "a non-subworkflow stage must lower subworkflow: None (additive)"
    );
}

/// A `subworkflow()` with an empty `pack=` is a clean authoring error, never a
/// silently-marked stage.
#[test]
fn subworkflow_dsl_rejects_empty_pack() {
    let source = r#"
child = subworkflow(pack = "")

workflow("wf-bad-subworkflow", root = child)
"#;
    let err = compile_starlark_execution_program(source, "wf_bad_subworkflow.star", &[])
        .expect_err("an empty pack= must be rejected");
    assert!(
        err.to_string().contains("pack"),
        "error should name the empty pack=; got: {err}"
    );
}

/// An ordinary stage that never mentions `subworkflow` carries no marker and
/// hashes IDENTICALLY across compiles — the field is serde-default +
/// `skip_serializing_if`, so a non-subworkflow program carries no such key. We
/// assert the marker is absent AND the program hash is non-zero and
/// stable across two compiles of the same source.
#[test]
fn subworkflow_absent_is_byte_identical_and_stable() {
    let source = r#"
only = stage(id = "only", prompt = "do the thing")
workflow("star-plain", root = [only])
"#;
    let first = compile_star(source, "plain.star");
    let second = compile_star(source, "plain.star");

    let only = first
        .stages
        .get(&StageId("only".into()))
        .expect("the `only` stage is present");
    assert_eq!(
        only.subworkflow, None,
        "a stage that never mentions subworkflow carries no marker"
    );
    assert_ne!(
        first.program_hash,
        ContentHash::zero(),
        "a real program has a non-zero hash"
    );
    assert_eq!(
        first.program_hash, second.program_hash,
        "the absent subworkflow field must not perturb the program hash (byte-identical)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Generic refusal: a builtin or a `workflow()` keyword the authoring surface does
// not declare is refused at load, naming it.
// ─────────────────────────────────────────────────────────────────────────────

/// REFUSED SET — an undeclared builtin and an undeclared `workflow()` keyword, and
/// nothing adjacent to them.
///
/// Positive arm: a pack calling `undeclared_builtin(..)` or `undeclared_kind(..)`
/// fails to load, and `workflow(undeclared_kinds=[..])` is an unknown keyword. Each
/// refusal must NAME the identifier, so an author reading the diagnostic learns the
/// name does not exist rather than that their arguments were wrong.
///
/// Negative arm (a refusal must not be wider than its claim): the memory builtins
/// the surface declares — `memory_selector(..)` and `memory_writeback(..)` — still
/// compile, and so does `subworkflow(..)`.
#[test]
fn an_undeclared_builtin_or_keyword_is_refused_by_name_and_nothing_adjacent_is() {
    // --- refused ---
    let builtin_pack = r#"
work = stage(id = "work", prompt = "do work")
undo = stage(id = "undo", prompt = "undo")
undeclared_builtin(body = [work], compensate = [undo])
workflow("wf", root = work)
"#;
    let err = compile_starlark_execution_program(builtin_pack, "wf_builtin.star", &[])
        .expect_err("an undeclared builtin must not resolve");
    let msg = err.to_string();
    assert!(
        msg.contains("undeclared_builtin"),
        "the refusal must name the undeclared builtin, got: {msg}"
    );

    let kind_pack = r#"
s = stage(id = "s", prompt = "p")
workflow(
    "wf",
    root = s,
    undeclared_kinds = [undeclared_kind("finding", contract("b", {"summary": field("string")}))],
)
"#;
    let err = compile_starlark_execution_program(kind_pack, "wf_kind.star", &[])
        .expect_err("an undeclared builtin must not resolve");
    let msg = err.to_string();
    assert!(
        msg.contains("undeclared_kind"),
        "the refusal must name the undeclared builtin, got: {msg}"
    );

    let kwarg_pack = r#"
s = stage(id = "s", prompt = "p")
workflow("wf", root = s, undeclared_kinds = [])
"#;
    let err = compile_starlark_execution_program(kwarg_pack, "wf_kind_kwarg.star", &[])
        .expect_err("workflow(undeclared_kinds=) must not be an accepted keyword");
    let msg = err.to_string();
    assert!(
        msg.contains("undeclared_kinds"),
        "the refusal must name the undeclared keyword, got: {msg}"
    );

    // --- NOT refused: the declared memory builtins and `subworkflow` ---
    let live_memory = r#"
read = stage(id = "read", prompt = "read")
write = stage(id = "write", prompt = "write", depends_on = [read])
workflow(
    "wf",
    root = read,
    max_memory_selectors = 1,
    memory_selectors = [
        memory_selector("ctx", stage = "read", expose_as = "ctx", kinds = ["task"]),
    ],
    max_memory_writebacks = 1,
    memory_writebacks = [
        memory_writeback("out", stage = "write", field = "memory_writebacks", kinds = ["finding"]),
    ],
)
"#;
    compile_starlark_execution_program(live_memory, "wf_memory_live.star", &[])
        .expect("memory_selector / memory_writeback are declared and must still load");

    let sibling = r#"
a = stage(id = "a", prompt = "a")
child = subworkflow(pack = "lib", id = "child", depends_on = [a])
workflow("wf", root = a)
"#;
    let library = common::child_library(&[("lib", common::SHELL_CHILD_PACK)]);
    compile_starlark_execution_program(
        sibling,
        "wf_subworkflow_kept.star",
        &[library.path().to_path_buf()],
    )
    .expect("subworkflow is declared and must still load");
}
