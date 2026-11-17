//! Unit tests for the `execution_program` module.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kata_types::KataResult;
use kata_types::workflow::{EdgeCondition, StageId};
use serde::Serialize;
use smol_str::SmolStr;

use super::lowering::ExecutionProgramHashSummaryMaterial;
use super::output_ref::{
    OutputReference, extract_head_references, extract_parsed_output_references,
};
use super::verify::edge_condition_routes_purely;
use super::*;

/// Determinism clause 1: EVERY edge-routing condition must be classified as pure
/// (routes on a recorded stage verdict, never wall-clock/RNG/host state). This
/// list is exhaustive over `EdgeCondition`; adding an impure variant must both
/// force a new match arm in `edge_condition_routes_purely` AND be rejected here.
#[test]
fn clause1_all_edge_conditions_route_purely() {
    for condition in [
        EdgeCondition::Always,
        EdgeCondition::OnPass,
        EdgeCondition::OnRefine,
        EdgeCondition::OnBlock,
        EdgeCondition::Custom(SmolStr::new("promote")),
    ] {
        assert!(
            edge_condition_routes_purely(&condition),
            "clause-1: {condition:?} must route purely on a recorded stage verdict"
        );
    }
}

#[derive(Serialize)]
struct LegacyV1ExecutionProgramHashMaterial {
    schema_version: u32,
    workflow_name: SmolStr,
    source: ExecutionProgramSource,
    summary: ExecutionProgramHashSummaryMaterial,
    stages: BTreeMap<StageId, ExecutionProgramStage>,
    edges: Vec<ExecutionProgramEdge>,
}

fn build_program(star: &str) -> ExecutionProgram {
    let checked = crate::starlark_eval::evaluate_starlark_checked(star, "exec_program.star")
        .expect("workflow parses");
    compile_execution_program(&checked).expect("execution program compiles")
}

fn try_build_program(star: &str) -> KataResult<ExecutionProgram> {
    let checked = crate::starlark_eval::evaluate_starlark_checked(star, "exec_program.star")
        .expect("workflow parses");
    compile_execution_program(&checked)
}

// ── SHARED FIXTURES ───────────────────────────────────────────────────────────
//
// Inputs shared by several tests are one named const each: the tests over a
// shared input assert genuinely DIFFERENT properties, so every test stays and
// only the COPY goes. A count of tests is not a count of properties: two tests
// over one input routinely assert two different things.
//
// The workflow NAME in each const is a SHAPE name rather than either copy's, so
// the const says what the input IS. Nothing asserts on it; the `.star` FILE names
// passed beside them are per-test and stay, because they name the test's subject.

/// The minimal prompt-only stage. Shared by
/// [`dispatch_preflight_rejects_verifier_error_program`] (which corrupts the
/// program's verifier) and [`v1_hash_material_omits_empty_checked_extensions`]
/// (which needs a program declaring no checked extensions).
const PROMPT_ONLY_SRC: &str = r#"
only = stage(id = "only", prompt = "do it")
workflow("prompt-only", root = [only])
"#;

/// [`PROMPT_ONLY_SRC`] plus a structured output, which is what makes the stage
/// CONTRACT hash non-trivial. Shared by
/// [`dispatch_preflight_accepts_matching_checked_stage`] (the accept arm) and
/// [`dispatch_preflight_rejects_checked_stage_contract_drift`] (the same input
/// with one policy mutated, so the contract hash moves).
const PROMPT_ONLY_WITH_OUTPUT_SRC: &str = r#"
only = stage(id = "only", prompt = "do it", outputs = {"done": "bool"})
workflow("prompt-only-bool-output", root = [only])
"#;

const RICH_SCHEMA_BASELINE_SRC: &str = r#"
a = stage(id = "a", prompt = "emit", outputs = {"flat_field": "string"})
b = stage(id = "b", depends_on = ["a"], prompt = "use {{ stages.a.parsed.flat_field }}")
workflow("rich-schema-baseline", root = [a])
"#;

#[test]
fn dispatch_preflight_accepts_matching_checked_stage() {
    let checked = crate::starlark_eval::evaluate_starlark_checked(
        PROMPT_ONLY_WITH_OUTPUT_SRC,
        "preflight-ok.star",
    )
    .expect("workflow parses");
    let program = compile_execution_program(&checked).expect("execution program compiles");

    preflight_stage_dispatch(&program, &StageId(SmolStr::new("only")))
        .expect("matching checked stage should pass dispatch preflight");
}

#[test]
fn dispatch_preflight_rejects_verifier_error_program() {
    let checked =
        crate::starlark_eval::evaluate_starlark_checked(PROMPT_ONLY_SRC, "preflight-stale.star")
            .expect("workflow parses");
    let mut program = compile_execution_program(&checked).expect("execution program compiles");
    program.verifier.status = VerifierStatus::Error;
    program.verifier.diagnostics.push(VerifierDiagnostic {
        severity: VerifierSeverity::Error,
        code: SmolStr::new("stage_missing_from_execution_program"),
        stage: Some(StageId(SmolStr::new("only"))),
        message: "stage only was normalized but not lowered into the execution program".into(),
        span: None,
    });

    let err = preflight_stage_dispatch(&program, &StageId(SmolStr::new("only")))
        .expect_err("verifier error should block dispatch");

    assert!(
        err.to_string()
            .contains("checked execution program verifier failed before dispatch"),
        "{err}"
    );
    assert!(
        err.to_string()
            .contains("stage_missing_from_execution_program")
    );
}

#[test]
fn dispatch_preflight_rejects_checked_stage_contract_drift() {
    let checked = crate::starlark_eval::evaluate_starlark_checked(
        PROMPT_ONLY_WITH_OUTPUT_SRC,
        "preflight-drift.star",
    )
    .expect("workflow parses");
    let mut program = compile_execution_program(&checked).expect("execution program compiles");
    program
        .stages
        .get_mut(&StageId(SmolStr::new("only")))
        .expect("checked stage exists")
        .policies
        .validate_retries = 9;

    let err = preflight_stage_dispatch(&program, &StageId(SmolStr::new("only")))
        .expect_err("contract drift should block dispatch");

    assert!(
        err.to_string().contains("contract hash"),
        "expected contract-hash mismatch, got {err}"
    );
}

#[test]
fn derived_dispatch_preflight_authorizes_validation_retry_attempts() {
    let program = build_program(
        r#"
test = stage(id = "test", prompt = "run", validate_retries = 2)
workflow("derived-validation-retry", root = [test])
"#,
    );
    let stage_id = StageId(SmolStr::new("test"));

    // dispatch_iter 0 = non-loop / iteration-0: bare `#validate-M`.
    let first = preflight_derived_dispatch(
        &program,
        &stage_id,
        DerivedDispatchKind::ValidationRetry {
            dispatch_iter: 0,
            attempt: 1,
        },
    )
    .expect("attempt 1 is authorized");
    assert_eq!(first.expected_stage_name.as_str(), "test#validate-1");
    let second = preflight_derived_dispatch(
        &program,
        &stage_id,
        DerivedDispatchKind::ValidationRetry {
            dispatch_iter: 0,
            attempt: 2,
        },
    )
    .expect("attempt 2 is authorized");
    assert_eq!(second.expected_stage_name.as_str(), "test#validate-2");

    // A NON-loop stage with a non-zero dispatch_iter is rejected:
    // only a checked review-loop participant may carry an iteration.
    let err = preflight_derived_dispatch(
        &program,
        &stage_id,
        DerivedDispatchKind::ValidationRetry {
            dispatch_iter: 3,
            attempt: 1,
        },
    )
    .expect_err("a non-loop stage must not authorize an iteration-tagged retry");
    assert!(
        err.to_string()
            .contains("is not a checked review-loop participant"),
        "{err}"
    );

    for attempt in [0, 3] {
        let err = preflight_derived_dispatch(
            &program,
            &stage_id,
            DerivedDispatchKind::ValidationRetry {
                dispatch_iter: 0,
                attempt,
            },
        )
        .expect_err("unauthorized retry attempt should fail");
        assert!(
            err.to_string()
                .contains(&format!("does not authorize attempt {attempt}")),
            "{err}"
        );
    }
}

#[test]
fn derived_dispatch_preflight_authorizes_child_invocation_roles() {
    let program = build_program(
        r#"
static_s = stage(
    id = "static",
    prompt = "static root",
    topology = topology(
        "static_children",
        max_concurrency = 1,
        workers = [role("package_writer", required = True)],
    ),
)
dynamic_s = stage(
    id = "dynamic",
    prompt = "dynamic root",
    topology = topology(
        "dynamic_children",
        max_concurrency = 2,
        fanout_limit = 2,
        dynamic_fanout = True,
        mutation_policy = "owned_paths",
        workers = [role("package_writer", required = False)],
    ),
)
workflow("derived-child-authority", root = [static_s, dynamic_s])
"#,
    );
    let role = SmolStr::new("package_writer");
    let static_stage = StageId(SmolStr::new("static"));
    let dynamic_stage = StageId(SmolStr::new("dynamic"));

    let static_child = preflight_derived_dispatch(
        &program,
        &static_stage,
        DerivedDispatchKind::ExecutableChild { role: &role },
    )
    .expect("static child role is authorized");
    assert_eq!(
        static_child.expected_stage_name.as_str(),
        "static#child-package_writer"
    );
    let err = preflight_derived_dispatch(
        &program,
        &static_stage,
        DerivedDispatchKind::DynamicChild {
            role: &role,
            derived_stage: &SmolStr::new("static#child-package_writer-core"),
        },
    )
    .expect_err("static topology must not authorize dynamic child dispatch");
    assert!(err.to_string().contains("dynamic child"), "{err}");

    let dynamic_child = preflight_derived_dispatch(
        &program,
        &dynamic_stage,
        DerivedDispatchKind::DynamicChild {
            role: &role,
            derived_stage: &SmolStr::new("dynamic#child-package_writer-core"),
        },
    )
    .expect("dynamic child role is authorized");
    assert_eq!(
        dynamic_child.expected_stage_name.as_str(),
        "dynamic#child-package_writer-core"
    );
    let unknown = SmolStr::new("unknown");
    let err = preflight_derived_dispatch(
        &program,
        &dynamic_stage,
        DerivedDispatchKind::DynamicChild {
            role: &unknown,
            derived_stage: &SmolStr::new("dynamic#child-unknown-core"),
        },
    )
    .expect_err("undeclared dynamic role should fail");
    assert!(
        err.to_string()
            .contains("does not authorize dynamic child role"),
        "{err}"
    );
}

#[test]
fn v1_hash_material_omits_empty_checked_extensions() {
    let program = build_program(PROMPT_ONLY_SRC);

    let legacy_material = LegacyV1ExecutionProgramHashMaterial {
        schema_version: EXECUTION_PROGRAM_SCHEMA_VERSION,
        workflow_name: program.workflow_name.clone(),
        source: program.source.clone(),
        summary: ExecutionProgramHashSummaryMaterial {
            stage_count: program.summary.stage_count,
            edge_count: program.summary.edge_count,
            review_loop_count: program.summary.review_loop_count,
            sandbox_profile_count: program.summary.sandbox_profile_count,
            planned_invocation_count: program.summary.planned_invocation_count,
            worktree_isolated: program.summary.worktree_isolated,
        },
        stages: program.stages.clone(),
        edges: program.edges.clone(),
    };

    assert_eq!(program.summary.human_request_count, 0);
    assert!(program.human_request_queue.requests.is_empty());
    assert!(program.workflow_pattern.is_none());
    // The program hash is minted by `hash_program_material` (the
    // placement-brand projection). This `only` program declares no sandbox, so
    // the projection is a no-op — the recompute must use the SAME hasher.
    assert_eq!(
        program.program_hash,
        hash_program_material(&legacy_material)
    );
}

// ---- load-time structured-output reference check ----

#[test]
fn dangling_output_reference_rejected() {
    let err = try_build_program(
        r#"
a = stage(id = "a", prompt = "emit", outputs = {"x": "string"})
b = stage(id = "b", depends_on = ["a"], prompt = "use {{ stages.a.parsed.nonexistent }}")
workflow("dangling-output-ref", root = [a])
"#,
    )
    .expect_err("a reference to an undeclared producer field must be rejected at load");

    let msg = err.to_string();
    assert!(msg.contains("nonexistent"), "{msg}");
    assert!(msg.contains('a') && msg.contains('b'), "{msg}");
    assert!(msg.contains("declared outputs: x"), "{msg}");
}

#[test]
fn valid_output_reference_accepted() {
    try_build_program(
        r#"
a = stage(id = "a", prompt = "emit", outputs = {"x": "string"})
b = stage(id = "b", depends_on = ["a"], prompt = "use {{ stages.a.parsed.x }}")
workflow("valid-output-ref", root = [a])
"#,
    )
    .expect("a reference to a declared producer field compiles");
}

/// `b` and `c` are sibling branches under `a`; `d` joins them. Only the reading
/// stage's prompt varies across the dependency-closure cells.
fn two_branch_pack(reader: &str, prompt: &str) -> String {
    let prompt_of = |id: &str| {
        if id == reader {
            prompt.to_owned()
        } else {
            "emit".to_owned()
        }
    };
    format!(
        r#"
a = stage(id = "a", prompt = "{pa}", outputs = {{"x": "string"}})
b = stage(id = "b", depends_on = ["a"], prompt = "{pb}", outputs = {{"x": "string"}})
c = stage(id = "c", depends_on = ["a"], prompt = "{pc}", outputs = {{"x": "string"}})
d = stage(id = "d", depends_on = ["b", "c"], prompt = "{pd}", outputs = {{"x": "string"}})
workflow("closure", root = [a])
"#,
        pa = prompt_of("a"),
        pb = prompt_of("b"),
        pc = prompt_of("c"),
        pd = prompt_of("d"),
    )
}

/// The refused set of `output_reference_outside_dependency_closure`: a producer
/// that is a stage of the program but not a transitive `depends_on` ancestor of
/// the reader — a sibling branch, a downstream stage, the reader itself — read
/// through any field, in either spelling.
#[test]
fn output_reference_outside_dependency_closure_refused() {
    for (reader, producer, read, why) in [
        ("b", "c", "stages.c.parsed.x", "a sibling branch"),
        ("b", "c", "stages.c.content", "a sibling's raw content"),
        (
            "b",
            "c",
            "stages['c'].parsed",
            "a sibling in bracket spelling",
        ),
        ("b", "d", "stages.d.parsed.x", "a downstream stage"),
        ("b", "b", "stages.b.parsed.x", "the reader itself"),
        ("a", "b", "stages.b.parsed.x", "a stage below the root"),
    ] {
        let err = try_build_program(&two_branch_pack(reader, &format!("use {{{{ {read} }}}}")))
            .expect_err(why);
        let msg = err.to_string();
        assert!(
            msg.contains("output_reference_outside_dependency_closure")
                && msg.contains(&format!("\"{reader}\" does not depend on \"{producer}\"")),
            "{why}: {msg}"
        );
    }
}

/// The admitted complement: a direct and a transitive ancestor, in both the
/// dotted and the whole-envelope spelling.
#[test]
fn output_reference_inside_dependency_closure_accepted() {
    try_build_program(&two_branch_pack(
        "d",
        "{{ stages.a.parsed.x }} {{ stages.b.parsed.x }} {{ stages.c.parsed }}",
    ))
    .expect("every stage a reader transitively depends on is readable");
}

/// The runtime context: `outputs_in_dependency_closure` keeps exactly the
/// reader's transitive ancestors out of a map holding every stage's envelope.
#[test]
fn outputs_in_dependency_closure_keeps_only_ancestors() {
    let program = build_program(&two_branch_pack("d", "emit"));
    let every_stage: BTreeMap<SmolStr, serde_json::Value> = ["a", "b", "c", "d"]
        .into_iter()
        .map(|s| (SmolStr::new(s), serde_json::json!({ "x": s })))
        .collect();
    for (reader, expected) in [
        ("a", &[][..]),
        ("b", &["a"][..]),
        ("c", &["a"][..]),
        ("d", &["a", "b", "c"][..]),
    ] {
        let visible =
            program.outputs_in_dependency_closure(&StageId(SmolStr::new(reader)), &every_stage);
        let names: Vec<&str> = visible.keys().map(SmolStr::as_str).collect();
        assert_eq!(names, expected, "the stages.* a template of {reader} sees");
    }
}

#[test]
fn reference_to_unstructured_producer_is_a_hard_error() {
    // `a` declares NEITHER produces= NOR flat outputs, so its emitted `parsed`
    // shape is unverifiable at load. The referenced-but-untyped edge is a hard
    // `Error`-severity `untyped_referenced_output` diagnostic that escalates the
    // verifier status to `Error` — `kata workflows check` rejects the pack
    // UNCONDITIONALLY (not merely under --deny-warnings).
    let program = try_build_program(
        r#"
a = stage(id = "a", prompt = "emit anything")
b = stage(id = "b", depends_on = ["a"], prompt = "use {{ stages.a.parsed.anything }}")
workflow("unstructured-producer", root = [a])
"#,
    )
    .expect("the program still compiles into checked IR; the untyped edge is an Error diagnostic");
    assert!(
        program.verifier.diagnostics.iter().any(|d| {
            d.severity == VerifierSeverity::Error && d.code.as_str() == "untyped_referenced_output"
        }),
        "{:?}",
        program.verifier.diagnostics
    );
    // The Error-severity diagnostic must drive the verifier status to Error so the
    // check command fails unconditionally (see `workflow_check_summary`).
    assert_eq!(
        program.verifier.status,
        VerifierStatus::Error,
        "an untyped referenced edge must set verifier status = Error: {:?}",
        program.verifier.diagnostics
    );
}

#[test]
fn non_stage_namespaces_ignored() {
    // `workspace.*` and `memory.*` are runtime context namespaces the load-time
    // checker does not model, so they never trigger it. (`external_inputs.*` and
    // `review.*` ARE checked and are covered by their own tests.)
    // Whole-object (`stages.x.parsed`) and `.content` refs to an upstream stage
    // also pass.
    try_build_program(
        r#"
up = stage(id = "up", prompt = "emit", outputs = {"done": "bool"})
only = stage(
    id = "only",
    depends_on = ["up"],
    prompt = """
files: {{ workspace.changed_files }}
mem: {{ memory.m.objects }}
whole: {{ stages.up.parsed }}
raw: {{ stages.up.content }}
""",
    outputs = {"done": "bool"},
)
workflow("non-stage-namespaces", root = [up])
"#,
    )
    .expect(
        "unmodeled runtime namespaces (and whole-object / content refs) do not trigger the check",
    );
}

#[test]
fn unknown_producer_stage_rejected() {
    let err = try_build_program(
        r#"
b = stage(id = "b", prompt = "use {{ stages.ghost.parsed.x }}")
workflow("unknown-producer", root = [b])
"#,
    )
    .expect_err("a reference to a producer that is not a stage must be rejected");
    assert!(err.to_string().contains("ghost"), "{err}");
    assert!(err.to_string().contains("unknown producer"), "{err}");
}

#[test]
fn extractor_captures_whole_envelope_and_nested_paths() {
    // The extractor now captures WHOLE-ENVELOPE refs (`stages.x.parsed`,
    // empty path) AND greedily consumes every nested `.<ident>` segment.
    let refs = extract_parsed_output_references(
        "a {{ stages.draft.parsed.text }} b {{ stages.draft.parsed.score | round }} \
         c {{ stages.draft.parsed }} d {{ stages.draft.content }} \
         e {{ workspace.changed_files }} f {{ stages.draft.parsed.obj.nested }} \
         g {{- stages.draft.parsed.trimmed -}}",
    );
    assert_eq!(
        refs,
        vec![
            OutputReference {
                producer: "draft".to_string(),
                path: vec!["text".to_string()],
            },
            OutputReference {
                producer: "draft".to_string(),
                path: vec!["score".to_string()],
            },
            // Whole-envelope reference: empty path.
            OutputReference {
                producer: "draft".to_string(),
                path: vec![],
            },
            // Nested path: both segments captured (was only the first).
            OutputReference {
                producer: "draft".to_string(),
                path: vec!["obj".to_string(), "nested".to_string()],
            },
            OutputReference {
                producer: "draft".to_string(),
                path: vec!["trimmed".to_string()],
            },
        ],
    );
}

#[test]
fn extractor_rejects_parsed_prefix_identifier() {
    // `parsed` must be a COMPLETE segment: `parsedX` / `parsed_foo` are longer
    // identifiers, not a `parsed` envelope reference.
    let refs =
        extract_parsed_output_references("{{ stages.a.parsedX }} {{ stages.b.parsed_foo.x }}");
    assert!(refs.is_empty(), "{refs:?}");
}

#[test]
fn extractor_ignores_refs_outside_expression_blocks() {
    // Prose and `{# #}` comments are genuinely not render contexts.
    //
    // The `{% if %}` row pins CURRENT behavior, NOT a correctness property: a
    // statement block IS evaluated under strict-undefined at render, so this
    // reference is a real data dependency that goes unchecked (a false NEGATIVE
    // — the safe direction). See the KNOWN GAP note on
    // `extract_parsed_output_references`; closing it requires modelling
    // `{% set %}` rebinding and `{% for %}` shadowing of `stages`.
    let refs = extract_parsed_output_references(
        "see stages.a.parsed.x in prose {% if stages.a.parsed.y %}{% endif %} \
         {# stages.a.parsed.z #}",
    );
    assert!(refs.is_empty(), "{refs:?}");
}

#[test]
fn extractor_respects_identifier_boundary() {
    // `my_stages.a.parsed.x` is a different head identifier, not `stages`.
    let refs = extract_parsed_output_references("{{ my_stages.a.parsed.x }}");
    assert!(refs.is_empty(), "{refs:?}");
}

#[test]
fn extractor_ignores_string_literals_and_commented_blocks() {
    // A quoted path is literal text (not a data render); a `{{ }}` nested in a
    // `{# #}` comment renders nothing. Neither is a data dependency — only the
    // bare `stages.d.parsed.real` render is captured.
    let refs = extract_parsed_output_references(
        "{{ \"stages.a.parsed.x\" }} {{ lookup('stages.b.parsed.y') }} \
         {# {{ stages.c.parsed.z }} #} {{ stages.d.parsed.real }}",
    );
    assert_eq!(
        refs,
        vec![OutputReference {
            producer: "d".to_string(),
            path: vec!["real".to_string()],
        }],
    );
}

#[test]
fn extractor_captures_bracket_indexed_producer_and_field() {
    // minijinja resolves `a.b` and `a["b"]` to the SAME lookup on a JSON object,
    // so both spellings must yield the same reference. An extractor that saw only
    // dotted access would extract NOTHING from `stages["x"]…` (producer existence
    // unchecked) and degrade `parsed["y"]` to a whole-envelope reference (field
    // unchecked) — both false negatives against a real data dependency.
    let refs = extract_parsed_output_references(
        "{{ stages[\"draft\"].parsed.text }} {{ stages['draft'].parsed['score'] }} \
         {{ stages.draft.parsed[\"obj\"].nested }}",
    );
    assert_eq!(
        refs,
        vec![
            OutputReference {
                producer: "draft".to_string(),
                path: vec!["text".to_string()],
            },
            OutputReference {
                producer: "draft".to_string(),
                path: vec!["score".to_string()],
            },
            OutputReference {
                producer: "draft".to_string(),
                path: vec!["obj".to_string(), "nested".to_string()],
            },
        ],
    );
}

#[test]
fn extractor_ignores_computed_index() {
    // A COMPUTED index names no statically-known producer or field. Guessing at
    // one risks a false POSITIVE on a valid pack, so it stays unextracted.
    let refs = extract_parsed_output_references(
        "{{ stages[name].parsed.x }} {{ stages.draft.parsed[key] }}",
    );
    assert_eq!(
        refs,
        vec![OutputReference {
            // The second reference resolves its producer, then stops at the
            // computed field index — a whole-envelope (existence-only) check.
            producer: "draft".to_string(),
            path: vec![],
        }],
    );
}

#[test]
fn extractor_skips_raw_block_bodies() {
    // `{% raw %}` emits its body VERBATIM — minijinja never renders it — so a
    // reference spelled inside one is literal text, not a data dependency.
    // Scanning it made the hard-error path FALSE-POSITIVE on a valid pack.
    let refs = extract_parsed_output_references(
        "{% raw %}{{ stages.ghost.parsed.x }}{% endraw %} {{ stages.real.parsed.y }}",
    );
    assert_eq!(
        refs,
        vec![OutputReference {
            producer: "real".to_string(),
            path: vec!["y".to_string()],
        }],
    );

    // Whitespace-control markers and an unterminated raw region are handled the
    // same conservative way (extract nothing from the raw body).
    assert!(
        extract_parsed_output_references("{%- raw -%}{{ stages.ghost.parsed.x }}{%- endraw -%}")
            .is_empty(),
    );
    assert!(
        extract_parsed_output_references("{% raw %}{{ stages.ghost.parsed.x }}").is_empty(),
        "an unterminated raw region swallows the rest of the template",
    );
}

#[test]
fn raw_block_reference_does_not_reject_a_valid_pack() {
    // SOUNDNESS regression: the hard-error path must NEVER false-positive on a
    // valid pack. A prompt that DOCUMENTS kata template syntax inside a raw
    // block renders fine at runtime, so naming a non-existent producer there
    // must not be a load failure.
    try_build_program(
        r#"
a = stage(id = "a", prompt = "emit", outputs = {"x": "string"})
b = stage(
    id = "b",
    depends_on = ["a"],
    prompt = "write {% raw %}{{ stages.ghost.parsed.anything }}{% endraw %} in your answer",
)
workflow("raw-doc", root = [a])
"#,
    )
    .expect("a reference inside a {% raw %} block is literal text, not a dangling reference");
}

#[test]
fn bracket_spelled_reference_is_checked_against_the_producer_contract() {
    // A stage id that is not a bare identifier is UNREACHABLE by dotted access,
    // so brackets are the ONLY legal spelling — a checker blind to brackets would
    // silently strip every such pack of its load-time guarantee.
    //
    // Non-vacuity first: the VALID bracket reference must still compile.
    try_build_program(
        r#"
a = stage(id = "my-stage", prompt = "emit", outputs = {"x": "string"})
b = stage(id = "b", depends_on = ["my-stage"], prompt = "use {{ stages[\"my-stage\"].parsed.x }}")
workflow("bracket-ok", root = [a])
"#,
    )
    .expect("a bracket reference to a DECLARED output must compile");

    // …and the same spelling naming an UNDECLARED field is rejected.
    let err = try_build_program(
        r#"
a = stage(id = "my-stage", prompt = "emit", outputs = {"x": "string"})
b = stage(id = "b", depends_on = ["my-stage"], prompt = "use {{ stages[\"my-stage\"].parsed.nope }}")
workflow("bracket-dangling", root = [a])
"#,
    )
    .expect_err("a bracket reference to an UNDECLARED output must be rejected");
    assert!(err.to_string().contains("nope"), "{err}");
    // The diagnostic echoes the reference in the spelling the author must use.
    assert!(
        err.to_string().contains("stages[\"my-stage\"].parsed.nope"),
        "diagnostic is copy-pasteable back into the pack: {err}"
    );
}

#[test]
fn rich_schema_producer_references_checked_against_properties() {
    // A producer carrying a rich `output_schema` (lowered from
    // `produces=contract(..)`) is AUTHORITATIVE at runtime and its contract
    // object is CLOSED, so a consumer reference is checked against the
    // schema's declared `properties` — not the flat `outputs`. The rich
    // schema takes precedence even when flat outputs are also present.
    let mut program =
        try_build_program(RICH_SCHEMA_BASELINE_SRC).expect("a valid flat reference compiles");

    let a = StageId(SmolStr::new("a"));
    let b = StageId(SmolStr::new("b"));
    // Make the producer rich-schema-bearing with a closed `{owned_paths}`
    // contract — `flat_field` is now decorative and NOT a runtime key.
    program.stages.get_mut(&a).unwrap().policies.output_schema = Some(serde_json::json!({
        "type": "object",
        "properties": { "owned_paths": { "type": "string" } },
        "additionalProperties": false
    }));

    // A reference to the (decorative) flat field is now dangling against the
    // authoritative rich contract.
    program.stages.get_mut(&b).unwrap().op.prompt_template =
        "use {{ stages.a.parsed.flat_field }}".to_string();
    let err = check_output_references(&program)
        .expect_err("a ref to a non-contract field on a rich producer is rejected");
    assert!(err.to_string().contains("flat_field"), "{err}");
    assert!(
        err.to_string().contains("owned_paths"),
        "error names the declared contract fields: {err}"
    );

    // A reference to a declared contract property compiles.
    program.stages.get_mut(&b).unwrap().op.prompt_template =
        "use {{ stages.a.parsed.owned_paths }}".to_string();
    check_output_references(&program).expect("a ref to a declared contract property is accepted");
}

#[test]
fn rich_schema_without_properties_is_skipped() {
    // A degenerate rich schema with no `properties` node is skipped
    // conservatively rather than flagging every reference.
    let mut program =
        try_build_program(RICH_SCHEMA_BASELINE_SRC).expect("a valid flat reference compiles");

    let a = StageId(SmolStr::new("a"));
    let b = StageId(SmolStr::new("b"));
    program.stages.get_mut(&a).unwrap().policies.output_schema =
        Some(serde_json::json!({ "type": "object" }));
    program.stages.get_mut(&b).unwrap().op.prompt_template =
        "use {{ stages.a.parsed.anything }}".to_string();
    check_output_references(&program)
        .expect("a rich schema with no `properties` is skipped (conservative)");
}

/// Build a two-stage `a → b` program where `b` references
/// `{{ stages.a.parsed.result }}`, plus the stage ids, for the template-ref type tests.
fn typed_ref_program() -> (ExecutionProgram, StageId, StageId) {
    let program = try_build_program(
        r#"
a = stage(id = "a", prompt = "emit", outputs = {"result": "string"})
b = stage(id = "b", depends_on = ["a"], prompt = "use {{ stages.a.parsed.result }}")
workflow("typed-ref", root = [a])
"#,
    )
    .expect("a valid flat reference compiles");
    let a = StageId(SmolStr::new("a"));
    let b = StageId(SmolStr::new("b"));
    (program, a, b)
}

fn object_schema(field: &str, ty: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": { field: { "type": ty } },
        "required": [field],
        "additionalProperties": false
    })
}

#[test]
fn template_ref_type_mismatch_against_declared_input_is_rejected() {
    // The producer emits `result: integer`; the consumer's `consumes=` input
    // contract declares `result: string`. `is_subtype(integer, string)` is
    // false → the reference is a cross-stage TYPE mismatch, not merely a
    // (passing) existence check.
    let (mut program, a, b) = typed_ref_program();
    program.stages.get_mut(&a).unwrap().policies.output_schema =
        Some(object_schema("result", "integer"));
    program.stages.get_mut(&b).unwrap().input_schema = Some(object_schema("result", "string"));

    let err = check_output_references(&program)
        .expect_err("an integer producer field vs a string declared input is rejected");
    assert!(err.to_string().contains("subtype"), "{err}");
    assert!(err.to_string().contains("result"), "{err}");
}

#[test]
fn template_ref_type_match_against_declared_input_is_accepted() {
    // Producer emits `result: integer`; the consumer declares `result:
    // number`. `integer ⊆ number`, so the reference type-checks.
    let (mut program, a, b) = typed_ref_program();
    program.stages.get_mut(&a).unwrap().policies.output_schema =
        Some(object_schema("result", "integer"));
    program.stages.get_mut(&b).unwrap().input_schema = Some(object_schema("result", "number"));

    check_output_references(&program)
        .expect("an integer producer field satisfies a number declared input (integer ⊆ number)");
}

#[test]
fn existence_only_when_consumer_declares_no_input_type() {
    // Producer emits `result: integer`. With NO declared input contract, the
    // reference stays EXISTENCE-only — the type is not checked, so a
    // would-be-mismatch still passes (we must not over-reject).
    let (mut program, a, b) = typed_ref_program();
    program.stages.get_mut(&a).unwrap().policies.output_schema =
        Some(object_schema("result", "integer"));
    // `input_schema` is `None` (the consumer declares no `consumes=`).
    check_output_references(&program).expect("no declared input type → existence-only, accepted");

    // Even an input contract that does NOT name `result` leaves the `result`
    // reference existence-only (don't type-check fields the consumer never
    // declares).
    program.stages.get_mut(&b).unwrap().input_schema = Some(object_schema("other", "string"));
    check_output_references(&program)
        .expect("an input contract not naming the field → existence-only, accepted");
}

#[test]
fn existence_check_precedes_type_check() {
    // A reference to a field the producer does NOT declare is an EXISTENCE
    // error regardless of the consumer's declared input type — existence is
    // checked first.
    let (mut program, a, b) = typed_ref_program();
    program.stages.get_mut(&a).unwrap().policies.output_schema =
        Some(object_schema("result", "string"));
    program.stages.get_mut(&b).unwrap().op.prompt_template =
        "use {{ stages.a.parsed.missing }}".to_string();
    program.stages.get_mut(&b).unwrap().input_schema = Some(object_schema("missing", "string"));
    let err = check_output_references(&program)
        .expect_err("a reference to an undeclared producer field is an existence error");
    assert!(
        err.to_string().contains("declares no contract field"),
        "{err}"
    );
}

// ── external_inputs.* + review.* namespace reference checks ─────────────────

#[test]
fn external_input_reference_to_declared_channel_alias_compiles() {
    // A `{{ external_inputs.<expose_as> }}` reference against a DECLARED channel
    // passes the load-time check (run as part of `compile_execution_program`).
    try_build_program(
        r#"
only = stage(id = "only", prompt = "Steering: {{ external_inputs.steering.default_value }}")
workflow(
    "ext-ok",
    root = [only],
    external_input_channels = [channel("operator_steering", expose_as = "steering", max_items = 4)],
    max_external_input_channels = 1,
)
"#,
    )
    .expect("a reference to a declared channel alias compiles clean");
}

#[test]
fn external_input_reference_to_undeclared_alias_is_rejected_at_check() {
    // A typo (`streering` vs the declared `steering`) FAILS at check rather
    // than booting and crashing at first render.
    let err = try_build_program(
        r#"
only = stage(id = "only", prompt = "Steering: {{ external_inputs.streering.items }}")
workflow(
    "ext-typo",
    root = [only],
    external_input_channels = [channel("operator_steering", expose_as = "steering", max_items = 4)],
    max_external_input_channels = 1,
)
"#,
    )
    .expect_err("a typo'd external-input alias must fail at check");
    assert!(
        err.to_string().contains("streering"),
        "names the bad alias: {err}"
    );
    assert!(
        err.to_string().contains("steering"),
        "names the declared alias set: {err}"
    );
}

#[test]
fn external_input_reference_without_any_declared_channel_is_rejected_at_check() {
    // Referencing `external_inputs.*` when the workflow declares NO channels: the
    // namespace is never defined at runtime, so the reference is dangling.
    let err = try_build_program(
        r#"
only = stage(id = "only", prompt = "Steering: {{ external_inputs.steering.items }}")
workflow("ext-none", root = [only])
"#,
    )
    .expect_err("an external-input reference with no declared channels must fail");
    assert!(
        err.to_string()
            .contains("declares no external_input_channels"),
        "{err}"
    );
}

#[test]
fn review_reference_to_known_field_compiles() {
    // The three review-loop context fields resolve — a field-name check only, so
    // it passes regardless of whether the stage is actually a loop body.
    try_build_program(
        r#"
only = stage(id = "only", prompt = "Iter {{ review.iteration }}: {{ review.feedback }}")
workflow("rev-ok", root = [only])
"#,
    )
    .expect("references to known review-context fields compile clean");
}

#[test]
fn review_reference_to_the_rollover_field_compiles() {
    // `loops::render_review_context` injects `rollover` from generation 1 on, and
    // `loops::RolloverContext` documents `{{ review.rollover.memory_key }}` to authors;
    // an author guards it for generation 0, where it is absent.
    try_build_program(
        r#"
only = stage(id = "only", prompt = "{% if review.rollover is defined %}Carry: {{ review.rollover.memory_key }}{% endif %}")
workflow("rev-rollover", root = [only])
"#,
    )
    .expect("a reference to the documented rollover field compiles clean");
}

#[test]
fn review_reference_to_unknown_field_is_rejected_at_check() {
    // A typo (`feeback` vs `feedback`) FAILS at check rather than booting and
    // crashing at first render.
    let err = try_build_program(
        r#"
only = stage(id = "only", prompt = "Feedback: {{ review.feeback }}")
workflow("rev-typo", root = [only])
"#,
    )
    .expect_err("a typo'd review-context field must fail at check");
    assert!(
        err.to_string().contains("feeback"),
        "names the bad field: {err}"
    );
    assert!(
        err.to_string()
            .contains("iteration, previous_output, feedback"),
        "lists the available review fields: {err}"
    );
}

#[test]
fn stages_review_parsed_reference_is_not_a_review_context_reference() {
    // SOUNDNESS: `{{ stages.review.parsed.verdict }}` reads the `review` STAGE via
    // the `stages` namespace, NOT the top-level `review.*` review-loop context. It
    // must not be misread as a `review.parsed` context typo (a false-positive).
    try_build_program(
        r#"
review = stage(id = "review", prompt = "assess", outputs = {"verdict": "string"})
consume = stage(id = "consume", depends_on = ["review"], prompt = "V: {{ stages.review.parsed.verdict }}")
workflow("stages-review", root = [review])
"#,
    )
    .expect("a stages.review.* reference is not a review-context reference");
}

#[test]
fn extract_head_references_matches_only_top_level_namespace() {
    // The top-level `review` var matches; the `review` inside `stages.review`
    // (preceded by `.`) does NOT. `reviewer` (a longer identifier) does NOT.
    let refs = extract_head_references(
        "{{ review.feedback }} {{ stages.review.parsed.verdict }} {{ reviewer.note }}",
        "review",
    );
    assert_eq!(
        refs,
        vec![vec!["feedback".to_string()]],
        "only the top-level review.* matches"
    );

    // A whole-namespace reference yields an empty path; a quoted literal and a
    // commented-out block are both skipped.
    let refs = extract_head_references(
        "{{ external_inputs }} {{ \"external_inputs.x\" }} {# {{ external_inputs.y }} #}",
        "external_inputs",
    );
    assert_eq!(
        refs,
        vec![Vec::<String>::new()],
        "whole-namespace ref; literal + comment skipped"
    );
}

/// The FLAGSHIP stdlib flows data through TYPED EDGES.
///
/// The non-vacuous, flagship-specific counterpart to the template-ref type unit tests
/// (which prove the mechanism in isolation). It loads the REAL flagship
/// self-improve factory pack, compiles it to an `ExecutionProgram` (running
/// `check_output_references`), and asserts:
///
/// 1. the pack compiles CLEAN with `consumes=` on its spine consumers — the
///    declared input contracts never false-reject the producers' `produces=`;
/// 2. the spine consumers actually CARRY input schemas AND the producers
///    carry output schemas, so `is_subtype` has real types to relate on each
///    edge (the checker is LIVE, not vacuous); and
/// 3. flipping one consumer's declared input type to one the producer
///    VIOLATES makes `check_output_references` REJECT — proving the checker
///    GOVERNS the flagship's real `plan → implement` edge, not just its
///    templates.
#[test]
fn flagship_self_improve_pack_flows_data_through_typed_edges() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under <repo>/crates/program")
        .to_path_buf();
    let stdlib_root = repo_root.join("workflows").join("std");
    // Two-root stdlib: the flagship pack loads
    // `kata/factory.star` from the parallel `workflows/kata-factory` bundled
    // root, so both roots must be on the loader whitelist.
    let factory_root = repo_root.join("workflows").join("kata-factory");
    let pack = stdlib_root.join("std.software_factory.kata_self_improve.star");

    // (1) The flagship compiles clean to an ExecutionProgram WITH the typed
    // edges declared — `check_output_references` + `is_subtype` accept it.
    let program = compile_execution_program_from_file(&pack, &[stdlib_root.clone(), factory_root])
        .expect("flagship self-improve pack compiles with consumes= typed edges");

    let stage = |id: &str| {
        program
            .stages
            .get(&StageId(SmolStr::new(id)))
            .unwrap_or_else(|| panic!("flagship stage {id:?} present"))
    };

    // (2a) Non-vacuous: the spine PRODUCERS carry a rich `produces=` output
    // schema, so each typed edge has a producer type to check against.
    for producer in ["context", "plan", "implement", "review"] {
        assert!(
            stage(producer).policies.output_schema.is_some(),
            "flagship producer {producer:?} must declare produces= (rich output_schema)",
        );
    }
    // (2b) Non-vacuous: the spine CONSUMERS carry a declared `consumes=`
    // input schema naming the edge field they read from their producer.
    for (consumer, field) in [
        ("plan", "objectives"),
        ("implement", "scope"),
        ("review", "summary"),
        ("validate", "verdict"),
    ] {
        let input_schema = stage(consumer).input_schema.as_ref().unwrap_or_else(|| {
            panic!("flagship consumer {consumer:?} must declare consumes= (input_schema)")
        });
        assert!(
            input_schema
                .get("properties")
                .and_then(|properties| properties.as_object())
                .is_some_and(|properties| properties.contains_key(field)),
            "flagship consumer {consumer:?}'s consumes= must name typed-edge field {field:?}",
        );
    }

    // (3) Governance proof on the flagship's real `plan → implement` edge:
    // the `implement` prompt reads `{{ stages.plan.parsed.scope }}`, and
    // `plan` PRODUCES `scope` as a string. Flip `implement`'s declared input
    // type for `scope` to `integer`; `is_subtype(string, integer)` is false,
    // so the SAME checker that passed in (1) now REJECTS the flagship — the
    // type system governs the cross-stage edge, not just the template text.
    let mut mutated = program.clone();
    mutated
        .stages
        .get_mut(&StageId(SmolStr::new("implement")))
        .unwrap()
        .input_schema = Some(object_schema("scope", "integer"));
    let err = check_output_references(&mutated).expect_err(
        "a consumer that consumes= a type the flagship producer violates must be rejected",
    );
    assert!(err.to_string().contains("subtype"), "{err}");
    assert!(err.to_string().contains("scope"), "{err}");
    assert!(
        err.to_string().contains("implement"),
        "error names the offending flagship consumer stage: {err}",
    );
}

/// A library of `levels` packs where pack `lK` invokes `l(K+1)` `fan_out` times and the
/// last is one shell stage: `fan_out + fan_out^2 + … + fan_out^levels` invocations of
/// `levels` DISTINCT children. Returns the library and the root pack's source.
fn wide_subworkflow_library(fan_out: usize, levels: usize) -> (tempfile::TempDir, String) {
    let invoking = |next: usize| {
        let mut stages = String::new();
        for i in 0..fan_out {
            writeln!(
                stages,
                "s{i} = subworkflow(id = \"s{i}\", pack = \"l{next}\")"
            )
            .expect("a String accepts a write");
        }
        let roots = (0..fan_out)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{stages}workflow(\"wf-l{}\", root = [{roots}])\n", next - 1)
    };
    let dir = tempfile::tempdir().expect("library tempdir");
    for k in 2..=levels {
        std::fs::write(dir.path().join(format!("l{}.star", k - 1)), invoking(k))
            .expect("write an invoking pack");
    }
    std::fs::write(
        dir.path().join(format!("l{levels}.star")),
        "only = stage(id = \"only\", agent = \"shell\", run = \":\")\nworkflow(\"leaf\", root = only)\n",
    )
    .expect("write the leaf pack");
    (dir, invoking(1))
}

/// The `workspace_effect` CHECK, judged on the checked program the `oci`
/// admission door applies: under `worktree_isolated` a `workspace_effect` stage
/// is admitted; without it, refused by name (the missing-isolation refusal).
#[test]
fn the_oci_check_admits_a_workspace_effect_only_under_isolation() {
    let dir = tempfile::tempdir().expect("a library dir");
    let isolated = "ship = stage(\n\
        \x20   id = \"ship\",\n\
        \x20   agent = \"workspace_effect\",\n\
        \x20   op = \"park\",\n\
        )\n\
        workflow(\"iso\", root = ship, worktree_isolated = True)\n";
    std::fs::write(dir.path().join("iso.star"), isolated).expect("write the pack");
    let program = compile_starlark_execution_program(isolated, "iso.star", &[])
        .expect("the isolated pack compiles");
    kata_types::node_profile::mark_node_installed();
    compile::refuse_program_under_capsule_profile(
        &program,
        compile::CoveringBounds::default(),
        &mut std::collections::HashSet::new(),
        &mut |_| {},
        &mut std::collections::BTreeSet::new(),
    )
    .unwrap_or_else(|error| panic!("an isolated `oci` run admits the effect: {error}"));

    // Isolation off — the same stage is refused by name at COMPILE (the
    // `oci` profile is installed node-wide, so the pack itself is not
    // well-formed before the CHECK runs).
    let unisolated = "ship = stage(\n\
        \x20   id = \"ship\",\n\
        \x20   agent = \"workspace_effect\",\n\
        \x20   op = \"park\",\n\
        )\n\
        workflow(\"no-iso\", root = ship, worktree_isolated = False)\n";
    let error = compile_starlark_execution_program(unisolated, "no.star", &[])
        .expect_err("a non-isolated `oci` pack refuses the effect at compile");
    assert!(
        error.to_string().contains("worktree_isolated"),
        "the refusal names the missing isolation: {error}"
    );
}

/// The loop CHECK: a `loop(...)` is a bounded expansion the `oci`
/// runner drives durably (claim → member capsules at child coordinates →
/// resolve → replay), so the CONSTRUCT is not refused at CHECK. The
/// pack's member stages are judged by the arms that judge every stage —
/// the shell class, the `/work` workspace profile, the authored bounds —
/// and an inadmissible member still refuses by THAT arm's name, not the
/// loop's.
#[test]
fn the_oci_check_admits_a_shell_stage_loop_and_still_judges_its_members() {
    kata_types::node_profile::mark_node_installed();
    let pack = "body = stage(\n\
        \x20   id = \"body\",\n\
        \x20   agent = \"shell\",\n\
        \x20   run = \"echo hi\",\n\
        \x20   sandbox = sandbox_profile(workspace = \"rw\"),\n\
        )\n\
        gate = stage(\n\
        \x20   id = \"gate\",\n\
        \x20   agent = \"shell\",\n\
        \x20   run = \"printf '{\\\"decision\\\":\\\"approve\\\"}'\",\n\
        \x20   sandbox = sandbox_profile(workspace = \"ro\"),\n\
        \x20   depends_on = [\"body\"],\n\
        \x20   outputs = {\"decision\": \"string\"},\n\
        )\n\
        loop(body = body, gate = gate, max_iterations = 2)\n\
        workflow(\"loop-oci\", root = [body, gate])\n";
    let program = compile_starlark_execution_program(pack, "loop.star", &[])
        .expect("a shell-stage loop compiles under `oci`");
    assert_eq!(program.review_loops.len(), 1, "the pack carries one loop");
    compile::refuse_program_under_capsule_profile(
        &program,
        compile::CoveringBounds::default(),
        &mut std::collections::HashSet::new(),
        &mut |_| {},
        &mut std::collections::BTreeSet::new(),
    )
    .expect("the checked judgement admits the loop under `oci`");

    // A member the profile still refuses — an agent stage with no declared
    // capsule adapter — stops the pack by ITS arm's name, not the loop's.
    let agent_member = "body = stage(\n\
        \x20   id = \"body\",\n\
        \x20   agent = \"undeclared_agent_label\",\n\
        \x20   prompt = \"do the thing\",\n\
        \x20   sandbox = sandbox_profile(workspace = \"rw\"),\n\
        )\n\
        gate = stage(\n\
        \x20   id = \"gate\",\n\
        \x20   agent = \"shell\",\n\
        \x20   run = \"printf '{\\\"decision\\\":\\\"approve\\\"}'\",\n\
        \x20   sandbox = sandbox_profile(workspace = \"ro\"),\n\
        \x20   depends_on = [\"body\"],\n\
        \x20   outputs = {\"decision\": \"string\"},\n\
        )\n\
        loop(body = body, gate = gate, max_iterations = 2)\n\
        workflow(\"loop-agent\", root = [body, gate])\n";
    let error = compile_starlark_execution_program(agent_member, "loop_agent.star", &[])
        .expect_err("a loop over an uncapsulable member still refuses");
    assert!(
        error.to_string().contains("adapter_undeclared"),
        "the member's own arm refuses, by its name: {error}"
    );
}

/// The `oci` judgement judges each DISTINCT
/// bound child once per hard dollar policy it is reached under — here always
/// none, so once. The tree is 3 wide and 6 deep — 3 + 9 + … + 729 = 1092 invocations of
/// 6 distinct children — and the seam observes every judgement the walk makes. The
/// oracle for "distinct" is the tree's shape (one child per level), not the memo.
///
/// **Would red if:** the walk judged a child per invocation (1092 judgements, each of the
/// 6 hashes repeated).
#[test]
fn each_distinct_bound_child_is_judged_once_under_oci() {
    const FAN_OUT: usize = 3;
    const LEVELS: usize = 6;
    let (dir, root) = wide_subworkflow_library(FAN_OUT, LEVELS);
    kata_types::node_profile::mark_node_installed();
    let program =
        compile_starlark_execution_program(&root, "root.star", &[dir.path().to_path_buf()])
            .expect("the wide tree compiles");

    let mut judged = Vec::new();
    compile::refuse_program_under_capsule_profile(
        &program,
        compile::CoveringBounds::default(),
        &mut std::collections::HashSet::new(),
        &mut |hash| judged.push(hash),
        &mut std::collections::BTreeSet::new(),
    )
    .expect("a tree of shell leaves is admitted under oci");

    let distinct = judged
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(
        (judged.len(), distinct),
        (LEVELS, LEVELS),
        "one judgement per distinct child: {judged:?}"
    );
}
