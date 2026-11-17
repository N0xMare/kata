//! Tests for crates/program/src/starlark_eval.rs. Extracted from the inline #[cfg(test)] module.

use std::path::PathBuf;
use std::time::Duration;

use super::{
    evaluate_starlark_checked, evaluate_starlark_checked_with_budget_for_tests,
    evaluate_starlark_with_loader_checked,
};
use kata_types::cache::CachePolicy;
use kata_types::review_loop::OnMaxAction;
use kata_types::sandbox::SandboxRef;
use kata_types::workflow::{AgentSelector, ProgressVisibility, StageId};
use smol_str::SmolStr;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate lives under <repo>/crates/program")
        .to_path_buf()
}

#[test]
fn syntax_error_returns_kata_error() {
    let bad = "impl = stage(\n  prompt = \"x\"\n";
    let err = evaluate_starlark_checked(bad, "bad.star").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Starlark parse error"),
        "expected parse error, got: {msg}"
    );
}

/// A `.star` module that defines and even loads
/// helpers but never calls `workflow()` / `sequence()` / `loop()` at module
/// scope drains no graph, so it produces no execution program. The evaluator
/// rejects it with a clear "call workflow() at module scope" error instead of
/// silently accepting nothing.
#[test]
fn module_without_module_scope_workflow_drain_is_rejected() {
    // Defines a stage builder and a contract but never drains a workflow().
    let source = r#"
def build():
    return stage(prompt = "do it", agent = "worker")

c = contract("Plan", {"summary": field("string")})
"#;
    let err = evaluate_starlark_checked(source, "no-drain.star").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("produced no execution program")
            && (msg.contains("workflow()") || msg.contains("workflow("))
            && msg.contains("module scope"),
        "expected the no-drain error, got: {msg}"
    );
}

/// A module that calls `stage()` but forgets the closing `workflow()` drain is
/// likewise rejected (the builder is left non-empty / undrained).
#[test]
fn stage_without_workflow_drain_is_rejected() {
    let source = r#"
orphan = stage(prompt = "orphan", agent = "worker")
"#;
    let err = evaluate_starlark_checked(source, "orphan.star").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("workflow()") || msg.contains("produced no execution program"),
        "expected an undrained-builder / no-program error, got: {msg}"
    );
}

/// A `workflow()` that declares `version=`, `tags=[..]`, and
/// `params={..}` alongside the existing `description=` surfaces ALL of them
/// through [`crate::parser::PackMetadata`] — the round-trip
/// `evaluate_starlark_checked` → `pack_metadata()` reflects exactly what was
/// authored. `tags` preserves author order; `params` reuses the shared
/// `decode_outputs` helper (same as stage `outputs=`), which sorts by key.
#[test]
fn pack_metadata_round_trips_description_version_tags_params() {
    let source = r#"
s = stage(prompt = "do it", agent = "worker")
workflow(
    "annotated",
    root = s,
    description = "does the thing",
    version = "1.2.3",
    tags = ["alpha", "beta"],
    params = {"target_repo": "string", "max_iterations": "integer"},
)
"#;
    let checked = evaluate_starlark_checked(source, "annotated.star")
        .expect("annotated workflow should compile");
    let metadata = checked.pack_metadata();
    assert_eq!(metadata.description.as_deref(), Some("does the thing"));
    assert_eq!(metadata.version.as_deref(), Some("1.2.3"));
    assert_eq!(metadata.tags, vec!["alpha".to_owned(), "beta".to_owned()]);
    // The flat `{name: "type"}` shape now promotes to typed, REQUIRED
    // params; the `(name, type-label)` discovery projection is derived from the
    // typed schema, so `"integer"` (a real primitive spelling) round-trips to
    // exactly that label.
    assert_eq!(
        metadata.params,
        vec![
            ("max_iterations".to_owned(), "integer".to_owned()),
            ("target_repo".to_owned(), "string".to_owned()),
        ]
    );
}

/// A pack that omits `version=`/`tags=`/`params=` loads, with those fields
/// defaulting to `None` / empty.
#[test]
fn pack_metadata_defaults_when_omitted() {
    let source = r#"
s = stage(prompt = "do it", agent = "worker")
workflow("bare", root = s, description = "bare pack")
"#;
    let checked = evaluate_starlark_checked(source, "bare.star")
        .expect("a pack omitting version/tags/params must still load");
    let metadata = checked.pack_metadata();
    assert_eq!(metadata.description.as_deref(), Some("bare pack"));
    assert_eq!(metadata.version, None);
    assert!(metadata.tags.is_empty());
    assert!(metadata.params.is_empty());
}

#[test]
fn evaluation_budget_kills_runaway_loop() {
    // An unbounded-ish computation at module scope: summing a very large range.
    // Under the 10s production budget this would still burn CPU for ~seconds on
    // release builds; the test uses a 200ms budget via
    // `evaluate_starlark_checked_with_budget_for_tests` so the timeout fires
    // quickly — before the native workflow() drain is ever reached.
    let source = r#"
# A runaway loop inside a module-scope `def` that is CALLED at module scope. The
# before-statement hook trips the wall-clock / statement budget long before this
# returns — and before the native workflow() drain is ever reached.
def burn():
    total = 0
    for i in range(1000000000):
        total += i
    return total

burned = burn()

s = stage(prompt = str(burned), agent = "worker")
workflow("runaway", root = s)
"#;
    let err = evaluate_starlark_checked_with_budget_for_tests(
        source,
        "runaway.star",
        Duration::from_millis(200),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("exceeded") && msg.contains("budget"),
        "expected timeout error, got: {msg}"
    );
}

#[test]
fn starlark_eval_kata_std_memory_snapshot_stage_builds() {
    let repo_root = repo_root();
    let stdlib_root = repo_root.join("workflows").join("std");

    // `memory_snapshot_stage` is a native stage builder: it
    // registers a `stage()` and returns its StageRef, so it is assembled through
    // the native `workflow()` path rather than wrapped in a dict workflow.
    let source = r#"
load("kata/std.star", "memory_snapshot_stage")

memory_context = memory_snapshot_stage(id = "memory_context", kind = "task", status = "active")
workflow("memory-stdlib", root = [memory_context])
"#;

    let checked =
        evaluate_starlark_with_loader_checked(source, "memory-stdlib.star", &[stdlib_root])
            .expect("memory snapshot stdlib helper must build");
    let def = checked.definition();
    let memory = def
        .stages
        .get(&StageId(SmolStr::new("memory_context")))
        .expect("memory_context stage present");

    // The helper lowers to the typed `memory_snapshot()` builtin —
    // the marker the runner diverts to its main-side resolution — not a shell
    // stage that calls the loopback API.
    assert_eq!(
        memory.memory_snapshot,
        Some(kata_types::workflow::MemorySnapshotSpec {
            kind: Some(kata_types::memory::MemoryObjectKind::Task),
            status: Some(kata_types::memory::MemoryObjectStatus::Active),
        }),
        "the helper authors the typed snapshot filters, not a shell call"
    );
    assert_eq!(memory.progress_visibility, ProgressVisibility::Summary);
    assert_eq!(memory.cache_policy, CachePolicy::Disabled);
    assert!(
        memory
            .outputs
            .iter()
            .any(|output| output.name.as_str() == "object_count")
    );
    assert!(
        memory
            .outputs
            .iter()
            .any(|output| output.name.as_str() == "objects")
    );
}

#[test]
fn starlark_eval_kata_loop_lite_uses_bundled_constructors() {
    let repo_root = repo_root();
    let stdlib_root = repo_root.join("workflows").join("std");
    let source =
        std::fs::read_to_string(stdlib_root.join("kata-loop-lite.star")).expect("read stdlib");

    let checked = evaluate_starlark_with_loader_checked(
        &source,
        "kata-loop-lite.star",
        std::slice::from_ref(&stdlib_root),
    )
    .expect("kata-loop-lite must build through the stdlib loader");
    let def = checked.definition();
    assert_eq!(def.name.as_str(), "kata-loop-lite");
    assert!(def.worktree_isolated);
    assert_eq!(def.review_loops.len(), 1);
    assert!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .capabilities
            .iter()
            .any(|capability| capability.as_str() == "implement_review_loop")
    );

    let validate = def
        .stages
        .get(&StageId(SmolStr::new("validate")))
        .expect("validate stage present");
    // The EXECUTED lines, not the reported `commands` list (which a stale run
    // line would leave unchanged), and each one must name a recipe the
    // justfile defines: a validate stage running a recipe that does not exist
    // fails every run.
    let executed: Vec<&str> = validate
        .prompt_template
        .lines()
        .filter(|line| line.starts_with("just "))
        .collect();
    assert_eq!(
        executed,
        [
            "just validate-crate kata-program starlark_eval >&2",
            "just workflows-check-all >&2",
        ]
    );
    let justfile =
        std::fs::read_to_string(repo_root.join("justfile")).expect("read the repo justfile");
    for line in &executed {
        let recipe = line.split_whitespace().nth(1).expect("a recipe name");
        assert!(
            justfile.lines().any(|header| {
                header
                    .strip_prefix(recipe)
                    .is_some_and(|rest| rest.starts_with(':') || rest.starts_with(' '))
            }),
            "the validate stage runs `just {recipe}`, which the justfile does not define"
        );
    }
    assert!(validate.prompt_template.contains(r#""status":"passed""#));
    assert!(
        !validate
            .prompt_template
            .contains(r#""status":"validation_completed""#)
    );
    assert!(!validate.prompt_template.contains("cargo nextest run"));
}

#[test]
fn starlark_eval_kata_std_plan_boundary_workflow_builds() {
    let repo_root = repo_root();
    let stdlib_root = repo_root.join("workflows").join("std");
    let factory_root = repo_root.join("workflows").join("kata-factory");
    let source = std::fs::read_to_string(stdlib_root.join("kata-loop-plan-check-std.star"))
        .expect("read stdlib-backed plan check workflow");

    let checked = evaluate_starlark_with_loader_checked(
        &source,
        "kata-loop-plan-check-std.star",
        &[stdlib_root.clone(), factory_root.clone()],
    )
    .expect("kata std plan-boundary workflow must build through the stdlib loader");
    let def = checked.definition();

    assert_eq!(def.name.as_str(), "kata-loop-plan-check-std");
    assert!(def.worktree_isolated);
    assert_eq!(def.stages.len(), 5);
    assert_eq!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .name
            .as_str(),
        "plan_boundary"
    );
    // Two-root stdlib: the pack directly loads
    // `kata/factory.star` (plan_boundary_workflow lives in the kata-factory
    // root), and factory.star transitively loads `kata/std.star` (json_only /
    // memory_snapshot_stage). Both imports are recorded through the shared
    // whitelisted loader.
    assert!(
        def.provenance
            .frontend
            .import_hashes
            .contains_key("kata/factory.star")
    );
    assert!(
        def.provenance
            .frontend
            .import_hashes
            .contains_key("kata/std.star")
    );

    let plan = def
        .stages
        .get(&StageId(SmolStr::new("plan")))
        .expect("plan stage present");
    assert_eq!(plan.cache_policy, CachePolicy::ModelReuse);
    assert!(plan.prompt_template.contains("phase_policy"));
    assert!(plan.prompt_template.contains("parallel_writers"));

    let validate = def
        .stages
        .get(&StageId(SmolStr::new("validate")))
        .expect("validate stage present");
    assert!(validate.prompt_template.contains("git status --short"));
    assert!(validate.prompt_template.contains(r#""status":"passed""#));

    let closeout = def
        .stages
        .get(&StageId(SmolStr::new("closeout")))
        .expect("closeout stage present");
    assert!(
        closeout
            .inputs
            .iter()
            .any(|input| input.from.0 == "validate")
    );
}

#[test]
fn starlark_eval_kata_self_improve_pack_builds() {
    let repo_root = repo_root();
    let stdlib_root = repo_root.join("workflows").join("std");
    let factory_root = repo_root.join("workflows").join("kata-factory");
    let source =
        std::fs::read_to_string(stdlib_root.join("std.software_factory.kata_self_improve.star"))
            .expect("read kata self-improve factory pack");

    let checked = evaluate_starlark_with_loader_checked(
        &source,
        "std.software_factory.kata_self_improve.star",
        &[stdlib_root.clone(), factory_root.clone()],
    )
    .expect("kata self-improve factory pack must build through the stdlib loader");
    let def = checked.definition();

    assert_eq!(def.name.as_str(), "std.software_factory.kata_self_improve");
    assert!(def.worktree_isolated);
    assert_eq!(def.stages.len(), 8);
    assert_eq!(def.review_loops.len(), 1);
    assert_eq!(def.review_loops[0].on_max, OnMaxAction::Accept);
    assert_eq!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .name
            .as_str(),
        "software_factory"
    );
    assert!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .capabilities
            .iter()
            .any(|capability| capability.as_str() == "validation_evidence")
    );
    assert_eq!(
        checked.extensions().external_input_channels.channels.len(),
        3
    );
    assert!(
        checked
            .extensions()
            .external_input_channels
            .channels
            .iter()
            .any(|channel| channel.id.as_str() == "controller_decision"
                && channel.expose_as.as_str() == "controller")
    );
    assert_eq!(checked.extensions().memory_selectors.selectors.len(), 1);
    let memory_selector = &checked.extensions().memory_selectors.selectors[0];
    assert_eq!(memory_selector.id.as_str(), "factory_active_context");
    assert_eq!(
        memory_selector.stage.as_ref().map(SmolStr::as_str),
        Some("context")
    );
    assert_eq!(memory_selector.expose_as.as_str(), "memory_context");
    assert_eq!(
        memory_selector
            .kinds
            .iter()
            .map(SmolStr::as_str)
            .collect::<Vec<_>>(),
        vec![
            "objective",
            "task",
            "scenario",
            "validation_criterion",
            "decision",
            "risk"
        ]
    );
    assert_eq!(memory_selector.max_objects, 200);
    assert!(!memory_selector.required);
    // Six criteria: a closeout packet and a model controller's verdict are not
    // validation proofs (the promotion gate may not trust either with a
    // verdict), so the pack declares no criterion for them.
    assert_eq!(checked.extensions().validation_criteria.criteria.len(), 6);
    assert!(
        checked
            .extensions()
            .validation_criteria
            .criteria
            .iter()
            .any(|criterion| criterion.id.as_str() == "validation-evidence")
    );
    assert!(
        checked
            .extensions()
            .validation_criteria
            .criteria
            .iter()
            .any(|criterion| criterion.id.as_str() == "memory-context")
    );
    // A model controller's verdict is not a validation proof, and the
    // promotion gate refuses to trust one. The controller's decision is
    // recorded on the plane that is actually its own: `ExecutionControllerDecisionEvidence`,
    // projected by `controller_decision_evidence_from_assignments`.
    assert!(
        !checked
            .extensions()
            .validation_criteria
            .criteria
            .iter()
            .any(|criterion| criterion.id.as_str() == "controller-decision"),
        "a model controller may not be a validation proof stage"
    );
    // Two-root stdlib: the factory pack directly loads
    // `kata/factory.star` (kata_self_improve_workflow lives in the kata-factory
    // root), and factory.star transitively loads `kata/std.star`.
    assert!(
        def.provenance
            .frontend
            .import_hashes
            .contains_key("kata/factory.star")
    );
    assert!(
        def.provenance
            .frontend
            .import_hashes
            .contains_key("kata/std.star")
    );

    let memory = def
        .stages
        .get(&StageId(SmolStr::new("memory_context")))
        .expect("memory_context stage present");
    // `memory_snapshot_stage` authors the typed builtin — the
    // marker carries the `status = "active"` filter, no kind filter.
    assert_eq!(
        memory.memory_snapshot,
        Some(kata_types::workflow::MemorySnapshotSpec {
            kind: None,
            status: Some(kata_types::memory::MemoryObjectStatus::Active),
        }),
        "the snapshot stage is the typed marker, not a loopback shell call"
    );
    assert!(
        memory
            .outputs
            .iter()
            .any(|output| output.name.as_str() == "objects")
    );
    assert!(
        memory
            .outputs
            .iter()
            .any(|output| output.name.as_str() == "object_count")
    );

    let context = def
        .stages
        .get(&StageId(SmolStr::new("context")))
        .expect("context stage present");
    assert!(
        context
            .inputs
            .iter()
            .any(|input| input.from.0 == "memory_context")
    );
    assert!(context.prompt_template.contains("Native memory snapshot"));
    assert!(
        context
            .prompt_template
            .contains("Checked memory selector packet")
    );
    assert!(
        context
            .prompt_template
            .contains("memory.memory_context.objects")
    );
    assert!(
        context
            .prompt_template
            .contains("external_inputs.steering.items")
    );
    assert!(
        context
            .prompt_template
            .contains("external_inputs.controller.items")
    );
    assert_eq!(context.timeout_ms, 300_000);
    assert!(
        context
            .outputs
            .iter()
            .any(|output| output.name.as_str() == "memory_influences")
    );

    let plan = def
        .stages
        .get(&StageId(SmolStr::new("plan")))
        .expect("plan stage present");
    assert!(
        plan.prompt_template
            .contains("external_inputs.steering.items")
    );
    assert!(
        plan.prompt_template
            .contains("external_inputs.controller.items")
    );
    assert_eq!(plan.timeout_ms, 300_000);
    assert!(
        plan.prompt_template
            .contains("validation commands are reserved")
    );
    assert!(
        plan.prompt_template
            .contains("The candidate workspace already exists")
    );
    assert!(
        plan.prompt_template
            .contains("Do not ask the implementer to create a second temp repo")
    );

    let implement = def
        .stages
        .get(&StageId(SmolStr::new("implement")))
        .expect("implement stage present");
    assert_eq!(implement.timeout_ms, 600_000);
    assert_eq!(
        implement.sandbox,
        Some(SandboxRef::Named("factory-implement".to_string()))
    );
    assert!(
        implement
            .prompt_template
            .contains("external_inputs.steering.items")
    );
    assert!(
        implement
            .prompt_template
            .contains("external_inputs.controller.items")
    );
    assert!(
        implement
            .prompt_template
            .contains("Do not run the declared validation commands")
    );
    assert!(
        implement
            .prompt_template
            .contains("Candidate workspace contract:")
    );
    assert!(
        implement
            .prompt_template
            .contains("Do not create, copy, or edit a second candidate repo")
    );
    // `implement` does not shell git to verify its changes
    // (the candidate worktree's gitdir is unreachable in-sandbox); it reports the
    // paths it edited and the runtime computes the authoritative changeset out of
    // sandbox for downstream stages.
    assert!(
        !implement.prompt_template.contains("git diff --name-only"),
        "implement must NOT instruct shelling git for change verification"
    );
    assert!(
        implement
            .prompt_template
            .contains("Report exactly the paths you edited")
    );
    let implement_topology = implement.topology.as_ref().expect("topology present");
    assert_eq!(implement_topology.mutation_policy.label(), "owned_paths");

    let review = def
        .stages
        .get(&StageId(SmolStr::new("review")))
        .expect("review stage present");
    assert!(
        review
            .prompt_template
            .contains("external_inputs.steering.items")
    );
    assert!(
        review
            .prompt_template
            .contains("external_inputs.controller.items")
    );
    assert!(
        review
            .prompt_template
            .contains("Bound the review to the declared candidate")
    );
    assert!(
        review
            .prompt_template
            .contains("The current execution worktree is")
    );
    assert!(
        review
            .prompt_template
            .contains("the only candidate workspace")
    );
    assert!(
        review
            .prompt_template
            .contains("This review stage runs before the")
    );
    assert!(review.prompt_template.contains("The validation stage owns"));
    assert_eq!(review.timeout_ms, 240_000);
    let review_topology = review.topology.as_ref().expect("review topology");
    assert_eq!(review_topology.kind.as_str(), "review_quorum");
    assert_eq!(review_topology.review_quorum.as_ref().unwrap().required, 1);

    let validate = def
        .stages
        .get(&StageId(SmolStr::new("validate")))
        .expect("validate stage present");
    assert_eq!(validate.progress_visibility, ProgressVisibility::Summary);
    assert!(validate.prompt_template.contains("subprocess.run"));
    assert!(
        validate
            .prompt_template
            .contains("kata check std.software_factory.kata_self_improve")
    );
    assert!(validate.prompt_template.contains("review verdict:"));
    assert!(validate.prompt_template.contains("git diff --check"));
    assert!(
        !validate
            .prompt_template
            .contains("validation command execution is not yet automated")
    );

    let controller = def
        .stages
        .get(&StageId(SmolStr::new("controller")))
        .expect("controller stage present");
    assert!(
        controller
            .inputs
            .iter()
            .any(|input| input.from.0 == "validate")
    );
    // The non-loop factory's controller is the SHARED
    // `factory_loop_controller_stage` builder — a model-backed eight-tag
    // externally-tagged variant gate that declares `produces=contract(..)`. The
    // rich `output_schema` (NOT flat `outputs`) carries the decision variants.
    assert!(controller.prompt_template.contains("decision"));
    assert!(controller.prompt_template.contains("repair"));
    assert!(
        controller
            .prompt_template
            .contains("EXTERNALLY-TAGGED VARIANT json shape")
    );
    assert!(
        controller
            .prompt_template
            .contains("factory_active_context")
    );
    assert!(
        controller
            .prompt_template
            .contains("factory_controller_decisions")
    );
    assert!(
        controller
            .prompt_template
            .contains("external_inputs.steering.items")
    );
    assert!(
        controller
            .prompt_template
            .contains("external_inputs.controller.items")
    );
    // The controller emits its shape via `produces=contract(..)`, which lowers
    // to `StageDefinition.output_schema` (a constrained JSON Schema). The
    // frontend also DERIVES the flat `outputs` surface from that SAME contract,
    // and from nothing else: the flat outputs are exactly the contract's
    // top-level fields, so no hand-authored `outputs=` entry can ride beside
    // them.
    let flat_outputs: std::collections::BTreeSet<&str> = controller
        .outputs
        .iter()
        .map(|output| output.name.as_str())
        .collect();
    assert_eq!(
        flat_outputs,
        std::collections::BTreeSet::from(["decision", "memory_writebacks"]),
        "controller flat outputs are exactly the produces=contract top-level fields"
    );
    let controller_schema = controller
        .output_schema
        .as_ref()
        .expect("rerouted controller carries a rich output_schema (produces=contract)")
        .to_string();
    for tag in [
        "continue",
        "repair",
        "split",
        "reduce_scope",
        "promote",
        "stop",
        "park",
        "ask_human",
    ] {
        assert!(
            controller_schema.contains(tag),
            "controller output_schema missing decision variant {tag}"
        );
    }
    assert!(
        controller_schema.contains("memory_writebacks"),
        "controller output_schema missing memory_writebacks field"
    );
    assert_eq!(controller.timeout_ms, 240_000);

    let closeout = def
        .stages
        .get(&StageId(SmolStr::new("closeout")))
        .expect("closeout stage present");
    assert_eq!(closeout.timeout_ms, 180_000);
    assert!(
        closeout
            .inputs
            .iter()
            .any(|input| input.from.0 == "controller")
    );
    assert!(
        closeout
            .prompt_template
            .contains("external_inputs.steering.items")
    );
    assert!(
        closeout
            .prompt_template
            .contains("external_inputs.controller.items")
    );
    assert!(
        closeout
            .prompt_template
            .contains("post-run harness artifacts")
    );
    assert!(
        closeout
            .outputs
            .iter()
            .any(|output| output.name.as_str() == "candidate_state")
    );

    // Regression for the worker/gate model split: the canonical
    // pack passes `gate_agent = None`, so the controller GATE must STILL resolve
    // to the `default` worker label (no split). The gatesplit variant pack is
    // the only place the controller diverges to `gate`.
    let controller = def
        .stages
        .get(&StageId(SmolStr::new("controller")))
        .expect("controller stage present");
    assert_eq!(
        controller.agent,
        AgentSelector::Labelled(SmolStr::new("default")),
        "canonical pack controller must stay on default (gate_agent = None)"
    );
}

#[test]
fn starlark_eval_kata_self_improve_inloop_pack_builds() {
    let repo_root = repo_root();
    let stdlib_root = repo_root.join("workflows").join("std");
    let factory_root = repo_root.join("workflows").join("kata-factory");
    let source = std::fs::read_to_string(
        stdlib_root.join("std.software_factory.kata_self_improve_inloop.star"),
    )
    .expect("read kata self-improve in-loop factory pack");

    let checked = evaluate_starlark_with_loader_checked(
        &source,
        "std.software_factory.kata_self_improve_inloop.star",
        &[stdlib_root.clone(), factory_root.clone()],
    )
    .expect("kata self-improve in-loop factory pack must build through the stdlib loader");
    let def = checked.definition();

    assert_eq!(
        def.name.as_str(),
        "std.software_factory.kata_self_improve_inloop"
    );
    assert!(def.worktree_isolated);

    // ONE outer wave loop; there is no inner implement<->review loop.
    assert_eq!(def.review_loops.len(), 1);
    assert_eq!(def.review_loops[0].on_max, OnMaxAction::Accept);

    assert_eq!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .name
            .as_str(),
        "software_factory"
    );

    // The five model-backed wave stages + memory snapshot + controller are the
    // declared root; the eight branch arms are registered via branch(arms=..).
    for stage_id in [
        "memory_context",
        "context",
        "plan",
        "implement",
        "review",
        "validate",
        "controller",
    ] {
        assert!(
            def.stages.contains_key(&StageId(SmolStr::new(stage_id))),
            "wave stage {stage_id} present"
        );
    }

    // The `ask_human` block-verdict arm is wired to a DURABLE blocking
    // InputChannel — a `blocking` human_request targeting `ask_human_request`
    // with a finite `timeout_ms` (self-heal) and a `default_assumption`. This
    // is what makes "require human" durably PAUSE (park before dispatch) instead
    // of printing a marker that never blocks.
    let ask_human = checked
        .extensions()
        .human_request_queue
        .requests
        .iter()
        .find(|request| request.stage.as_deref() == Some("ask_human_request"))
        .expect("ask_human_request must carry a declared human_request");
    assert!(ask_human.blocking, "the ask_human request must be blocking");
    assert!(
        ask_human.timeout_ms.is_some_and(|ms| ms > 0),
        "the ask_human request must declare a finite self-heal timeout"
    );
    assert!(
        !ask_human.default_assumption.trim().is_empty(),
        "the ask_human request must declare a default_assumption for self-heal"
    );

    // The controller is the model-backed eight-tag variant gate: it depends on
    // the body exit `validate` and instructs the externally-tagged variant shape.
    let controller = def
        .stages
        .get(&StageId(SmolStr::new("controller")))
        .expect("controller stage present");
    assert!(
        controller
            .inputs
            .iter()
            .any(|input| input.from.0 == "validate")
    );
    assert!(
        controller
            .prompt_template
            .contains("EXTERNALLY-TAGGED VARIANT json shape")
    );
    assert_eq!(controller.timeout_ms, 240_000);

    // The memory selector software_factory_loop_workflow declares.
    assert_eq!(checked.extensions().memory_selectors.selectors.len(), 1);
    assert_eq!(
        checked.extensions().memory_selectors.selectors[0]
            .id
            .as_str(),
        "factory_active_context"
    );
    assert_eq!(checked.extensions().memory_writebacks.writebacks.len(), 2);
    assert!(
        checked
            .extensions()
            .memory_writebacks
            .writebacks
            .iter()
            .any(|wb| wb.id.as_str() == "factory_controller_decisions")
    );

    // Exactly one branch route, on the controller, exhaustive over all eight tags.
    assert_eq!(def.branch_routes.len(), 1);
    let route = &def.branch_routes[0];
    assert_eq!(route.condition_stage.0.as_str(), "controller");
    assert_eq!(route.verdict_field.as_str(), "decision");
    let mut tags: Vec<&str> = route.arms.iter().map(|arm| arm.tag.as_str()).collect();
    tags.sort_unstable();
    assert_eq!(
        tags,
        vec![
            "ask_human",
            "continue",
            "park",
            "promote",
            "reduce_scope",
            "repair",
            "split",
            "stop",
        ]
    );
    // The promote arm routes to the real workspace-effect promote stage.
    let promote_arm = route
        .arms
        .iter()
        .find(|arm| arm.tag.as_str() == "promote")
        .expect("promote arm present");
    assert!(
        promote_arm
            .targets
            .iter()
            .any(|target| target.0.as_str() == "promote_effect")
    );
}

#[test]
fn starlark_eval_kata_self_improve_inloop_gatesplit_pack_builds() {
    let repo_root = repo_root();
    let stdlib_root = repo_root.join("workflows").join("std");
    let factory_root = repo_root.join("workflows").join("kata-factory");
    let source = std::fs::read_to_string(
        stdlib_root.join("std.software_factory.kata_self_improve_inloop_gatesplit.star"),
    )
    .expect("read kata self-improve in-loop gatesplit factory pack");

    let checked = evaluate_starlark_with_loader_checked(
        &source,
        "std.software_factory.kata_self_improve_inloop_gatesplit.star",
        &[stdlib_root.clone(), factory_root.clone()],
    )
    .expect(
        "kata self-improve in-loop gatesplit factory pack must build through the stdlib loader",
    );
    let def = checked.definition();

    assert_eq!(
        def.name.as_str(),
        "std.software_factory.kata_self_improve_inloop_gatesplit"
    );
    assert!(def.worktree_isolated);

    // Same in-execution loop shape as the canonical inloop pack: ONE outer wave
    // loop, software_factory workflow pattern.
    assert_eq!(def.review_loops.len(), 1);
    assert_eq!(def.review_loops[0].on_max, OnMaxAction::Accept);
    assert_eq!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .name
            .as_str(),
        "software_factory"
    );

    // Agent selectors surface as `StageDefinition.agent: AgentSelector`. Both the
    // dict and starlark frontends wrap a non-empty agent string as
    // `AgentSelector::Labelled(<string>)`, never resolving it to a
    // `BackendType::Backend` variant at this layer — so a string-equality
    // assertion against the label is exact and non-vacuous.
    //
    // Worker/gate split: the in-execution loop GATE is the `controller` stage
    // (`factory_loop_controller_stage(agent = gate_agent or reasoning_agent)`); it
    // routes to the distinct `gate` label (operator wires it to a stronger
    // model)...
    let controller = def
        .stages
        .get(&StageId(SmolStr::new("controller")))
        .expect("controller stage present");
    // Belt-and-suspenders that this IS the loop gate: it is the branch route's
    // condition stage and depends on the wave body exit `validate`.
    assert_eq!(def.branch_routes.len(), 1);
    assert_eq!(
        def.branch_routes[0].condition_stage.0.as_str(),
        "controller"
    );
    assert!(
        controller
            .inputs
            .iter()
            .any(|input| input.from.0 == "validate"),
        "controller gate must consume the wave body exit `validate`"
    );
    assert_eq!(
        controller.agent,
        AgentSelector::Labelled(SmolStr::new("gate")),
        "inloop gatesplit pack controller gate must route to gate"
    );

    // ...while the wave-body WORKER stages (context + implement shown) stay on
    // `default`.
    for worker_stage in ["context", "implement"] {
        let stage = def
            .stages
            .get(&StageId(SmolStr::new(worker_stage)))
            .unwrap_or_else(|| panic!("{worker_stage} stage present"));
        assert_eq!(
            stage.agent,
            AgentSelector::Labelled(SmolStr::new("default")),
            "inloop gatesplit pack worker stage {worker_stage} must stay on default"
        );
    }

    // Belt-and-suspenders: the distinct agent-label SET contains BOTH the split
    // gate label and the worker label.
    let labels: std::collections::BTreeSet<&str> = def
        .stages
        .values()
        .filter_map(|stage| match &stage.agent {
            AgentSelector::Labelled(label) => Some(label.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        labels.contains("gate"),
        "inloop gatesplit pack distinct agent labels must contain gate, got {labels:?}"
    );
    assert!(
        labels.contains("default"),
        "inloop gatesplit pack workers must still use default, got {labels:?}"
    );
}

#[test]
fn starlark_eval_kata_self_improve_preflight_pack_builds() {
    let repo_root = repo_root();
    let stdlib_root = repo_root.join("workflows").join("std");
    let factory_root = repo_root.join("workflows").join("kata-factory");
    let source = std::fs::read_to_string(
        stdlib_root.join("std.software_factory.kata_self_improve_preflight.star"),
    )
    .expect("read kata self-improve preflight factory pack");

    let checked = evaluate_starlark_with_loader_checked(
        &source,
        "std.software_factory.kata_self_improve_preflight.star",
        &[stdlib_root.clone(), factory_root.clone()],
    )
    .expect("kata self-improve preflight factory pack must build through the stdlib loader");
    let def = checked.definition();

    assert_eq!(
        def.name.as_str(),
        "std.software_factory.kata_self_improve_preflight"
    );
    assert!(def.worktree_isolated);
    assert_eq!(def.stages.len(), 8);
    assert_eq!(
        def.review_loops.len(),
        0,
        "validation-only preflight must not dispatch mutating review loops"
    );
    assert_eq!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .name
            .as_str(),
        "software_factory"
    );
    assert!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .capabilities
            .iter()
            .any(|capability| capability.as_str() == "validation_only_preflight")
    );
    assert_eq!(
        checked.extensions().external_input_channels.channels.len(),
        3
    );
    assert_eq!(checked.extensions().memory_selectors.selectors.len(), 1);
    // Six criteria: a closeout packet and a model controller's verdict are not
    // validation proofs (the promotion gate may not trust either with a
    // verdict), so the pack declares no criterion for them.
    assert_eq!(checked.extensions().validation_criteria.criteria.len(), 6);

    let implement = def
        .stages
        .get(&StageId(SmolStr::new("implement")))
        .expect("implement stage present");
    assert_eq!(
        implement.sandbox,
        Some(SandboxRef::Named("factory-review".to_string())),
        "validation-only implement stage must use the read-only factory sandbox"
    );
    assert!(
        implement
            .topology
            .as_ref()
            .is_some_and(|topology| topology.mutation_policy.label() == "advisory"),
        "validation-only implement stage must not declare owned-path mutation authority"
    );
    assert!(implement.prompt_template.contains("changed_files"));
    assert!(
        implement
            .prompt_template
            .contains("validation-only preflight")
    );

    let validate = def
        .stages
        .get(&StageId(SmolStr::new("validate")))
        .expect("validate stage present");
    assert!(
        validate
            .prompt_template
            .contains("kata check std.software_factory.kata_self_improve_preflight")
    );
    // The validate stage must name PRODUCT commands, never a `just` recipe: it
    // executes in the execution workspace, where `just` reports `error: No
    // justfile found`, and a pack whose command invoked this test would only prove
    // the string was present, never that the command could RUN. The
    // pack validates itself with the shipped binary, so it works for someone who
    // pulled it off a shelf rather than only inside this repo.
    assert!(
        validate
            .prompt_template
            .contains("kata build std.software_factory.kata_self_improve_preflight"),
        "the validate stage must declare the product BUILD command, not just the check"
    );
    assert!(
        !validate.prompt_template.contains("just test-one-crate"),
        "a product pack must not validate via the dev harness — it cannot run outside \
         this repo, and it could not run inside it either"
    );

    let controller = def
        .stages
        .get(&StageId(SmolStr::new("controller")))
        .expect("controller stage present");
    assert!(controller.prompt_template.contains("validation_passed"));
    assert!(
        controller
            .prompt_template
            .contains("decision = \"stop\" if validation_passed else \"repair\"")
    );
    assert!(
        controller
            .outputs
            .iter()
            .any(|output| output.name.as_str() == "memory_writebacks")
    );
}

#[test]
fn starlark_eval_kata_self_improve_implementation_smoke_pack_builds() {
    let repo_root = repo_root();
    let stdlib_root = repo_root.join("workflows").join("std");
    let factory_root = repo_root.join("workflows").join("kata-factory");
    let source = std::fs::read_to_string(
        repo_root
            .join("workflows/smoke")
            .join("std.software_factory.kata_self_improve_implementation_smoke.star"),
    )
    .expect("read kata self-improve implementation smoke factory pack");

    let checked = evaluate_starlark_with_loader_checked(
        &source,
        "std.software_factory.kata_self_improve_implementation_smoke.star",
        &[stdlib_root.clone(), factory_root.clone()],
    )
    .expect("kata self-improve implementation smoke pack must build through the stdlib loader");
    let def = checked.definition();

    assert_eq!(
        def.name.as_str(),
        "std.software_factory.kata_self_improve_implementation_smoke"
    );
    assert!(def.worktree_isolated);
    assert_eq!(def.stages.len(), 7);
    assert_eq!(def.review_loops.len(), 1);
    assert_eq!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .name
            .as_str(),
        "software_factory_smoke"
    );
    // Five criteria: a closeout packet and a controller verdict are not
    // validation proofs, and under the declaration binding a criterion is what
    // makes its stage record VALIDATION evidence.
    assert_eq!(checked.extensions().validation_criteria.criteria.len(), 5);
    assert!(
        checked
            .extensions()
            .validation_criteria
            .criteria
            .iter()
            .any(|criterion| criterion.id.as_str() == "candidate-mutation")
    );

    let implement = def
        .stages
        .get(&StageId(SmolStr::new("implement")))
        .expect("implement stage present");
    assert!(
        implement
            .prompt_template
            .contains("roadmap/kata-self-improve-implementation-smoke.md")
    );
    let validate = def
        .stages
        .get(&StageId(SmolStr::new("validate")))
        .expect("validate stage present");
    // The deterministic validation inspects the target artifact inside the
    // confined workspace — `test -f` + `grep -q`, no git and no host state.
    assert!(validate.prompt_template.contains("test -f"));
    assert!(validate.prompt_template.contains("grep -q"));
    assert!(
        validate
            .prompt_template
            .contains("roadmap/kata-self-improve-implementation-smoke.md")
    );
    let controller = def
        .stages
        .get(&StageId(SmolStr::new("controller")))
        .expect("controller stage present");
    assert!(controller.prompt_template.contains(r#""decision":"park""#));
}

/// The model-free `parallel-smoke` live-proof pack builds
/// through the native graph DSL into a checked definition whose synthetic JOIN
/// fans in BOTH branches and gates the downstream collector. This is the
/// build-time mirror of the live smoke (`workflows/smoke/parallel-smoke.star`).
#[test]
fn starlark_eval_parallel_smoke_pack_builds() {
    let repo_root = repo_root();
    let source = std::fs::read_to_string(
        repo_root
            .join("workflows")
            .join("smoke")
            .join("parallel-smoke.star"),
    )
    .expect("read parallel-smoke pack");

    let checked = evaluate_starlark_checked(&source, "parallel-smoke.star")
        .expect("parallel-smoke pack must build");
    let def = checked.definition();

    assert_eq!(def.name.as_str(), "parallel-smoke");
    // branch_a, branch_b, collector, + the synthetic __parallel_join_0.
    assert_eq!(def.stages.len(), 4);
    assert_eq!(def.max_concurrency, Some(2));

    // The synthetic join fans in BOTH branches and is a deterministic shell
    // no-op with the default cache policy (never trips clause-4). RE-PINNED at
    // That default is `Omitted` — `StageFlatFields::join_default`
    // reads `CachePolicy::default()`, and the whole point of that field is that
    // a synthetic join lowers byte-identically to a minimal AUTHORED stage,
    // which now lowers `""` to `Omitted`.
    let join = def
        .stages
        .get(&StageId(SmolStr::new("__parallel_join_0")))
        .expect("synthetic parallel join present");
    assert_eq!(join.agent, AgentSelector::Labelled(SmolStr::new("shell")));
    assert_eq!(join.cache_policy, CachePolicy::Omitted);
    let mut join_deps: Vec<String> = join.inputs.iter().map(|i| i.from.0.to_string()).collect();
    join_deps.sort();
    assert_eq!(
        join_deps,
        vec!["branch_a".to_string(), "branch_b".to_string()],
        "the join must depend_on BOTH branches"
    );

    // The collector chains off the join (waits for all branches), and the two
    // branches do NOT depend on each other (true fan-out).
    let collector = def
        .stages
        .get(&StageId(SmolStr::new("collector")))
        .expect("collector stage present");
    let collector_deps: Vec<String> = collector
        .inputs
        .iter()
        .map(|i| i.from.0.to_string())
        .collect();
    assert_eq!(collector_deps, vec!["__parallel_join_0".to_string()]);

    for branch in ["branch_a", "branch_b"] {
        let stage = def
            .stages
            .get(&StageId(SmolStr::new(branch)))
            .unwrap_or_else(|| panic!("{branch} present"));
        assert!(
            stage.inputs.is_empty(),
            "{branch} must have no upstream (fan-out branches share no edge)"
        );
    }
}

#[test]
fn starlark_eval_standard_software_factory_smoke_pack_builds() {
    let repo_root = repo_root();
    let stdlib_root = repo_root.join("workflows").join("std");
    let factory_root = repo_root.join("workflows").join("kata-factory");
    let source = std::fs::read_to_string(
        repo_root
            .join("workflows/smoke")
            .join("std.software_factory.smoke.star"),
    )
    .expect("read deterministic factory smoke pack");

    let checked = evaluate_starlark_with_loader_checked(
        &source,
        "std.software_factory.smoke.star",
        &[stdlib_root.clone(), factory_root.clone()],
    )
    .expect("deterministic factory smoke pack must build through the stdlib loader");
    let def = checked.definition();

    assert_eq!(def.name.as_str(), "std.software_factory.smoke");
    assert!(def.worktree_isolated);
    assert_eq!(def.stages.len(), 7);
    assert_eq!(def.review_loops.len(), 1);
    assert_eq!(
        checked
            .extensions()
            .workflow_pattern
            .as_ref()
            .expect("workflow pattern")
            .name
            .as_str(),
        "software_factory_smoke"
    );
    // Five criteria: no controller-decision or closeout criterion.
    assert_eq!(checked.extensions().validation_criteria.criteria.len(), 5);
    assert!(
        checked
            .extensions()
            .validation_criteria
            .criteria
            .iter()
            .any(|criterion| criterion.id.as_str() == "candidate-mutation")
    );
    // No `controller-decision` criterion; see the count note above.
    assert!(
        !checked
            .extensions()
            .validation_criteria
            .criteria
            .iter()
            .any(|criterion| criterion.id.as_str() == "controller-decision")
    );
    assert!(
        checked
            .extensions()
            .external_input_channels
            .channels
            .iter()
            .any(|channel| channel.id.as_str() == "controller_decision"
                && channel.expose_as.as_str() == "controller")
    );
    let validate = def
        .stages
        .get(&StageId(SmolStr::new("validate")))
        .expect("validate stage present");
    // The deterministic validation inspects the target artifact inside the
    // confined workspace — `test -f` + `grep -q`, no git and no host state.
    assert!(validate.prompt_template.contains("test -f"));
    assert!(validate.prompt_template.contains("grep -q"));
    assert!(
        validate
            .outputs
            .iter()
            .any(|output| output.name.as_str() == "criteria")
    );
    let controller = def
        .stages
        .get(&StageId(SmolStr::new("controller")))
        .expect("controller stage present");
    assert!(
        controller
            .inputs
            .iter()
            .any(|input| input.from.0 == "validate")
    );
    assert!(controller.prompt_template.contains(r#""decision":"park""#));
    assert!(
        controller
            .outputs
            .iter()
            .any(|output| output.name.as_str() == "memory_writebacks")
    );
    let closeout = def
        .stages
        .get(&StageId(SmolStr::new("closeout")))
        .expect("closeout stage present");
    assert!(
        closeout
            .inputs
            .iter()
            .any(|input| input.from.0 == "controller")
    );
}

#[test]
fn load_without_loader_roots_is_rejected() {
    // Default path: no loader installed, so `load()` must fail
    // rather than silently falling back to filesystem reads.
    let source = r#"
load("helpers.star", "x")

s = stage(prompt = "p", agent = "worker")
workflow("bad", root = s)
"#;
    let err = evaluate_starlark_checked(source, "bad.star")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Starlark eval error") || err.contains("load"),
        "expected eval error, got: {err}"
    );
}

/// The positive fast-workflow budget guard. A trivial native
/// `stage()` + `workflow()` source must still evaluate successfully under a tight
/// 5s budget — the watchdog/limiter wrapper adds no measurable per-evaluation
/// overhead, so a fast workflow never trips the budget.
#[test]
fn small_budget_still_allows_fast_native_workflows() {
    let source = r#"
s = stage(id = "s", prompt = "do s", agent = "worker")
workflow("fast-native", root = s)
"#;
    let checked = evaluate_starlark_checked_with_budget_for_tests(
        source,
        "fast-native.star",
        Duration::from_secs(5),
    )
    .expect("a trivial native workflow must evaluate well within a 5s budget");
    assert_eq!(checked.definition().name.as_str(), "fast-native");
}

/// Adversarial-draw conformance: `arbitrary`-driven conformance harness for the
/// Starlark workflow DSL frontend — the highest-value untrusted-input
/// surface in this crate.
///
/// Workflow `.star` source is normally operator-authored, but `kata
/// build` also compiles workflow definitions that can originate from
/// less-trusted packs, so the frontend must degrade to a `KataError`
/// on any malformed input — never panic, OOM, or hang. This harness
/// feeds two disjoint input shapes through the full frontend
/// (`AstModule::parse` → kata DSL builtins → JSON normalize →
/// validate): raw arbitrary UTF-8, and grammar-aware "token soup"
/// spliced from DSL keywords/builtins so evaluation reaches deep past
/// the lexer into builtin dispatch and normalization.
///
/// Determinism + speed: inputs come from fixed seeds via a splitmix64
/// PRNG (no OS entropy), the sample count is fixed, and each evaluation
/// is pinned to a small wall-clock budget so a pathological near-valid
/// input cannot stall the gate. The `conformance` module path makes it
/// ride `just test-conformance`.
mod conformance {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};

    /// Fixed per-input evaluation budget. Small enough that an input
    /// that trips an eval loop can't stall the gate; large enough that
    /// a legitimately fast workflow still finishes.
    const FUZZ_EVAL_BUDGET: Duration = Duration::from_millis(250);

    /// Deterministic sample count. Kept modest so the harness stays
    /// well under a second even if a handful of inputs reach the budget.
    const FUZZ_SAMPLES: u64 = 256;

    /// Deterministic splitmix64 step. Same seed → same stream on every
    /// platform, so any failing sample is exactly reproducible.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Fill a deterministic byte buffer for `Unstructured` from a seed.
    fn seed_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&splitmix64(&mut state).to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Grammar-aware token alphabet: keywords, kata DSL builtin names,
    /// punctuation, and literals. Splicing these reaches far deeper into
    /// the frontend than raw random UTF-8, which nearly always dies at
    /// the lexer.
    const TOKENS: &[&str] = &[
        "workflow",
        "stage",
        "workflow",
        "sequence",
        "loop",
        "def ",
        "return ",
        "contract",
        "field",
        "enum",
        "list_of",
        "variant",
        "cost_budget",
        "prompt",
        "agent",
        "id",
        "root",
        "name",
        "on_max",
        "=",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        ",",
        ":",
        "\n",
        "  ",
        "\"x\"",
        "\"worker\"",
        "0",
        "1",
        "-1",
        "True",
        "False",
        "None",
        "load",
        "+",
    ];

    /// Build a near-valid source string by splicing tokens under seed
    /// control, occasionally interleaving raw arbitrary text to perturb
    /// the grammar.
    fn token_soup(u: &mut Unstructured<'_>) -> String {
        let n = u.int_in_range(0u32..=64).unwrap_or(0);
        let mut s = String::new();
        for _ in 0..n {
            let pick = u.int_in_range(0usize..=TOKENS.len() + 2).unwrap_or(0);
            if let Some(tok) = TOKENS.get(pick) {
                s.push_str(tok);
            } else if let Ok(extra) = <&str>::arbitrary(u) {
                s.push_str(extra);
            }
        }
        s
    }

    #[test]
    fn starlark_frontend_arbitrary_source_never_panics() {
        let mut completed = 0u64;
        for seed in 0..FUZZ_SAMPLES {
            // Raw arbitrary UTF-8: exercises the lexer/parser error path.
            let raw_buf = seed_bytes(seed, 96);
            let mut u_raw = Unstructured::new(&raw_buf);
            let raw = String::arbitrary(&mut u_raw).unwrap_or_default();
            let _ = evaluate_starlark_checked_with_budget_for_tests(
                &raw,
                "fuzz-raw.star",
                FUZZ_EVAL_BUDGET,
            );

            // Grammar-aware token soup: reaches builtin dispatch,
            // JSON normalization, and validation with malformed shapes.
            let soup_buf = seed_bytes(seed ^ 0xA5A5_A5A5_A5A5_A5A5, 160);
            let mut u_soup = Unstructured::new(&soup_buf);
            let soup = token_soup(&mut u_soup);
            let _ = evaluate_starlark_checked_with_budget_for_tests(
                &soup,
                "fuzz-soup.star",
                FUZZ_EVAL_BUDGET,
            );

            completed += 1;
        }
        // Reaching here without a panic/hang IS the property under test;
        // the count assertion documents the fixed, deterministic budget.
        assert_eq!(completed, FUZZ_SAMPLES);
    }
}

/// Collect-all + "did you mean" DSL diagnostics, exercised END-TO-END
/// through the real evaluator seam (`evaluate_starlark_checked`), the exact path
/// `kata workflows check` / `kata check` compile through.
///
/// Pristine starlark-rust surfaces three common authoring stumbles as
/// bare, non-actionable errors — `Found \`model\` extra named parameter(s) for
/// call to stage`, `Missing positional-only parameter \`name\``, and `Missing
/// named-only parameter \`root\``. None names the fix. Here each renders a
/// one-shot actionable message, and a multi-error file reports ALL of them at
/// once instead of first-error-wins.
#[cfg(test)]
mod authoring_diagnostics {
    use super::evaluate_starlark_checked;

    /// The collect-all diagnostic carries its `pack.star:LINE:COL`
    /// CALL-SITE span — threaded from the evaluator's call-stack top location —
    /// so an author is pointed at the exact offending `stage()` / `workflow()`
    /// call, not just told the builtin name.
    #[test]
    fn diagnostic_carries_call_site_span() {
        // The bad `model=` kwarg is on the `stage()` call at line 2, column 5
        // (`s = ` is 4 columns; the call expression starts at `stage`).
        let source = "# a leading comment\ns = stage(prompt = \"x\", agent = \"worker\", model = \"opus\")\nworkflow(\"w\", root = s)\n";
        let msg = evaluate_starlark_checked(source, "pack.star")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("pack.star:2:5: ✗ stage() got an unknown keyword `model`"),
            "want the pack.star:LINE:COL call-site span prefix, got: {msg}"
        );
    }

    /// A `workflow()` diagnostic likewise carries its own call-site span.
    #[test]
    fn workflow_diagnostic_carries_call_site_span() {
        let source =
            "s = stage(prompt = \"x\", agent = \"worker\")\nworkflow(name = \"w\", root = s)\n";
        let msg = evaluate_starlark_checked(source, "pack.star")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("pack.star:2:1: ✗ workflow()'s name is the first POSITIONAL argument"),
            "want the workflow() call-site span at line 2 col 1, got: {msg}"
        );
    }

    /// Stumble 1: `model=` instead of `model_hint=` on `stage()`.
    #[test]
    fn stage_model_kwarg_suggests_model_hint() {
        let source = "s = stage(prompt = \"x\", agent = \"worker\", model = \"opus\")\nworkflow(\"w\", root = s)\n";
        let msg = evaluate_starlark_checked(source, "s1.star")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("stage() got an unknown keyword `model`; did you mean `model_hint`?"),
            "want the model→model_hint suggestion, got: {msg}"
        );
        // The full accepted-keyword menu rides along.
        assert!(
            msg.contains("accepted stage() keywords: agent, allowed_tools,"),
            "want the accepted stage() menu, got: {msg}"
        );
    }

    /// Stumble 2: `workflow(name=..)` — name is the first positional argument.
    #[test]
    fn workflow_name_as_kwarg_states_positional_signature() {
        let source =
            "s = stage(prompt = \"x\", agent = \"worker\")\nworkflow(name = \"w\", root = s)\n";
        let msg = evaluate_starlark_checked(source, "s2.star")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains(
                "workflow()'s name is the first POSITIONAL argument, not a keyword — \
                 write workflow(\"my-workflow\", root=...)"
            ),
            "want the positional-name signature, got: {msg}"
        );
    }

    /// A `workflow()` whose positional name is omitted entirely is likewise
    /// taught the positional signature.
    #[test]
    fn workflow_missing_name_states_positional_signature() {
        let source = "s = stage(prompt = \"x\", agent = \"worker\")\nworkflow(root = s)\n";
        let msg = evaluate_starlark_checked(source, "s2b.star")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("workflow() is missing its name — it is the first POSITIONAL argument"),
            "want the missing-name diagnostic, got: {msg}"
        );
    }

    /// A name supplied BOTH positionally and as a `name=` keyword must NOT be
    /// silently dropped — the redundant keyword lands in the catch-all and is
    /// reported (the catch-all would otherwise swallow it).
    #[test]
    fn workflow_duplicate_name_positional_and_kwarg_is_reported() {
        let source = "s = stage(prompt = \"x\", agent = \"worker\")\nworkflow(\"w\", name = \"x\", root = s)\n";
        let msg = evaluate_starlark_checked(source, "dupname.star")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("workflow() got its name both positionally and as a `name=` keyword"),
            "want the duplicate-name diagnostic, got: {msg}"
        );
        // It must NOT be mistaken for a plain unknown keyword (`name` is pulled
        // out of the catch-all before the unknown-kwarg pass).
        assert!(
            !msg.contains("unknown keyword `name`"),
            "duplicate name must not render as a generic unknown keyword: {msg}"
        );
    }

    /// Stumble 3: `stages=` instead of `root=` on `workflow()`.
    #[test]
    fn workflow_stages_kwarg_suggests_root() {
        let source = "s = stage(prompt = \"x\", agent = \"worker\")\nworkflow(\"w\", stages = s)\n";
        let msg = evaluate_starlark_checked(source, "s3.star")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("workflow() got an unknown keyword `stages`; did you mean `root`?"),
            "want the stages→root suggestion, got: {msg}"
        );
        // A single mis-named keyword must NOT ALSO emit a redundant "missing
        // root" line for the same underlying mistake.
        assert!(
            !msg.contains("missing its required root="),
            "stages→root should not double-report a missing root: {msg}"
        );
    }

    /// COLLECT-ALL: a file with several distinct definition errors reports EVERY
    /// one in a single diagnostic pass rather than stopping at the first.
    #[test]
    fn collect_all_reports_every_error_in_one_pass() {
        let source = "\
a = stage(prompt = \"x\", agent = \"worker\", model = \"opus\")
b = stage(prompt = \"y\", agent = \"worker\", modl_hint = \"z\", depends_on = [a])
workflow(\"w\", stages = b)
";
        let msg = evaluate_starlark_checked(source, "multi.star")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("3 definition errors found"),
            "want a 3-error collect-all header, got: {msg}"
        );
        assert!(
            msg.contains("unknown keyword `model`; did you mean `model_hint`?"),
            "error 1 (model) missing from collect-all: {msg}"
        );
        assert!(
            msg.contains("unknown keyword `modl_hint`; did you mean `model_hint`?"),
            "error 2 (modl_hint typo) missing from collect-all: {msg}"
        );
        assert!(
            msg.contains("unknown keyword `stages`; did you mean `root`?"),
            "error 3 (stages→root) missing from collect-all: {msg}"
        );
        // Both builtins' accepted menus ride along, once each.
        assert!(
            msg.contains("accepted stage() keywords:"),
            "stage menu: {msg}"
        );
        assert!(
            msg.contains("accepted workflow() keywords:"),
            "workflow menu: {msg}"
        );
    }

    /// A CLEAN workflow is entirely unaffected — no diagnostics, no behavior
    /// change (the catch-all only fires on unrecognized keywords).
    #[test]
    fn clean_workflow_compiles_unaffected() {
        let source = "\
s = stage(prompt = \"x\", agent = \"worker\", model_hint = \"opus\")
workflow(\"w\", root = s)
";
        assert!(
            evaluate_starlark_checked(source, "clean.star").is_ok(),
            "a valid workflow must still compile with no diagnostics"
        );
    }
}
// ── agent fallback panel lowering ────────────────────────────────────────────

/// `stage(agent=["primary","fallback"])` lowers to `AgentSelector::Panel`, while
/// the scalar `agent="worker"` spelling stays `Labelled` (single-agent stages
/// unchanged).
#[test]
fn stage_agent_list_lowers_to_panel() {
    let source = r#"
prim = stage(prompt = "impl", agent = ["primary", "fallback"], id = "prim")
solo = stage(prompt = "solo", agent = "worker", id = "solo")
bare = stage(prompt = "bare", id = "bare")
workflow("panel-demo", root = [prim, solo, bare])
"#;
    let def = evaluate_starlark_checked(source, "panel-demo.star")
        .expect("panel workflow builds")
        .definition()
        .clone();

    assert_eq!(
        def.stages
            .get(&StageId(SmolStr::new("prim")))
            .unwrap()
            .agent,
        AgentSelector::Panel(vec![SmolStr::new("primary"), SmolStr::new("fallback")]),
        "a 2+-member agent list lowers to AgentSelector::Panel (primary first)"
    );
    assert_eq!(
        def.stages
            .get(&StageId(SmolStr::new("solo")))
            .unwrap()
            .agent,
        AgentSelector::Labelled(SmolStr::new("worker")),
        "the scalar agent= spelling is unchanged"
    );
    assert_eq!(
        def.stages
            .get(&StageId(SmolStr::new("bare")))
            .unwrap()
            .agent,
        AgentSelector::Any,
        "an omitted agent= stays Any"
    );
}

/// A one-element list collapses to the scalar `Labelled` form so it is
/// byte-identical to `agent="only"`.
#[test]
fn stage_single_element_agent_list_collapses_to_labelled() {
    let source = r#"
only = stage(prompt = "x", agent = ["only"], id = "only")
workflow("collapse-demo", root = [only])
"#;
    let def = evaluate_starlark_checked(source, "collapse-demo.star")
        .expect("single-member list builds")
        .definition()
        .clone();
    assert_eq!(
        def.stages
            .get(&StageId(SmolStr::new("only")))
            .unwrap()
            .agent,
        AgentSelector::Labelled(SmolStr::new("only")),
        "a one-element agent list is a single-agent stage, not a panel"
    );
}

/// An empty agent list is an authoring error, rejected at construction time.
#[test]
fn stage_empty_agent_list_is_rejected() {
    let source = r#"
bad = stage(prompt = "x", agent = [], id = "bad")
workflow("bad-demo", root = [bad])
"#;
    let err = evaluate_starlark_checked(source, "bad-demo.star")
        .expect_err("empty agent list must be rejected")
        .to_string();
    assert!(
        err.contains("agent=[]") || err.contains("at least one agent"),
        "empty-panel error should be actionable: {err}"
    );
}

/// Every top-level `workflows/std/*.star` and `workflows/smoke/*.star` pack,
/// evaluated through the stdlib loader into its checked definition (no node
/// CHECK), with its path relative to `workflows/`. Every one must evaluate: a pack
/// that does not panics naming itself, so no pack drops out of a caller's refusal
/// unseen.
fn std_and_smoke_pack_definitions() -> Vec<(String, kata_types::workflow::WorkflowDefinition)> {
    let workflows = repo_root().join("workflows");
    let roots = [
        workflows.join("std"),
        workflows.join("kata-factory"),
        workflows.join("smoke"),
    ];
    let mut packs: Vec<(String, PathBuf)> = Vec::new();
    for tree in ["std", "smoke"] {
        packs.extend(
            std::fs::read_dir(workflows.join(tree))
                .unwrap_or_else(|error| panic!("workflows/{tree} reads: {error}"))
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "star"))
                .map(|path| (tree.to_owned(), path)),
        );
    }
    packs.sort();
    packs
        .into_iter()
        .map(|(tree, path)| {
            let source = std::fs::read_to_string(&path).expect("a pack reads");
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a pack's file name is UTF-8")
                .to_owned();
            let checked = evaluate_starlark_with_loader_checked(&source, &name, &roots)
                .unwrap_or_else(|error| panic!("{tree}/{name} evaluates: {error}"));
            (format!("{tree}/{name}"), checked.definition().clone())
        })
        .collect()
}

/// **The std packs author no spend limit and no spend budget, only `time_bound`s.**
/// kata applies no spend limit by default; a `cost_bound` or `token_bound` is
/// opt-in and CHECK refuses a `cost_bound` wherever kata cannot price its
/// adapter's spend, so a shipped std pack — read off its checked definition, including the
/// workflows the `kata/factory.star` helpers build for it — bounds its workflow
/// and its loops with `time_bound`s alone and declares no `cost_budget` of any
/// mode, `warn` or `halt`, at workflow or stage scope. A `warn` budget halts
/// nothing and, under an unpriced adapter, never fires: shipping one would claim
/// a spend watch kata cannot keep. The `workflows/smoke` rigs the gate runs are
/// held to the same rule. (The examples may keep opt-in dollar bounds, as
/// documented demonstrations of the refusal.)
///
/// **Would red if:** a std or smoke pack authored a `cost_bound` or `token_bound`
/// (workflow or loop scope) or any `cost_budget(..)` (workflow or stage scope).
#[test]
fn the_std_packs_author_no_spend_limit_or_budget_but_a_time_bound() {
    use kata_types::bound::Bound;
    use kata_types::budget::BudgetPolicy;
    let packs = std_and_smoke_pack_definitions();
    assert!(
        packs.len() >= 40,
        "the std and smoke corpus evaluates: {} packs",
        packs.len()
    );
    let mut limits = Vec::new();
    for (pack, definition) in &packs {
        let not_time = |bounds: &[Bound]| {
            bounds
                .iter()
                .filter(|bound| !matches!(bound, Bound::Time { .. }))
                .map(|bound| format!("{bound:?}"))
                .collect::<Vec<_>>()
        };
        let workflow = not_time(&definition.bounds);
        if !workflow.is_empty() {
            limits.push(format!("{pack}: workflow bounds {workflow:?}"));
        }
        for review_loop in &definition.review_loops {
            let looped = not_time(&review_loop.bounds);
            if !looped.is_empty() {
                limits.push(format!("{pack}: loop bounds {looped:?}"));
            }
        }
        if definition.cost_budget != BudgetPolicy::Unlimited {
            limits.push(format!(
                "{pack}: workflow cost_budget {:?}",
                definition.cost_budget
            ));
        }
        for (stage, declared) in &definition.stages {
            if declared.cost_budget != BudgetPolicy::Unlimited {
                limits.push(format!(
                    "{pack}: stage {} cost_budget {:?}",
                    stage.0, declared.cost_budget
                ));
            }
        }
    }
    assert!(
        limits.is_empty(),
        "std or smoke packs authoring a spend limit or budget:\n{}",
        limits.join("\n")
    );
}
/// **`review-loop-smoke`, `sandbox-smoke-workspace-ro` and `self-review` author
/// `net = "offline"`.** Their model stages need none of the node's `[node]
/// egress_allow` — an agent's model calls leave from the worker, never from its
/// capsule — so, under the offline default (B5), every stage of each, read off
/// its checked definition through its inline or named profile, is offline.
///
/// **Would red if:** any of the three authored `net = "host"`.
#[test]
fn the_offline_smoke_and_review_packs_author_no_node_egress() {
    use kata_types::sandbox::NetPolicy;
    let packs = std_and_smoke_pack_definitions();
    let mut host = Vec::new();
    for wanted in [
        "smoke/review-loop-smoke.star",
        "smoke/sandbox-smoke-workspace-ro.star",
        "std/self-review.star",
    ] {
        let (_, definition) = packs
            .iter()
            .find(|(pack, _)| pack == wanted)
            .unwrap_or_else(|| panic!("{wanted} evaluates"));
        for (stage, declared) in &definition.stages {
            let net = match declared.sandbox.as_ref() {
                Some(SandboxRef::Inline(profile)) => Some(profile.net.clone()),
                Some(SandboxRef::Named(name)) => definition
                    .sandbox_profiles
                    .get(name)
                    .map(|profile| profile.net.clone()),
                None => None,
            };
            if let Some(net) = net
                && net != NetPolicy::Offline
            {
                host.push(format!("{wanted}: stage {} net {net:?}", stage.0));
            }
        }
    }
    assert!(
        host.is_empty(),
        "stages authoring node egress:\n{}",
        host.join("\n")
    );
}
